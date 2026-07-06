"""
server/config.py — Load and validate server.yml.

Auto-generates jwt_secret on first run and writes it back to the file.

auth_mode:
  local       — username/password from users[] in server.yml (default)
  oidc-manual — OIDC via Keycloak; allowed_identities whitelist required
  oidc-auto   — OIDC via Keycloak; any authenticated user allowed unless blocked
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

DEFAULT_PATH = Path("server.yml")

VALID_AUTH_MODES = {"local", "oidc-manual", "oidc-auto"}


@dataclass
class TLSConfig:
    mode: str = "self-signed"   # "self-signed" | "provided"
    cert: str = "certs/server.crt"
    key: str  = "certs/server.key"


@dataclass
class User:
    username: str
    password: str  # cleartext — file must be chmod 600


@dataclass
class OIDCConfig:
    provider_url: str          = ""
    client_id: str             = ""
    client_secret: str         = ""
    # Claim used as stable identity key (whitelist/blocklist, file config, session).
    # Normalised to lowercase internally.
    # Default: email. Alternatives: preferred_username, sub, name, or any custom claim.
    identity_claim: str        = "email"
    # Claim shown in WebUI as display name. Not normalised, not used as key.
    # Default: preferred_username. Alternatives: name, email, given_name, or any custom claim.
    display_claim: str         = "preferred_username"
    # oidc-manual only: whitelist of identity_claim values
    allowed_identities: list   = field(default_factory=list)
    # oidc-auto only: blocklist of identity_claim values
    blocked_identities: list   = field(default_factory=list)


@dataclass
class Settings:
    jwt_expiry_hours: int            = 24
    jwt_secret: str                  = ""
    build_timeout_sec: int           = 300
    heartbeat_retain_days: int       = 90
    cmd_lock_timeout_multiplier: int = 5
    hb_warn_multiplier: int          = 3   # LOW-6: online→idle threshold = sleep × this
    hb_dead_multiplier: int          = 6   # LOW-6: idle→offline threshold = sleep × this
    timezone: str                    = "UTC"
    log_level: str                   = "info"
    log_file: str                    = ""     # filename inside log_dir; "" = console only
    key_password: str                = ""     # passphrase to encrypt private_key.pem at rest; "" = no encryption
    allowed_origins: list            = None   # CORS whitelist; None/[] = wildcard (default); set to restrict
    max_upload_mb: int               = 512    # max staging upload size in MB


@dataclass
class ServerConfig:
    host: str                   = "0.0.0.0"
    port: int                   = 7443
    tls: TLSConfig              = field(default_factory=TLSConfig)
    session_dir: str            = "sessions/"
    log_dir: str                = "logs/"
    key_dir: str                = "keys/"
    auth_mode: str              = "local"
    users: list[User]           = field(default_factory=list)
    oidc: Optional[OIDCConfig]  = None
    settings: Settings          = field(default_factory=Settings)
    _yml_path: str              = "server.yml"

    def find_user(self, username: str) -> Optional[User]:
        for u in self.users:
            if u.username == username:
                return u
        return None

    @property
    def is_oidc(self) -> bool:
        return self.auth_mode in ("oidc-manual", "oidc-auto")

    def known_identities(self) -> set[str]:
        """Return the set of identity keys that should have prefs files.

        local       → usernames from users[]
        oidc-manual → normalised allowed_identities
        oidc-auto   → unknown at boot; returns empty set (lazy provisioning)
        """
        if self.auth_mode == "local":
            return {u.username for u in self.users}
        if self.auth_mode == "oidc-manual" and self.oidc:
            return {i.lower().strip() for i in self.oidc.allowed_identities}
        return set()  # oidc-auto: no pre-known set


def _fatal(msg: str) -> None:
    print(f"\n[!!] CONFIGURATION ERROR: {msg}", file=sys.stderr)
    print("[!!] Server cannot start. Fix server.yml and retry.\n", file=sys.stderr)
    sys.exit(1)


def _validate(cfg: ServerConfig, data: dict) -> None:
    """Abort with a descriptive error if the config is invalid."""

    if cfg.auth_mode not in VALID_AUTH_MODES:
        _fatal(
            f"auth_mode '{cfg.auth_mode}' is not valid. "
            f"Allowed values: {', '.join(sorted(VALID_AUTH_MODES))}"
        )

    if cfg.auth_mode == "local":
        if not cfg.users:
            _fatal(
                "auth_mode is 'local' but no users are defined. "
                "Add at least one entry under 'users:' in server.yml."
            )
        for u in cfg.users:
            if not u.username:
                _fatal("A user entry is missing 'username'.")
            if not u.password:
                _fatal(f"User '{u.username}' has no password set.")

    if cfg.auth_mode in ("oidc-manual", "oidc-auto"):
        oidc = cfg.oidc
        missing = []
        if not oidc or not oidc.provider_url:
            missing.append("oidc.provider_url")
        if not oidc or not oidc.client_id:
            missing.append("oidc.client_id")
        if not oidc or not oidc.client_secret:
            missing.append("oidc.client_secret")
        if missing:
            _fatal(
                f"auth_mode is '{cfg.auth_mode}' but the following required OIDC "
                f"fields are missing or empty: {', '.join(missing)}"
            )

        if cfg.auth_mode == "oidc-manual" and not oidc.allowed_identities:
            _fatal(
                "auth_mode is 'oidc-manual' but 'oidc.allowed_identities' is empty. "
                "Add at least one identity or switch to 'oidc-auto'."
            )

        if not oidc.identity_claim:
            _fatal("oidc.identity_claim cannot be empty.")
        if not oidc.display_claim:
            _fatal("oidc.display_claim cannot be empty.")

    _MAX_JWT_EXPIRY_HOURS = 72
    if cfg.settings.jwt_expiry_hours > _MAX_JWT_EXPIRY_HOURS:
        _fatal(
            f"jwt_expiry_hours is {cfg.settings.jwt_expiry_hours} — "
            f"maximum allowed is {_MAX_JWT_EXPIRY_HOURS}h (3 days). "
            "Reduce the value in server.yml."
        )


def load(path: Path = DEFAULT_PATH) -> ServerConfig:
    if not path.exists():
        raise FileNotFoundError(
            f"server.yml not found at {path}. Copy server.yml.example and edit it."
        )
    with open(path) as f:
        raw = f.read()

    try:
        data = yaml.safe_load(raw) or {}
    except yaml.YAMLError as exc:
        print(f"\n[!!] CONFIGURATION ERROR: server.yml is not valid YAML.\n{exc}", file=sys.stderr)
        print("[!!] Server cannot start. Fix server.yml and retry.\n", file=sys.stderr)
        sys.exit(1)

    srv      = data.get("server", {})
    tls_data = srv.get("tls", {})
    tls = TLSConfig(
        mode=tls_data.get("mode", "self-signed"),
        cert=tls_data.get("cert", "certs/server.crt"),
        key=tls_data.get("key", "certs/server.key"),
    )

    auth_mode = str(data.get("auth_mode", "local")).strip()

    users = []
    for u in data.get("users", []):
        if not isinstance(u, dict):
            _fatal(f"Invalid entry in 'users:' — expected a mapping, got: {u!r}")
        users.append(User(username=str(u.get("username", "")), password=str(u.get("password", ""))))

    oidc: Optional[OIDCConfig] = None
    oidc_data = data.get("oidc", {}) or {}
    if oidc_data or auth_mode in ("oidc-manual", "oidc-auto"):
        oidc = OIDCConfig(
            provider_url         = str(oidc_data.get("provider_url", "")).rstrip("/"),
            client_id            = str(oidc_data.get("client_id", "")),
            client_secret        = str(oidc_data.get("client_secret", "")),
            identity_claim       = str(oidc_data.get("identity_claim", "email")),
            display_claim        = str(oidc_data.get("display_claim", "preferred_username")),
            allowed_identities   = [str(x) for x in (oidc_data.get("allowed_identities") or [])],
            blocked_identities   = [str(x) for x in (oidc_data.get("blocked_identities") or [])],
        )

    s = data.get("settings", {})
    if not s.get("jwt_secret"):
        secret = os.urandom(32).hex()
        if "settings" not in data:
            data["settings"] = {}
        data["settings"]["jwt_secret"] = secret
        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True)
        s["jwt_secret"] = secret

    settings = Settings(
        jwt_expiry_hours=int(s.get("jwt_expiry_hours", 24)),
        jwt_secret=s["jwt_secret"],
        build_timeout_sec=int(s.get("build_timeout_sec", 300)),
        heartbeat_retain_days=int(s.get("heartbeat_retain_days", 90)),
        cmd_lock_timeout_multiplier=int(s.get("cmd_lock_timeout_multiplier", 5)),
        hb_warn_multiplier=int(s.get("hb_warn_multiplier", 3)),
        hb_dead_multiplier=int(s.get("hb_dead_multiplier", 6)),
        timezone=str(s.get("timezone", "UTC")),
        log_level=str(s.get("log_level", "info")).upper(),
        log_file=str(s.get("log_file", "") or ""),
        key_password=str(s.get("key_password", "") or ""),
        allowed_origins=[str(o) for o in (s.get("allowed_origins") or [])],
        max_upload_mb=int(s.get("max_upload_mb", 512)),
    )

    cfg = ServerConfig(
        host=srv.get("host", "0.0.0.0"),
        port=int(srv.get("port", 7443)),
        tls=tls,
        session_dir=srv.get("session_dir", "sessions/"),
        log_dir=srv.get("log_dir", "logs/"),
        key_dir=srv.get("key_dir", "keys/"),
        auth_mode=auth_mode,
        users=users,
        oidc=oidc,
        settings=settings,
    )
    cfg._yml_path = str(path)
    _validate(cfg, data)
    return cfg
