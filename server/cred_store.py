"""
cred_store.py — Shared on-disk credential profile store.

Stores credential profiles in  credentials/{provider}.json  relative to CWD.
The same files are read/written by both:
  - server/routers/credentials.py  (REST API → WebGUI)
  - providers/*/wizard.py          (deploy wizard, at session creation time)

Profile format (JSON array):
    [{"id": "uuid", "label": "abc…", "saved_at": "ISO-8601", "creds": {...}}]
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

CREDS_DIR = Path("credentials")

# Fields considered "credentials" — everything else (channel paths, config) is excluded
_CRED_KEYS: frozenset[str] = frozenset({
    "app_key", "app_secret", "refresh_token",
    "client_id", "client_secret", "tenant_id",
    "access_key_id", "secret_access_key", "bucket", "region",
    "folder_id",   # Google Drive root folder ID
    "site_id",     # SharePoint site ID
})


# ── internal helpers ──────────────────────────────────────────────────────────

def _path(provider: str) -> Path:
    CREDS_DIR.mkdir(exist_ok=True)
    safe = "".join(c for c in provider if c.isalnum() or c in "-_")
    if not safe:
        raise ValueError(f"Invalid provider name: {provider!r}")
    return CREDS_DIR / f"{safe}.json"


_PROVIDER_NAMES: dict[str, str] = {
    "dropbox":     "Dropbox",
    "onedrive":    "OneDrive",
    "googledrive": "Google Drive",
    "s3":          "AWS S3",
    "sharepoint":  "SharePoint",
}


def _primary_key(creds: dict) -> str:
    """Return the primary identifying field of a credential set."""
    return (creds.get("app_key") or creds.get("client_id")
            or creds.get("access_key_id") or "")


# ── public API ────────────────────────────────────────────────────────────────

def load_profiles(provider: str) -> list[dict]:
    """Return the list of saved credential profiles for *provider*."""
    p = _path(provider)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text())
        return data if isinstance(data, list) else []
    except Exception:
        return []


def load_profiles_safe(provider: str) -> list[dict]:
    """Return profiles with only the non-secret identifier field exposed.

    Credential secrets (refresh_token, app_secret, client_secret,
    secret_access_key) are stripped.  Only the primary identifying field
    (app_key / client_id / access_key_id) is included so the WebUI can
    display which account a profile belongs to without exposing secrets.
    """
    result = []
    for p in load_profiles(provider):
        creds = p.get("creds", {})
        identifier = _primary_key(creds)
        safe: dict = {
            "id":         p.get("id", ""),
            "label":      p.get("label", ""),
            "saved_at":   p.get("saved_at", ""),
            "identifier": identifier,
        }
        result.append(safe)
    return result


def save_profiles(provider: str, profiles: list[dict]) -> None:
    _path(provider).write_text(json.dumps(profiles, indent=2))


def upsert_profile(provider: str, creds: dict, label: str = "") -> dict:
    """Add or update a profile (matched by primary key field).

    Only credential fields (_CRED_KEYS) are stored — channel paths and
    deployment-specific options are stripped automatically.
    Returns the saved entry dict.
    """
    cred_only = {k: v for k, v in creds.items() if k in _CRED_KEYS and v}
    profiles  = load_profiles(provider)
    key       = _primary_key(cred_only)

    idx = next(
        (i for i, p in enumerate(profiles)
         if key and _primary_key(p.get("creds", {})) == key),
        -1,
    )
    existing_label = profiles[idx].get("label", "") if idx >= 0 else ""
    entry: dict = {
        "id":       profiles[idx]["id"] if idx >= 0 else str(uuid.uuid4()),
        "label":    label or existing_label or _PROVIDER_NAMES.get(provider, provider.capitalize()),
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "creds":    cred_only,
    }
    if idx >= 0:
        profiles[idx] = entry
    else:
        profiles.insert(0, entry)
    save_profiles(provider, profiles)
    return entry


def remove_profile(provider: str, profile_id: str) -> None:
    profiles = [p for p in load_profiles(provider) if p.get("id") != profile_id]
    save_profiles(provider, profiles)


def has_valid_profiles(provider: str) -> bool:
    """True if at least one profile has a usable credential (token or key)."""
    return any(
        p.get("creds", {}).get("refresh_token")
        or p.get("creds", {}).get("access_key_id")
        for p in load_profiles(provider)
    )


def extract_creds(obj) -> dict:
    """Extract credential fields from a SessionProfile / config object."""
    creds: dict = {}
    for key in _CRED_KEYS:
        val = getattr(obj, key, None)
        if val:
            creds[key] = str(val)
    return creds
