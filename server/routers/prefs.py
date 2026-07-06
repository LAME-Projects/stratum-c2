"""
server/routers/prefs.py — Per-user UI preferences (theme, font size, zoom, notifications).
Stored as JSON files in <log_dir>/prefs/<username>.json — one file per operator.

Cleanup: call cleanup_orphaned(log_dir, known_usernames) at startup to remove
prefs files belonging to users that no longer exist in server.yml.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, Set

_log = logging.getLogger("stratum.startup")

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from server.routers.auth import get_current_user

router = APIRouter(prefix="/api/v1/me", tags=["prefs"])

_ALLOWED_KEYS = {
    "sc2_theme",
    "sc2_font_size",
    "sc2_zoom_sessions",
    "sc2_zoom_detail",
    "sc2_zoom_tabs",
    "sc2_zoom_chat",
    "notifications",
}


def _prefs_path(log_dir: Path, username: str) -> Path:
    p = log_dir / "prefs"
    p.mkdir(parents=True, exist_ok=True)
    return p / f"{username}.json"


def _load(log_dir: Path, username: str) -> Dict[str, Any]:
    path = _prefs_path(log_dir, username)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def _save(log_dir: Path, username: str, data: Dict[str, Any]) -> None:
    _prefs_path(log_dir, username).write_text(json.dumps(data, indent=2))


def ensure_exists(log_dir: Path, username: str) -> None:
    """Create an empty prefs file for username if it does not exist yet.

    Used by oidc-auto mode to lazily provision prefs on first login.
    """
    path = _prefs_path(log_dir, username)
    if not path.exists():
        _save(log_dir, username, {})
        _log.info("Created prefs for new OIDC user: %s", username)


def cleanup_orphaned(log_dir: Path, known_usernames: Set[str]) -> list[str]:
    """Delete prefs files for users no longer in the known set.

    For local and oidc-manual modes the known set is derived from server.yml
    at startup. For oidc-auto mode known_usernames is empty, so no cleanup
    is performed (files persist until manually removed).

    Returns the list of removed usernames.
    """
    if not known_usernames:
        return []  # oidc-auto: no pre-known set — skip cleanup
    prefs_dir = log_dir / "prefs"
    if not prefs_dir.exists():
        return []
    removed = []
    for f in prefs_dir.glob("*.json"):
        if f.stem not in known_usernames:
            try:
                f.unlink()
                removed.append(f.stem)
            except OSError:
                pass
    if removed:
        _log.info("Prefs cleanup: removed orphaned files for: %s", ", ".join(removed))
    return removed


class PrefsBody(BaseModel):
    prefs: Dict[str, Any]


@router.get("/prefs")
def get_prefs(request: Request, username: str = Depends(get_current_user)):
    return _load(Path(request.app.state.cfg.log_dir), username)


@router.patch("/prefs")
def patch_prefs(body: PrefsBody, request: Request, username: str = Depends(get_current_user)):
    log_dir = Path(request.app.state.cfg.log_dir)
    current = _load(log_dir, username)
    for k, v in body.prefs.items():
        if k in _ALLOWED_KEYS:
            current[k] = v
    _save(log_dir, username, current)
    return current
