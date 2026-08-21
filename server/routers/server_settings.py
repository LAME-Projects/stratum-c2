"""
server/routers/server_settings.py — Server-wide runtime settings (timezone, etc.).
Changes are applied immediately and persisted to server.yml.
"""
from __future__ import annotations

from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from core import tz as _tz
from server.routers.auth import get_current_user

router = APIRouter(prefix="/api/v1/server", tags=["server-settings"])


def _yml_path(request: Request) -> Path:
    return Path(request.app.state.cfg._yml_path)


@router.get("/settings")
def get_settings(request: Request, _: str = Depends(get_current_user)):
    cfg = request.app.state.cfg
    return {
        "timezone": str(_tz.current_zone()),
        "auto_update_enabled": cfg.auto_update.enabled,
    }


@router.get("/time")
def get_server_time(_: str = Depends(get_current_user)):
    import time as _time
    now = _tz.now()
    return {
        "utc_unix": _time.time(),
        "iso":      now.isoformat(),
        "tz":       str(_tz.current_zone()),
    }


class ServerSettingsPatch(BaseModel):
    timezone: str | None = None
    auto_update_enabled: bool | None = None


@router.patch("/settings")
async def patch_settings(body: ServerSettingsPatch, request: Request,
                         username: str = Depends(get_current_user)):
    cfg = request.app.state.cfg

    if body.timezone is not None:
        tz_name = body.timezone.strip()
        try:
            ZoneInfo(tz_name)
        except (ZoneInfoNotFoundError, KeyError, Exception):
            raise HTTPException(status_code=422, detail=f"Unknown timezone: '{tz_name}'")

        _tz.configure(tz_name)
        cfg.settings.timezone = tz_name

        yml = Path(cfg._yml_path)
        if yml.exists():
            with open(yml) as f:
                data = yaml.safe_load(f) or {}
            data.setdefault("settings", {})["timezone"] = tz_name
            with open(yml, "w") as f:
                yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

        await request.app.state.ws.broadcast({
            "type":    "server.timezone",
            "payload": {"timezone": tz_name, "by": username},
        })

    if body.auto_update_enabled is not None:
        cfg.auto_update.enabled = body.auto_update_enabled

        yml = Path(cfg._yml_path)
        if yml.exists():
            with open(yml) as f:
                data = yaml.safe_load(f) or {}
            data.setdefault("auto_update", {})["enabled"] = body.auto_update_enabled
            with open(yml, "w") as f:
                yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

    return {
        "timezone": str(_tz.current_zone()),
        "auto_update_enabled": cfg.auto_update.enabled,
    }
