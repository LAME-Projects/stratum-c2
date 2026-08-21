"""
server/routers/update.py — /api/v1/update endpoints.

GET    /api/v1/update/status     — current update state
GET    /api/v1/update/preflight  — pre-flight checks before applying
POST   /api/v1/update/apply      — fetch + merge from upstream
GET    /api/v1/update/changelog  — read CHANGELOG.md from repo root
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse

from server.routers.auth import get_current_user
from server.updater import apply_update, check_for_update, get_update_info, preflight

router = APIRouter(prefix="/api/v1/update", tags=["update"])


@router.get("/status")
async def update_status(username: str = Depends(get_current_user)):
    info = get_update_info()
    if info:
        return {"update": info}
    return {"update": None}


@router.get("/preflight")
async def update_preflight(username: str = Depends(get_current_user)):
    return preflight()


@router.post("/apply")
async def update_apply(request: Request, username: str = Depends(get_current_user)):
    cfg = request.app.state.cfg
    ws  = request.app.state.ws
    repo = cfg.auto_update.repo
    if not repo:
        return {"ok": False, "error": "No repository configured in auto_update.repo"}
    result = await apply_update(repo, ws_mgr=ws)
    return result


@router.post("/check")
async def update_check(request: Request, username: str = Depends(get_current_user)):
    cfg = request.app.state.cfg
    repo = cfg.auto_update.repo
    if not repo:
        return {"update": None, "error": "No repository configured"}
    info = await check_for_update(repo)
    return {"update": info}


@router.get("/changelog")
async def update_changelog(_: str = Depends(get_current_user)):
    p = Path("CHANGELOG.md")
    if not p.exists():
        return PlainTextResponse("No changelog available.", status_code=200)
    return PlainTextResponse(p.read_text(encoding="utf-8"))
