"""
server/routers/tradecraft.py — /api/v1/tradecraft endpoints.

Manages deployment packages in the  deployments/  directory.

GET    /api/v1/tradecraft              — list all packages with metadata
GET    /api/v1/tradecraft/{name}/zip   — stream agent/ folder + guide as ZIP
DELETE /api/v1/tradecraft/{name}       — remove a deployment directory
"""
from __future__ import annotations

import io
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import Response
from core import tz as _tz

from server.routers.auth import get_current_user

router = APIRouter(prefix="/api/v1/tradecraft", tags=["tradecraft"])

_DEPLOYMENTS = Path("deployments")


def _ws(request: Request):
    return request.app.state.ws


def _guard(name: str) -> str:
    if not name or "/" in name or "\\" in name or ".." in name or "\x00" in name:
        raise HTTPException(status_code=400, detail="Invalid deployment name")
    return name


def _parse_guide(path: Path) -> dict:
    out: dict = {}
    try:
        for line in path.read_text(errors="replace").splitlines():
            line = line.strip()
            for prefix, key in (
                ("Session ID:", "session_id"),
                ("Generated:",  "generated"),
                ("Provider:",   "provider"),
                ("Mode:",       "mode"),
                ("Folder:",     "folder"),
                ("Sleep:",      "sleep"),
            ):
                if line.startswith(prefix):
                    out[key] = line[len(prefix):].strip()
                    break
    except Exception:
        pass
    return out


def _fmt_size(n: int) -> str:
    if n >= 1_048_576:
        return f"{n / 1_048_576:.1f} MB"
    if n >= 1_024:
        return f"{n // 1024} KB"
    return f"{n} B"


@router.get("")
def list_deployments(username: str = Depends(get_current_user)):
    """Return all deployment packages newest-first, enriched with DEPLOYMENT_GUIDE metadata."""
    if not _DEPLOYMENTS.exists():
        return {"deployments": []}

    results = []
    for d in sorted(_DEPLOYMENTS.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        if not d.is_dir():
            continue

        guide = _parse_guide(d / "DEPLOYMENT_GUIDE.txt")

        agent_dir = d / "agent"
        files: list[dict] = []
        total_size = 0
        if agent_dir.is_dir():
            for f in sorted(agent_dir.iterdir()):
                if f.is_file():
                    sz = f.stat().st_size
                    total_size += sz
                    files.append({"name": f.name, "size": sz, "size_str": _fmt_size(sz)})

        created_at = datetime.fromtimestamp(
            d.stat().st_mtime, tz=timezone.utc
        ).isoformat()

        # Provider ID from guide text or directory prefix
        provider_label = guide.get("provider", d.name.split("_")[0])
        provider_id    = provider_label.lower().replace(" ", "")

        results.append({
            "name":             d.name,
            "provider":         provider_id,
            "provider_label":   provider_label,
            "session_id":       guide.get("session_id", ""),
            "generated":        guide.get("generated", ""),
            "mode":             guide.get("mode", ""),
            "folder":           guide.get("folder", ""),
            "sleep":            guide.get("sleep", ""),
            "files":            files,
            "total_size":       total_size,
            "total_size_str":   _fmt_size(total_size),
            "created_at":       created_at,
        })

    return {"deployments": results}


@router.get("/{name}/zip")
def download_zip(name: str, username: str = Depends(get_current_user)):
    """Stream agent/ + DEPLOYMENT_GUIDE.txt as an authenticated ZIP download."""
    _guard(name)
    d = _DEPLOYMENTS / name
    if not d.is_dir():
        raise HTTPException(status_code=404, detail="Deployment not found")

    agent_dir = d / "agent"
    if not agent_dir.is_dir():
        raise HTTPException(status_code=404, detail="agent/ directory not found")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(agent_dir.iterdir()):
            if f.is_file():
                zf.write(f, f"agent/{f.name}")
        guide = d / "DEPLOYMENT_GUIDE.txt"
        if guide.exists():
            zf.write(guide, "DEPLOYMENT_GUIDE.txt")

    safe = "".join(c for c in name if c.isalnum() or c in "_-")
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{safe}.zip"'},
    )


@router.delete("/{name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_deployment(name: str, request: Request, username: str = Depends(get_current_user)):
    """Permanently remove a deployment directory and all its contents."""
    _guard(name)
    d = _DEPLOYMENTS / name
    if not d.is_dir():
        raise HTTPException(status_code=404, detail="Deployment not found")
    shutil.rmtree(d)
    ws = _ws(request)
    await ws.broadcast({"type": "tradecraft.deleted", "payload": {"name": name, "deleted_by": username}})
