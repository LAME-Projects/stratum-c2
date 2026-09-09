"""
server/updater.py — Check GitHub for new releases and apply updates via git.

Safety:
  - All operational data (sessions/, keys/, logs/, credentials/, server.yml,
    certs/) is in .gitignore and never touched by git merge.
  - On merge conflict: git merge --abort → no damage.
  - Restart is always the operator's choice.
"""

from __future__ import annotations

import asyncio
import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

import httpx

from server.version import __version__

log = logging.getLogger("stratum.updater")

_update_state: Optional[dict] = None


def _parse_semver(tag: str) -> tuple[int, ...]:
    m = re.match(r"v?(\d+)\.(\d+)\.(\d+)", tag)
    if not m:
        return (0, 0, 0)
    return tuple(int(x) for x in m.groups())


def _extract_section(changelog: str, version: str) -> str:
    header = f"## v{version}"
    start = changelog.find(header)
    if start == -1:
        return ""
    start += len(header)
    end = changelog.find("\n## ", start)
    section = changelog[start:end].strip() if end != -1 else changelog[start:].strip()
    if section.startswith("---"):
        section = section[3:].strip()
    return section


async def check_for_update(repo: str) -> Optional[dict]:
    global _update_state

    if not repo:
        return None

    url = f"https://raw.githubusercontent.com/{repo}/main/VERSION"
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(url)
            if r.status_code == 404:
                log.warning("Update check: VERSION file not found for %s", repo)
                _update_state = None
                return None
            r.raise_for_status()
            remote_version = r.text.strip()
    except Exception as exc:
        log.warning("Update check failed: %s", exc)
        _update_state = None
        return None

    latest_ver = _parse_semver(remote_version)
    current_ver = _parse_semver(__version__)

    if latest_ver <= current_ver:
        log.info("Up to date: v%s (latest: v%s)", __version__, remote_version)
        _update_state = None
        return None

    notes = ""
    try:
        cl_url = f"https://raw.githubusercontent.com/{repo}/main/CHANGELOG.md"
        async with httpx.AsyncClient(timeout=15) as client:
            cl = await client.get(cl_url)
            if cl.status_code == 200:
                notes = _extract_section(cl.text, remote_version)
    except Exception:
        pass

    _update_state = {
        "available": True,
        "current": __version__,
        "latest": remote_version,
        "release_notes": notes,
        "published_at": "",
        "html_url": f"https://github.com/{repo}",
    }
    log.info("Update available: v%s → v%s", __version__, remote_version)
    return _update_state


def get_update_info() -> Optional[dict]:
    return _update_state


def preflight() -> dict:
    result = {"ok": True, "warnings": [], "errors": []}

    if not shutil.which("git"):
        result["ok"] = False
        result["errors"].append("git is not installed or not in PATH")
        return result

    project = Path(".")
    if not (project / ".git").is_dir():
        result["ok"] = False
        result["errors"].append("Not a git repository — cannot update")
        return result

    try:
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True, text=True, timeout=10, cwd=str(project),
        )
        if status.stdout.strip():
            result["warnings"].append("Working tree has uncommitted changes — they will be preserved but may cause merge conflicts")
    except Exception as exc:
        result["ok"] = False
        result["errors"].append(f"git status failed: {exc}")

    return result


async def apply_update(repo: str, ws_mgr=None) -> dict:
    project = Path(".")

    pf = preflight()
    if not pf["ok"]:
        return {"ok": False, "error": "; ".join(pf["errors"])}

    loop = asyncio.get_event_loop()

    try:
        fetch = await loop.run_in_executor(None, lambda: subprocess.run(
            ["git", "fetch", "origin", "main"],
            capture_output=True, text=True, timeout=60, cwd=str(project),
        ))
        if fetch.returncode != 0:
            return {"ok": False, "error": f"git fetch failed: {fetch.stderr.strip()}"}

        merge = await loop.run_in_executor(None, lambda: subprocess.run(
            ["git", "merge", "origin/main", "--no-edit"],
            capture_output=True, text=True, timeout=60, cwd=str(project),
        ))
        if merge.returncode != 0:
            await loop.run_in_executor(None, lambda: subprocess.run(
                ["git", "merge", "--abort"],
                capture_output=True, text=True, timeout=10, cwd=str(project),
            ))
            return {"ok": False, "error": f"Merge conflict — aborted cleanly. {merge.stderr.strip()}"}

    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "git operation timed out"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

    pip_msg = ""
    req_file = project / "requirements.txt"
    if req_file.exists():
        try:
            diff = await loop.run_in_executor(None, lambda: subprocess.run(
                ["git", "diff", "HEAD~1", "--name-only", "--", "requirements.txt"],
                capture_output=True, text=True, timeout=10, cwd=str(project),
            ))
            if diff.stdout.strip():
                pip = await loop.run_in_executor(None, lambda: subprocess.run(
                    ["pip", "install", "-r", "requirements.txt", "--quiet"],
                    capture_output=True, text=True, timeout=120, cwd=str(project),
                ))
                if pip.returncode != 0:
                    pip_msg = f" (pip install had errors: {pip.stderr.strip()[:200]})"
                else:
                    pip_msg = " (dependencies updated)"
        except Exception:
            pip_msg = " (could not check/install dependencies)"

    new_ver = Path("VERSION").read_text().strip() if Path("VERSION").exists() else "unknown"

    result = {
        "ok": True,
        "message": f"Updated to v{new_ver}{pip_msg}",
        "new_version": new_ver,
        "restart_required": True,
    }

    if ws_mgr:
        from core import tz as _tz
        await ws_mgr.broadcast({
            "type": "update.complete",
            "ts": _tz.now().isoformat(),
            "payload": result,
        })

    log.info("Update applied: v%s → v%s%s", __version__, new_ver, pip_msg)
    return result
