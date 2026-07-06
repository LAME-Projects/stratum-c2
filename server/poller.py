"""
server/poller.py — Bridge between thread-based session monitors and asyncio WS.

Two background tasks run inside the uvicorn event loop:

1. StateWatcher  — polls session.state snapshots every STATE_POLL_INTERVAL
   seconds and broadcasts "session.update" when anything changed.

2. LockReaper   — calls ServerSessionManager.expire_locks() every 60 s so
   hung commands don't block an operator forever.

The HeartbeatMonitor and AsyncPoller threads from providers/base.py keep
running as before; the StateWatcher simply reads their results asynchronously.

Output notification hook:
  install_notification_hooks() replaces providers.base._hub with a
  _ServerNotificationHub so that when AsyncPoller / HeartbeatMonitor emit
  notifications from their threads, asyncio.run_coroutine_threadsafe() pushes
  a WS event onto the server event loop.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from core import tz as _tz
from pathlib import Path
from typing import TYPE_CHECKING
from .models import _session_summary

_log_cmd  = logging.getLogger("stratum.cmd")
_log_sess = logging.getLogger("stratum.session")

if TYPE_CHECKING:
    from .session import ServerSessionManager
    from .ws import ConnectionManager

STATE_POLL_INTERVAL = 5   # seconds between state snapshot comparisons


def _ts() -> str:
    return _tz.now().isoformat()


class StateWatcher:
    """
    Asyncio background task that detects session state changes and broadcasts them.
    """

    def __init__(self, sm: "ServerSessionManager", ws: "ConnectionManager") -> None:
        self._sm          = sm
        self._ws          = ws
        self._snapshots:  dict[str, dict]         = {}
        self._hist_sizes: dict[str, int]          = {}
        self._pending_ids: dict[str, str | None]  = {}

    async def run(self) -> None:
        while True:
            await asyncio.sleep(STATE_POLL_INTERVAL)
            try:
                await self._tick()
            except Exception:
                _log_sess.exception("StateWatcher._tick failed")

    async def _tick(self) -> None:
        for session in self._sm.all():
            sid        = session.id
            snap       = session.state.snapshot()
            pending    = self._sm.pending(sid)
            pending_id = pending.cmd_id if pending else None

            old     = self._snapshots.get(sid)
            old_pid = self._pending_ids.get(sid)
            if snap != old or pending_id != old_pid:
                self._snapshots[sid]   = snap
                self._pending_ids[sid] = pending_id
                await self._ws.broadcast({
                    "type": "session.update",
                    "ts":   _ts(),
                    "payload": _session_summary(session, pending),
                })

    async def expire_loop(self, sm: "ServerSessionManager") -> None:
        while True:
            await asyncio.sleep(60)
            try:
                await sm.expire_locks()
            except Exception:
                pass


class HBScheduler:
    """
    Single asyncio task that replaces per-session HeartbeatMonitor threads.

    Iterates over all sessions every HB_REFRESH_INTERVAL seconds and runs
    each session's _hb._tick() in the default ThreadPoolExecutor so blocking
    I/O (cloud API calls, crypto) does not stall the event loop.

    Replaces O(N) persistent threads with O(concurrent-ticks) transient threads.
    """

    def __init__(self, sm: "ServerSessionManager") -> None:
        self._sm = sm

    async def run(self) -> None:
        while True:
            await asyncio.sleep(15)   # matches HB_REFRESH_INTERVAL in providers/base.py
            try:
                await self._tick()
            except Exception:
                _log_sess.exception("HBScheduler._tick failed")

    async def _tick(self) -> None:
        loop = asyncio.get_event_loop()
        sessions = [s for s in self._sm.all() if not s.polling_stopped and s._hb]
        if not sessions:
            return
        await asyncio.gather(
            *(loop.run_in_executor(None, s._hb._tick) for s in sessions),
            return_exceptions=True,
        )


def install_notification_hooks(
    sm: "ServerSessionManager",
    ws: "ConnectionManager",
    loop: asyncio.AbstractEventLoop,
) -> None:
    """
    Replace the default CLI notification hub with a server hub that bridges
    background-thread calls → asyncio WS broadcasts via run_coroutine_threadsafe.
    """
    import providers.base as _base

    def _push(msg: dict) -> None:
        if not loop.is_closed():
            asyncio.run_coroutine_threadsafe(ws.broadcast(msg), loop)

    class _ServerNotificationHub(_base._NotificationHub):
        def ok(self, text: str) -> None:
            _log_cmd.info("ok: %s", text)
            _push({"type": "server.info", "ts": _ts(), "payload": {"text": f"✓ {text}"}})

        def err(self, text: str) -> None:
            _log_cmd.error("err: %s", text)
            _push({"type": "server.error", "ts": _ts(), "payload": {"text": text}})

        def warn(self, text: str) -> None:
            _log_cmd.warning("warn: %s", text)
            _push({"type": "server.warn", "ts": _ts(), "payload": {"text": text}})

        def info(self, text: str) -> None:
            _log_cmd.info("info: %s", text)

        def output(self, cmd_id: str, content: str) -> None:
            _log_cmd.info("output: cmd_id=%s length=%d", cmd_id, len(content or ""))
            sid = sm.session_for_cmd(cmd_id)

            async def _handle():
                if sid:
                    await sm.clear_pending(sid, cmd_id)
                sess_obj = sm.get(sid) if sid else None
                cwd = sess_obj.state.snapshot().get("remote_cwd", "") if sess_obj else ""
                await ws.broadcast({
                    "type": "session.output",
                    "ts":   _ts(),
                    "payload": {
                        "session_id": sid or "",
                        "cmd_id":     cmd_id,
                        "output":     content,
                        "remote_cwd": cwd,
                    },
                })

            asyncio.run_coroutine_threadsafe(_handle(), loop)

        def ul_confirmed(self, session_id: str) -> None:
            _push({"type": "session.artifacts.changed", "ts": _ts(), "payload": {"session_id": session_id}})

        def heartbeat(self, session_id: str, state: dict) -> None:
            _push({"type": "session.heartbeat", "ts": _ts(), "payload": {"session_id": session_id, "state": state}})

        def agent_dead(self, session_id: str) -> None:
            sess = sm.get(session_id)
            if sess:
                snap = sess.state.snapshot()
                _push({"type": "session.dead", "ts": _ts(), "payload": snap})

        def save_session(self, sess) -> None:
            from server.session import _dataclass_to_dict
            p = sm.pending(sess.id)
            sm._sm._write_session_file(sess, pending_cmd=_dataclass_to_dict(p))

        def persist_updated(self, session_id: str) -> None:
            sess = sm.get(session_id)
            if not sess:
                return
            pending = sm.pending(session_id)
            _push({
                "type":    "session.update",
                "ts":      _ts(),
                "payload": _session_summary(sess, pending),
            })

    import providers._notifications as _notif
    _notif._hub = _ServerNotificationHub()
