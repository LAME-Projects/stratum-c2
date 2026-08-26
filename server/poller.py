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
import time
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
                expired = await sm.expire_locks()
                for sid in expired:
                    session = sm.get(sid)
                    if session:
                        await self._ws.broadcast({
                            "type": "session.update",
                            "ts":   _ts(),
                            "payload": _session_summary(session, None),
                        })
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

    @staticmethod
    def _should_poll(s) -> bool:
        """Adaptive polling: skip sessions whose agent is known to be mid-sleep.

        With long sleep intervals (e.g. 300 s) the server would otherwise
        download and decrypt the *same* heartbeat file ~20 times between
        actual agent check-ins.  This method returns False when the next
        heartbeat is not yet expected, cutting redundant cloud API calls
        by ~80 %.
        """
        last_seen = s.state.last_seen_at
        if not last_seen or s.state.state != "online" or s.agent_sleep <= 30:
            return True
        now = time.time()
        # Prefer agent-provided next_hb_at hint (Phase 2) when available
        next_hb = getattr(s, '_next_hb_at', None)
        if next_hb is not None:
            return now >= next_hb - 15
        # Fallback: estimate from last_seen + minimum sleep interval
        earliest = last_seen + s.agent_sleep * (100 - s.agent_jitter) / 100
        # Start polling one tick before the earliest expected heartbeat
        return now >= earliest - 15

    async def _tick(self) -> None:
        loop = asyncio.get_event_loop()
        all_sessions = self._sm.all()
        sessions = [s for s in all_sessions
                    if not s.polling_stopped and s._hb and self._should_poll(s)]
        if not sessions:
            return
        results = await asyncio.gather(
            *(loop.run_in_executor(None, s._hb._tick) for s in sessions),
            return_exceptions=True,
        )


import re as _re


def _update_p2p_state(sess_obj, sm, ws, loop, content: str) -> None:
    """Parse agent P2P command responses to update topology in session profile."""
    if not content:
        return

    # p2p_link_tcp / p2p_link_smb: "OK: Linked to <addr> via TCP (child GUID: <hex>)"
    # May include embedded child sysinfo after "---CHILD_SYSINFO---"
    if content.upper().startswith("OK: LINKED TO "):
        m = _re.search(r'[Ll]inked to (.+?) via (TCP|SMB|tcp|smb) \(child GUID: ([0-9a-fA-F]+)\)', content)
        _log_sess.info("p2p: link regex match=%s content=%r", m is not None, content[:120])
        if m:
            link_addr = m.group(1).strip()
            link_type = m.group(2).lower()
            child_guid_hex = m.group(3).lower()
            _log_sess.info("p2p: looking up child guid=%s", child_guid_hex)
            child_sid = _find_session_by_p2p_guid(sm, child_guid_hex)
            _log_sess.info("p2p: child_sid=%s", child_sid)
            if child_sid:
                child = sm.get(child_sid)
                if child:
                    child.profile.p2p_parent_guid = sess_obj.id
                    child.profile.p2p_link_type = link_type
                    child.profile.p2p_link_address = link_addr
                    child.profile.p2p_is_internal = True

                    # Parse embedded child checkin if present
                    checkin_marker = "---CHILD_CHECKIN---"
                    if checkin_marker in content:
                        checkin_raw = content.split(checkin_marker, 1)[1].strip()
                        _log_sess.info("p2p: parsing embedded child checkin (%d bytes)", len(checkin_raw))
                        _apply_p2p_checkin(child, checkin_raw)

                    sm.save_session(child_sid)
                children = set(
                    c.strip()
                    for c in getattr(sess_obj.profile, 'p2p_children_guids', '').split(",")
                    if c.strip()
                )
                children.add(child_sid)
                sess_obj.profile.p2p_children_guids = ",".join(sorted(children))
                sm.save_session(sess_obj.id)
                _push_p2p_event(ws, loop, "p2p.link_established", {
                    "parent_id": sess_obj.id,
                    "child_id": child_sid,
                    "link_type": link_type,
                    "link_address": link_addr,
                })
                # Broadcast session.update for the child so frontend renders info
                import asyncio as _aio
                async def _broadcast_child_update():
                    await ws.broadcast({
                        "type": "session.update",
                        "ts": _ts(),
                        "payload": _session_summary(child, sm.pending(child_sid)),
                    })
                _aio.run_coroutine_threadsafe(_broadcast_child_update(), loop)

    # p2p_link failed: "ERROR: Link to ... failed after N attempts"
    elif "Link to" in content and "failed after" in content:
        _log_sess.warning("p2p: link failed for %s: %s", sess_obj.id, content)
        _push_p2p_event(ws, loop, "p2p.link_failed", {
            "parent_id": sess_obj.id,
            "message": content,
        })

    # p2p_unlink: "OK: Unlinked child <guid>"
    elif content.upper().startswith("OK: UNLINKED"):
        m = _re.search(r'[Uu]nlinked (?:child )?([0-9a-fA-F]+)', content)
        if m:
            child_guid_hex = m.group(1)
            child_sid = _find_session_by_p2p_guid(sm, child_guid_hex)
            if child_sid:
                child = sm.get(child_sid)
                if child:
                    child.profile.p2p_parent_guid = ""
                    child.profile.p2p_link_type = ""
                    child.profile.p2p_link_address = ""
                    sm.save_session(child_sid)
                children = set(
                    c.strip()
                    for c in getattr(sess_obj.profile, 'p2p_children_guids', '').split(",")
                    if c.strip()
                )
                children.discard(child_sid)
                sess_obj.profile.p2p_children_guids = ",".join(sorted(children))
                sm.save_session(sess_obj.id)
                _push_p2p_event(ws, loop, "p2p.link_lost", {
                    "parent_id": sess_obj.id,
                    "child_id": child_sid,
                })


def _find_session_by_p2p_guid(sm, guid_hex: str):
    """Find a session whose P2P GUID matches."""
    for s in sm.all():
        stored = getattr(s.profile, 'p2p_guid', '')
        if stored and stored == guid_hex:
            return s.id
        if s.id.startswith(guid_hex) or guid_hex.startswith(s.id[:16]):
            return s.id
    return None


def _push_p2p_event(ws, loop, event_type: str, payload: dict):
    import asyncio as _aio

    async def _broadcast():
        await ws.broadcast({
            "type": event_type,
            "ts": _ts(),
            "payload": payload,
        })
        await ws.broadcast({
            "type": "topology_changed",
            "ts": _ts(),
            "payload": payload,
        })

    if not loop.is_closed():
        _aio.run_coroutine_threadsafe(_broadcast(), loop)


def _parse_p2p_sysinfo(sess_obj, content: str) -> None:
    """Extract host/user/os/pid/process from sysinfo text and update P2P child state."""
    import time as _time
    upd: dict = {"state": "linked", "last_seen_at": _time.time()}
    for line in content.splitlines():
        if line.startswith("Hostname:"):
            upd["target_host"] = line.split(":", 1)[1].strip()
        elif line.startswith("Username:"):
            upd["target_user"] = line.split(":", 1)[1].strip()
        elif line.startswith("OS:"):
            upd["target_os"] = line.split(":", 1)[1].strip()
        elif line.startswith("Privs:"):
            upd["target_privs"] = line.split(":", 1)[1].strip()
        elif line.startswith("Domain:"):
            upd["target_domain"] = line.split(":", 1)[1].strip()
        elif line.startswith("PID:"):
            upd["agent_pid"] = line.split(":", 1)[1].strip()
        elif line.startswith("Process:"):
            upd["agent_process"] = line.split(":", 1)[1].strip()
    for line in content.splitlines():
        m = _re.match(r'\s*(?:Int\s+IP|Local\s+IP|IP):?\s+(.+)', line)
        if m and not upd.get("target_ip"):
            upd["target_ip"] = m.group(1).strip()
    if not upd.get("target_ip"):
        for line in content.splitlines():
            ips = _re.findall(r'(\d+\.\d+\.\d+\.\d+)', line)
            for ip in ips:
                if not ip.startswith("127."):
                    upd["target_ip"] = ip
                    break
            if upd.get("target_ip"):
                break
    sess_obj.state.update(**upd)


def _apply_p2p_checkin(sess_obj, checkin_raw: str) -> None:
    """Apply structured JSON checkin from P2P child (same fields as heartbeat)."""
    import time as _time
    import json as _json
    try:
        data = _json.loads(checkin_raw)
    except (ValueError, TypeError):
        _log_sess.warning("p2p: checkin JSON parse failed: %r", checkin_raw[:200])
        return
    upd: dict = {"state": "linked", "last_seen_at": _time.time()}
    _map = {
        "hostname": "target_host",
        "username": "target_user",
        "os":       "target_os",
        "privs":    "target_privs",
        "domain":   "target_domain",
        "ip_int":   "target_ip",
        "ip_ext":   "target_ip_ext",
        "pid":      "agent_pid",
        "process":  "agent_process",
    }
    for src, dst in _map.items():
        val = data.get(src, "")
        if val or val == 0:
            upd[dst] = str(val)
    sess_obj.state.update(**upd)


def _update_listener_state(sess_obj, content: str) -> None:
    """Parse agent response to maintain persistent listener state in AgentState."""
    # listen_dump() output with credentials starts with "[SMB:445]" etc, no "[creds listen]" prefix
    if "[creds listen]" not in content and not _re.search(r'\[(SMB|HTTP[-\w]*):(\d+)\]\s+\d+\s+credential', content, _re.IGNORECASE):
        return

    with sess_obj.state._lock:
        listeners = sess_obj.state.listeners
        now_iso = _tz.now().isoformat()
        changed = False

        # ── listen start: "[creds listen] Active: HTTP-NTLM:80 + LLMNR + NBNS"
        if "Active:" in content and "started" not in content.lower():
            m = _re.search(r'Active:\s*(.+?)(?:\n|$)', content)
            if m:
                parts = m.group(1).split("+")
                for part in parts:
                    part = part.strip()
                    pm = _re.match(r'(SMB|HTTP-NTLM|HTTP):(\d+)', part, _re.IGNORECASE)
                    if pm:
                        proto_raw = pm.group(1).lower()
                        port = int(pm.group(2))
                        proto = "http-ntlm" if "ntlm" in proto_raw else "http" if "http" in proto_raw else "smb"
                        key = f"{proto}:{port}"
                        if key not in listeners:
                            listeners[key] = {
                                "proto": proto,
                                "port": port,
                                "started_at": now_iso,
                                "creds": [],
                            }
                            changed = True

        # ── listen stop (all): "Stopped N listener(s)."
        elif "Stopped" in content and "listener(s)" in content:
            if listeners:
                listeners.clear()
                changed = True

        # ── listen stop (specific): "Stopped http:80."
        elif "Stopped" in content and "listener(s)" not in content:
            m = _re.search(r'Stopped\s+([\w]+:\d+)', content)
            if m:
                key = m.group(1)
                if key in listeners:
                    del listeners[key]
                    changed = True

        # ── listen dump: parse credentials per listener
        elif content.strip() and not content.startswith("[creds listen] No listeners"):
            current_key = None
            for line in content.split("\n"):
                hdr = _re.match(r'\[([\w-]+):(\d+)\]\s+(\d+)\s+credential', line, _re.IGNORECASE)
                if hdr:
                    proto_raw = hdr.group(1).lower()
                    port = int(hdr.group(2))
                    proto = "http-ntlm" if "ntlm" in proto_raw else "http" if "http" in proto_raw else "smb"
                    current_key = f"{proto}:{port}"
                    if current_key not in listeners:
                        listeners[current_key] = {
                            "proto": proto,
                            "port": port,
                            "started_at": now_iso,
                            "creds": [],
                        }
                        changed = True
                    continue
                if current_key and line.startswith("  ") and line.strip():
                    cred_line = line.strip()
                    entry = listeners.get(current_key)
                    if entry and cred_line not in entry["creds"]:
                        entry["creds"].append(cred_line)
                        changed = True


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
            # Async P2P link results arrive with cmd_id="p2p-link-{session_id}"
            if not sid and cmd_id.startswith("p2p-link-"):
                sid = cmd_id[len("p2p-link-"):]
            # Always clean reverse-index after response (handles late replies
            # where expire_locks already cleared _pending but poller still ran).
            sm._cmd_session.pop(cmd_id, None)

            # Apply deferred sleep/jitter once agent confirms the specific command
            sess_obj = sm.get(sid) if sid else None
            if sess_obj:
                is_error = (content or "").startswith("ERROR")
                if sess_obj._pending_sleep_cmd == cmd_id:
                    if not is_error:
                        sess_obj.agent_sleep = sess_obj._pending_sleep
                        _log_cmd.info("sleep confirmed by agent: %ds (sid=%s)", sess_obj.agent_sleep, sid)
                    else:
                        _log_cmd.info("sleep change rejected (timeout/error), reverting profile (sid=%s)", sid)
                        sess_obj.profile.base_sleep = sess_obj.agent_sleep
                    sess_obj._pending_sleep = None
                    sess_obj._pending_sleep_cmd = None
                if sess_obj._pending_jitter_cmd == cmd_id:
                    if not is_error:
                        sess_obj.agent_jitter = sess_obj._pending_jitter
                        _log_cmd.info("jitter confirmed by agent: %d%% (sid=%s)", sess_obj.agent_jitter, sid)
                    else:
                        _log_cmd.info("jitter change rejected (timeout/error), reverting profile (sid=%s)", sid)
                        sess_obj.profile.jitter_percent = sess_obj.agent_jitter
                    sess_obj._pending_jitter = None
                    sess_obj._pending_jitter_cmd = None

                # ── Listener state tracking (persisted in AgentState) ─────
                _update_listener_state(sess_obj, content or "")
                # ── P2P link state tracking ─────
                _update_p2p_state(sess_obj, sm, ws, loop, content or "")
                # ── P2P child sysinfo parsing ─────
                _is_p2p_child = (getattr(sess_obj.profile, 'p2p_is_internal', False)
                                 or getattr(sess_obj.profile, 'p2p_parent_guid', ''))
                if _is_p2p_child and content and "=== SYSTEM INFO ===" in content:
                    _parse_p2p_sysinfo(sess_obj, content)
                    sm.save_session(sid)
                    _push({"type": "session.update", "ts": _ts(), "payload": _session_summary(sess_obj, sm.pending(sid))})

            async def _handle():
                if sid:
                    await sm.clear_pending(sid, cmd_id)
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
            if state.get("alive"):
                sess = sm.get(session_id)
                if sess:
                    for cid in (c.strip() for c in getattr(sess.profile, 'p2p_children_guids', '').split(",") if c.strip()):
                        child = sm.get(cid)
                        if child and child.state.state != "linked":
                            child.state.update(state="linked")
                            _push({"type": "session.update", "ts": _ts(), "payload": _session_summary(child, sm.pending(cid))})

        def agent_dead(self, session_id: str) -> None:
            sess = sm.get(session_id)
            if sess:
                snap = sess.state.snapshot()
                _push({"type": "session.dead", "ts": _ts(), "payload": snap})
                for cid in (c.strip() for c in getattr(sess.profile, 'p2p_children_guids', '').split(",") if c.strip()):
                    child = sm.get(cid)
                    if child and child.state.state == "linked":
                        child.state.update(state="offline")
                        _push({"type": "session.update", "ts": _ts(), "payload": _session_summary(child, sm.pending(cid))})

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
