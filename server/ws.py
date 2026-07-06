"""
server/ws.py — WebSocket connection manager.

Maintains the live set of connected WebGUI operator sessions. Handles:
  - connect / disconnect
  - per-connection and broadcast message delivery
  - 30-second keepalive ping; closes connections that miss 2 pongs (65s window)

WS message envelope:
    {"type": "namespace.event", "ts": "<ISO>", "payload": {...}}

Clients MUST pass (not error on) unknown message types for forward-compatibility.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from core import tz as _tz
from typing import Dict, Optional

from fastapi import WebSocket


def _ts() -> str:
    return _tz.now().isoformat()


class ConnectionManager:
    PING_INTERVAL = 30.0
    PONG_TIMEOUT  = PING_INTERVAL * 2 + 5   # 65 s

    def __init__(self) -> None:
        self._ws:        Dict[str, WebSocket] = {}   # conn_id → ws
        self._usernames: Dict[str, str]       = {}   # conn_id → username
        self._pong_at:   Dict[str, float]     = {}   # conn_id → monotonic ts
        self._lock = asyncio.Lock()

    # ── lifecycle ──────────────────────────────────────────────────────────────

    async def connect(self, conn_id: str, ws: WebSocket, username: str) -> bool:
        """Register the connection. Returns False if username is already connected."""
        async with self._lock:
            if username in self._usernames.values():
                return False
            self._ws[conn_id]        = ws
            self._usernames[conn_id] = username
            self._pong_at[conn_id]   = asyncio.get_event_loop().time()
        return True

    async def disconnect(self, conn_id: str) -> None:
        async with self._lock:
            ws_obj = self._ws.pop(conn_id, None)
            self._usernames.pop(conn_id, None)
            self._pong_at.pop(conn_id, None)
        if ws_obj:
            try:
                await ws_obj.close(1001)
            except Exception:
                pass

    async def record_pong(self, conn_id: str) -> None:
        async with self._lock:
            if conn_id in self._pong_at:
                self._pong_at[conn_id] = asyncio.get_event_loop().time()

    # ── send helpers ──────────────────────────────────────────────────────────

    async def send(self, conn_id: str, msg: dict) -> None:
        ws = self._ws.get(conn_id)
        if ws:
            try:
                await ws.send_json(msg)
            except Exception:
                await self.disconnect(conn_id)

    async def broadcast(self, msg: dict, exclude: str | None = None) -> None:
        async with self._lock:
            conn_ids = list(self._ws.keys())
        dead: list[str] = []
        for cid in conn_ids:
            if cid == exclude:
                continue
            ws = self._ws.get(cid)
            if ws:
                try:
                    await ws.send_json(msg)
                except Exception:
                    dead.append(cid)
        for cid in dead:
            await self.disconnect(cid)

    # ── background keepalive ──────────────────────────────────────────────────

    async def keepalive_loop(self) -> None:
        """Runs forever as an asyncio background task."""
        while True:
            await asyncio.sleep(self.PING_INTERVAL)
            now  = asyncio.get_event_loop().time()
            dead: list[str] = []
            async with self._lock:
                conn_ids = list(self._ws.keys())
            for cid in conn_ids:
                last = self._pong_at.get(cid, 0.0)
                if now - last > self.PONG_TIMEOUT:
                    dead.append(cid)
                else:
                    ws = self._ws.get(cid)
                    if ws:
                        try:
                            await ws.send_json({"type": "ping", "ts": _ts(), "payload": {}})
                        except Exception:
                            dead.append(cid)
            for cid in dead:
                await self.disconnect(cid)

    # ── introspection ─────────────────────────────────────────────────────────

    def count(self) -> int:
        return len(self._ws)

    def username_of(self, conn_id: str) -> Optional[str]:
        return self._usernames.get(conn_id)

    def has_username(self, username: str) -> bool:
        """Return True if a connection with this username is already active."""
        return username in self._usernames.values()

    def connected_operators(self) -> list[dict]:
        """Return list of {username} for all connected WS clients."""
        return [
            {"username": u}
            for u in self._usernames.values()
        ]

    async def disconnect_user(self, username: str) -> None:
        """MED-3: close all WS connections belonging to username (called on logout)."""
        async with self._lock:
            target_ids = [cid for cid, u in self._usernames.items() if u == username]
        for cid in target_ids:
            await self.disconnect(cid)
