"""
server/routers/ws.py — WebSocket endpoint.

WS /ws

Auth via httpOnly cookie (stratum_token) attached automatically by the browser
on the HTTP upgrade request. No token in URL or first message.

Message flow (server → client):
  {"type": "session.update",  "ts": "...", "payload": {<SessionSummary>}}
  {"type": "session.output",  "ts": "...", "payload": {"session_id","cmd_id","output"}}
  {"type": "session.heartbeat","ts": "...","payload": {"session_id","...hb fields"}}
  {"type": "chat.message",    "ts": "...", "payload": {<ChatMessage>}}
  {"type": "server.info",     "ts": "...", "payload": {"text": "..."}}
  {"type": "server.error",    "ts": "...", "payload": {"text": "..."}}
  {"type": "ping",            "ts": "...", "payload": {}}

Message flow (client → server):
  {"type": "pong"}   — keepalive reply (any other type is silently ignored)

Clients MUST pass unknown message types for forward-compatibility.
"""

from __future__ import annotations

import json
import os
from core import tz as _tz

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from server import auth as auth_mod
from server.ws import ConnectionManager

router = APIRouter(prefix="/api/v1", tags=["ws"])


def _ts() -> str:
    return _tz.now().isoformat()


@router.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    """WebSocket endpoint. Auth via httpOnly cookie on the HTTP upgrade request."""
    cfg = websocket.app.state.cfg
    ws  = websocket.app.state.ws

    raw      = websocket.cookies.get("stratum_token")
    username = auth_mod.verify_token(cfg, raw) if raw else None
    if not username:
        await websocket.close(code=4001, reason="Unauthorized")
        return

    await websocket.accept()

    conn_id = os.urandom(6).hex()
    if not await ws.connect(conn_id, websocket, username):
        await websocket.close(code=4009, reason="Already connected with this account")
        return

    # Notify all OTHER operators that someone joined (exclude the connecting client)
    await ws.broadcast({
        "type": "operator.connected",
        "ts":   _ts(),
        "payload": {"username": username},
    }, exclude=conn_id)

    try:
        # Send initial snapshot of sessions + current operator list
        sm = websocket.app.state.sm
        from server.poller import _session_summary
        sessions_payload  = [_session_summary(s, sm.pending(s.id)) for s in sm.all()]
        operators_payload = ws.connected_operators()
        await ws.send(conn_id, {
            "type": "server.hello",
            "ts":   _ts(),
            "payload": {
                "username":  username,
                "sessions":  sessions_payload,
                "operators": operators_payload,
            },
        })

        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except Exception:
                continue

            mtype = msg.get("type", "")
            if mtype == "pong":
                await ws.record_pong(conn_id)
            # All other client-originated types are silently ignored
            # (future extension point — clients must pass unknown types)

    except WebSocketDisconnect:
        pass
    finally:
        await ws.disconnect(conn_id)
        # Notify remaining operators that someone left
        await ws.broadcast({
            "type": "operator.disconnected",
            "ts":   _ts(),
            "payload": {"username": username},
        })
