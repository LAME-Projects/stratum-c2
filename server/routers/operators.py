"""
server/routers/operators.py — /api/v1/operators endpoint.

GET /api/v1/operators — list currently connected WebSocket clients (operators).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from server.routers.auth import get_current_user

router = APIRouter(prefix="/api/v1/operators", tags=["operators"])


@router.get("")
def list_operators(request: Request, username: str = Depends(get_current_user)):
    ws = request.app.state.ws
    return {"operators": ws.connected_operators()}
