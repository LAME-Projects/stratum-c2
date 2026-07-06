"""
server/routers/chat.py — /api/v1/chat endpoints.

GET  /api/v1/chat/dates   — list of dates with chat logs
GET  /api/v1/chat         — today's messages (or ?date=YYYY-MM-DD for archive)
POST /api/v1/chat         — post a new message (broadcast via WS)
"""

from __future__ import annotations

import logging
from datetime import date, datetime, timezone
from core import tz as _tz
from typing import List, Optional

from fastapi import APIRouter, Depends, Query, Request, HTTPException
from fastapi.responses import StreamingResponse

from server import chat as chat_mod
from server.models import ChatMessage, ChatMessageIn
from server.routers.auth import get_current_user
from server.ws import ConnectionManager

_log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/chat", tags=["chat"])


def _ws(request: Request) -> ConnectionManager:
    return request.app.state.ws


@router.get("/dates", response_model=List[str])
def get_chat_dates(username: str = Depends(get_current_user)):
    return chat_mod.available_dates()


@router.get("/history/dates", response_model=List[str])
def get_chat_history_dates(username: str = Depends(get_current_user)):
    """Get dates with actual messages (for Chat History modal)."""
    return chat_mod.available_dates_for_history()


@router.get("/history/dates/info", response_model=List[dict])
def get_chat_history_dates_with_info(username: str = Depends(get_current_user)):
    """Get dates with messages and metadata (count, last activity, size)."""
    return chat_mod.available_dates_for_history_with_info()


@router.get("", response_model=List[ChatMessage])
def get_chat(
    limit: int = Query(default=200, ge=1, le=2000),
    before: Optional[str] = Query(default=None),
    date_param: Optional[str] = Query(default=None, alias="date"),
    username: str = Depends(get_current_user),
):
    today = date.today().isoformat()
    if date_param and date_param != today:
        return chat_mod.history_for_date(date_param)
    return chat_mod.history(limit=limit, before=before)


@router.post("", response_model=ChatMessage)
async def post_chat(
    body: ChatMessageIn,
    request: Request,
    username: str = Depends(get_current_user),
):
    ws  = _ws(request)
    msg = chat_mod.post(username, body.text)
    await ws.broadcast({
        "type":    "chat.message",
        "ts":      _tz.now().isoformat(),
        "payload": msg,
    })
    return msg


@router.delete("", response_model=dict)
async def delete_chat_date(
    request: Request,
    date_param: str = Query(alias="date"),
    username: str = Depends(get_current_user),
):
    """Delete all messages for a specific date."""
    if not chat_mod.delete_date(date_param):
        raise HTTPException(status_code=404, detail="No chat log found for that date")

    ws = _ws(request)
    await ws.broadcast({"type": "chat.date_deleted", "payload": {"date": date_param, "deleted_by": username}})
    return {"deleted": date_param}


@router.get("/export")
def export_chat_date(
    date_param: str = Query(alias="date"),
    username: str = Depends(get_current_user),
):
    """Export chat messages for a date as JSONL."""
    content = chat_mod.export_date(date_param)
    return StreamingResponse(
        iter([content]),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": f'attachment; filename="chat_{date_param}.jsonl"'},
    )
