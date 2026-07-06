"""
server/notifications.py — Generic broadcast notification system.

All user-facing notifications go through a central broadcast channel with
standardized level (normal/warn/error) and message format.
"""

from datetime import datetime
from core import tz as _tz


async def notify(ws, level: str, title: str, message: str, notif_id: str = ""):
    """
    Broadcast a generic notification to all operators.

    Args:
        ws: ConnectionManager instance
        level: "normal" | "warn" | "error"
        title: Short notification title (e.g. "Session Wiped")
        message: Notification message (e.g. "36350e")
        notif_id: Optional unique ID for deduplication
    """
    if level not in ("normal", "warn", "error"):
        level = "normal"

    await ws.broadcast({
        "type": "notification",
        "ts": _tz.now().isoformat(),
        "payload": {
            "level": level,
            "title": title,
            "message": message,
            "notif_id": notif_id or "",
        },
    })
