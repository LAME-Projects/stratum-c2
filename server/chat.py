"""
server/chat.py — Operator chat storage with daily file rotation.

Each day's messages live in: <log_dir>/chat_YYYY-MM-DD.jsonl
In-memory deque holds only the current calendar day's messages so
history survives server restarts without loading all past logs.

Message schema:
    {"id": "<hex8>", "ts": "<ISO>", "username": "alice", "text": "..."}
"""

from __future__ import annotations

import json
import os
import re
from collections import deque
from datetime import datetime, timezone, date
from core import tz as _tz
from pathlib import Path
from typing import Optional

_MAXLEN    = 2000
_FNAME_RE  = re.compile(r'^chat_(\d{4}-\d{2}-\d{2})\.jsonl$')

_messages:     deque[dict]    = deque(maxlen=_MAXLEN)
_log_dir:      Optional[Path] = None
_current_date: str            = ""   # "YYYY-MM-DD"


# ── helpers ───────────────────────────────────────────────────────────────────

def _today() -> str:
    return date.today().isoformat()


def _path_for(d: str) -> Optional[Path]:
    return (_log_dir / f"chat_{d}.jsonl") if _log_dir else None


def _append_to_disk(msg: dict, d: str) -> None:
    path = _path_for(d)
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(msg, ensure_ascii=False) + "\n")


def _read_day(d: str) -> list[dict]:
    """Read messages for `d` from disk (no validation of content)."""
    if not re.match(r'^\d{4}-\d{2}-\d{2}$', d):
        return []
    path = _path_for(d)
    if not path or not path.exists():
        return []
    result = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            result.append(json.loads(line))
        except Exception:
            pass
    return result


def _check_rollover() -> None:
    """If the calendar day has changed, reset the in-memory deque."""
    global _current_date
    today = _today()
    if today != _current_date:
        _current_date = today
        _messages.clear()


# ── public API ────────────────────────────────────────────────────────────────

def init(log_dir: str) -> None:
    global _log_dir, _current_date
    p = Path(log_dir)
    p.mkdir(parents=True, exist_ok=True)
    _log_dir = p
    _current_date = _today()
    # Load today's existing messages into the deque
    for msg in _read_day(_current_date):
        _messages.append(msg)


def post(username: str, text: str) -> dict:
    _check_rollover()
    msg = {
        "id":       os.urandom(4).hex(),
        "ts":       _tz.now().isoformat(),
        "username": username,
        "text":     text,
    }
    _messages.append(msg)
    _append_to_disk(msg, _current_date)
    return msg


def history(limit: int = 200, before: Optional[str] = None) -> list[dict]:
    """Return today's messages (up to `limit`), optionally paged by `before` id."""
    _check_rollover()
    msgs = list(_messages)
    if before:
        try:
            idx = next(i for i, m in enumerate(msgs) if m["id"] == before)
            msgs = msgs[:idx]
        except StopIteration:
            pass
    return msgs[-limit:]


def history_for_date(d: str) -> list[dict]:
    """Return all messages for a past date (read from disk)."""
    _check_rollover()
    if d == _current_date:
        return list(_messages)
    return _read_day(d)


def available_dates() -> list[str]:
    """Return sorted list of dates for which chat log files exist."""
    if _log_dir is None:
        return []
    dates = []
    for f in _log_dir.iterdir():
        m = _FNAME_RE.match(f.name)
        if m:
            dates.append(m.group(1))
    # Always include today even if no messages yet (users can start typing in Stratum Chat)
    today = _today()
    if today not in dates:
        dates.append(today)
    return sorted(dates)


def available_dates_for_history() -> list[str]:
    """Return dates with actual messages (for Chat History view - excludes empty today)."""
    _check_rollover()
    if _log_dir is None:
        return []
    dates = []
    for f in _log_dir.iterdir():
        m = _FNAME_RE.match(f.name)
        if m:
            dates.append(m.group(1))
    # Include today if it has messages in memory (even if file not on disk yet)
    today = _today()
    if today not in dates and len(_messages) > 0:
        dates.append(today)
    return sorted(dates)


def available_dates_for_history_with_info() -> list[dict]:
    """Return dates with messages and metadata (date, count, last_activity, size)."""
    _check_rollover()
    result = []
    dates = available_dates_for_history()

    for d in dates:
        msgs = history_for_date(d)
        if not msgs:
            continue

        path = _path_for(d)
        size_bytes = path.stat().st_size if (path and path.exists()) else 0
        last_ts = msgs[-1].get("ts", "") if msgs else ""

        result.append({
            "date": d,
            "message_count": len(msgs),
            "last_activity": last_ts,
            "size_bytes": size_bytes,
        })

    return result


def delete_date(d: str) -> bool:
    """Delete chat log for a specific date. Returns True if deleted, False if not found."""
    _check_rollover()
    if d == _current_date:
        _messages.clear()
    path = _path_for(d)
    if path and path.exists():
        path.unlink()
        return True
    return False


def export_date(d: str) -> str:
    """Export chat messages for a date as JSON (one message per line)."""
    _check_rollover()
    return "\n".join(json.dumps(msg, ensure_ascii=False) for msg in history_for_date(d))
