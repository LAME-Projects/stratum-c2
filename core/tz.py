"""
core/tz.py — Operational timezone for log/event timestamps.

Configure once at server startup; all subsystems call now() for a
timezone-aware datetime.  JWT and TLS validity stay in UTC (standards
requirement) and do NOT use this module.
"""
from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

_tz: ZoneInfo = ZoneInfo("UTC")


def configure(tz_name: str) -> None:
    """Set the operational timezone.  Call once at startup."""
    global _tz
    try:
        _tz = ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, KeyError):
        import warnings
        warnings.warn(
            f"[tz] Unknown timezone '{tz_name}' — falling back to UTC",
            stacklevel=2,
        )
        _tz = ZoneInfo("UTC")


def now() -> datetime:
    """Current time in the configured operational timezone."""
    return datetime.now(_tz)


def current_zone() -> ZoneInfo:
    return _tz
