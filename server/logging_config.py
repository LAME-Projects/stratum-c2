"""
server/logging_config.py — Centralised logging configuration for Stratum C2.

Call configure_logging(cfg) once before uvicorn.run().  Uses dictConfig so the
config is applied atomically — no duplicate-handler risk, no basicConfig clash.

Logger hierarchy (all propagate=False so root never double-emits):
  stratum.startup   — server boot sequence
  stratum.session   — session lifecycle (start/stop/load)
  stratum.poller    — AsyncPoller, HeartbeatMonitor
  stratum.wizard    — deploy wizard steps
  stratum.cmd       — command send/receive cycle
  stratum.ws        — WebSocket connections

Third-party noise suppression:
  uvicorn.access    — silenced at WARNING (one line per HTTP request, not useful)
  uvicorn / uvicorn.error / uvicorn.asgi — WARNING by default; follow app level at DEBUG
  httpx / httpcore / requests / urllib3 / multipart.multipart — WARNING only
"""

from __future__ import annotations

import logging
import logging.config
import logging.handlers
import os
from pathlib import Path
from typing import Optional


# ── format strings ────────────────────────────────────────────────────────────

# Standard: timestamp [LEVEL] logger: message
_FMT_STANDARD = "%(asctime)s  %(levelname)-8s  %(name)-22s  %(message)s"
# Debug: adds function name and line number for tracing
_FMT_DEBUG    = "%(asctime)s  %(levelname)-8s  %(name)-22s  %(funcName)s:%(lineno)d  %(message)s"
_DATEFMT      = "%Y-%m-%d %H:%M:%S"


def configure_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    log_dir: str = "logs/",
) -> None:
    """
    Apply dictConfig for the whole process.

    Args:
        level:    Root log level string — DEBUG | INFO | WARNING | ERROR | CRITICAL.
        log_file: Filename for the rotating file handler (relative to log_dir).
                  None disables file logging.
        log_dir:  Directory where log files are written.  Created if absent.
    """
    level_upper = level.upper()
    numeric     = getattr(logging, level_upper, logging.INFO)

    # Use debug format when DEBUG so callers get func:line context
    fmt = _FMT_DEBUG if numeric <= logging.DEBUG else _FMT_STANDARD

    # ── handler definitions ────────────────────────────────────────────────────
    handlers_def: dict = {
        "console": {
            "class":     "logging.StreamHandler",
            "formatter": "standard",
            "stream":    "ext://sys.stdout",
        },
    }

    if log_file:
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        filepath = str(Path(log_dir) / log_file)
        handlers_def["file"] = {
            "class":       "logging.handlers.TimedRotatingFileHandler",
            "formatter":   "standard",
            "filename":    filepath,
            "when":        "midnight",
            "interval":    1,
            "backupCount": 0,
            "encoding":    "utf-8",
            "delay":       True,        # don't create file until first record
        }

    active_handlers = list(handlers_def.keys())

    # uvicorn at DEBUG is very chatty — cap it at INFO unless operator is debugging
    uv_level = level_upper if numeric <= logging.DEBUG else "WARNING"

    cfg: dict = {
        "version":                  1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {
                "format":  fmt,
                "datefmt": _DATEFMT,
            },
        },
        "handlers": handlers_def,
        "loggers": {
            # ── Stratum app namespace — fully verbose ──────────────────────────
            "stratum": {
                "level":     level_upper,
                "handlers":  active_handlers,
                "propagate": False,
            },
            # ── uvicorn: access log always quiet; error/startup at uv_level ──
            "uvicorn.access": {
                "level":     "WARNING",
                "handlers":  active_handlers,
                "propagate": False,
            },
            "uvicorn": {
                "level":     uv_level,
                "handlers":  active_handlers,
                "propagate": False,
            },
            "uvicorn.error": {
                "level":     uv_level,
                "handlers":  active_handlers,
                "propagate": False,
            },
            # ── uvicorn.asgi: explicit entry so level isn't inherited implicitly ─
            "uvicorn.asgi": {
                "level":     uv_level,
                "handlers":  active_handlers,
                "propagate": False,
            },
            # ── third-party noise — WARNING and above only ────────────────────
            "httpx":              {"level": "WARNING", "handlers": active_handlers, "propagate": False},
            "httpcore":           {"level": "WARNING", "handlers": active_handlers, "propagate": False},
            "requests":           {"level": "WARNING", "handlers": active_handlers, "propagate": False},
            "urllib3":            {"level": "WARNING", "handlers": active_handlers, "propagate": False},
            "multipart.multipart":{"level": "WARNING", "handlers": active_handlers, "propagate": False},
        },
        # Root catches everything not claimed by a named logger above
        "root": {
            "level":    "WARNING",
            "handlers": active_handlers,
        },
    }

    logging.config.dictConfig(cfg)

    log = logging.getLogger("stratum.startup")
    log.debug("logging configured: level=%s file=%s", level_upper, log_file or "none")
