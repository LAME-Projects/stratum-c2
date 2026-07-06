"""
server/main.py — FastAPI application factory for Stratum C2 server mode.

Usage (called by stratum-server.py):
    from server.main import create_app, run
    run(config_path="server.yml")

IMPORTANT — Single-worker mandate:
    uvicorn MUST be started with workers=1.  All state (sessions, WS connections,
    JWT revocation list, pending command locks) is in-process.  Multiple workers
    would silently break WS broadcast and the asyncio.Lock concurrency model.

Startup sequence:
    1. Load server.yml
    2. Generate/load TLS cert; print fingerprint for browser verification
    3. Install notification hooks (thread→asyncio bridge)
    4. Load existing sessions from sessions/
    5. Start background tasks: WS keepalive, state watcher, lock reaper
    6. Start uvicorn
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path
from typing import Optional

from server.logging_config import configure_logging

_PID_FILE = Path(".stratum_server.pid")

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles as _StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.requests import Request as _StarRequest
from starlette.responses import Response as _StarResponse


class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """LOW-1/LOW-2: inject security headers and strip Server fingerprint."""

    _HEADERS = {
        "X-Frame-Options":           "DENY",
        "X-Content-Type-Options":    "nosniff",
        "Referrer-Policy":           "no-referrer",
        "Permissions-Policy":        "geolocation=(), microphone=(), camera=()",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "font-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self' wss:; "
            "frame-ancestors 'none';"
        ),
    }

    async def dispatch(self, request: _StarRequest, call_next) -> _StarResponse:
        response = await call_next(request)
        for k, v in self._HEADERS.items():
            response.headers[k] = v
        response.headers["Server"] = ""
        return response


class StaticFiles(_StaticFiles):
    """StaticFiles that silently ignores non-HTTP scopes (WebSocket, lifespan).
    Without this guard, Starlette asserts scope["type"] == "http" and crashes
    when a WS request falls through the catch-all mount at "/"."""
    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http":
            await super().__call__(scope, receive, send)

from server import auth as auth_mod
from server import chat as chat_mod
from server.config import ServerConfig, load as load_config
from server.poller import StateWatcher, HBScheduler, install_notification_hooks
from server.session import ServerSessionManager
from server.tls import ensure_cert
from server.ws import ConnectionManager

from server.routers import auth, sessions, chat, ws, deploy, operators, credentials, tradecraft, prefs, server_settings, history_archives


def create_app(cfg: ServerConfig) -> FastAPI:
    app = FastAPI(
        title="API",
        version="1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    _cors_origins = cfg.settings.allowed_origins or ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    app.add_middleware(_SecurityHeadersMiddleware)

    app.state.cfg = cfg

    # ── shared singletons ──────────────────────────────────────────────────────
    ws_mgr = ConnectionManager()
    _kp = cfg.settings.key_password.encode() if cfg.settings.key_password else None
    sm     = ServerSessionManager(
        sessions_dir       = Path(cfg.session_dir),
        project_dir        = Path("."),
        lock_multiplier    = cfg.settings.cmd_lock_timeout_multiplier,
        key_password       = _kp,
        hb_warn_multiplier = cfg.settings.hb_warn_multiplier,
        hb_dead_multiplier = cfg.settings.hb_dead_multiplier,
    )
    app.state.ws = ws_mgr
    app.state.sm = sm

    # ── routers ────────────────────────────────────────────────────────────────
    app.include_router(auth.router)
    app.include_router(sessions.router)
    app.include_router(chat.router)
    app.include_router(ws.router)
    app.include_router(deploy.router)
    app.include_router(operators.router)
    app.include_router(credentials.router)
    app.include_router(tradecraft.router)
    app.include_router(prefs.router)
    app.include_router(server_settings.router)
    app.include_router(history_archives.router)

    # ── static WebGUI (served from webui/ if present) ────────────────────────
    webgui = Path("webui")
    if webgui.exists():
        app.mount("/", StaticFiles(directory=str(webgui), html=True), name="webgui")

    # ── lifespan ──────────────────────────────────────────────────────────────

    @app.on_event("startup")
    async def _startup():
        loop = asyncio.get_event_loop()

        log = logging.getLogger("stratum.startup")
        log.info("Stratum C2 starting — auth=%s host=%s port=%d",
                 cfg.auth_mode, cfg.host, cfg.port)
        if not cfg.settings.key_password:
            log.warning("key_password is not set — deployment private keys are stored UNENCRYPTED on disk")

        # Remove prefs files for identities no longer in server.yml.
        # For oidc-auto, known_identities() returns empty set → no cleanup.
        identities = cfg.known_identities()
        removed = prefs.cleanup_orphaned(Path(cfg.log_dir), identities)
        if not removed:
            log.debug("Prefs cleanup: nothing to remove")

        # Bridge thread notifications → asyncio WS push
        install_notification_hooks(sm, ws_mgr, loop)
        log.debug("Notification hooks installed (thread→asyncio bridge)")

        # Load existing sessions
        await sm.load_all()
        count = len(sm.all())
        log.info("Sessions loaded: count=%d", count)

        # Background tasks
        asyncio.create_task(ws_mgr.keepalive_loop())
        watcher = StateWatcher(sm, ws_mgr)
        asyncio.create_task(watcher.run())
        asyncio.create_task(watcher.expire_loop(sm))
        asyncio.create_task(HBScheduler(sm).run())

        async def _auth_prune_loop():
            from server.auth import prune_auth_stores
            while True:
                await asyncio.sleep(3600)   # hourly — revoked JTIs are ≤8h lived
                try:
                    prune_auth_stores()
                except Exception:
                    pass

        asyncio.create_task(_auth_prune_loop())
        log.debug("Background tasks started: keepalive, state-watcher, hb-scheduler, lock-reaper, auth-pruner")

        log.info("Server ready — https://%s:%d  log_level=%s",
                 cfg.host, cfg.port, cfg.settings.log_level)

    @app.on_event("shutdown")
    async def _shutdown():
        sm.stop_all()

    return app


def run(config_path: str = "server.yml") -> None:
    try:
        cfg = load_config(Path(config_path))
    except FileNotFoundError as e:
        print(f"[!!] {e}")
        sys.exit(1)

    _PID_FILE.write_text(str(os.getpid()))
    try:
        _run_server(cfg)
    finally:
        _PID_FILE.unlink(missing_ok=True)


def _run_server(cfg: ServerConfig) -> None:

    # Populate TRANSPORT_REGISTRY before sessions are loaded
    import providers.all as _  # noqa: F401

    # Configure operational timezone first — all subsystems inherit it
    from core import tz as _tz_mod
    _tz_mod.configure(cfg.settings.timezone)

    # Initialise subsystems
    auth_mod.init(cfg.log_dir)
    chat_mod.init(cfg.log_dir)

    # TLS
    fp = ensure_cert(cfg.tls.cert, cfg.tls.key)
    _url = f"https://{cfg.host}:{cfg.port}"
    if cfg.is_oidc:
        _auth_info    = f"{cfg.auth_mode} ({cfg.oidc.provider_url})"
        _users_label  = "Identities"
        _users_value  = str(len(cfg.oidc.allowed_identities)) if cfg.auth_mode == "oidc-manual" else "auto"
    else:
        _auth_info    = "local"
        _users_label  = "Users     "
        _users_value  = str(len(cfg.users))

    W = 53  # inner width between │ and │

    def _rows(label: str, value: str) -> list[str]:
        prefix  = f"{label}: "
        avail   = W - len(prefix)
        cont    = " " * len(prefix)   # continuation indent
        lines   = []
        while value:
            chunk  = value[:avail]
            value  = value[avail:]
            indent = prefix if not lines else cont
            lines.append(f"  │  {indent}{chunk:<{avail}}│")
        return lines or [f"  │  {prefix}{'':<{avail}}│"]

    def _print_row(label: str, value: str) -> None:
        for line in _rows(label, value):
            print(line)

    print()
    print("  ┌───────────────────────────────────────────────────────┐")
    print("  │            STRATUM C2 — SERVER MODE                   │")
    print("  ├───────────────────────────────────────────────────────┤")
    _print_row("Listen  ", _url)
    _print_row("TLS     ", cfg.tls.mode)
    _print_row("Cert    ", fp)
    _print_row("Auth    ", _auth_info)
    _print_row(_users_label, _users_value)
    print("  └───────────────────────────────────────────────────────┘")
    print()
    print("  Confirm this fingerprint in your browser on first connect.")
    print()

    # ── Logging — must be configured before uvicorn.run() ────────────────────
    # dictConfig applied atomically; uvicorn receives log_config=None so it
    # does NOT override our setup with its own dictConfig on startup.
    configure_logging(
        level    = cfg.settings.log_level,
        log_file = cfg.settings.log_file or None,
        log_dir  = cfg.log_dir,
    )

    app = create_app(cfg)

    uvicorn.run(
        app,
        host        = cfg.host,
        port        = cfg.port,
        ssl_certfile= cfg.tls.cert,
        ssl_keyfile = cfg.tls.key,
        log_config  = None,   # prevent uvicorn from overriding our dictConfig
        workers     = 1,      # MUST be 1 — see module docstring
    )
