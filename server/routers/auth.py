"""
server/routers/auth.py — /api/v1/auth endpoints.

POST /api/v1/auth/login          — exchange username+password for JWT (local mode)
POST /api/v1/auth/logout         — revoke the caller's token
GET  /api/v1/auth/me             — return current username (token probe)
GET  /api/v1/auth/oidc/start     — return OIDC provider redirect URL
GET  /api/v1/auth/oidc/callback  — handle provider callback, issue JWT
GET  /api/v1/auth/mode           — return current auth_mode (for login page)
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse, Response

from pathlib import Path

from server import auth as auth_mod
from server.config import ServerConfig
from server.models import LoginRequest

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

_COOKIE_NAME = "stratum_token"
_COOKIE_OPTS = dict(httponly=True, secure=True, samesite="strict", path="/")


def _cfg(request: Request) -> ServerConfig:
    return request.app.state.cfg


def get_current_user(request: Request) -> str:
    cfg = _cfg(request)
    raw = request.cookies.get(_COOKIE_NAME)
    if not raw:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    username = auth_mod.verify_token(cfg, raw)
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    return username


# ── local login ───────────────────────────────────────────────────────────────

@router.post("/login")
def login(body: LoginRequest, request: Request):
    cfg       = _cfg(request)
    client_ip = request.client.host if request.client else "unknown"

    if cfg.is_oidc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Server is configured for OIDC login. Use /api/v1/auth/oidc/start.",
        )

    if not auth_mod.check_rate_limit(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Try again in 60 seconds.",
        )

    user = auth_mod.authenticate(cfg, body.username, body.password)
    if not user:
        auth_mod.record_failure(client_ip)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    auth_mod.record_success(client_ip)
    token = auth_mod.issue_token(cfg, user.username)
    resp  = JSONResponse({"username": user.username, "display": user.username})
    resp.set_cookie(_COOKIE_NAME, token, **_COOKIE_OPTS)
    return resp


# ── logout ────────────────────────────────────────────────────────────────────

@router.post("/logout")
async def logout(request: Request):
    cfg = _cfg(request)
    refresh_token = ""
    raw = request.cookies.get(_COOKIE_NAME)
    identity = None
    if raw:
        identity = auth_mod.verify_token(cfg, raw)
        refresh_token = auth_mod.revoke_token(cfg, raw) or ""
    if cfg.is_oidc:
        auth_mod.oidc_backchannel_logout(cfg.oidc, refresh_token)
    # MED-3: close the WS connection for this operator so the session cannot survive logout.
    if identity:
        try:
            await request.app.state.ws.disconnect_user(identity)
        except Exception:
            pass
    resp = Response(status_code=status.HTTP_204_NO_CONTENT)
    resp.delete_cookie(_COOKIE_NAME, path="/")
    return resp


# ── me ────────────────────────────────────────────────────────────────────────

@router.get("/me")
def me(request: Request):
    cfg = _cfg(request)
    raw = request.cookies.get(_COOKIE_NAME)
    if not raw:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    identity, display = auth_mod.verify_token_display(cfg, raw)
    if not identity:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    return {"username": identity, "display": display or identity}


# ── auth mode probe (used by login page to decide which UI to show) ───────────

@router.get("/mode")
def auth_mode(request: Request):
    cfg = _cfg(request)
    return {"auth_mode": cfg.auth_mode}


# ── OIDC ──────────────────────────────────────────────────────────────────────

@router.get("/oidc/start")
def oidc_start(request: Request):
    """Return the provider authorization URL. Browser redirects there."""
    cfg = _cfg(request)
    if not cfg.is_oidc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OIDC not enabled.")
    redirect_uri = str(request.base_url) + "api/v1/auth/oidc/callback"
    try:
        url, _ = auth_mod.oidc_authorization_url(cfg.oidc, redirect_uri)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service unavailable.\nPlease try again later.",
        )
    return {"url": url}



@router.get("/oidc/callback")
def oidc_callback(request: Request, code: Optional[str] = None, state: Optional[str] = None, error: Optional[str] = None, error_description: Optional[str] = None):
    """Handle redirect from OIDC provider. Issues JWT and redirects to /?token=..."""
    cfg = _cfg(request)
    if not cfg.is_oidc:
        return RedirectResponse("/?oidc_error=OIDC+not+enabled.")

    # Provider returned an error — MED-12: use fixed codes, never reflect free-text from provider
    if error:
        return RedirectResponse("/?oidc_error=provider_error")

    if not code or not state:
        return RedirectResponse("/?oidc_error=missing_params")

    redirect_uri = str(request.base_url) + "api/v1/auth/oidc/callback"
    try:
        claims   = auth_mod.oidc_exchange_code(cfg.oidc, code, state, redirect_uri)
        identity = auth_mod.oidc_identity(cfg.oidc, claims)
        display  = auth_mod.oidc_display(cfg.oidc, claims)
    except ValueError:
        return RedirectResponse("/?oidc_error=invalid_token")
    except Exception:
        return RedirectResponse("/?oidc_error=auth_error")

    allowed, reason = auth_mod.oidc_authorize(cfg, identity)
    if not allowed:
        refresh_token = claims.pop("_refresh_token", "")
        auth_mod.oidc_backchannel_logout(cfg.oidc, refresh_token)
        return RedirectResponse("/?oidc_error=not_authorized")

    # oidc-auto: ensure prefs file exists (lazy provisioning)
    if cfg.auth_mode == "oidc-auto":
        from server.routers.prefs import ensure_exists as _ensure_prefs
        _ensure_prefs(Path(cfg.log_dir), identity)

    refresh_token = claims.pop("_refresh_token", "")
    token = auth_mod.issue_token(cfg, identity, display=display, oidc_refresh_token=refresh_token)
    resp  = RedirectResponse(f"/?oidc_display={_urlencode(display)}", status_code=302)
    resp.set_cookie(_COOKIE_NAME, token, **_COOKIE_OPTS)
    return resp


def _urlencode(s: str) -> str:
    from urllib.parse import quote_plus
    return quote_plus(s)
