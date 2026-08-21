"""
server/routers/deploy.py — /api/v1/deploy endpoints.

GET  /api/v1/deploy/providers           — list available providers + their config schema
POST /api/v1/deploy                     — start a deploy task (returns task_id)
GET  /api/v1/deploy/{task_id}/stream    — SSE stream of build progress
DELETE /api/v1/deploy/{task_id}         — cancel an in-progress deploy

The WebGUI wizard posts a fully-filled config dict to POST /deploy, then opens
an SSE connection to stream cargo build output in real time.

Concurrency: only one cargo build at a time (shared compile cache + linker).
A queued second request gets 409 until the first finishes.
"""

from __future__ import annotations

import asyncio
import json
import os
import queue
import subprocess
import threading
import time as _time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from html import escape as _html_escape
from urllib.parse import quote as _url_quote

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from core import tz as _tz
from server.notifications import notify
from fastapi.responses import HTMLResponse, StreamingResponse
from server import auth as _auth_mod
from server.models import DeployRequest, DeployTaskStatus, _session_summary
from server.routers.auth import get_current_user

router = APIRouter(prefix="/api/v1/deploy", tags=["deploy"])

# ── global deploy state ───────────────────────────────────────────────────────

_deploy_locks: dict[str, threading.Lock] = {}  # HIGH-6: per-provider lock
_deploy_locks_mu = threading.Lock()
_tasks: dict[str, "_DeployTask"] = {}   # task_id → task


def _get_provider_lock(provider: str) -> threading.Lock:
    with _deploy_locks_mu:
        if provider not in _deploy_locks:
            _deploy_locks[provider] = threading.Lock()
        return _deploy_locks[provider]


class _DeployTask:
    def __init__(self, task_id: str, provider: str, config: dict, ws = None, loop = None, deployed_by: str = ""):
        self.task_id     = task_id
        self.provider    = provider
        self.config      = config
        self.status      = "running"
        self.session_id: Optional[str] = None
        self._error:     Optional[str] = None
        self._cancelled: bool = False
        self._q: queue.Queue = queue.Queue()
        self.ws          = ws
        self.loop        = loop
        self.deployed_by = deployed_by
        self._cancel     = threading.Event()

    def push(self, line: str) -> None:
        self._q.put(line)

    def done(self, session_id: Optional[str] = None, error: Optional[str] = None,
             session=None, sm=None) -> None:
        self.session_id = session_id
        self._error     = error
        self._cancelled = error == "Cancelled by operator"
        self.status     = "failed" if error else "done"
        if error:
            self._q.put(f"✗ {error}")
        self._q.put(None)   # sentinel

        # Broadcast deploy completion to all operators
        if self.ws and self.loop:
            import asyncio
            async def _broadcast():
                if self._cancelled:
                    await notify(self.ws, "warn", "Deploy Cancelled",
                                 f"{self.provider} deploy cancelled by operator")
                elif self._error:
                    await notify(self.ws, "error", "Deploy Failed",
                                 f"{self.provider} → {self.session_id}" if self.session_id else self.provider)
                elif session:
                    pending = sm.pending(session.id) if sm else None
                    payload = _session_summary(session, pending)
                    payload["deployed_by"] = self.deployed_by
                    await self.ws.broadcast({"type": "session.new", "payload": payload})
            try:
                asyncio.run_coroutine_threadsafe(_broadcast(), self.loop)
            except Exception:
                pass

    def lines(self):
        """Generator that yields SSE lines until sentinel."""
        while True:
            line = self._q.get()
            if line is None:
                return
            yield line


# ── provider config schemas ───────────────────────────────────────────────────

# Channel-configuration fields shared by every provider (appended after credentials)
_CHANNEL_FIELDS = [
    {"name": "folder_path",    "label": "Folder Path",    "type": "text", "group": "channel", "default": "/Machine1"},
    {"name": "input_file",     "label": "Input File",     "type": "text", "group": "channel", "default": "/input.txt"},
    {"name": "output_file",    "label": "Output File",    "type": "text", "group": "channel", "default": "/output.txt"},
    {"name": "heartbeat_file", "label": "Heartbeat File", "type": "text", "group": "channel", "default": "/heartbeat.txt"},
]

_PROVIDER_SCHEMAS = {
    "dropbox": {
        "label": "Dropbox",
        "fields": [
            {"name": "app_key",       "label": "App Key",       "type": "text",     "required": True},
            {"name": "app_secret",    "label": "App Secret",    "type": "password", "required": True},
            {"name": "refresh_token", "label": "Refresh Token", "type": "password", "required": True},
        ] + _CHANNEL_FIELDS,
    },
    "onedrive": {
        "label": "OneDrive",
        "fields": [
            {"name": "app_key",       "label": "Client ID",     "type": "text",     "required": True,
             "hint": "Application (client) ID", "row_with": ["tenant_id"]},
            {"name": "tenant_id",     "label": "Tenant ID",     "type": "text",     "required": True,
             "default": "consumers",
             "hint": "Use <code>consumers</code> for personal Microsoft accounts (outlook.com, live.com, hotmail.com). Use the Directory (tenant) ID GUID for work/school Azure AD accounts."},
            {"name": "app_secret",    "label": "Client Secret", "type": "password", "required": True,
             "hint": "Value — from Client credentials"},
            {"name": "refresh_token", "label": "Refresh Token", "type": "password", "required": True},
        ] + _CHANNEL_FIELDS,
    },
    "s3": {
        "label": "AWS S3",
        "fields": [
            {"name": "access_key_id",     "label": "Access Key",        "type": "text",     "required": True,
             "hint": "IAM user → Security credentials → Access keys — starts with <code>AKIA…</code>"},
            {"name": "secret_access_key", "label": "Secret Access Key", "type": "password", "required": True,
             "hint": "Shown only at key creation — if lost, delete the key and create a new one"},
            {"name": "region",            "label": "Region",            "type": "text",     "default": "us-east-1",
             "hint": "Must match exactly the bucket region (e.g. <code>eu-north-1</code>, <code>us-east-1</code>)"},
            {"name": "bucket",            "label": "Bucket",            "type": "text",     "required": True,
             "hint": "Exact bucket name as shown in the S3 console — lowercase, no spaces"},
        ] + _CHANNEL_FIELDS,
    },
    "sharepoint": {
        "label": "SharePoint",
        "fields": [
            {"name": "app_key",       "label": "Client ID",     "type": "text",     "required": True},
            {"name": "app_secret",    "label": "Client Secret", "type": "password", "required": True},
            {"name": "tenant_id",     "label": "Tenant ID",     "type": "text",     "required": True},
            {"name": "refresh_token", "label": "Refresh Token", "type": "password", "required": True},
            {"name": "site_id",       "label": "Site ID",       "type": "text",     "required": True},
        ] + _CHANNEL_FIELDS,
    },
    "googledrive": {
        "label": "Google Drive",
        "fields": [
            {"name": "app_key",       "label": "Client ID",     "type": "text",     "required": True},
            {"name": "app_secret",    "label": "Client Secret", "type": "password", "required": True},
            {"name": "refresh_token", "label": "Refresh Token", "type": "password", "required": True},
            {"name": "folder_id",     "label": "Folder ID",     "type": "text",     "required": True,
             "hint": "Open your folder on drive.google.com — copy the ID from the URL: drive.google.com/drive/folders/<b>THIS_PART</b>. It's a random alphanumeric string, never starts with 4/.<br>If you don't have a folder yet, create one: New → Folder, name it (e.g. <code>stratum-drop</code>), open it, then grab the ID from the URL.<br>Subfolders are supported — use a path like <code>stratum-drop/ops/agent1</code> and they will be created automatically."},
        ] + _CHANNEL_FIELDS,
    },
}

_COMMON_FIELDS = [
    {"name": "mode",           "label": "Deploy Mode",    "type": "select",
     "options": ["staged-enc", "stageless-enc", "stageless-plain"], "default": "staged-enc"},
    {"name": "base_sleep",     "label": "Sleep (s)",      "type": "number",   "default": 30},
    {"name": "jitter_percent", "label": "Jitter (%)",     "type": "number",   "default": 30},
    {"name": "window_start",   "label": "Window Start",   "type": "time",     "default": ""},
    {"name": "window_end",     "label": "Window End",     "type": "time",     "default": ""},
    {"name": "kill_date",      "label": "Kill Date",      "type": "date",     "default": ""},
    {"name": "blob_path_linux","label": "Linux Blob Path","type": "text",
     "default": "${HOME}/.config/pulse/.pid"},
    {"name": "blob_path_win",  "label": "Windows Blob Path","type": "text",
     "default": r"%APPDATA%\Microsoft\Windows\Themes\.ddb"},
    {"name": "debug_mode",     "label": "Debug Mode",     "type": "bool",     "default": False},
    {"name": "agent_name_win",   "label": "Windows Agent Name", "type": "text", "default": ""},
    {"name": "agent_name_linux", "label": "Linux Agent Name",   "type": "text", "default": ""},
]


@router.get("/providers")
def get_providers(username: str = Depends(get_current_user)):
    return {
        "providers": [
            {"id": pid, "label": schema["label"], "fields": schema["fields"]}
            for pid, schema in _PROVIDER_SCHEMAS.items()
        ],
        "common_fields": _COMMON_FIELDS,
    }


# ── OAuth callback flow ───────────────────────────────────────────────────────
#
# POST /oauth/start      — create pending session, return {session_id, auth_url, callback_url}
# GET  /oauth/callback   — provider redirects here with ?code=&state=session_id (no auth)
# GET  /oauth/result/{s} — poll for {status, refresh_token?}

_OAUTH_SCOPES: dict[str, str] = {
    "onedrive":    "Files.ReadWrite.All offline_access",
    "sharepoint":  "Sites.ReadWrite.All Files.ReadWrite.All offline_access",
    "googledrive": "https://www.googleapis.com/auth/drive",
}

_oauth_sessions: dict[str, dict] = {}   # session_id → {status, provider, credentials, result?, _expires}
_OAUTH_SESSION_TTL = 600  # 10 minutes — abandoned sessions are purged after this


def _broadcast_creds_changed(request: Request, provider: str) -> None:
    """Fire-and-forget broadcast from a sync context (OAuth endpoints, wizard thread)."""
    try:
        import asyncio as _asyncio
        ws = request.app.state.ws
        loop = _asyncio.get_event_loop()
        _asyncio.run_coroutine_threadsafe(
            ws.broadcast({"type": "credentials.changed", "payload": {"provider": provider}}),
            loop,
        )
    except Exception:
        pass


def _oauth_callback_url(request: Request) -> str:
    base = str(request.base_url).rstrip("/")
    return f"{base}/api/v1/deploy/oauth/callback"


def _oauth_build_auth_url(provider: str, creds: dict, callback_url: str, state: str) -> str | None:
    key    = (creds.get("app_key") or "").strip()
    tenant = (creds.get("tenant_id") or "common").strip() or "common"
    cb     = _url_quote(callback_url, safe="")

    if not key:
        return None

    if provider == "dropbox":
        return (f"https://www.dropbox.com/oauth2/authorize"
                f"?response_type=code&client_id={_url_quote(key)}"
                f"&redirect_uri={cb}&state={state}&token_access_type=offline")

    if provider == "onedrive":
        scope = _url_quote(_OAUTH_SCOPES["onedrive"])
        return (f"https://login.microsoftonline.com/{_url_quote(tenant)}/oauth2/v2.0/authorize"
                f"?client_id={_url_quote(key)}&response_type=code"
                f"&redirect_uri={cb}&scope={scope}&state={state}&response_mode=query")

    if provider == "sharepoint":
        scope = _url_quote(_OAUTH_SCOPES["sharepoint"])
        return (f"https://login.microsoftonline.com/{_url_quote(tenant)}/oauth2/v2.0/authorize"
                f"?client_id={_url_quote(key)}&response_type=code"
                f"&redirect_uri={cb}&scope={scope}&state={state}&response_mode=query")

    if provider == "googledrive":
        scope = _url_quote(_OAUTH_SCOPES["googledrive"])
        return (f"https://accounts.google.com/o/oauth2/v2/auth"
                f"?client_id={_url_quote(key)}&redirect_uri={cb}"
                f"&response_type=code&scope={scope}"
                f"&access_type=offline&prompt=consent&state={state}")

    return None


def _oauth_do_exchange(provider: str, creds: dict, code: str,
                       callback_url: str | None = None) -> str:
    """Exchange auth code → refresh_token.

    When callback_url is None the OOB redirect is used:
      Dropbox    — no redirect_uri (code shown on page)
      MS (v2)    — redirect_uri=http://localhost
      Google     — redirect_uri=urn:ietf:wg:oauth:2.0:oob
    Raises ValueError on failure.
    """
    import requests as _http

    key    = (creds.get("app_key") or "").strip()
    secret = (creds.get("app_secret") or "").strip()
    tenant = (creds.get("tenant_id") or "common").strip() or "common"

    if provider == "dropbox":
        payload: dict = {
            "grant_type": "authorization_code", "code": code,
            "client_id": key, "client_secret": secret,
        }
        if callback_url:
            payload["redirect_uri"] = callback_url
        # OOB: no redirect_uri → Dropbox shows code directly on page
        resp = _http.post("https://api.dropboxapi.com/oauth2/token",
                          data=payload, timeout=15)

    elif provider in ("onedrive", "sharepoint"):
        redir = callback_url or "http://localhost"
        # OneDrive personal uses 'consumers' authority; SharePoint uses tenant ID
        token_tenant = "consumers" if provider == "onedrive" else tenant
        resp = _http.post(
            f"https://login.microsoftonline.com/{token_tenant}/oauth2/v2.0/token",
            data={
                "grant_type": "authorization_code", "code": code,
                "client_id": key, "client_secret": secret,
                "scope": _OAUTH_SCOPES[provider],
                "redirect_uri": redir,
            }, timeout=15)

    elif provider == "googledrive":
        redir = callback_url or "urn:ietf:wg:oauth:2.0:oob"
        resp = _http.post("https://oauth2.googleapis.com/token", data={
            "grant_type": "authorization_code", "code": code,
            "client_id": key, "client_secret": secret,
            "redirect_uri": redir,
        }, timeout=15)

    else:
        raise ValueError(f"Unsupported provider: {provider}")

    data = resp.json()
    if "refresh_token" in data:
        return data["refresh_token"]
    err = data.get("error_description") or data.get("error") or "No refresh_token in response"
    raise ValueError(str(err))


def _oauth_close_html(success: bool, message: str) -> str:
    color = "#22c55e" if success else "#ef4444"
    icon  = "✓" if success else "✗"
    title = "Authorization complete" if success else "Authorization failed"
    safe_msg = _html_escape(message)
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<style>
  body{{font-family:monospace;background:#0d0a0a;color:{color};
       display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
  .b{{text-align:center}}.i{{font-size:3rem;display:block;margin-bottom:1rem}}
  .m{{font-size:1rem;color:#aaa;margin-top:.5rem}}
  .s{{margin-top:1.5rem;font-size:.8rem;color:#555}}
</style></head><body>
<div class="b">
  <span class="i">{icon}</span>
  <div>{title}</div>
  <div class="m">{safe_msg}</div>
  <div class="s">This window will close automatically…</div>
</div>
<script>setTimeout(()=>window.close(),1500)</script>
</body></html>"""


@router.post("/oauth/start")
def oauth_start(body: dict = Body(...), request: Request = None,
                username: str = Depends(get_current_user)):
    """Begin the OAuth authorization-code flow for a provider.

    Returns {session_id, auth_url, callback_url}.
    The caller opens auth_url in a popup; the provider redirects to callback_url,
    which exchanges the code and stores the refresh_token in the session.
    Poll GET /oauth/result/{session_id} to retrieve it.
    """
    provider = (body.get("provider") or "").strip()
    creds    = body.get("credentials") or {}

    if provider not in _OAUTH_SCOPES and provider != "dropbox":
        raise HTTPException(status_code=400, detail=f"OAuth not supported for '{provider}'")

    session_id   = os.urandom(10).hex()
    callback_url = _oauth_callback_url(request)
    auth_url     = _oauth_build_auth_url(provider, creds, callback_url, session_id)

    if not auth_url:
        raise HTTPException(status_code=400,
                            detail="App Key / Client ID is required to build the auth URL")

    # prune expired sessions on each new start
    now = _time.monotonic()
    expired = [sid for sid, s in _oauth_sessions.items() if now >= s["_expires"]]
    for sid in expired:
        _oauth_sessions.pop(sid, None)

    _oauth_sessions[session_id] = {
        "status":      "pending",
        "provider":    provider,
        "credentials": creds,
        "cred_label":  (body.get("cred_label") or "").strip(),
        "_expires":    now + _OAUTH_SESSION_TTL,
    }

    return {"session_id": session_id, "auth_url": auth_url, "callback_url": callback_url}


@router.get("/oauth/callback")
def oauth_callback(
    request: Request,
    code:  str = Query(default=None),
    state: str = Query(default=None),
    error: str = Query(default=None),
):
    """OAuth redirect target — called by the provider, NOT by the WebGUI directly.

    No JWT auth: the `state` parameter (= session_id) is the CSRF token.
    Exchanges the authorization code server-side and stores the result.
    Returns a self-closing HTML page the popup can display.
    """
    if error:
        if state and state in _oauth_sessions:
            _oauth_sessions[state].update({"status": "error", "error": error})
        return HTMLResponse(_oauth_close_html(False, error))

    now = _time.monotonic()
    session_entry = _oauth_sessions.get(state)
    if not code or not state or session_entry is None or now >= session_entry["_expires"]:
        _oauth_sessions.pop(state, None)
        return HTMLResponse(_oauth_close_html(False, "Invalid or expired session"))

    session      = session_entry
    callback_url = _oauth_callback_url(request)

    try:
        rt = _oauth_do_exchange(session["provider"], session["credentials"], code, callback_url)
        session.update({"status": "done", "refresh_token": rt})
        # Persist immediately — credentials are valid regardless of whether the deploy completes.
        try:
            from server import cred_store as _cs
            _cs.upsert_profile(session["provider"],
                               {**session["credentials"], "refresh_token": rt},
                               label=session.get("cred_label") or "")
            _broadcast_creds_changed(request, session["provider"])
        except Exception:
            pass
        return HTMLResponse(_oauth_close_html(True, "Refresh token acquired"))
    except Exception as exc:
        session.update({"status": "error", "error": str(exc)})
        return HTMLResponse(_oauth_close_html(False, str(exc)))


@router.get("/oauth/result/{session_id}")
def oauth_result(session_id: str, username: str = Depends(get_current_user)):
    """Poll for the result of an ongoing OAuth flow.

    Returns {status: "pending"|"done"|"error", refresh_token?, error?}.
    Clean up the session once "done" or "error" is acknowledged.
    """
    session = _oauth_sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found or expired")

    st  = session["status"]
    out = {"status": st}
    if st == "done":
        out["refresh_token"] = session.get("refresh_token", "")
        _oauth_sessions.pop(session_id, None)   # consume once
    elif st == "error":
        out["error"] = session.get("error", "Unknown error")
        _oauth_sessions.pop(session_id, None)
    return out


@router.post("/oauth/exchange")
def oauth_exchange(body: dict = Body(...), request: Request = None, username: str = Depends(get_current_user)):
    """Exchange an authorization code for a refresh token (OOB flow, no callback URL).

    Body: {provider, credentials, code}
    Returns: {refresh_token}
    """
    provider = (body.get("provider") or "").strip()
    creds    = body.get("credentials") or {}
    code     = (body.get("code") or "").strip()

    if not provider or not code:
        raise HTTPException(status_code=400, detail="provider and code are required")

    if provider not in _OAUTH_SCOPES and provider != "dropbox":
        raise HTTPException(status_code=400, detail=f"OAuth not supported for '{provider}'")

    try:
        rt = _oauth_do_exchange(provider, creds, code)   # callback_url=None → OOB
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Persist immediately — credentials are valid regardless of whether the deploy completes.
    try:
        from server import cred_store as _cs
        _cs.upsert_profile(provider, {**creds, "refresh_token": rt},
                           label=(body.get("cred_label") or "").strip())
        if request:
            _broadcast_creds_changed(request, provider)
    except Exception:
        pass

    return {"refresh_token": rt}


# ── deploy task ───────────────────────────────────────────────────────────────

@router.post("", response_model=DeployTaskStatus, status_code=status.HTTP_202_ACCEPTED)
async def start_deploy(body: DeployRequest, request: Request,
                       username: str = Depends(get_current_user)):
    from providers.all import PROVIDERS

    if body.provider not in PROVIDERS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown provider '{body.provider}'. Valid: {list(PROVIDERS)}",
        )

    provider_lock = _get_provider_lock(body.provider)
    if not provider_lock.acquire(blocking=False):
        raise HTTPException(
            status_code=409,
            detail=f"Another {body.provider} deploy is already in progress. Wait for it to finish.",
        )

    task_id = os.urandom(4).hex()
    ws = request.app.state.ws
    loop = asyncio.get_running_loop()
    task    = _DeployTask(task_id, body.provider, body.config, ws, loop, deployed_by=username)
    _tasks[task_id] = task

    sm  = request.app.state.sm
    cfg = request.app.state.cfg

    def _run():
        try:
            if not task._cancel.is_set():
                _run_wizard(task, body.provider, body.config, sm, cfg,
                            profile_id=body.profile_id,
                            cred_label=body.cred_label or "")
        finally:
            provider_lock.release()

    threading.Thread(target=_run, daemon=True, name=f"deploy-{task_id}").start()
    return DeployTaskStatus(task_id=task_id, status="running")


def _run_wizard(task: "_DeployTask", provider: str, config: dict,
                sm, cfg, profile_id: Optional[str] = None,
                cred_label: str = "") -> None:
    """
    Run a provider wizard non-interactively using the config dict from the WebGUI.

    Patching strategy: wizard modules use `from providers import ask, err, ...`
    creating LOCAL bindings at import time. We must patch every loaded providers.*
    submodule directly (not just providers.ask) to override those local references.
    step_auth is overridden on the wizard instance to inject credentials directly
    and skip the interactive auth-code exchange (the WebGUI already obtained the
    refresh_token via /oauth/exchange).
    """
    import sys as _sys
    import re as _re
    import traceback as _tb
    import providers.base as _base
    from providers.all import PROVIDERS
    from providers import WizardError as _WizardError
    from providers._notifications import CancelledError as _CancelledError

    task.push(f"[deploy] starting {provider} wizard…")

    # Non-channel config keys that belong to credentials (not to wizard prompts)
    _CRED_KEYS = frozenset({
        'app_key', 'app_secret', 'refresh_token',
        'client_id', 'client_secret', 'tenant_id',
        'folder_id',
        # S3-specific
        'access_key_id', 'secret_access_key', 'region', 'bucket',
        # SharePoint-specific
        'site_id',
    })

    _cfg = dict(config)
    # Aliases for prompts whose key↔name mapping isn't obvious
    for orig, alias in {
        "blob_path_linux": "linux_blob_path",
        "blob_path_win":   "windows_blob_path",
        "debug_mode":      "enable_debug_output",
        "session_label":   "label",
        # Google Drive: form sends app_key/app_secret, config expects client_id/client_secret
        "app_key":    "client_id",
        "app_secret": "client_secret",
    }.items():
        if orig in _cfg:
            _cfg[alias] = _cfg[orig]

    def _norm(s: str) -> str:
        return _re.sub(r'[\s\-]+', '_', s.lower().strip())

    class _WizardAbort(Exception):
        pass

    def _patched_ask(prompt_text: str, default: str = "", choices=()) -> str:
        # MED-17: exact match only — no substring/fuzzy matching to prevent injection
        import secrets as _sec
        np = _norm(prompt_text)
        for key, val in _cfg.items():
            if _norm(key) == np:
                sv = str(val)
                if sv == "__random__":
                    sv = "/" + _sec.token_hex(4)
                elif sv == "__random_folder__":
                    from providers._wizard import _random_folder
                    sv = _random_folder()
                task.push(f"  {prompt_text}: {sv}")
                return sv
        task.push(f"  {prompt_text}: {default} (default)")
        return str(default)

    def _patched_ask_int(prompt_text: str, default: int, lo: int, hi: int) -> int:
        np = _norm(prompt_text)
        for key, val in _cfg.items():
            nk = _norm(key)
            if nk == np or (len(nk) >= 5 and (nk in np or np in nk)):
                try:
                    v = int(val)
                    if lo <= v <= hi:
                        task.push(f"  {prompt_text}: {v}")
                        return v
                except (ValueError, TypeError):
                    pass
        task.push(f"  {prompt_text}: {default} (default)")
        return default

    def _patched_ask_yn(prompt_text: str, default: bool = True) -> bool:
        np = _norm(prompt_text)
        for key, val in _cfg.items():
            nk = _norm(key)
            if nk == np or (len(nk) >= 5 and (nk in np or np in nk)):
                if isinstance(val, bool):   return val
                if isinstance(val, str):    return val.lower() in ("true", "1", "yes")
        return default

    def _patched_ok(m: str):   task.push(f"✓ {m}")
    def _patched_warn(m: str): task.push(f"⚠ {m}")
    def _patched_info(m: str): task.push(f"  {m}")
    def _patched_step(n, t):   task.push(f"=== STEP {n}: {t} ===")
    def _patched_err(m: str):
        task.push(f"✗ {m}")
        raise _WizardAbort(m)
    def _patched_p(pairs):
        # pairs is [(class_name, text), ...] — strip styling, join text, push as plain line
        text = "".join(t for _, t in (pairs or []))
        if text.strip():
            task.push(text)

    # Patch EVERY loaded providers.* submodule (covers local `from providers import X`)
    _saved: dict[str, dict] = {}
    _REPLACEMENTS = {
        "_p":      _patched_p,
        "ask":     _patched_ask,
        "ask_int": _patched_ask_int,
        "ask_yn":  _patched_ask_yn,
        "ok":      _patched_ok,
        "err":     _patched_err,
        "warn":    _patched_warn,
        "info":    _patched_info,
        "step":    _patched_step,
    }
    for _mod_name, _mod in list(_sys.modules.items()):
        if not _mod_name.startswith("providers") or _mod is None:
            continue
        for _attr, _repl in _REPLACEMENTS.items():
            if hasattr(_mod, _attr):
                _saved.setdefault(_mod_name, {})[_attr] = getattr(_mod, _attr)
                setattr(_mod, _attr, _repl)

    # Temporarily replace the notification hub so runtime _n_* calls during
    # the wizard (AsyncPoller, HeartbeatMonitor) are routed to the task stream.
    import providers._notifications as _notif
    _orig_hub = _notif._hub

    class _DeployHub(_base._NotificationHub):
        def ok(self, m: str)                     -> None: task.push(f"✓ {m}")
        def err(self, m: str)                    -> None: task.push(f"✗ {m}")
        def warn(self, m: str)                   -> None: task.push(f"⚠ {m}")
        def info(self, m: str)                   -> None: task.push(f"  {m}")
        def output(self, cid: str, c: str)       -> None: task.push(f"↵ [{cid}] {(c or '').strip()[:200]}")
        # Delegate session-persistence and WS-push handlers to the original server hub
        # so heartbeats and session saves still work correctly during deploy.
        def ul_confirmed(self, sid: str)         -> None: _orig_hub.ul_confirmed(sid)
        def heartbeat(self, sid: str, s: dict)   -> None: _orig_hub.heartbeat(sid, s)
        def agent_dead(self, sid: str)           -> None: _orig_hub.agent_dead(sid)
        def save_session(self, sess)             -> None: _orig_hub.save_session(sess)
        def persist_updated(self, sid: str)      -> None: _orig_hub.persist_updated(sid)

    _notif._hub = _DeployHub()

    try:
        wizard_cls = PROVIDERS[provider]
        wizard     = wizard_cls()

        # Override step_auth: inject credentials into the config object and skip
        # the interactive auth-code exchange. When profile_id is set the WebUI
        # sent only channel fields; credentials are loaded from disk by profile_id.
        # When profile_id is absent the WebUI sent new credentials in _cfg directly
        # (new-credentials flow).
        def _auto_step_auth(cfg_obj) -> None:
            task.push("=== STEP 1: Credentials ===")

            if profile_id:
                # Resolve full credentials from disk — never trust the client for secrets.
                from server import cred_store as _cs
                profiles = _cs.load_profiles(provider)
                matched  = next((p for p in profiles if p.get("id") == profile_id), None)
                if not matched:
                    raise _WizardAbort(
                        f"Saved credential profile '{profile_id}' not found — "
                        "delete the profile and re-enter credentials."
                    )
                disk_creds = matched.get("creds", {})
                for k, v in disk_creds.items():
                    if hasattr(cfg_obj, k) and str(v).strip():
                        setattr(cfg_obj, k, str(v).strip())
                task.push(f"  ✓ Credentials loaded from saved profile: {matched.get('label', profile_id)}")
                # Also apply aliases (app_key→client_id for Google Drive)
                for orig, alias in {
                    "app_key":    "client_id",
                    "app_secret": "client_secret",
                }.items():
                    val = disk_creds.get(orig, "")
                    if val and hasattr(cfg_obj, alias) and not getattr(cfg_obj, alias):
                        setattr(cfg_obj, alias, val)
                # Channel-only fields still come from _cfg (user-supplied per-deploy paths).
                import secrets as _sec
                for k, v in _cfg.items():
                    if k not in _CRED_KEYS and hasattr(cfg_obj, k):
                        sv = str(v).strip()
                        if sv == "__random__":
                            sv = "/" + _sec.token_hex(4)
                            task.push(f"  {k}: {sv} (randomized)")
                        elif sv == "__random_folder__":
                            from providers._wizard import _random_folder
                            sv = _random_folder()
                            task.push(f"  {k}: {sv} (randomized)")
                        if sv:
                            setattr(cfg_obj, k, sv)
                # Provider-specific IDs (folder_id, site_id) may come from the form
                # when the saved profile predates the field or the user overrides it.
                for k in ("folder_id", "site_id"):
                    if hasattr(cfg_obj, k) and not getattr(cfg_obj, k):
                        v = str(_cfg.get(k, "")).strip()
                        if v:
                            setattr(cfg_obj, k, v)
                            task.push(f"  {k}: {v} (from form)")
            else:
                # New-credentials flow: all fields come from the WebGUI form.
                if hasattr(cfg_obj, "load_creds"):
                    try:
                        cfg_obj.load_creds()
                    except Exception:
                        pass
                for k, v in _cfg.items():
                    if k in _CRED_KEYS and hasattr(cfg_obj, k) and str(v).strip():
                        setattr(cfg_obj, k, str(v).strip())
                task.push(f"  ✓ Credentials injected from WebGUI configuration")

            required_missing = [k for k in ('app_key', 'app_secret', 'refresh_token')
                                 if hasattr(cfg_obj, k) and not getattr(cfg_obj, k)]
            if required_missing:
                raise _WizardAbort(f"Missing required credentials: {', '.join(required_missing)}")

            # Persist credentials to disk so the session JSON can be reloaded after
            # a server restart.  Without this, load_all() raises FileNotFoundError on
            # the creds_file path and the session silently disappears from the list.
            try:
                cfg_obj.save_creds()
                task.push(f"  ✓ Credentials saved to disk for session persistence")
            except Exception as exc:
                task.push(f"  ⚠ Could not save credentials to disk ({exc}) — session will not survive restart")

            # Register credentials in the WebGUI credential store immediately after
            # validation — even if the deploy is cancelled later the credentials
            # remain available for reuse in subsequent deployments.
            try:
                from server import cred_store as _cs
                _cs.upsert_profile(provider, _cs.extract_creds(cfg_obj), label=cred_label)
                if task.ws and task.loop:
                    import asyncio as _asyncio
                    _asyncio.run_coroutine_threadsafe(
                        task.ws.broadcast({"type": "credentials.changed", "payload": {"provider": provider}}),
                        task.loop,
                    )
            except Exception:
                pass

        wizard.step_auth = _auto_step_auth

        # Register cancel event so cargo subprocesses can be interrupted
        _base._set_cancel_event(task._cancel)
        try:
            session = wizard.run(sm._sm, Path("."))   # blocking
        finally:
            _base._set_cancel_event(None)

        task.push(f"✓ Deploy complete — session {session.id}")
        task.done(session_id=session.id, session=session, sm=sm)

    except (_WizardAbort, _WizardError) as e:
        task.done(error=str(e))
    except _CancelledError:
        task.push("✗ Deploy cancelled — all artifacts rolled back")
        task.done(error="Cancelled by operator")
    except Exception as e:
        import logging as _log
        _log.getLogger(__name__).error("Deploy task %s failed: %s", task.task_id, _tb.format_exc())
        task.push(f"✗ Internal deploy error — check server logs")
        task.done(error="Internal deploy error")
    finally:
        # Restore all patched wizard-UI attributes
        for _mod_name, _attrs in _saved.items():
            _mod = _sys.modules.get(_mod_name)
            if _mod:
                for _attr, _orig in _attrs.items():
                    setattr(_mod, _attr, _orig)
        # Restore notification hub
        _notif._hub = _orig_hub


# ── SSE stream ────────────────────────────────────────────────────────────────

@router.get("/{task_id}/stream")
async def stream_deploy(task_id: str, request: Request,
                        username: str = Depends(get_current_user)):
    task = _tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    async def _sse():
        loop = asyncio.get_event_loop()
        while True:
            try:
                line = await loop.run_in_executor(None, task._q.get, True, 1.0)
            except queue.Empty:
                yield "data: \n\n"   # heartbeat
                continue
            if line is None:
                data = json.dumps({
                    "status":     task.status,
                    "session_id": task.session_id,
                    "message":    task._error,
                })
                yield f"event: done\ndata: {data}\n\n"
                return
            yield f"data: {json.dumps({'line': line})}\n\n"

    return StreamingResponse(
        _sse(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.delete("/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
def cancel_deploy(task_id: str, username: str = Depends(get_current_user)):
    task = _tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.status == "running":
        task._cancel.set()
        task.push("⚠ Cancel requested — waiting for rollback…")
