"""
server/models.py — Pydantic schemas for API request/response bodies.
"""

from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel


# ── auth ──────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    display: Optional[str] = None   # display name (may differ from username in OIDC mode)


# ── sessions ──────────────────────────────────────────────────────────────────

class SessionSummary(BaseModel):
    id: str
    session_id: str
    label: str
    provider: str
    deploy_mode: str
    state: str
    target_host: str
    target_user: str
    target_os: str
    target_ip: str
    target_ip_ext: str
    target_privs: str
    remote_cwd: str
    last_hb_ts: str
    added_at: str
    polling_stopped: bool = False
    pending_cmd: Optional[dict] = None
    s2_uploaded_at: str = ""
    s2_deleted: bool = False
    # P2P topology
    p2p_parent_guid: str = ""
    p2p_children_guids: str = ""
    p2p_link_type: str = ""
    p2p_link_address: str = ""
    p2p_is_internal: bool = False

class SessionDetail(SessionSummary):
    folder_path: str
    input_file: str
    output_file: str
    heartbeat_file: str
    base_sleep: int
    jitter_percent: int
    blob_path: str
    blob_path_win: str
    key_mismatch: bool
    agent_sleep: Optional[int] = None
    agent_jitter: Optional[int] = None
    agent_pid: str = ""
    agent_process: str = ""
    target_domain: str = ""

class CommandRequest(BaseModel):
    command: str
    display: Optional[str] = None   # human-readable label (defaults to command)

class CommandResponse(BaseModel):
    ok: bool
    cmd_id: Optional[str]  = None
    error: Optional[str]   = None
    locked_by: Optional[str] = None
    command: Optional[str] = None        # the in-flight command (when locked)
    locked_cmd_id: Optional[str] = None  # cmd_id of the blocking command

class HistoryEntry(BaseModel):
    timestamp: str
    session_id: str
    cmd_id: str
    command: str
    response: str
    operator: str = ""

class DownloadedFile(BaseModel):
    filename:    str
    local_path:  str
    remote_path: Optional[str] = None
    size_bytes:  Optional[int] = None
    timestamp:   str
    cmd_id:      str
    exists:      bool = False
    downloadable: bool = False   # True only if the path is under downloads/
    md5:         Optional[str] = None
    mime_type:   Optional[str] = None


# ── chat ──────────────────────────────────────────────────────────────────────

class ChatMessageIn(BaseModel):
    text: str

class ChatMessage(BaseModel):
    id: str
    ts: str
    username: str
    text: str


# ── session actions ───────────────────────────────────────────────────────────

class SleepRequest(BaseModel):
    seconds: int

class JitterRequest(BaseModel):
    percent: int

class PersistRequest(BaseModel):
    action: str   # "install" | "remove" | "check"

class PersistProbeRequest(BaseModel):
    techniques: Optional[str] = None   # comma-separated IDs, or None for all

class PersistTechniqueRequest(BaseModel):
    technique: str   # e.g. "cron-reboot", "schtask-logon"

class TimestompRequest(BaseModel):
    target: str
    reference: str = ""
    explicit_time: str = ""   # /timestomp -v "YYYY-MM-DD HH:MM" <target>

class ArtifactEntry(BaseModel):
    type: str
    path: str
    recorded_at: str

class StagedFile(BaseModel):
    name: str
    path: str   # full cloud path, used for proxy download

# ── captured credentials ──────────────────────────────────────────────────────

class CredentialEntry(BaseModel):
    id: str = ""
    timestamp: str = ""
    session_id: str = ""
    source: str = ""
    username: str = ""
    secret: str = ""
    secret_type: str = "password"
    domain: str = ""
    protocol: str = ""
    host: str = ""
    port: str = ""
    notes: str = ""
    operator: str = ""

class CredentialRequest(BaseModel):
    username: str
    secret: str
    secret_type: str = "password"
    source: str = "manual"
    domain: str = ""
    protocol: str = ""
    host: str = ""
    port: str = ""
    notes: str = ""


# ── deploy ────────────────────────────────────────────────────────────────────

class DeployRequest(BaseModel):
    provider: str
    config: dict[str, Any]   # provider-specific; passed to wizard.make_config_from_dict()
    profile_id: Optional[str] = None  # if set, credentials are loaded server-side from disk
    cred_label: Optional[str] = None  # human-readable name for the credential profile

class DeployTaskStatus(BaseModel):
    task_id: str
    status: str   # "running" | "done" | "failed"
    session_id: Optional[str] = None


# ── session serialisation helper ─────────────────────────────────────────────

def _session_summary(session, pending) -> dict:
    """Serialise a Session + optional PendingCommand to a plain dict for WS/REST."""
    snap = session.state.snapshot()
    sid  = session.id
    return {
        "id":            sid,
        "session_id":    sid,
        "label":         session.profile.label,
        "provider":      session.profile.provider,
        "deploy_mode":   session.profile.deploy_mode,
        "folder_path":   session.profile.folder_path,
        "state":         snap.get("state", "unknown"),
        "target_host":   snap.get("target_host", ""),
        "target_user":   snap.get("target_user", ""),
        "target_os":     snap.get("target_os", ""),
        "target_ip":     snap.get("target_ip", ""),
        "target_ip_ext": snap.get("target_ip_ext", ""),
        "target_privs":  snap.get("target_privs", ""),
        "target_domain": snap.get("target_domain", ""),
        "remote_cwd":    snap.get("remote_cwd", ""),
        "last_hb_ts":    snap.get("last_hb_ts", ""),
        "last_seen_at":  snap.get("last_seen_at"),
        "agent_sleep":   session.agent_sleep,
        "agent_jitter":  session.agent_jitter,
        "agent_pid":     snap.get("agent_pid", ""),
        "agent_process": snap.get("agent_process", ""),
        "input_file":    session.profile.input_file,
        "output_file":   session.profile.output_file,
        "heartbeat_file": session.profile.heartbeat_file,
        "added_at":         session.profile.added_at,
        "s2_uploaded_at":   session.profile.s2_uploaded_at,
        "s2_deleted":       session.profile.s2_deleted,
        "polling_stopped":  session.polling_stopped,
        "persist_probe_data": snap.get("persist_probe_data", {}),
        "listeners":          snap.get("listeners", {}),
        "stratum_version":    getattr(session.profile, 'stratum_version', ''),
        "locked":             getattr(session.profile, 'locked', False),
        # P2P topology
        "p2p_parent_guid":    getattr(session.profile, 'p2p_parent_guid', ''),
        "p2p_children_guids": getattr(session.profile, 'p2p_children_guids', ''),
        "p2p_link_type":      getattr(session.profile, 'p2p_link_type', ''),
        "p2p_link_address":   getattr(session.profile, 'p2p_link_address', ''),
        "p2p_is_internal":    getattr(session.profile, 'p2p_is_internal', False),
        "p2p_guid":           getattr(session.profile, 'p2p_guid', ''),
        "pending_cmd":   {
            "cmd_id":     pending.cmd_id,
            "command":    pending.display or pending.command,
            "issued_by":  pending.issued_by,
            "expires_at": pending.expires_at,
        } if pending else None,
    }


# ── P2P topology ─────────────────────────────────────────────────────────────

class TopologyNode(BaseModel):
    guid: str
    label: str = ""
    hostname: str = ""
    ip: str = ""
    os: str = ""
    username: str = ""
    is_admin: bool = False
    is_egress: bool = False
    link_type: str = ""
    status: str = "unknown"
    last_seen: Optional[str] = None
    provider: str = ""
    folder_path: str = ""
    input_file: str = ""
    output_file: str = ""
    heartbeat_file: str = ""

class TopologyEdge(BaseModel):
    source: str
    target: str
    link_type: str = ""
    link_port: Optional[int] = None
    link_address: str = ""
    status: str = "up"

class TopologyResponse(BaseModel):
    nodes: list[TopologyNode]
    edges: list[TopologyEdge]

class LinkRequest(BaseModel):
    child_session_id: str
    link_type: str = "tcp"
    link_address: str = ""

class UnlinkRequest(BaseModel):
    child_session_id: str


# ── jump (lateral movement) ──────────────────────────────────────────────────

class JumpRequest(BaseModel):
    module: str                        # psexec | psexec_psh | winrm | wmi | scshell | ssh
    target: str                        # IP or hostname
    user: str = ""                     # username (default: current creds)
    password: str = ""                 # password
    hash: str = ""                     # NTLM hash (pass-the-hash)
    key_path: str = ""                 # SSH private key path on agent
    link_type: str = ""                # tcp | smb (default: smb on Win, tcp on Linux)
    port: int = 0                      # P2P listener port (0 = auto)
    pipe: str = ""                     # SMB pipe name (empty = random)
    service: str = ""                  # service name for scshell (default: XblAuthManager)
    platform: str = ""                 # target platform hint: windows | linux (auto-detect)

class JumpStatus(BaseModel):
    ok: bool
    error: str = ""
    cmd_id: str = ""
    child_session_id: str = ""
    module: str = ""
    target: str = ""


class CascadeKillResponse(BaseModel):
    ok: bool
    killed: list[str] = []
    errors: list[str] = []


class P2PListenerGenRequest(BaseModel):
    donor_session_id: str              # existing session to clone transport creds from
    bind_type: str = "tcp"             # tcp | smb
    bind_address: str = ""             # e.g. "0.0.0.0:4444" or "\\.\pipe\svc_name"
    port: int = 0                      # TCP port (0 = random 4444-5443)
    pipe: str = ""                     # SMB pipe name (empty = random)
    platform: str = "linux"            # linux | windows
    label: str = ""                    # operator label for the new session


class P2PListenerGenResponse(BaseModel):
    ok: bool
    error: str = ""
    session_id: str = ""
    bind_type: str = ""
    bind_address: str = ""
    platform: str = ""
    download_url: str = ""


# ── WS envelope ───────────────────────────────────────────────────────────────

class WSMessage(BaseModel):
    type: str
    ts: str
    payload: dict[str, Any]
