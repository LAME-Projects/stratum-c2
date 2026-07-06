# providers/_notifications.py
# Notification hub, thin wrappers, upload-record helper, cancelable subprocess.
# No imports from other providers.* internal modules.

import io as _io
import json
import logging
import os
import subprocess
import threading
from pathlib import Path
from typing import Optional

_log = logging.getLogger("stratum.cmd")

# ── thread-local cancel event ─────────────────────────────────────────────────

_tl = threading.local()


def _set_cancel_event(ev: "Optional[threading.Event]") -> None:
    """Register a cancel event for the current wizard thread."""
    _tl.cancel_event = ev


def _cancelable_run(cmd: list, **kwargs) -> "subprocess.CompletedProcess":
    """subprocess.run() replacement that terminates the child when cancelled.

    Falls back to a plain subprocess.run() if no cancel event is registered.
    Raises subprocess.CalledProcessError with returncode=-1 on cancellation.
    """
    cancel: "Optional[threading.Event]" = getattr(_tl, "cancel_event", None)
    if cancel is None:
        return subprocess.run(cmd, **kwargs)

    kwargs.setdefault("stdout", subprocess.PIPE)
    kwargs.setdefault("stderr", subprocess.PIPE)
    text = kwargs.pop("text", False)
    capture = kwargs.pop("capture_output", False)
    if capture:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE

    proc = subprocess.Popen(cmd, **kwargs)

    # Drain stdout/stderr in background threads to prevent pipe deadlock,
    # then poll proc.wait() so we can honour cancel without blocking forever.
    _out_buf = _io.BytesIO()
    _err_buf = _io.BytesIO()

    def _drain(src, dst):
        if src:
            dst.write(src.read())

    _t_out = threading.Thread(target=_drain, args=(proc.stdout, _out_buf), daemon=True)
    _t_err = threading.Thread(target=_drain, args=(proc.stderr, _err_buf), daemon=True)
    _t_out.start(); _t_err.start()

    while True:
        try:
            proc.wait(timeout=2)
            break
        except subprocess.TimeoutExpired:
            if cancel.is_set():
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                _t_out.join(timeout=2); _t_err.join(timeout=2)
                raise subprocess.CalledProcessError(-1, cmd,
                    output=b"", stderr=b"Cancelled by operator")

    _t_out.join(); _t_err.join()
    stdout_b = _out_buf.getvalue()
    stderr_b = _err_buf.getvalue()
    rc = proc.returncode
    if text:
        enc = kwargs.get("encoding", "utf-8")
        return subprocess.CompletedProcess(
            cmd, rc,
            stdout_b.decode(enc, errors="replace"),
            stderr_b.decode(enc, errors="replace"),
        )
    return subprocess.CompletedProcess(cmd, rc, stdout_b, stderr_b)


# ── notification hub ──────────────────────────────────────────────────────────

class _NotificationHub:
    """Abstract base — override any handler that needs non-default behaviour."""
    def ok(self, msg: str) -> None: pass
    def err(self, msg: str) -> None: pass
    def warn(self, msg: str) -> None: pass
    def info(self, msg: str) -> None: pass
    def output(self, cmd_id: str, content: str) -> None: pass
    def ul_confirmed(self, session_id: str) -> None: pass
    def heartbeat(self, session_id: str, state: dict) -> None: pass
    def agent_dead(self, session_id: str) -> None: pass
    def save_session(self, sess) -> None: pass
    def persist_updated(self, session_id: str) -> None: pass


class _CliNotificationHub(_NotificationHub):
    """Default hub: log + print to stdout (used when running outside the server)."""
    def ok(self, msg: str) -> None:
        _log.info("ok: %s", msg)
        print(f"  ✓ {msg}")
    def err(self, msg: str) -> None:
        _log.error("err: %s", msg)
        print(f"  ✗ {msg}")
    def warn(self, msg: str) -> None:
        _log.warning("warn: %s", msg)
        print(f"  ⚠ {msg}")
    def info(self, msg: str) -> None:
        _log.debug("info: %s", msg)
        print(f"  {msg}")
    def output(self, cmd_id: str, content: str) -> None:
        _log.info("output: cmd_id=%s length=%d", cmd_id, len(content))
        print(f"  ↵ [{cmd_id}] response:")
        print("  " + "─" * 43)
        print(content.rstrip())
        print("  " + "─" * 43)
        print()


_hub: _NotificationHub = _CliNotificationHub()

# ── thin module-level wrappers (call sites unchanged) ─────────────────────────
def _n_ok(msg: str)                          -> None: _hub.ok(msg)
def _n_err(msg: str)                         -> None: _hub.err(msg)
def _n_warn(msg: str)                        -> None: _hub.warn(msg)
def _n_info(msg: str)                        -> None: _hub.info(msg)
def _n_output(cmd_id: str, content: str)    -> None: _hub.output(cmd_id, content)
def _n_ul_confirmed(session_id: str)        -> None: _hub.ul_confirmed(session_id)
def _n_heartbeat(session_id: str, state: dict) -> None: _hub.heartbeat(session_id, state)
def _n_agent_dead(session_id: str)          -> None: _hub.agent_dead(session_id)
def _n_save_session(sess)                   -> None: _hub.save_session(sess)
def _n_persist_updated(session_id: str)     -> None: _hub.persist_updated(session_id)


def _save_ul_record(sess_id: str, info: dict, log_dir: Path) -> None:
    path = log_dir / f"uploads_{sess_id}.json"
    records = []
    if path.exists():
        try:
            records = json.loads(path.read_text())
        except Exception:
            records = []
    records.append(info)
    path.write_text(json.dumps(records, indent=2))
    path.chmod(0o600)
