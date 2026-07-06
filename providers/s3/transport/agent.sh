# === TRANSPORT: AWS S3 (Sig V4) ===
# Provider-specific: upload, upload_file, download, cleanup.
# No token refresh — each request is individually signed with AWS Sig V4.
# Requires: openssl, curl, date (GNU coreutils).
# Credentials are base64 placeholders substituted by the wizard at deploy time.

_AK=$(printf '%s' 'PLACEHOLDER_ACCESS_KEY_ID_B64'     | base64 -d)
_SK=$(printf '%s' 'PLACEHOLDER_SECRET_ACCESS_KEY_B64'  | base64 -d)
_SR=$(printf '%s' 'PLACEHOLDER_S3_REGION_B64'           | base64 -d)
_SB=$(printf '%s' 'PLACEHOLDER_S3_BUCKET_B64'           | base64 -d)
_SH="${_SB}.s3.${_SR}.amazonaws.com"
_SE="https://${_SH}"
_EH='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

_hmac256() {
    # _hmac256 hexkey message → lowercase hex
    printf '%s' "$2" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$1" 2>/dev/null \
        | awk '{print $NF}'
}

_sha256s() {
    printf '%s' "$1" | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}'
}

_sha256f() {
    openssl dgst -sha256 -hex "$1" 2>/dev/null | awk '{print $NF}'
}

_s3_sigkey() {
    local _d="$1" _k0 _k1 _k2
    _k0=$(printf '%s' "$_d" | openssl dgst -sha256 -mac HMAC \
            -macopt "key:AWS4${_SK}" 2>/dev/null | awk '{print $NF}')
    _k1=$(_hmac256 "$_k0" "$_SR")
    _k2=$(_hmac256 "$_k1" "s3")
    _hmac256 "$_k2" "aws4_request"
}

# Sets globals: _S3A (Authorization), _S3D (X-Amz-Date), _S3P (payload hash)
_s3_sign() {
    local _meth="$1" _key="$2" _phash="$3" _ctype="$4"
    local _dt _date _scope _hdrs _canon _sts _skey _sig
    _dt=$(date -u +%Y%m%dT%H%M%SZ)
    _date="${_dt:0:8}"
    _scope="${_date}/${_SR}/s3/aws4_request"

    if [ -n "$_ctype" ]; then
        _hdrs="content-type;host;x-amz-content-sha256;x-amz-date"
        _canon="${_meth}
/${_key}

content-type:${_ctype}
host:${_SH}
x-amz-content-sha256:${_phash}
x-amz-date:${_dt}

content-type;host;x-amz-content-sha256;x-amz-date
${_phash}"
    else
        _hdrs="host;x-amz-content-sha256;x-amz-date"
        _canon="${_meth}
/${_key}

host:${_SH}
x-amz-content-sha256:${_phash}
x-amz-date:${_dt}

host;x-amz-content-sha256;x-amz-date
${_phash}"
    fi

    _sts=$(printf 'AWS4-HMAC-SHA256\n%s\n%s\n%s' "$_dt" "$_scope" "$(_sha256s "$_canon")")
    _skey=$(_s3_sigkey "$_date")
    _sig=$(_hmac256 "$_skey" "$_sts")
    _S3A="AWS4-HMAC-SHA256 Credential=${_AK}/${_scope}, SignedHeaders=${_hdrs}, Signature=${_sig}"
    _S3D="$_dt"
    _S3P="$_phash"
}

_upload() {
    local _path="$1" _key _data _phash
    _key="${_path#/}"
    _data=$(cat)
    _phash=$(printf '%s' "$_data" | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}')
    _s3_sign "PUT" "$_key" "$_phash" "application/octet-stream"
    printf '%s' "$_data" | curl -s --connect-timeout 10 --max-time 60 \
        -X PUT "${_SE}/${_key}" \
        -H "Authorization: ${_S3A}" \
        -H "X-Amz-Date: ${_S3D}" \
        -H "X-Amz-Content-Sha256: ${_S3P}" \
        -H "Content-Type: application/octet-stream" \
        --data-binary @- >/dev/null
}

_upload_file() {
    local _path="$1" _file="$2" _key _phash
    _key="${_path#/}"
    _phash=$(_sha256f "$_file")
    _s3_sign "PUT" "$_key" "$_phash" "application/octet-stream"
    curl -s --connect-timeout 10 --max-time 120 \
        -X PUT "${_SE}/${_key}" \
        -H "Authorization: ${_S3A}" \
        -H "X-Amz-Date: ${_S3D}" \
        -H "X-Amz-Content-Sha256: ${_S3P}" \
        -H "Content-Type: application/octet-stream" \
        -T "$_file" >/dev/null
    [ $? -eq 0 ]
}

_download() {
    local _path="$1" _key
    _key="${_path#/}"
    _s3_sign "GET" "$_key" "$_EH" ""
    curl -sf --connect-timeout 10 --max-time 30 \
        -X GET "${_SE}/${_key}" \
        -H "Authorization: ${_S3A}" \
        -H "X-Amz-Date: ${_S3D}" \
        -H "X-Amz-Content-Sha256: ${_EH}"
}

_transport_cleanup() {
    unset _AK _SK _SR _SB _SH _SE _S3A _S3D _S3P
}
