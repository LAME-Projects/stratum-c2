# Changelog

All notable changes to Stratum C2 are documented in this file.
Format: features, fixes, and breaking changes grouped by release.

---

## v3.0

### Features

- **P2P mesh networking** — TCP and SMB named-pipe transports with bidirectional routing. Agents can link to each other forming a mesh network; traffic is relayed through parent nodes to the C2 server. Supports multi-hop chains
- **Cross-platform SMB P2P** — Linux agents can connect as SMB clients to Windows named-pipe listeners via pure Rust SMB2 userspace implementation (Negotiate → NTLMSSP anonymous → Tree Connect IPC$ → named pipe I/O). Windows agents use native Win32 API
- **Jump modules** — lateral movement via PsExec, SSH, and WMI. Deploy and link agents in a single command
- **P2P graph visualization** — interactive network graph in WebUI showing mesh topology, link status, and routing paths
- **Server-side P2P routing** — task routing and session relay for P2P-linked agents

### Credential Harvesting

- **WebDAV trap page for silent NTLMv2 capture** — `http-ntlm` listener serves a trap page with embedded UNC paths (`\\IP@80\docs\logo.png`) that trigger Windows WebClient to authenticate via NTLM on the same HTTP port. Cross-subnet, no SMB:445 required
- **Negotiate header for Intranet Zone auto-logon** — `WWW-Authenticate: Negotiate` triggers automatic NTLM credential submission from Windows browsers when the server hostname is in the Intranet Zone. Zero-click NTLMv2 capture — no popup, no user interaction
- **SPNEGO/NTLMSSP unwrapping** — `Authorization: Negotiate` tokens are parsed for both raw NTLMSSP and SPNEGO-wrapped payloads
- **Per-IP visit tracking** — all credential listener types (HTTP, HTTP-NTLM, SMB) track per-IP visit counts. `/creds listen dump` shows total visits, per-IP breakdown sorted by frequency, and IP-to-credential association

### WebUI

- **P2P command autocomplete** — shell hints updated with `/p2p link tcp <addr:port>`, `/p2p link smb <target> [pipe]`, `/p2p unlink <guid>`
- **P2P help modal** — three new entries in the Lateral Movement section of the help modal
- **OS platform icons** — session list shows OS-specific icons (Windows, Linux, macOS)
- **Context menu improvements** — enhanced right-click menus across the interface

---

## v2.0

### Breaking Changes

- **v2-only protocol** — removed all v1 backward compatibility. All agents must be re-deployed
- **Forward secrecy (Epoch ECDH)** — per-check-in X25519 key exchange with KDF chain. Compromising any single key reveals zero past or future traffic. See wiki §2.6 for protocol details

### Features

- **Auto-update system** — checks GitHub at startup, notifies operators of new versions via topbar banner + modal, applies updates via `git fetch/merge` without touching operational data
- **Agent version mismatch warning** — tracks which Stratum version deployed each agent; shows amber badge when session was deployed with an older version
- **Right-click context menus** — Cobalt Strike-style context menus on session rows, shell output, session header, and topbar with quick actions (commands, clipboard copy, kill/wipe); CSS-styled prompt modals for `/sleep`, `/jitter`, `/download` replace browser-native `prompt()`
- **Centralized VERSION** — single `VERSION` file as source of truth; server version displayed dynamically in login footer, about modal, and WS hello payload
- **`auto_update` config section** — `enabled` (bool) + `repo` (string) in server.yml; checks disabled by default until repo is set
- **Session lock** — right-click any session row → Lock Session to prevent accidental kill/stop/delete/wipe. Locked sessions show a lock badge in the session list and header. Lock state persists across server reboots. Server enforces lock with HTTP 423 on all destructive endpoints. All operators see lock/unlock events in real-time via WebSocket
- **HTTP listener protocol swap** — `http` now defaults to Basic auth (plaintext credentials), `http-ntlm` for NTLMv2 hash capture. Previous `http-basic` protocol renamed to `http`. Requires agent re-deploy
- **Info tab — channel file details** — Dead-Drop Channel section now shows Folder Name (last path segment), Output File, and Heartbeat File alongside the existing Folder Path and Input File

### Agent — In-Memory Execution

- **`/assembly` — .NET assembly in-memory execution** — full CLR hosting chain (CLRCreateInstance → GetRuntime → GetInterface → Start → GetDefaultDomain → Load_3 → Invoke_3). Loads and runs .NET assemblies entirely in memory without writing to disk. Supports passing command-line arguments. Pipe-redirected output capture with dedicated reader thread prevents deadlocks on large output. Embedded ConsoleReset helper rebinds `Console.Out` after pipe redirect. Windows only, Rust native agent
- **`/assembly-amsibypass` — .NET assembly with AMSI bypass** — same CLR hosting chain as `/assembly`, but bypasses AMSI via hardware breakpoint on `AmsiScanBuffer`. Sets CPU debug register (DR0) + Vectored Exception Handler; when AMSI calls `AmsiScanBuffer`, VEH intercepts and returns `AMSI_RESULT_CLEAN`. Zero `VirtualProtect`, zero memory writes on `amsi.dll` — patchless and invisible to `Behavior:Win32/AMSI_Patch_T` detections. Breakpoint removed after execution. Allows execution of assemblies that would otherwise be blocked by Windows Defender (e.g. Rubeus, Seatbelt, SharpUp)
- **`/script` — fileless script execution** — stages script in cloud provider, agent downloads to memory, pipes to interpreter stdin. Never touches disk. Auto-detects interpreter from shebang or hint arg: PowerShell (default on Windows), bash/sh (default on Linux), python, cmd. Output captured via stdout/stderr pipe. Cross-platform (Windows: powershell/cmd, Linux: bash/sh/python). CREATE_NO_WINDOW on Windows
- **`/script-amsibypass` — fileless script + AMSI bypass** — same pipe-to-stdin flow as `/script`, but bypasses AMSI via hardware breakpoint on `AmsiScanBuffer` before spawning PowerShell (Windows only). CPU debug register + VEH intercept — zero memory patching on `amsi.dll`, evades `Behavior:Win32/AMSI_Patch_T` detections. Breakpoint removed after execution

### Agent — Credential Harvesting

- **OPSEC: hidden command execution** — all Windows subprocess calls (`reg`, `wmic`, `whoami`, `netsh`, `schtasks`) now use `CREATE_NO_WINDOW` flag; zero visible console windows during credential harvesting, persistence, and shell operations
- **OPSEC: in-memory SAM extraction** — `/creds sam` no longer spawns `reg.exe` or creates hive files on disk; hashes are extracted via registry API with `REG_OPTION_BACKUP_RESTORE` — zero child processes, zero files, zero flagged command lines. `RtlAdjustPrivilege` auto-enables `SeBackupPrivilege`, so SAM works from elevated Admin (not just SYSTEM)
- **Smart credential harvesting** — `/creds harvest` now decrypts Firefox passwords inline (no DPAPI, zero monitored APIs), parses cloud credentials (AWS/Azure/GCloud/Docker/Kube), classifies SSH keys (encrypted/plaintext), extracts `/etc/shadow` hashes (Linux root), and parses Kerberos ccache metadata. Optional `decrypt` flag enables Chrome/Edge/DPAPI decryption via `CryptUnprotectData` (higher OPSEC risk, opt-in only). Windows-expanded: FileZilla credentials (XML), mRemoteNG connections (confCons.xml staged, default key `mR3m`), PowerShell history secrets grep, Git credentials, unattend/sysprep XML (staged if containing passwords). All new sources use pure file reads — zero registry API, zero flagged imports. After the Summary, contextual Hints print actionable offline cracking workflows based on what was found
- **Credential harvesting v2.0 — 27 new sources** — `/creds harvest` expanded from 24 to 51 credential sources across Windows and Linux:
  - **Windows (16 new):** PuTTY saved sessions (registry), WinSCP sessions (registry + WinSCP.ini), VNC passwords (RealVNC/TightVNC/UltraVNC registry with DES decrypt hint), WinLogon auto-logon (DefaultPassword), `cmdkey /list` saved credential targets, RDP MRU recent hosts + UsernameHint, IIS `web.config` connectionStrings, Sticky Notes `plum.sqlite`, GPP `cpassword` from SYSVOL (Groups/Services/Scheduledtasks XML), MsCacheV2/DCC2 cached domain logons (SECURITY hive, SYSTEM-only), `.env` file recursive search, Terraform `.tfstate` files, Chrome/Edge cookies (session hijack), Recycle Bin scan for secrets, Opera/Brave browser passwords
  - **Linux (15 new):** all-users SSH keys when root (`/home/*/.ssh/id_*` + authorized_keys + `/root/.ssh`), all-users Kerberos ccache (`/tmp/krb5cc_*`), keytab files (`/etc/krb5.keytab` + `/etc/security/keytabs/`), `/etc/security/opasswd` PAM old hashes, Chromium/Chrome/Edge on Linux (Login Data + Local State), config file credential search (`.pgpass`, `.my.cnf`, `debian.cnf`, `.netrc`, `.s3cfg`, `wp-config.php`), `.env` file recursive search, npm/pip/gem/composer tokens (`.npmrc`, `.pypirc`, `.gem/credentials`), Terraform `.tfstate`, core dumps (`/var/crash`, `/var/lib/systemd/coredump`), systemd service secrets grep, KWallet (`kwalletd/`), Ansible vault files (`$ANSIBLE_VAULT` marker), HashiCorp Vault token (`~/.vault-token`)
  - All new sources are passive file reads or registry queries — zero process creation beyond existing `cmd /C reg query` pattern
- **Credential file auto-retrieval** — `/creds sam` and `/creds harvest` staged files are now automatically pulled from cloud, saved to `downloads/<session>/`, and listed in the Artifacts tab as exfiltrated files with download/preview/delete actions

### WebUI

- **Credentials tab improvements** — column order reorganized (Source, Protocol, Host, Domain, Notes, Username, Secret, Type, Actions) for context-first readability; resizable columns with localStorage persistence; "Show" detail button on each row opens a popup with the full untruncated secret in a scrollable monospace box + Copy Secret button; listener credentials (HTTP Basic, SMB NTLMv2, HTTP-NTLM) correctly extracted and attributed to their listener protocol; added AWS session token and SSH plaintext key extraction
- **Artifact type detection** — file type column in Artifacts tab now correctly identifies all file types. Server-side `_detect_mime()` uses a 4-tier detection cascade: extension (`mimetypes`), filename pattern matching (Login Data → DB, known_hosts → TEXT, web.config → XML), extended extension map (`.tfstate` → JSON, `.service` → TEXT, `.keytab` → BLOB), and magic byte sniffing (SQLite, PNG, JPEG, PDF, ZIP, GZIP, Kerberos ccache/keytab, UTF-8 text fallback). Frontend maps new types: KRB, PHP, SHELL; renamed fallback from BIN to BLOB
- **Deploy background continuation** — closing the deploy wizard (X button) during an active build no longer cancels and errors. The deploy continues running in background; a Toast notifies "Deploy in background — session will appear when ready." Explicit cancel requires clicking the overlay and confirming. Server-side: cancelled deploys broadcast "Deploy Cancelled" (warning) instead of "Deploy Failed" (error), preventing misleading error toasts for all operators

### Fixes

- **Session label fix** — label entered in wizard step 1 now correctly persists to the session profile. Fixed `_collectChannelFields()` not reading the `ch-session-label` input when using saved credentials. Label textbox now preserves its value across step re-renders
- **HTTP-Basic regex** — fixed regex that silently failed to match plaintext credentials from HTTP listeners
- **NTLMv2 extraction** — fixed `/creds coerce` output parsing (was skipped due to missing indent in dump section)

---

## v1.1

### Features

- **Credential harvesting module** (`/creds`) — harvest DPAPI/SSH/browser/cloud creds, coerce local auth, dump SAM hives
- **Multi-protocol listener** — simultaneous SMB + HTTP listeners on arbitrary ports (`/creds listen start http:80` for Basic, `http-ntlm:80` for NTLMv2)
- **NTLMv2 + Basic auth capture** — `http` = plaintext Basic (default), `http-ntlm` = NTLMv2 hash; LLMNR/NBNS poisoners auto-start
- **Multiple concurrent listeners** — start/stop individually (`/creds listen stop http:80`) or all at once
- **Persistent listener state** — active listeners, start time, and captured credentials survive server reboots
- **WebUI listener badge** — expandable badge shows per-listener status, protocol, uptime, and credentials in real-time
- **Shell command suggestions** — autocomplete for all `/creds` subcommands with descriptions
- **Windows port-conflict warning** — popup warns when starting SMB on port 445 (occupied by LanmanServer)

---

## v1.0

Initial release.

- Dead-drop C2 via Dropbox (RSA-4096 + AES-256-GCM encrypted channel)
- Three deploy modes: staged-enc, stageless-enc, stageless-plain
- Native Rust agent (Windows + Linux cross-compile)
- WebUI operator console with multi-session management
- Shell, History, Artifacts, Persistence, and Control tabs
- Cloud provider support: Dropbox, OneDrive, SharePoint, Google Drive, AWS S3
- Deploy wizard with OAuth flow, credential profiles, OPSEC presets
- Persistence module (`/persist`) — scheduled tasks, registry Run keys, cron, rc.local, systemd
- File transfer (`/download`, `/upload`) with cloud staging
- In-line execution: BOF, .NET assembly, PE memexec
- Session polling with configurable sleep/jitter and active hours window
- Kill date guardrail (agent self-destructs after expiry)
- Multi-operator support with real-time WebSocket sync
