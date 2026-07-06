#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Stratum C2 — Install Script
# Usage:
#   ./install.sh              # install deps + runtime dirs
#   ./install.sh --operator   # same as above
#   ./install.sh --server     # full setup (server.yml, TLS cert, optional systemd)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── colours ──────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  C_OK="\033[0;32m"; C_ERR="\033[0;31m"; C_WARN="\033[0;33m"
  C_INFO="\033[0;36m"; C_DIM="\033[0;90m"; C_BOLD="\033[1m"; C_RST="\033[0m"
else
  C_OK=""; C_ERR=""; C_WARN=""; C_INFO=""; C_DIM=""; C_BOLD=""; C_RST=""
fi

ok()   { echo -e "  ${C_OK}[✓]${C_RST} $*"; }
err()  { echo -e "  ${C_ERR}[✗]${C_RST} $*"; }
warn() { echo -e "  ${C_WARN}[!]${C_RST} $*"; }
info() { echo -e "  ${C_INFO}[i]${C_RST} $*"; }
step() { echo -e "\n${C_BOLD}${C_INFO}── $* ${C_RST}${C_DIM}$(printf '%.0s─' {1..50})${C_RST}"; }
ask()  { echo -en "  ${C_WARN}[?]${C_RST} $* "; }

# ── parse args ────────────────────────────────────────────────────────────────
MODE="operator"
for arg in "$@"; do
  case "$arg" in
    --server)   MODE="server"   ;;
    --operator) MODE="operator" ;;
    --help|-h)
      echo "Usage: $0 [--operator|--server]"
      echo "  --operator   Install deps + runtime dirs (default)"
      echo "  --server     Operator setup + server.yml + TLS + optional systemd"
      exit 0 ;;
    *)
      err "Unknown argument: $arg"
      echo "  Run '$0 --help' for usage."
      exit 1 ;;
  esac
done

# ── banner ────────────────────────────────────────────────────────────────────
echo -e ""
echo -e "${C_BOLD}${C_INFO}  ╔═══════════════════════════════════════════╗${C_RST}"
echo -e "${C_BOLD}${C_INFO}  ║       STRATUM C2 — INSTALLER              ║${C_RST}"
echo -e "${C_BOLD}${C_INFO}  ║  mode: ${C_WARN}$(printf '%-36s' "${MODE^^}")${C_INFO}║${C_RST}"
echo -e "${C_BOLD}${C_INFO}  ╚═══════════════════════════════════════════╝${C_RST}"
echo ""

# ── working directory check ───────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ ! -f "$SCRIPT_DIR/stratum-server.py" ]; then
  err "Must be run from the stratum-c2 project root."
  exit 1
fi
cd "$SCRIPT_DIR"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — Python
# ─────────────────────────────────────────────────────────────────────────────
step "Python"

PYTHON=""
for candidate in python3 python3.12 python3.11 python3.10 python3.9 python3.8; do
  if command -v "$candidate" &>/dev/null; then
    ver=$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    major="${ver%%.*}"; minor="${ver##*.}"
    if [ "$major" -ge 3 ] && [ "$minor" -ge 8 ]; then
      PYTHON="$candidate"
      ok "Found $PYTHON ($ver)"
      break
    fi
  fi
done

if [ -z "$PYTHON" ]; then
  err "Python 3.8+ required but not found."
  err "Install with: sudo apt install python3"
  exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — pip dependencies
# ─────────────────────────────────────────────────────────────────────────────
step "Python dependencies"

# Detect if we're in a venv or on a system that needs --break-system-packages
PIP_EXTRA=""
if "$PYTHON" -c "import sys; sys.exit(0 if sys.prefix != sys.base_prefix else 1)" 2>/dev/null; then
  info "Virtual environment detected — no extra pip flags needed."
else
  # On Debian/Ubuntu/Kali, pip may refuse to install into the system site-packages
  # unless --break-system-packages is passed. Detect this by running a real dry-run
  # and capturing combined stdout+stderr (the error goes to stderr, not stdout).
  if "$PYTHON" -m pip install --dry-run requests 2>&1 | grep -q "externally-managed"; then
    PIP_EXTRA="--break-system-packages"
    warn "System-managed Python detected — using --break-system-packages"
  fi
fi

if "$PYTHON" -m pip install -q $PIP_EXTRA -r requirements.txt; then
  ok "All Python packages installed"
else
  err "pip install failed. Check errors above."
  exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — Rust / Cargo (needed for binary builds; optional)
# ─────────────────────────────────────────────────────────────────────────────
step "Rust toolchain (binary builds)"

CARGO_OK=false
if command -v cargo &>/dev/null; then
  CARGO_VER=$(cargo --version 2>/dev/null | awk '{print $2}')
  ok "Cargo $CARGO_VER found"
  CARGO_OK=true

  # Check Windows cross-compilation targets (MSVC via clang/xwin — primary)
  WIN_MSVC="x86_64-pc-windows-msvc"
  WIN_GNU="x86_64-pc-windows-gnu"
  LINUX_MUSL="x86_64-unknown-linux-musl"
  LINUX_NONE="x86_64-unknown-none"
  for tgt in "$WIN_MSVC" "$WIN_GNU" "$LINUX_MUSL" "$LINUX_NONE"; do
    if rustup target list --installed 2>/dev/null | grep -q "$tgt"; then
      ok "Rust target $tgt installed"
    else
      warn "Rust target $tgt not installed"
      info "Install with: rustup target add $tgt"
    fi
  done
  # xwin Windows SDK (required for x86_64-pc-windows-msvc)
  if [ -d "$HOME/.xwin" ] || [ -d "/root/.xwin" ]; then
    ok "xwin Windows SDK found"
  else
    warn "xwin Windows SDK not found — Windows MSVC builds disabled"
    info "Install with: cargo install xwin --locked && xwin --accept-license splat --output ~/.xwin"
    info "Also needed:  apt install clang lld llvm"
  fi
else
  warn "Cargo not found — binary agent builds will be unavailable"
  info "Install rustup: curl https://sh.rustup.rs -sSf | sh"
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — Runtime directories
# ─────────────────────────────────────────────────────────────────────────────
step "Runtime directories"

for d in sessions logs keys downloads certs; do
  if [ -d "$d" ]; then
    ok "  $d/ (exists)"
  else
    mkdir -p "$d"
    ok "  $d/ (created)"
  fi
done

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — File permissions
# ─────────────────────────────────────────────────────────────────────────────
step "File permissions"

find . -maxdepth 4 \( -name "*.pem" -o -name "*.key" -o -name "*.crt" \) \
  ! -path "./.git/*" ! -path "./deployments/*" 2>/dev/null | while read -r f; do
  chmod 600 "$f"
  ok "chmod 600 $f"
done

[ -f "server.yml" ]     && { chmod 600 server.yml;           ok "chmod 600 server.yml"; }
[ -d "credentials" ]    && { chmod 700 credentials/;         ok "chmod 700 credentials/"; }
find credentials/ -maxdepth 1 -type f 2>/dev/null | while read -r f; do
  chmod 600 "$f"
  ok "chmod 600 $f"
done


# ─────────────────────────────────────────────────────────────────────────────
# SERVER-ONLY STEPS
# ─────────────────────────────────────────────────────────────────────────────
if [ "$MODE" = "server" ]; then

  # ── server.yml ─────────────────────────────────────────────────────────────
  step "server.yml"

  if [ -f "server.yml" ]; then
    ok "server.yml already exists (not overwriting)"
  else
    cp server.yml.example server.yml
    chmod 600 server.yml
    ok "Copied server.yml.example → server.yml"
    warn "Edit server.yml: set users/passwords before running the server"
  fi

  # ── JWT secret ─────────────────────────────────────────────────────────────
  step "JWT secret"

  CURRENT_SECRET=$(grep 'jwt_secret:' server.yml | awk -F'"' '{print $2}' | tr -d '[:space:]')
  if [ -z "$CURRENT_SECRET" ]; then
    JWT_SECRET=$("$PYTHON" -c "import secrets; print(secrets.token_hex(32))")
    # Replace `jwt_secret: ""` or `jwt_secret: ''` or `jwt_secret:` (empty) with the new value
    sed -i "s|jwt_secret:.*|jwt_secret: \"${JWT_SECRET}\"|" server.yml
    ok "JWT secret generated and written to server.yml"
  else
    ok "JWT secret already set in server.yml"
  fi

  # ── TLS certificate ─────────────────────────────────────────────────────────
  step "TLS certificate"

  CERT_PATH=$(grep 'cert:' server.yml | head -1 | awk '{print $2}')
  KEY_PATH=$(grep '^\s*key:' server.yml | head -1 | awk '{print $2}')
  CERT_PATH="${CERT_PATH:-certs/server.crt}"
  KEY_PATH="${KEY_PATH:-certs/server.key}"

  if [ -f "$CERT_PATH" ] && [ -f "$KEY_PATH" ]; then
    ok "TLS certificate already exists ($CERT_PATH)"
    FP=$("$PYTHON" -c "
from server.tls import fingerprint
print(fingerprint('${CERT_PATH}'))
" 2>/dev/null || echo "")
    [ -n "$FP" ] && info "SHA-256: $FP"
  else
    "$PYTHON" -c "
import sys; sys.path.insert(0, '.')
from server.tls import ensure_cert
fp = ensure_cert('${CERT_PATH}', '${KEY_PATH}')
print(fp)
" > /tmp/_stratum_fp.txt 2>&1
    if [ $? -eq 0 ]; then
      FP=$(cat /tmp/_stratum_fp.txt)
      rm -f /tmp/_stratum_fp.txt
      ok "Self-signed TLS certificate generated"
      info "SHA-256: $FP"
      info "Confirm this fingerprint in your browser on first connect."
    else
      warn "TLS cert pre-generation failed — will be generated at first server start"
      cat /tmp/_stratum_fp.txt 2>/dev/null || true
      rm -f /tmp/_stratum_fp.txt
    fi
  fi

  # ── systemd unit (optional) ─────────────────────────────────────────────────
  step "systemd service (optional)"

  INSTALL_SYSTEMD=false
  if command -v systemctl &>/dev/null; then
    ask "Install systemd service (stratum-server.service)? [y/N]:"
    read -r ans </dev/tty || ans="n"
    [[ "$ans" =~ ^[Yy]$ ]] && INSTALL_SYSTEMD=true
  else
    info "systemd not available — skipping"
  fi

  if $INSTALL_SYSTEMD; then
    PROJ_DIR="$SCRIPT_DIR"
    PYTHON_BIN=$(command -v "$PYTHON")
    RUN_USER="${SUDO_USER:-$(whoami)}"
    SERVICE_FILE="/etc/systemd/system/stratum-server.service"

    SERVICE_CONTENT="[Unit]
Description=Stratum C2 Server
After=network.target

[Service]
Type=simple
User=${RUN_USER}
WorkingDirectory=${PROJ_DIR}
ExecStart=${PYTHON_BIN} stratum-server.py
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target"

    if [ "$(id -u)" -eq 0 ]; then
      echo "$SERVICE_CONTENT" > "$SERVICE_FILE"
      systemctl daemon-reload
      ok "Service installed: $SERVICE_FILE"
      info "Enable with: sudo systemctl enable --now stratum-server"
    else
      # Write to temp then sudo-copy
      TMP_SVC=$(mktemp)
      echo "$SERVICE_CONTENT" > "$TMP_SVC"
      if sudo cp "$TMP_SVC" "$SERVICE_FILE" && sudo systemctl daemon-reload; then
        rm -f "$TMP_SVC"
        ok "Service installed: $SERVICE_FILE"
        info "Enable with: sudo systemctl enable --now stratum-server"
      else
        rm -f "$TMP_SVC"
        warn "Could not install systemd service (need sudo). Content:"
        echo "$SERVICE_CONTENT" | sed 's/^/    /'
      fi
    fi
  fi

fi  # end server-only steps

# ─────────────────────────────────────────────────────────────────────────────
# DONE
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${C_BOLD}${C_OK}  ╔═══════════════════════════════════════════╗${C_RST}"
echo -e "${C_BOLD}${C_OK}  ║  Installation complete ✓                  ║${C_RST}"
echo -e "${C_BOLD}${C_OK}  ╚═══════════════════════════════════════════╝${C_RST}"
echo ""

if [ "$MODE" = "server" ]; then
  echo -e "  ${C_BOLD}Next steps:${C_RST}"
  echo -e "  ${C_DIM}1.${C_RST} Edit   ${C_WARN}server.yml${C_RST}  — set usernames/passwords"
  echo -e "  ${C_DIM}2.${C_RST} Run    ${C_INFO}python3 stratum-server.py${C_RST}"
  echo -e "  ${C_DIM}3.${C_RST} Open   ${C_INFO}https://<host>:<port>${C_RST}  in your browser"
else
  echo -e "  ${C_BOLD}Next steps:${C_RST}"
  echo -e "  ${C_DIM}1.${C_RST} Run    ${C_INFO}./install.sh --server${C_RST}  for full server setup, or"
  echo -e "  ${C_DIM}2.${C_RST} Run    ${C_INFO}python3 stratum-server.py${C_RST}  if server.yml is already configured"
fi
echo ""
