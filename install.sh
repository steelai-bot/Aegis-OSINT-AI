#!/usr/bin/env bash
# Aegis OSINT AI - Linux installer for Kali, Ubuntu, and Ubuntu VPS.
#
# Local install:
#   ./install.sh --run
#
# One-line VPS/service install:
#   curl -fsSL https://raw.githubusercontent.com/steelai-bot/Aegis-OSINT-AI/main/install.sh | sudo bash -s -- --service --run

set -Eeuo pipefail

REPO_URL="https://github.com/steelai-bot/Aegis-OSINT-AI.git"
INSTALL_DIR="${INSTALL_DIR:-/opt/aegis-osint-ai}"
SERVICE_NAME="${SERVICE_NAME:-aegis-osint}"
SERVICE_USER="${SERVICE_USER:-aegis}"
RUN_AFTER_INSTALL=0
SERVICE_INSTALL=0
DEV_INSTALL=0

usage() {
  cat <<USAGE
Aegis OSINT AI Linux installer

Usage:
  ./install.sh [--run] [--dev]
  sudo ./install.sh --service [--run]
  curl -fsSL https://raw.githubusercontent.com/steelai-bot/Aegis-OSINT-AI/main/install.sh | sudo bash -s -- --service --run

Options:
  --run       Start the app after installation. In --service mode, starts systemd service.
  --service   Install/update into /opt/aegis-osint-ai and configure systemd service.
  --dev       Install development dependencies from requirements-dev.txt.
  -h, --help  Show this help.
USAGE
}

log() { printf '\033[0;36m%s\033[0m\n' "$*"; }
ok() { printf '  \033[0;32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[1;33m!\033[0m %s\n' "$*"; }
fail() { printf '  \033[0;31m✗\033[0m %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run) RUN_AFTER_INSTALL=1 ;;
    --service) SERVICE_INSTALL=1 ;;
    --dev) DEV_INSTALL=1 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "Unknown option: $1" ;;
  esac
  shift
done

require_root_for_service() {
  if [[ "${SERVICE_INSTALL}" -eq 1 && "${EUID}" -ne 0 ]]; then
    fail "--service requires root. Re-run with sudo."
  fi
}

install_system_deps() {
  log "[1/6] Installing system dependencies"
  if ! command -v apt-get >/dev/null 2>&1; then
    warn "apt-get not found. Install python3, python3-venv, git, curl, and npm manually."
    return
  fi

  if [[ "${EUID}" -ne 0 ]]; then
    warn "Not root - skipping apt install. Re-run with sudo if dependencies are missing."
    return
  fi

  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends \
    ca-certificates curl git python3 python3-venv python3-pip build-essential npm
  ok "System dependencies ready"
}

prepare_source() {
  log "[2/6] Preparing source tree"
  if [[ "${SERVICE_INSTALL}" -eq 1 ]]; then
    mkdir -p "${INSTALL_DIR}"
    if [[ -d "${INSTALL_DIR}/.git" ]]; then
      git -C "${INSTALL_DIR}" pull --ff-only
    else
      rm -rf "${INSTALL_DIR:?}"/*
      git clone "${REPO_URL}" "${INSTALL_DIR}"
    fi
    cd "${INSTALL_DIR}"
  else
    cd "$(dirname "$(readlink -f "$0")")"
  fi
  ok "Source ready: $(pwd)"
}

run_python_installer() {
  log "[3/6] Running Python installer"
  local args=()
  [[ "${DEV_INSTALL}" -eq 1 ]] && args+=(--dev)
  python3 install.py "${args[@]}"
  ok "Python installer completed"
}

create_service_user() {
  [[ "${SERVICE_INSTALL}" -eq 1 ]] || return
  log "[4/6] Configuring service user"
  if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    useradd --system --home-dir "${INSTALL_DIR}" --shell /usr/sbin/nologin "${SERVICE_USER}"
  fi
  chown -R "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}"
  ok "Service user ready: ${SERVICE_USER}"
}

install_systemd_service() {
  [[ "${SERVICE_INSTALL}" -eq 1 ]] || return
  log "[5/6] Installing systemd service"
  cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<SERVICE
[Unit]
Description=Aegis OSINT AI
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
Environment=PYTHONUNBUFFERED=1
ExecStart=${INSTALL_DIR}/.venv/bin/python -m backend.main
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=${INSTALL_DIR}/data ${INSTALL_DIR}/reports ${INSTALL_DIR}/.env

[Install]
WantedBy=multi-user.target
SERVICE
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}.service"
  ok "Systemd service installed: ${SERVICE_NAME}.service"
}

finish() {
  log "[6/6] Finalizing"
  if [[ "${SERVICE_INSTALL}" -eq 1 ]]; then
    if [[ "${RUN_AFTER_INSTALL}" -eq 1 ]]; then
      systemctl restart "${SERVICE_NAME}.service"
      ok "Service started"
    else
      warn "Service installed but not started. Run: sudo systemctl start ${SERVICE_NAME}"
    fi
    echo ""
    echo "Next steps:"
    echo "  1. Edit ${INSTALL_DIR}/.env"
    echo "  2. Start: sudo systemctl start ${SERVICE_NAME}"
    echo "  3. Status: sudo systemctl status ${SERVICE_NAME}"
    echo "  4. Open: http://<server-ip>:8000"
  else
    if [[ "${RUN_AFTER_INSTALL}" -eq 1 ]]; then
      exec ./.venv/bin/python -m backend.main
    fi
    echo ""
    echo "Next steps:"
    echo "  1. Edit .env"
    echo "  2. Run: ./.venv/bin/python -m backend.main"
    echo "  3. Open: http://localhost:8000"
  fi
}

require_root_for_service
install_system_deps
prepare_source
run_python_installer
create_service_user
install_systemd_service
finish