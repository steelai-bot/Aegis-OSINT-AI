#!/bin/bash
# install_or_update.sh — Aegis-OSINT-AI Kali update wrapper
# Delegates to the unified install.py installer
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

if command -v python3 &>/dev/null; then
  echo "==> Delegating to install.py --update"
  exec sudo python3 install.py --update
else
  echo "ERROR: python3 not found. Run: sudo apt install python3"
  exit 1
fi
