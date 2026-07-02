#!/bin/bash
# install_or_update.sh — Aegis-OSINT-AI Kali Linux installer/updater
set -euo pipefail

REQUIRED_APT=(
  python3 python3-venv python3-pip
  postgresql postgresql-contrib pgvector
  redis-server
  git tesseract-ocr
  nodejs npm
  build-essential cmake
  holehe
)

echo "==> Checking apt packages"
MISSING_APT=()
for pkg in "${REQUIRED_APT[@]}"; do
  if ! dpkg -s "$pkg" >/dev/null 2>&1; then
    MISSING_APT+=("$pkg")
  fi
done

if [[ ${#MISSING_APT[@]} -gt 0 ]]; then
  echo "==> Installing missing apt packages: ${MISSING_APT[*]}"
  apt install -y "${MISSING_APT[@]}"
else
  echo "==> All apt packages present"
fi

echo "==> Ensuring PostgreSQL is running"
systemctl enable --now redis-server >/dev/null 2>&1 || true
systemctl start postgresql || true

echo "==> Setting up database if needed"
su - postgres -c "psql -c \"CREATE DATABASE aegis;\"" 2>/dev/null || true
su - postgres -c "psql -d aegis -c \"CREATE EXTENSION IF NOT EXISTS vector;\"" 2>/dev/null || true

echo "==> Updating Python dependencies"
if [[ -d .venv ]]; then
  source .venv/bin/activate
else
  python3 -m venv .venv
  source .venv/bin/activate
fi

pip install --upgrade pip
pip install -r requirements.txt
pip install -r backend/requirements.txt

echo "==> Updating frontend dependencies"
pushd frontend >/dev/null
npm install
popd >/dev/null

echo "==> Update complete"
echo "Run 'bash scripts/start.sh' to start services"