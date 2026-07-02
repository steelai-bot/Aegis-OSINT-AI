#!/bin/bash
# setup-kali.sh — Aegis-OSINT-AI Kali Linux full setup
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root or with sudo: sudo bash scripts/setup-kali.sh"
  exit 1
fi

echo "==> Updating Kali"
apt update && apt full-upgrade -y

echo "==> Installing system dependencies"
apt install -y \
  python3 python3-venv python3-pip \
  postgresql postgresql-contrib pgvector \
  redis-server \
  git tesseract-ocr \
  nodejs npm \
  build-essential cmake

echo "==> Setting up PostgreSQL database"
su - postgres -c "psql -c \"CREATE DATABASE aegis;\"" || true
su - postgres -c "psql -d aegis -c \"CREATE EXTENSION IF NOT EXISTS vector;\"" || true

echo "==> Enabling and starting Redis"
systemctl enable --now redis-server

echo "==> Creating Python virtual environment"
python3 -m venv .venv
source .venv/bin/activate

echo "==> Installing Python dependencies"
pip install --upgrade pip
pip install -r requirements.txt
pip install -r backend/requirements.txt

echo "==> Installing frontend dependencies"
pushd frontend >/dev/null
npm install
popd >/dev/null

echo "==> Running setup wizard"
python3 setup_wizard.py --silent

echo "==> Kali setup complete"
echo "Next: run 'bash scripts/start.sh' to start all services"