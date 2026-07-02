#!/bin/bash
# start.sh — Aegis-OSINT-AI service launcher for Kali Linux
set -euo pipefail

MODE="${1:-dev}"

echo "==> Starting Aegis-OSINT-AI in ${MODE} mode"

# Activate venv if present
if [[ -d .venv ]]; then
  source .venv/bin/activate
fi

# Ensure PostgreSQL is running
if ! systemctl is-active --quiet postgresql; then
  echo "==> Starting PostgreSQL"
  systemctl start postgresql
fi

# Ensure Redis is running
if ! systemctl is-active --quiet redis-server; then
  echo "==> Starting Redis"
  systemctl start redis-server
fi

# Create logs directory
mkdir -p logs

if [[ "${MODE}" == "production" ]]; then
  echo "==> Starting backend (production)"
  nohup uvicorn backend.main:app --host 0.0.0.0 --port 8000 --workers 4 > logs/backend.log 2>&1 &
  
  echo "==> Building frontend (production)"
  pushd frontend >/dev/null
  npm run build
  npm start &
  popd >/dev/null
else
  echo "==> Starting backend (development)"
  nohup uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload > logs/backend.log 2>&1 &
  
  echo "==> Starting frontend (development)"
  pushd frontend >/dev/null
  nohup npm run dev > ../logs/frontend.log 2>&1 &
  popd >/dev/null
fi

echo "==> Services starting..."
echo "    Backend:  http://localhost:8000"
echo "    Frontend: http://localhost:3000"
echo ""
echo "Logs:"
echo "  tail -f logs/backend.log"
echo "  tail -f logs/frontend.log"