#!/bin/bash
# stop.sh — Aegis-OSINT-AI service stopper for Kali Linux
set -euo pipefail

echo "==> Stopping Aegis-OSINT-AI services"

# Kill backend (uvicorn)
BACKEND_PID=$(pgrep -f "uvicorn backend.main:app" 2>/dev/null || true)
if [[ -n "$BACKEND_PID" ]]; then
  echo "  Stopping backend (PID $BACKEND_PID)"
  kill "$BACKEND_PID" 2>/dev/null || true
  sleep 1
  # Force kill if still running
  if kill -0 "$BACKEND_PID" 2>/dev/null; then
    kill -9 "$BACKEND_PID" 2>/dev/null || true
  fi
fi

# Kill frontend (Next.js)
FRONTEND_PID=$(pgrep -f "next.*dev|next.*start" 2>/dev/null || true)
if [[ -n "$FRONTEND_PID" ]]; then
  echo "  Stopping frontend (PID $FRONTEND_PID)"
  kill "$FRONTEND_PID" 2>/dev/null || true
  sleep 1
  if kill -0 "$FRONTEND_PID" 2>/dev/null; then
    kill -9 "$FRONTEND_PID" 2>/dev/null || true
  fi
fi

# Kill any remaining node processes from this project
FRONTEND_NODE=$(lsof -ti:3000 2>/dev/null || true)
if [[ -n "$FRONTEND_NODE" ]]; then
  echo "  Cleaning up port 3000 (PID $FRONTEND_NODE)"
  kill -9 "$FRONTEND_NODE" 2>/dev/null || true
fi

BACKEND_NODE=$(lsof -ti:8000 2>/dev/null || true)
if [[ -n "$BACKEND_NODE" ]]; then
  echo "  Cleaning up port 8000 (PID $BACKEND_NODE)"
  kill -9 "$BACKEND_NODE" 2>/dev/null || true
fi

echo "==> All services stopped"