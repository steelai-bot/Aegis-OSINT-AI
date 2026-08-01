#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "$(readlink -f "$0")")"

if [[ ! -x ".venv/bin/python" ]]; then
  echo "Local .venv not found. Run ./install.sh first."
  exit 1
fi

exec ./.venv/bin/python -m backend.main