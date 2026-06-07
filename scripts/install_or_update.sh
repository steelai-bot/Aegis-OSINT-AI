#!/usr/bin/env bash
# One-line installer/updater for Aegis.
#
# Intended usage:
#   curl -fsSL https://raw.githubusercontent.com/steelai-bot/Aegis-OSINT-AI/main/scripts/install_or_update.sh | bash
#
# Behavior:
# - If run inside an existing git clone, update that clone.
# - Else if $AEGIS_DIR exists and is a git clone, update it.
# - Else clone the repository into $AEGIS_DIR.

set -euo pipefail

REPO_URL="${AEGIS_REPO_URL:-https://github.com/steelai-bot/Aegis-OSINT-AI.git}"
BRANCH="${AEGIS_BRANCH:-main}"
INSTALL_DIR="${AEGIS_DIR:-$HOME/Aegis-OSINT-AI}"
REMOTE="${AEGIS_UPDATE_REMOTE:-origin}"
INSTALL_DEPS="${AEGIS_INSTALL_DEPS:-0}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[aegis bootstrap] Missing required command: $1" >&2
    exit 127
  fi
}

require_cmd git

is_aegis_clone() {
  local candidate="$1"
  [[ -d "$candidate/.git" ]] || return 1
  git -C "$candidate" remote -v 2>/dev/null | grep -Eq 'Aegis-OSINT-AI(\.git)?([[:space:]]|$)'
}

if REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" && is_aegis_clone "$REPO_ROOT"; then
  TARGET_DIR="$REPO_ROOT"
  echo "[aegis bootstrap] Existing Aegis git clone detected: $TARGET_DIR"
elif is_aegis_clone "$INSTALL_DIR"; then
  TARGET_DIR="$INSTALL_DIR"
  echo "[aegis bootstrap] Existing Aegis clone detected: $TARGET_DIR"
else
  TARGET_DIR="$INSTALL_DIR"
  echo "[aegis bootstrap] Cloning $REPO_URL into $TARGET_DIR"
  mkdir -p "$(dirname "$TARGET_DIR")"
  git clone --branch "$BRANCH" "$REPO_URL" "$TARGET_DIR"
fi

cd "$TARGET_DIR"

if [[ ! -f scripts/update_from_repo.sh ]]; then
  echo "[aegis bootstrap] update_from_repo.sh not present yet; using plain git update."
  git fetch --prune "$REMOTE"
  git pull --ff-only "$REMOTE" "$BRANCH"
else
  chmod +x scripts/update_from_repo.sh || true
  UPDATE_ARGS=(--remote "$REMOTE" --branch "$BRANCH")
  if [[ "$INSTALL_DEPS" == "1" || "$INSTALL_DEPS" == "true" ]]; then
    UPDATE_ARGS+=(--install)
  fi
  ./scripts/update_from_repo.sh "${UPDATE_ARGS[@]}"
fi

echo "[aegis bootstrap] Ready: $TARGET_DIR"
echo "[aegis bootstrap] Next:  cd '$TARGET_DIR'"
