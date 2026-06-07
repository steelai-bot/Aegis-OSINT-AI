#!/usr/bin/env bash
# Safely update an existing Aegis clone from the configured Git remote.
#
# Default behavior is conservative:
# - fetches from origin
# - refuses to overwrite local changes
# - pulls with --ff-only so history is not rewritten or merged unexpectedly

set -euo pipefail

REMOTE="${AEGIS_UPDATE_REMOTE:-origin}"
BRANCH=""
USE_STASH=0
INSTALL_DEPS=0

usage() {
  cat <<'EOF_USAGE'
Usage: ./scripts/update_from_repo.sh [options]

Options:
  --branch <name>   Branch to update. Defaults to the current branch, or main if detached.
  --remote <name>   Git remote to fetch/pull from. Defaults to origin.
  --stash           Stash local changes before updating, then try to re-apply them.
  --install         After updating, refresh backend runtime dependencies in .venv if present.
  -h, --help        Show this help.

Examples:
  ./scripts/update_from_repo.sh
  ./scripts/update_from_repo.sh --branch main
  ./scripts/update_from_repo.sh --stash
  ./scripts/update_from_repo.sh --install

Notes:
  - The script uses `git pull --ff-only` to avoid surprise merge commits.
  - Without `--stash`, it stops if you have local modified/untracked files.
EOF_USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --branch)
      BRANCH="${2:-}"
      shift 2
      ;;
    --remote)
      REMOTE="${2:-}"
      shift 2
      ;;
    --stash)
      USE_STASH=1
      shift
      ;;
    --install)
      INSTALL_DEPS=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[aegis update] Unknown argument: $1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

if ! command -v git >/dev/null 2>&1; then
  echo "[aegis update] Missing required command: git" >&2
  exit 127
fi

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$REPO_ROOT" ]]; then
  echo "[aegis update] This command must be run inside an existing Aegis git clone." >&2
  exit 2
fi
cd "$REPO_ROOT"

if [[ -z "$BRANCH" ]]; then
  BRANCH="$(git rev-parse --abbrev-ref HEAD)"
  if [[ "$BRANCH" == "HEAD" ]]; then
    BRANCH="main"
  fi
fi

if ! git remote get-url "$REMOTE" >/dev/null 2>&1; then
  echo "[aegis update] Git remote '$REMOTE' does not exist." >&2
  echo "[aegis update] Available remotes:" >&2
  git remote -v >&2
  exit 3
fi

echo "[aegis update] Repository: $REPO_ROOT"
echo "[aegis update] Remote:     $REMOTE ($(git remote get-url "$REMOTE"))"
echo "[aegis update] Branch:     $BRANCH"

STASHED=0
if [[ -n "$(git status --porcelain)" ]]; then
  if [[ "$USE_STASH" -eq 1 ]]; then
    echo "[aegis update] Local changes detected; stashing them before update."
    git stash push -u -m "aegis-auto-stash-before-update-$(date -u +%Y%m%dT%H%M%SZ)"
    STASHED=1
  else
    cat >&2 <<'EOF_DIRTY'
[aegis update] Local changes detected. Refusing to overwrite them.

Options:
  1. Review your changes:
       git status --short
  2. Commit or stash them manually.
  3. Or run this helper with:
       ./scripts/update_from_repo.sh --stash
EOF_DIRTY
    exit 4
  fi
fi

echo "[aegis update] Fetching latest refs..."
git fetch --prune "$REMOTE"

if git show-ref --verify --quiet "refs/heads/$BRANCH"; then
  CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
  if [[ "$CURRENT_BRANCH" != "$BRANCH" ]]; then
    git checkout "$BRANCH"
  fi
elif git show-ref --verify --quiet "refs/remotes/$REMOTE/$BRANCH"; then
  git checkout --track "$REMOTE/$BRANCH"
else
  echo "[aegis update] Branch '$BRANCH' does not exist locally or on '$REMOTE'." >&2
  exit 5
fi

BEFORE="$(git rev-parse --short HEAD)"
git pull --ff-only "$REMOTE" "$BRANCH"
AFTER="$(git rev-parse --short HEAD)"

if [[ "$STASHED" -eq 1 ]]; then
  echo "[aegis update] Re-applying stashed local changes..."
  if ! git stash pop; then
    cat >&2 <<'EOF_CONFLICT'
[aegis update] Update completed, but stash re-apply produced conflicts.
Resolve conflicts manually, then run:
  git status --short
EOF_CONFLICT
    exit 6
  fi
fi

if [[ "$INSTALL_DEPS" -eq 1 ]]; then
  if [[ -x ".venv/bin/python" ]]; then
    echo "[aegis update] Refreshing backend runtime dependencies in .venv..."
    .venv/bin/python -m pip install -r backend/requirements.runtime.txt
  else
    echo "[aegis update] Skipping dependency refresh: .venv/bin/python not found or not executable."
    echo "[aegis update] Create it with: python3 -m venv .venv && source .venv/bin/activate"
  fi
fi

echo "[aegis update] Done: $BEFORE -> $AFTER"
echo "[aegis update] Current status:"
git status --short
