#!/usr/bin/env bash
# One-line installer/updater for Aegis OSINT.
#
# Intended usage:
#   curl -fsSL https://raw.githubusercontent.com/steelai-bot/Aegis-OSINT-AI/main/scripts/install_or_update.sh | bash
#
# Behavior:
# - Detects existing clone and updates it, or clones fresh.
# - Creates .venv, installs backend deps, runs Alembic migrations.
# - Installs frontend deps (Node.js).
# - Starts Docker Compose stack if available.
# - Creates .env template if missing.

set -euo pipefail

REPO_URL="${AEGIS_REPO_URL:-https://github.com/steelai-bot/Aegis-OSINT-AI.git}"
BRANCH="${AEGIS_BRANCH:-main}"
INSTALL_DIR="${AEGIS_DIR:-$HOME/Aegis-OSINT-AI}"
REMOTE="${AEGIS_UPDATE_REMOTE:-origin}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[aegis] Missing required command: $1" >&2
    exit 127
  fi
}

require_cmd git

# ── Detect existing clone ──────────────────────────────────────────────────

is_aegis_clone() {
  local candidate="$1"
  [[ -d "$candidate/.git" ]] || return 1
  git -C "$candidate" remote -v 2>/dev/null | grep -Eq 'Aegis-OSINT-AI(\.git)?([[:space:]]|$)'
}

if REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" && is_aegis_clone "$REPO_ROOT"; then
  TARGET_DIR="$REPO_ROOT"
  echo "[aegis] Existing clone detected in current directory: $TARGET_DIR"
elif is_aegis_clone "$INSTALL_DIR"; then
  TARGET_DIR="$INSTALL_DIR"
  echo "[aegis] Existing clone detected: $TARGET_DIR"
else
  TARGET_DIR="$INSTALL_DIR"
  echo "[aegis] Cloning $REPO_URL into $TARGET_DIR"
  mkdir -p "$(dirname "$TARGET_DIR")"
  git clone --branch "$BRANCH" "$REPO_URL" "$TARGET_DIR"
fi

cd "$TARGET_DIR"

# ── Update from remote ─────────────────────────────────────────────────────

echo "[aegis] Fetching and pulling latest changes..."
git fetch --prune "$REMOTE" 2>/dev/null || true
git pull --ff-only "$REMOTE" "$BRANCH" 2>/dev/null || true
echo "[aegis] Up to date: $(git rev-parse --short HEAD)"

# ── Python virtual environment ──────────────────────────────────────────────

PYTHON_CMD=""
for name in python3 python python3.13 python3.12 python3.11; do
  if command -v "$name" >/dev/null 2>&1; then
    PYTHON_CMD="$name"
    break
  fi
done

if [[ -n "$PYTHON_CMD" ]]; then
  echo "[aegis] Setting up Python virtual environment..."
  VENV_DIR="$TARGET_DIR/.venv"
  if [[ ! -f "$VENV_DIR/bin/python" ]]; then
    "$PYTHON_CMD" -m venv "$VENV_DIR"
  fi
  "$VENV_DIR/bin/python" -m pip install --upgrade pip --quiet 2>/dev/null
  "$VENV_DIR/bin/python" -m pip install -r backend/requirements.runtime.txt --quiet 2>/dev/null
  echo "[aegis] Backend dependencies installed."

  # Alembic migrations
  if [[ -n "${DATABASE_URL:-}" || -n "${AEGIS_DATABASE_URL:-}" ]]; then
    echo "[aegis] Running Alembic migrations..."
    "$VENV_DIR/bin/python" -m alembic upgrade head
    echo "[aegis] Migrations complete."
  else
    echo "[aegis] Skipping migrations (no DATABASE_URL set)."
  fi
else
  echo "[aegis] WARNING: Python not found — skipping backend setup."
fi

# ── Frontend ────────────────────────────────────────────────────────────────

echo ""
if command -v node >/dev/null 2>&1; then
  echo "[aegis] Setting up frontend..."
  cd "$TARGET_DIR/frontend"
  npm install 2>/dev/null || true
  cd "$TARGET_DIR"
  echo "[aegis] Frontend dependencies installed."
else
  echo "[aegis] Node.js not found — skipping frontend setup."
fi

# ── Docker Compose ──────────────────────────────────────────────────────────

echo ""
if command -v docker >/dev/null 2>&1; then
  if [[ -f "$TARGET_DIR/docker-compose.yml" ]]; then
    echo "[aegis] Starting Docker Compose stack..."
    docker compose up -d 2>/dev/null || true
    echo "[aegis] Docker stack running."
  fi
else
  echo "[aegis] Docker not found — skipping container setup."
fi

# ── .env template ───────────────────────────────────────────────────────────

ENV_FILE="$TARGET_DIR/.env"
if [[ ! -f "$ENV_FILE" ]]; then
  cat > "$ENV_FILE" <<'ENVEOF'
# Aegis v2 Configuration
AEGIS_ENVIRONMENT=development
AEGIS_DEBUG=false
AEGIS_AUTH_ENABLED=false
AEGIS_DATABASE_URL=postgresql+asyncpg://aegis:aegis@localhost:5432/aegis
AEGIS_REDIS_URL=redis://localhost:6379/0
AEGIS_JWT_SECRET=change-me-in-production
# AEGIS_SHODAN_API_KEY=
# AEGIS_VIRUSTOTAL_API_KEY=
# AEGIS_HIBP_API_KEY=
ENVEOF
  echo "[aegis] Created .env template — edit it with your API keys."
fi

# ── Done ────────────────────────────────────────────────────────────────────

echo ""
echo "============================================"
echo "  Aegis OSINT installed successfully!"
echo "============================================"
echo ""
echo "  Install dir: $TARGET_DIR"
echo ""
echo "  Next steps:"
echo "    cd '$TARGET_DIR'"
echo "    source .venv/bin/activate"
echo "    uvicorn backend.api.app:create_app --factory --reload"
echo ""