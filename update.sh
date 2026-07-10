#!/bin/bash
# ============================================================
# Aegis OSINT AI - Update Script (Linux)
# ============================================================
# ONE-LINE UPDATE:
# curl -fsSL https://raw.githubusercontent.com/steelai-bot/Aegis-OSINT-AI/main/update.sh | bash
# ============================================================

set -e

echo ""
echo "========================================"
echo "  Aegis OSINT AI - Update (Linux)"
echo "========================================"
echo ""

# Check if this is a git repository
if [ ! -d ".git" ]; then
    echo "ERROR: This is not a git repository."
    echo "Please clone the repository first or run this script from the project root."
    exit 1
fi

# Pull latest changes
echo "[1/5] Pulling latest changes from repository..."
git fetch origin
git pull origin main --ff-only || {
    echo "WARNING: Could not fast-forward. Trying normal pull..."
    git pull origin main
}
echo "      Repository updated."

# Update Python dependencies (if requirements changed)
echo ""
echo "[2/5] Updating Python dependencies..."
if [ -d ".venv" ]; then
    ./.venv/bin/pip install -r requirements.txt -q
    echo "      Python dependencies updated."
else
    echo "      Virtual environment not found. Skipping Python update."
fi

# Update frontend dependencies and rebuild (if frontend changed)
echo ""
echo "[3/5] Checking frontend..."
if [ -d "frontend" ]; then
    cd frontend
    if [ -f "package.json" ]; then
        echo "      Updating frontend dependencies..."
        npm install --silent
        echo "      Rebuilding frontend..."
        npm run build --silent
        echo "      Frontend rebuilt successfully."
    fi
    cd ..
else
    echo "      No frontend directory found."
fi

# Re-initialize database (safe)
echo ""
echo "[4/5] Checking database..."
if [ -f ".venv/bin/python" ]; then
    ./.venv/bin/python -c "
import sys
sys.path.insert(0, '.')
try:
    from backend.main import init_db
    init_db()
    print('      Database schema up to date.')
except:
    print('      Database check skipped.')
" 2>/dev/null || echo "      Database check skipped."
fi

echo ""
echo "[5/5] Update complete!"
echo ""
echo "========================================"
echo "  ✅ Update finished successfully!"
echo "========================================"
echo ""
echo "You can now restart the application with:"
echo "  ./run.sh"
echo ""
echo "Or if the server is running, restart it manually."
echo ""