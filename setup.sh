#!/bin/bash
# ============================================================
# Aegis OSINT AI - Complete Linux Setup (One-Click)
# ============================================================
# ONE-LINE INSTALL:
# curl -fsSL https://raw.githubusercontent.com/steelai-bot/Aegis-OSINT-AI/main/setup.sh | bash
# ============================================================

set -e

echo ""
echo "========================================"
echo "  Aegis OSINT AI - Full Setup (Linux)"
echo "========================================"
echo ""

# --- 1. Check Python ---
echo "[1/10] Checking Python 3.11+..."
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python3 not found."
    echo "Install with: sudo apt update && sudo apt install python3 python3-venv python3-pip"
    exit 1
fi
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
    echo "ERROR: Python 3.11+ is required. Found Python $PYTHON_VERSION."
    exit 1
fi
echo "      Python $PYTHON_VERSION found."

# --- 2. Check optional Node.js ---
echo ""
echo "[2/10] Checking optional Node.js + npm..."
HAS_NODE=0
if command -v node &> /dev/null && command -v npm &> /dev/null; then
    HAS_NODE=1
    NODE_VERSION=$(node --version)
    echo "      Node.js $NODE_VERSION found."
else
    echo "      Node.js/npm not found. Current bundled frontend does not require it."
fi

# --- 3. Create virtual environment ---
echo ""
echo "[3/10] Creating Python virtual environment..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    echo "      Virtual environment created."
else
    echo "      Virtual environment already exists."
fi

# --- 4. Install Python dependencies ---
echo ""
echo "[4/10] Installing Python dependencies..."
./.venv/bin/pip install --upgrade pip -q
./.venv/bin/pip install -r requirements.txt -q
echo "      Python dependencies installed."

# --- 5. Install frontend dependencies if needed ---
echo ""
echo "[5/10] Checking frontend dependencies..."
if [ -f "frontend/package.json" ]; then
    if [ "$HAS_NODE" -eq 1 ]; then
        (cd frontend && npm install --silent)
        echo "      Frontend dependencies installed."
    else
        echo "ERROR: frontend/package.json exists, but Node.js/npm is not installed."
        exit 1
    fi
else
    echo "      Legacy static frontend detected; no npm dependencies required."
fi

# --- 6. Build frontend if needed ---
echo ""
echo "[6/10] Building frontend if required..."
if [ -f "frontend/package.json" ]; then
    (cd frontend && npm run build --silent)
    echo "      Frontend built successfully."
else
    echo "      Using bundled frontend/ static files."
fi

# --- 7. Create directories ---
echo ""
echo "[7/10] Creating required directories..."
mkdir -p data reports
echo "      Directories created."

# --- 8. Create .env if missing ---
echo ""
echo "[8/10] Setting up configuration (.env)..."
if [ ! -f ".env" ]; then
    if [ -f "config/.env.example" ]; then
        cp config/.env.example .env
    else
        echo "# Aegis OSINT AI Configuration" > .env
    fi
    echo "      Created .env file."
else
    echo "      .env already exists."
fi

# --- 9. Initialize database ---
echo ""
echo "[9/10] Initializing database..."
./.venv/bin/python -c "
import sys
sys.path.insert(0, '.')
try:
    from backend.main import init_db
    init_db()
    print('      Database initialized successfully.')
except Exception as e:
    print(f'      WARNING: {e}')
" 2>/dev/null || echo "      Database will be created on first run."

# --- 10. Final verification ---
echo ""
echo "[10/10] Verifying installation..."
./.venv/bin/python -c "import fastapi, httpx, pydantic; print('      Core Python modules OK')" 2>/dev/null || echo "      Python modules verification skipped."
if [ -f "frontend/index.html" ] || [ -f "frontend_dist/index.html" ]; then
    echo "      Frontend files verified."
fi

echo ""
echo "========================================"
echo "  ✅ Installation Complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo "  1. Edit .env and add your API keys"
echo "  2. Run the application:"
echo "     ./run.sh"
echo ""
echo "  Application will be available at: http://localhost:8000"
echo ""
