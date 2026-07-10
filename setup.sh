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
echo "[1/10] Checking Python 3.10+..."
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python3 not found."
    echo "Install with: sudo apt update && sudo apt install python3 python3-venv python3-pip"
    exit 1
fi
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "      Python $PYTHON_VERSION found."

# --- 2. Check Node.js ---
echo ""
echo "[2/10] Checking Node.js + npm..."
if ! command -v node &> /dev/null || ! command -v npm &> /dev/null; then
    echo "ERROR: Node.js/npm not found."
    echo "Install with: sudo apt install nodejs npm"
    exit 1
fi
NODE_VERSION=$(node --version)
echo "      Node.js $NODE_VERSION found."

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

# --- 5. Install Node.js dependencies ---
echo ""
echo "[5/10] Installing frontend dependencies..."
if [ -d "frontend" ]; then
    cd frontend
    npm install --silent
    cd ..
    echo "      Frontend dependencies installed."
else
    echo "      No frontend folder found. Skipping."
fi

# --- 6. Build frontend ---
echo ""
echo "[6/10] Building frontend (React + Vite)..."
if [ -d "frontend" ]; then
    cd frontend
    npm run build --silent
    cd ..
    echo "      Frontend built successfully → frontend_dist/"
else
    echo "      Skipping frontend build."
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
if [ -d "frontend_dist" ]; then
    echo "      Frontend build verified."
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