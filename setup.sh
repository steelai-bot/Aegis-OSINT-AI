#!/bin/bash
# Aegis OSINT AI - Linux Setup Script
# One-click installation for Linux

# ============================================
# ONE-LINE INSTALL (copy & paste):
# curl -fsSL https://raw.githubusercontent.com/steelai-bot/Aegis-OSINT-AI/main/setup.sh | bash
# ============================================

set -e

echo ""
echo "========================================"
echo "  Aegis OSINT AI - Setup (Linux)"
echo "========================================"
echo ""

# Check Python
echo "[1/12] Checking Python..."
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python3 not found. Please install Python 3.10+ using your package manager."
    echo "Example: sudo apt update && sudo apt install python3 python3-venv python3-pip"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo "      Python $PYTHON_VERSION found."

# Create virtual environment
echo ""
echo "[2/12] Creating virtual environment..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    echo "      Virtual environment created."
else
    echo "      Virtual environment already exists."
fi

# Upgrade pip
echo ""
echo "[3/12] Upgrading pip..."
./.venv/bin/pip install --upgrade pip > /dev/null 2>&1
echo "      Pip upgraded."

# Install Python dependencies
echo ""
echo "[4/12] Installing Python dependencies..."
./.venv/bin/pip install -r requirements.txt > /dev/null
if [ $? -ne 0 ]; then
    echo "      ERROR: Failed to install dependencies"
    exit 1
fi
echo "      Dependencies installed."

# Create directories
echo ""
echo "[5/12] Creating directories..."
mkdir -p data
mkdir -p reports
echo "      Directories created."

# Create .env from template if missing
echo ""
echo "[6/12] Setting up configuration..."
if [ ! -f ".env" ]; then
    cp config/.env.example .env
    echo "      Created .env from template."
else
    echo "      .env already exists."
fi

# Initialize database
echo ""
echo "[7/12] Initializing database..."
./.venv/bin/python -c "
import sys
sys.path.insert(0, '.')
try:
    from backend.main import init_db
    init_db()
    print('      Database initialized.')
except Exception as e:
    print(f'      WARNING: {e}')
" 2>/dev/null || echo "      WARNING: Could not initialize database (may be created on first run)"

# Verify installation
echo ""
echo "[8/12] Verifying installation..."
./.venv/bin/python -c "import fastapi; import sqlalchemy; print('       Core modules OK')" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "      ERROR: Verification failed"
    exit 1
fi
echo "      Core modules verified."

# Summary
echo ""
echo "========================================"
echo "  Installation Complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo "  1. Edit .env and add your API keys"
echo "  2. Run: ./run.sh"
echo "  3. Open: http://localhost:8000"
echo ""
echo "Press Enter to attempt to start the application..."
read -r

./run.sh