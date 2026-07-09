#!/bin/bash
# Aegis OSINT AI - Linux Update Script
# Updates the application while preserving configuration and data

echo ""
echo "========================================"
echo "  Aegis OSINT AI - Update (Linux)"
echo "========================================"
echo ""

# Check if .venv exists
if [ ! -d ".venv" ]; then
    echo "ERROR: Virtual environment not found."
    echo "Please run ./setup.sh first."
    exit 1
fi

# Backup .env
echo "[1/5] Backing up configuration..."
if [ -f ".env" ]; then
    cp .env .env.backup
    echo "      Configuration backed up."
else
    echo "      No .env to backup."
fi

# Git pull
echo ""
echo "[2/5] Pulling latest changes..."
git pull || echo "      WARNING: Git pull failed (not a git repo or no changes)"

# Update Python dependencies
echo ""
echo "[3/5] Updating Python dependencies..."
./.venv/bin/pip install -r requirements.txt --upgrade > /dev/null 2>&1 || echo "      WARNING: Some dependencies may not have updated"
echo "      Dependencies update step completed."

# Database migration (if needed)
echo ""
echo "[4/5] Checking database..."
if [ -f "data/aegis.db" ]; then
    echo "      Database exists - no migration needed."
else
    echo "      Database will be created on next run."
fi

# Restore .env
echo ""
echo "[5/5] Restoring configuration..."
if [ -f ".env.backup" ]; then
    mv .env.backup .env
    echo "      Configuration restored."
fi

echo ""
echo "========================================"
echo "  Update Complete!"
echo "========================================"
echo ""
echo "Run: ./run.sh"
echo ""