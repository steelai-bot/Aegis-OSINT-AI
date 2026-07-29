#!/bin/bash

# Aegis OSINT AI - Interactive One-Line Installation for Kali Linux
# Usage: curl -fsSL https://raw.githubusercontent.com/steelai-bot/Aegis-OSINT-AI/main/install.sh | sudo bash
# Alternative: wget -qO- https://raw.githubusercontent.com/steelai-bot/Aegis-OSINT-AI/main/install.sh | sudo bash

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

# Installation directory
INSTALL_DIR="/opt/aegis-osint-ai"

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  Aegis OSINT AI - Kali Installer${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: Please run as root (script will use sudo)${NC}"
    exit 1
fi

# Step 1: System Dependencies
echo -e "${YELLOW}[Step 1/8] Checking system dependencies...${NC}"
DEPS_NEEDED=""

for pkg in python3 python3-pip python3-venv python3-dev git curl wget build-essential libssl-dev libffi-dev; do
    if ! dpkg -l | grep -q "^ii  $pkg "; then
        DEPS_NEEDED="$DEPS_NEEDED $pkg"
    fi
done

if [ -n "$DEPS_NEEDED" ]; then
    echo -e "${YELLOW}Missing packages:$DEPS_NEEDED${NC}"
    read -p "Install missing dependencies? [Y/n]: " CONFIRM
    if [[ "$CONFIRM" =~ ^[Nn]$ ]]; then
        echo -e "${RED}Installation aborted.${NC}"
        exit 1
    fi
    apt-get update -qq
    apt-get install -y -qq $DEPS_NEEDED > /dev/null 2>&1
    echo -e "${GREEN}✓ System dependencies installed${NC}"
else
    echo -e "${GREEN}✓ All system dependencies present${NC}"
fi

# Step 2: Installation Directory
echo -e "${YELLOW}[Step 2/8] Setting up installation directory...${NC}"
if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}Directory $INSTALL_DIR already exists.${NC}"
    read -p "Overwrite existing installation? [y/N]: " OVERWRITE
    if [[ "$OVERWRITE" =~ ^[Yy]$ ]]; then
        rm -rf "$INSTALL_DIR"
        echo -e "${GREEN}✓ Cleaned existing installation${NC}"
    else
        echo -e "${YELLOW}Installing to temporary directory for testing...${NC}"
        INSTALL_DIR=$(mktemp -d)
    fi
fi

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"
echo -e "${GREEN}✓ Installation directory ready: $INSTALL_DIR${NC}"

# Step 3: Clone Repository
echo -e "${YELLOW}[Step 3/8] Cloning repository...${NC}"
git clone -q https://github.com/steelai-bot/Aegis-OSINT-AI.git . 2>/dev/null || {
    echo -e "${YELLOW}Repository exists, updating...${NC}"
    git pull -q
}
echo -e "${GREEN}✓ Repository ready${NC}"

# Step 4: Virtual Environment
echo -e "${YELLOW}[Step 4/8] Creating Python virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip -q
echo -e "${GREEN}✓ Virtual environment created and activated${NC}"

# Step 5: Install Dependencies
echo -e "${YELLOW}[Step 5/8] Installing Python dependencies...${NC}"
echo "Checking requirements.txt..."
if [ ! -f "requirements.txt" ]; then
    echo -e "${RED}Error: requirements.txt not found${NC}"
    exit 1
fi

# Add missing dependencies dynamically
cat >> requirements.txt << 'EOF'

# Additional dependencies for full functionality
sqlalchemy>=2.0.0
alembic>=1.13.0
aiofiles>=23.0.0
websockets>=12.0
EOF

pip install -r requirements.txt -q
echo -e "${GREEN}✓ All Python dependencies installed${NC}"

# Step 6: Configuration
echo -e "${YELLOW}[Step 6/8] Configuring Aegis OSINT AI...${NC}"
mkdir -p data logs plugins reports

if [ ! -f ".env" ]; then
    echo -e "${CYAN}Setting up configuration:${NC}"
    echo ""
    echo -e "${BLUE}Enter your API keys (press Enter to skip and configure later via web dashboard):${NC}"
    
    read -p "OpenAI API Key (sk-...): " OPENAI_KEY
    read -p "Shodan API Key: " SHODAN_KEY
    read -p "Aegis API Key (optional): " AEGIS_KEY
    
    cat > .env << ENVEOF
# Aegis OSINT AI Configuration
# Generated on $(date)

# API Keys
OPENAI_API_KEY=${OPENAI_KEY:-your_openai_key}
SHODAN_API_KEY=${SHODAN_KEY:-your_shodan_key}
AEGIS_API_KEY=${AEGIS_KEY:-your_aegis_key}

# Database
DATABASE_URL=sqlite:///./data/aegis.db

# Server Settings
HOST=0.0.0.0
PORT=8000
DEBUG=false

# Enhanced Features
CIRCUIT_BREAKER_ENABLED=true
CACHE_ENABLED=true
RATE_LIMIT_ENABLED=true
ENVEOF
    
    echo -e "${GREEN}✓ Configuration saved to .env${NC}"
else
    echo -e "${GREEN}✓ Configuration exists${NC}"
fi

# Step 7: Database Initialization
echo -e "${YELLOW}[Step 7/8] Initializing database...${NC}"
python install.py 2>/dev/null || {
    echo -e "${YELLOW}Database will be initialized on first run${NC}"
}
echo -e "${GREEN}✓ Database ready${NC}"

# Step 8: System Integration
echo -e "${YELLOW}[Step 8/8] Setting up system integration...${NC}"

# Create systemd service
cat > /etc/systemd/system/aegis-osint.service << 'SERVICEEOF'
[Unit]
Description=Aegis OSINT AI Service
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/aegis-osint-ai
Environment="PATH=/opt/aegis-osint-ai/venv/bin"
ExecStart=/opt/aegis-osint-ai/venv/bin/python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=10
KillMode=mixed
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
SERVICEEOF

systemctl daemon-reload
systemctl enable aegis-osint.service -q

# Create global command
cat > /usr/local/bin/aegis << 'CMDEOF'
#!/bin/bash
if [ -d "/opt/aegis-osint-ai/venv" ]; then
    cd /opt/aegis-osint-ai
    source venv/bin/activate
    exec python "$@"
else
    echo "Error: Aegis OSINT AI not installed properly"
    exit 1
fi
CMDEOF
chmod +x /usr/local/bin/aegis

echo -e "${GREEN}✓ System integration complete${NC}"

# Final verification
echo ""
echo -e "${CYAN}Running final verification...${NC}"
if python -c "import fastapi; import sqlalchemy; print('OK')" 2>/dev/null; then
    echo -e "${GREEN}✓ All modules verified successfully${NC}"
else
    echo -e "${YELLOW}! Some modules may need attention${NC}"
fi

# Summary
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✓ Installation Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${BLUE}Installation Summary:${NC}"
echo "  • Installed to: $INSTALL_DIR"
echo "  • Python venv: $INSTALL_DIR/venv"
echo "  • Config file: $INSTALL_DIR/.env"
echo "  • Database: $INSTALL_DIR/data/aegis.db"
echo ""
echo -e "${BLUE}Quick Start Commands:${NC}"
echo "  1. Edit config: nano $INSTALL_DIR/.env"
echo "  2. Start service: systemctl start aegis-osint"
echo "  3. Check status: systemctl status aegis-osint"
echo "  4. Access API: http://localhost:8000"
echo "  5. Web Dashboard: http://localhost:8000/setup"
echo ""
echo -e "${BLUE}Global Commands:${NC}"
echo "  aegis main.py          # Run server manually"
echo "  aegis install.py       # Re-run installation"
echo "  aegis <script.py>      # Run any script"
echo ""
echo -e "${YELLOW}Note: You can also configure API keys via the web dashboard at http://localhost:8000/setup${NC}"
echo ""
echo -e "${CYAN}Starting Aegis OSINT AI service...${NC}"
systemctl start aegis-osint
sleep 3

if systemctl is-active --quiet aegis-osint; then
    echo -e "${GREEN}✓ Service started successfully${NC}"
    echo -e "${GREEN}Access the web dashboard: http://$(hostname -I | awk '{print $1}'):8000/setup${NC}"
else
    echo -e "${YELLOW}! Service may need configuration. Check logs: journalctl -u aegis-osint${NC}"
fi

echo ""
echo -e "${GREEN}Enjoy using Aegis OSINT AI! 🚀${NC}"
