#!/bin/bash

# Aegis OSINT AI - One-Line Installation for Kali Linux
# Usage: curl -fsSL https://raw.githubusercontent.com/steelai-bot/Aegis-OSINT-AI/main/install.sh | bash

set -e

echo "========================================"
echo "  Aegis OSINT AI - Kali Linux Installer"
echo "========================================"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: Please run as root (sudo ./install.sh)${NC}"
    exit 1
fi

# System dependencies
echo -e "${YELLOW}[1/6] Installing system dependencies...${NC}"
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv python3-dev git curl wget build-essential libssl-dev libffi-dev > /dev/null 2>&1
echo -e "${GREEN}✓ System dependencies installed${NC}"

# Create installation directory
INSTALL_DIR="/opt/aegis-osint-ai"
echo -e "${YELLOW}[2/6] Creating installation directory...${NC}"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Clone or update repository
if [ -d ".git" ]; then
    echo -e "${YELLOW}Updating existing installation...${NC}"
    git pull -q
else
    echo -e "${YELLOW}Cloning repository...${NC}"
    git clone -q https://github.com/steelai-bot/Aegis-OSINT-AI.git .
fi
echo -e "${GREEN}✓ Repository ready${NC}"

# Create virtual environment
echo -e "${YELLOW}[3/6] Setting up Python virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip -q
echo -e "${GREEN}✓ Virtual environment created${NC}"

# Install Python dependencies
echo -e "${YELLOW}[4/6] Installing Python dependencies...${NC}"
pip install -q -r requirements.txt
echo -e "${GREEN}✓ Dependencies installed${NC}"

# Create directories and config
echo -e "${YELLOW}[5/6] Setting up configuration...${NC}"
mkdir -p data logs plugins
if [ ! -f ".env" ]; then
    cat > .env << 'ENVEOF'
# Aegis OSINT AI Configuration
AEGIS_API_KEY=your_api_key_here
OPENAI_API_KEY=your_openai_key
SHODAN_API_KEY=your_shodan_key
DATABASE_URL=sqlite:///./data/aegis.db
HOST=0.0.0.0
PORT=8000
DEBUG=false
ENVEOF
    echo -e "${YELLOW}! Created .env file - edit with your API keys${NC}"
else
    echo -e "${GREEN}✓ Configuration exists${NC}"
fi

# Initialize database
echo -e "${YELLOW}[6/6] Initializing database...${NC}"
python install.py -q 2>/dev/null || true
echo -e "${GREEN}✓ Database initialized${NC}"

# Create systemd service
echo -e "${YELLOW}Creating systemd service...${NC}"
cat > /etc/systemd/system/aegis-osint.service << 'SERVICEEOF'
[Unit]
Description=Aegis OSINT AI Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/aegis-osint-ai
ExecStart=/opt/aegis-osint-ai/venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SERVICEEOF

systemctl daemon-reload
systemctl enable aegis-osint.service -q
echo -e "${GREEN}✓ Systemd service created${NC}"

# Create global command
if [ ! -f "/usr/local/bin/aegis" ]; then
    cat > /usr/local/bin/aegis << 'CMDEOF'
#!/bin/bash
cd /opt/aegis-osint-ai
source venv/bin/activate
exec python "$@"
CMDEOF
    chmod +x /usr/local/bin/aegis
fi

echo ""
echo "========================================"
echo -e "${GREEN}✓ Installation Complete!${NC}"
echo "========================================"
echo ""
echo "Quick Start:"
echo "  1. Edit config: nano /opt/aegis-osint-ai/.env"
echo "  2. Start service: systemctl start aegis-osint"
echo "  3. Check status: systemctl status aegis-osint"
echo "  4. Access API: http://localhost:8000"
echo "  5. Use command: aegis install.py --run"
echo ""
echo "Global commands available:"
echo "  aegis <script.py>     - Run any script"
echo "  aegis install.py      - Setup plugins"
echo "  aegis main.py         - Run manually"
echo ""
echo -e "${YELLOW}Note: Remember to add your API keys in .env!${NC}"
echo ""
