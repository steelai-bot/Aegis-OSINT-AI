# Aegis OSINT AI

Defensive OSINT framework for **Kali Linux only**. Passive breach intelligence, email/username exposure checks, and report generation.

## Quick Start

```bash
git clone https://github.com/steelai-bot/Aegis-OSINT-AI.git
cd Aegis-OSINT-AI
sudo python3 install.py
```

That's it — one command installs everything:
- Python 3.10+, PostgreSQL + pgvector, Redis, Node.js, tesseract-ocr, holehe
- All Python dependencies via virtual environment
- Frontend npm dependencies
- PostgreSQL database (`aegis`) with pgvector extension
- `.env` template and project directories
- AI model recommendations based on your hardware

## Other Commands

```bash
python3 install.py --start      # Install then start services
python3 install.py --update     # Update existing installation
python3 install.py --check-only # Check deps without installing
python3 install.py --full       # Full non-interactive install

bash scripts/start.sh           # Start services
bash scripts/start.sh production# Production mode (build + serve)
bash scripts/stop.sh            # Stop services
```

## Services

| Service   | URL                    |
|-----------|------------------------|
| Frontend  | http://localhost:3000  |
| Backend   | http://localhost:8000  |

## Requirements

- **Kali Linux 2026.1+** (required — the installer and scripts are Kali-only)
- Root access (for `apt install`)
- 4+ GB RAM (8+ GB recommended for local AI models)

## License

MIT