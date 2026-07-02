# Aegis OSINT AI

Defensive OSINT framework for Kali Linux. Passive breach intelligence, email/username exposure checks, and report generation.

## Requirements

- Kali Linux 2026.1 or newer
- Python 3.12+
- PostgreSQL + pgvector
- Redis
- Node.js + npm

## Quick Start

```bash
# Full setup (run once)
sudo bash scripts/setup-kali.sh

# Start services
bash scripts/start.sh

# Or production mode
bash scripts/start.sh production
```

## Services

- Backend: http://localhost:8000
- Frontend: http://localhost:3000

## Kali Tools Used

- `holehe` — email exposure checking
- `tesseract-ocr` — OCR for PDF/image intelligence
- Additional Kali tools are tracked in `docs/kali_compatibility.md`

## Project Structure

- `backend/` — FastAPI backend
- `frontend/` — Next.js frontend
- `scripts/` — Kali setup and launcher scripts
- `docs/` — architecture and compatibility docs

## License

MIT