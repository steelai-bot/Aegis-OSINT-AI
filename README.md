# Aegis OSINT AI

A lightweight Windows-first OSINT investigation framework for defensive security research.

## Features

- **OSINT Search**: Australian ABN, domains, phone lookup, IP geolocation, company search
- **New Zealand Support**: NZ company and domain lookups
- **Custom Search**: DuckDuckGo, Bing, Google searches
- **AI Analysis**: OpenRouter, OpenAI, Anthropic, Gemini, Nvidia integration
- **Report Generation**: HTML, JSON, CSV, Markdown formats
- **Simple Deployment**: One-click setup and run

## Requirements

- Windows 10/11
- Python 3.10+ (download from python.org)
- Internet connection for API calls

## Quick Start

```cmd
setup.bat    # Install everything
run.bat      # Start the application
```

That's it! Open http://localhost:8000 in your browser.

## Installation

1. Double-click `setup.bat` or run from Command Prompt
2. The script will:
   - Check Python installation
   - Create virtual environment (`.venv/`)
   - Install Python dependencies
   - Create configuration files
   - Initialize the database

## Configuration

Edit `.env` to add your API keys:

```env
# AI Providers (OpenRouter recommended - has free models)
OPENROUTER_API_KEY=sk-or-...
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
GEMINI_API_KEY=...
NVIDIA_API_KEY=...
```

## Usage

### OSINT Search
- Enter an ABN (Australian Business Number)
- Enter a domain name
- Enter an Australian phone number
- Enter the name of an Australian or NZ company
- Enter an IP address for geolocation

### AI Chat
- Configure API keys in Settings
- Select your preferred provider
- Ask questions or request analysis

### Reports
- View previous searches
- Generate reports in HTML, JSON, or Markdown format

## Updating

```cmd
update.bat   # Pull latest changes, update dependencies
```

Your `.env` and database will be preserved.

## Project Structure

```
Aegis-OSINT-AI/
├── backend/
│   ├── main.py       # FastAPI application
│   ├── osint.py      # OSINT search functions
│   ├── providers.py  # AI API clients
│   └── report.py     # Report generation
├── frontend/
│   ├── index.html    # Main UI
│   ├── style.css     # Dark theme styles
│   └── app.js        # Frontend logic
├── config/
│   └── .env.example  # Configuration template
├── data/
│   └── aegis.db      # SQLite database (created on first run)
├── reports/          # Generated reports directory
├── setup.bat         # Installation script
├── run.bat           # Startup script
├── update.bat        # Update script
├── requirements.txt  # Python dependencies
└── README.md         # This file
```

## Supported OSINT Sources

| Source | Type | Description |
|--------|------|-------------|
| ABR | Australian | Business Register lookup |
| DNS-Google | Global | DNS records via Google DNS |
| CertTransparency | Global | Subdomain enumeration |
| ASIC | Australian | Company search |
| IP-API | Global | IP geolocation |
| NZ Companies Office | New Zealand | NZ company search |

## AI Providers

| Provider | Free Models | Notes |
|----------|-------------|-------|
| OpenRouter | Yes | Recommended for testing |
| OpenAI | No | GPT models |
| Anthropic | No | Claude models |
| Gemini | Yes | Google's models |
| Nvidia | No | Enterprise models |

## Troubleshooting

**Python not found**
- Download Python from python.org
- Ensure "Add to PATH" is checked during installation

**API calls failing**
- Check your `.env` file has valid API keys
- Verify internet connection
- Check API provider status pages

**Database errors**
- Delete `data/aegis.db` and restart (will recreate)

## License

MIT License - See LICENSE file