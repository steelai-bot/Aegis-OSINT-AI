# 🛡️ Aegis-OSINT-AI

## Australian OSINT Reconnaissance & Breach Intelligence Platform

Multi-module OSINT tool focused on Australian data breaches, leaked credentials, corporate intelligence, and vulnerability scanning. Designed for red team operations and security research.

### Modules

| Module | Description |
|--------|-------------|
| **Breach Search** | HIBP, DeHashed, IntelX, LeakCheck, Snusbase, BreachDirectory |
| **AU OSINT** | ABN/ASIC lookup, phone carrier detection, BSB mapping, gov directories |
| **Exploit Scanner** | SQLi, XSS, SSRF, LFI, SSTI, CMDi, CRLF, Open Redirect |
| **Dark Web Crawler** | Ahmia, DarkSearch, forum scraping, ransomware leak monitoring |
| **Telegram Monitor** | MTProto search, channel discovery, bot interaction |
| **Paste Scraper** | Pastebin, GitHub Gists/Secrets, Rentry, dpaste |
| **Credential Parser** | Multi-format parsing (combo, SQL, CSV), hash ID, analysis |

### Quick Start

```bash
# Terminal UI
pip install rich
cd scripts && python3 tui.py

# CLI
python3 scripts/orchestrator.py --target example.com.au --modules all

# Web Dashboard
open assets/dashboard.html
```

### Usage Examples

```bash
# Full recon on email
python3 scripts/orchestrator.py --email user@company.com.au --modules all

# Exploit scan
python3 scripts/orchestrator.py --url https://target.com.au --modules exploit

# Company intelligence
python3 scripts/orchestrator.py --company "Optus" --modules osint,breach,darkweb

# Phone lookup
python3 scripts/orchestrator.py --phone "+61412345678"

# ABN lookup
python3 scripts/orchestrator.py --abn "33051775556"
```

### API Keys

Set as environment variables or via the TUI config menu:

- `HIBP_API_KEY` — Have I Been Pwned
- `DEHASHED_API_KEY` + `DEHASHED_EMAIL` — DeHashed  
- `INTELX_API_KEY` — Intelligence X
- `LEAKCHECK_API_KEY` — LeakCheck
- `SNUSBASE_API_KEY` — Snusbase
- `TELEGRAM_API_ID` + `TELEGRAM_API_HASH` — Telegram MTProto
- `GITHUB_TOKEN` — GitHub code search

### Architecture

```
├── scripts/
│   ├── orchestrator.py       # Main engine
│   ├── tui.py                # Terminal UI (Rich)
│   ├── breach_search.py      # 6 breach APIs
│   ├── osint_australia.py    # AU-specific OSINT
│   ├── exploit_scanner.py    # Multi-vector vuln scanner
│   ├── darkweb_crawler.py    # Dark web intelligence
│   ├── telegram_monitor.py   # Telegram monitoring
│   ├── paste_scraper.py      # Paste site scraping
│   ├── credential_parser.py  # Credential parsing & analysis
│   └── utils.py              # Shared utilities
├── assets/
│   └── dashboard.html        # Web dashboard
├── references/
│   ├── australian_sources.md  # AU data sources
│   └── exploit_payloads.md   # Payload reference
└── SKILL.md                  # Skill documentation
```
