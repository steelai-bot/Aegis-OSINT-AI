---
name: au-osint-recon
description: "Australian OSINT Reconnaissance & Breach Intelligence Platform. Multi-module tool for searching leaked accounts, databases, combos, passwords, phone numbers, bank accounts, and corporate data targeting Australian entities. Supports clearnet, dark web, and Telegram sources with integrated exploit scanning (SQLi, XSS, SSRF, etc.)."
icon: shield-alert
color: Red
---

# AU-OSINT-RECON — Australian Breach Intelligence & OSINT Platform

## Overview
A comprehensive multi-module OSINT tool focused on Australian data breaches, leaked credentials, corporate intelligence, and vulnerability scanning. Designed for red team operations and security research.

## Architecture

```
au-osint-recon/
├── scripts/
│   ├── orchestrator.py          # Main engine — coordinates all modules
│   ├── breach_search.py         # Breach database & combo list search
│   ├── osint_australia.py       # Australia-specific OSINT (ABN, ASIC, ATO patterns)
│   ├── darkweb_crawler.py       # Dark web marketplace & forum crawler
│   ├── telegram_monitor.py      # Telegram group/channel leak monitoring
│   ├── exploit_scanner.py       # SQLi, XSS, SSRF, LFI, RCE scanner
│   ├── paste_scraper.py         # Pastebin/paste site scraper
│   ├── credential_parser.py     # Parse & normalize leaked credentials
│   ├── report_generator.py      # HTML/JSON/CSV report generation
│   └── utils.py                 # Shared utilities, rate limiting, proxying
├── references/
│   ├── australian_sources.md    # Known AU data sources & endpoints
│   └── exploit_payloads.md      # SQLi/XSS/SSRF payload reference
└── assets/
    └── dashboard_template.html  # Interactive results dashboard
```

## Modules

### 1. Breach Search (`breach_search.py`)
- Have I Been Pwned API integration
- DeHashed API search
- LeakCheck API
- BreachDirectory search
- IntelX (Intelligence X) archive search
- Snusbase lookup
- Custom combo list parsing (.txt, .csv, .sql dumps)
- Australian email domain filtering (.com.au, .gov.au, .edu.au, .org.au)

### 2. Australian OSINT (`osint_australia.py`)
- ABN (Australian Business Number) lookup via ABR
- ASIC company register search
- Australian domain WHOIS (.com.au, .net.au)
- Government employee directory scraping
- Australian phone number format validation & carrier lookup
- BSB (Bank-State-Branch) number database
- Medicare/TFN pattern detection in leaks
- Australian IP range identification (APNIC)

### 3. Dark Web Crawler (`darkweb_crawler.py`)
- Tor-based .onion site crawling
- Ahmia.fi search engine integration
- Dark web marketplace monitoring (databases, credentials)
- Forum post scraping (breach announcements)
- Paste .onion sites monitoring
- Australian-tagged listing detection
- Pricing intelligence for AU data lots

### 4. Telegram Monitor (`telegram_monitor.py`)
- Channel/group discovery for AU leak channels
- Message scraping with keyword filters
- File download & parsing (combo lists, databases)
- Bot interaction for breach lookup services
- Real-time monitoring with alerts
- Known AU leak channel database

### 5. Exploit Scanner (`exploit_scanner.py`)
- **SQL Injection**: Union-based, blind boolean, time-based, error-based, stacked queries, second-order SQLi
- **XSS**: Reflected, stored, DOM-based, polyglot payloads, CSP bypass
- **SSRF**: Internal network scanning, cloud metadata extraction (AWS/GCP/Azure)
- **LFI/RFI**: Path traversal, PHP wrapper exploitation, log poisoning
- **RCE**: Command injection, deserialization attacks, template injection (SSTI)
- **Auth Bypass**: JWT manipulation, IDOR, privilege escalation vectors
- **API Abuse**: GraphQL introspection, REST endpoint fuzzing, rate limit bypass
- **Novel Techniques**: HTTP request smuggling, cache poisoning, prototype pollution, WebSocket hijacking

### 6. Paste Scraper (`paste_scraper.py`)
- Pastebin monitoring (API + scraping)
- GitHub Gist search
- Ghostbin, Rentry, dpaste scanning
- Regex-based Australian data detection
- Auto-classification (credentials, PII, financial)

### 7. Credential Parser (`credential_parser.py`)
- Multi-format parsing (email:pass, user:pass, hash:pass)
- Hash identification & cracking integration
- Deduplication & normalization
- Australian email domain extraction
- Password pattern analysis
- Combo list merging & export

### 8. Report Generator (`report_generator.py`)
- Interactive HTML dashboard
- JSON export for API consumption
- CSV export for spreadsheet analysis
- Executive summary generation
- Risk scoring per finding
- Timeline visualization of breaches

## Usage

### Quick Search (single target)
```python
python3 scripts/orchestrator.py --target "example.com.au" --modules all
```

### Breach Search Only
```python
python3 scripts/orchestrator.py --email "user@company.com.au" --modules breach
```

### Full Australian Corporate Recon
```python
python3 scripts/orchestrator.py --company "CompanyName" --country AU --modules osint,breach,paste,darkweb
```

### Exploit Scan
```python
python3 scripts/orchestrator.py --url "https://target.com.au" --modules exploit --scan-type full
```

### Telegram Monitoring
```python
python3 scripts/orchestrator.py --modules telegram --keywords "australia,aussie,com.au" --monitor
```

## Configuration
Set API keys in environment or pass via CLI:
- `HIBP_API_KEY` — Have I Been Pwned
- `DEHASHED_API_KEY` + `DEHASHED_EMAIL` — DeHashed
- `INTELX_API_KEY` — Intelligence X
- `LEAKCHECK_API_KEY` — LeakCheck
- `SNUSBASE_API_KEY` — Snusbase
- `TELEGRAM_API_ID` + `TELEGRAM_API_HASH` — Telegram MTProto
- `TOR_PROXY` — SOCKS5 proxy for Tor (default: socks5://127.0.0.1:9050)
