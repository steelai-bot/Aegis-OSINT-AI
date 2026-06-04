# AU-OSINT-RECON
### Australian Breach Intelligence & OSINT Platform

> Multi-module red team toolkit for Australian data breach discovery, credential hunting,
> infostealer log analysis, exploit scanning, and AI-assisted intelligence analysis.
> Designed for offensive security research and corporate threat intelligence.

---

## Table of Contents
1. [Architecture](#architecture)
2. [Module Reference](#module-reference)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Usage Examples](#usage-examples)
6. [AI Module — HuggingFace Integration](#ai-module--huggingface-integration)
7. [Hardware Auto-Detection & Model Recommender](#hardware-auto-detection--model-recommender)
8. [API Keys Reference](#api-keys-reference)
9. [Output Formats](#output-formats)

---

## Architecture

```
au-osint-recon/
├── scripts/
│   ├── orchestrator.py          # Master engine — coordinates all modules
│   ├── breach_search.py         # Breach DB & combo list search (HIBP, DeHashed, etc.)
│   ├── osint_australia.py       # AU-specific OSINT: ABN, ASIC, ATO, BSB, Medicare
│   ├── darkweb_crawler.py       # Tor-based .onion crawler & marketplace monitor
│   ├── telegram_monitor.py      # Telegram leak channel monitor (MTProto)
│   ├── exploit_scanner.py       # SQLi, XSS, SSRF, LFI, RCE, JWT, GraphQL scanner
│   ├── paste_scraper.py         # Pastebin / GitHub Gist / paste site scraper
│   ├── credential_parser.py     # Parse & normalize leaked credential dumps
│   ├── report_generator.py      # HTML dashboard / JSON / CSV report engine
│   ├── pdf_extractor.py         # PDF data extraction with 30+ AU regex patterns
│   ├── infostealer_parser.py    # Infostealer log parser with date-range filtering
│   ├── leaked_db_hunter.py      # Multi-source breach API + paid combo market intel
│   ├── ai_modules.py            # HuggingFace AI analysis & intelligence synthesis
│   ├── advanced_exploits.py     # Extended exploit techniques & novel attack vectors
│   ├── pivot_chain.py           # Pivot chaining & lateral movement mapping
│   ├── pre_exploit.py           # Pre-exploitation recon & fingerprinting
│   ├── sneaky_recon.py          # Stealth recon with evasion techniques
│   ├── eni_signature.py         # ENI signature & session watermarking
│   └── utils.py                 # Shared utilities, rate limiting, proxy management
├── references/
│   ├── australian_sources.md    # Known AU data sources, endpoints, registries
│   └── exploit_payloads.md      # SQLi / XSS / SSRF payload reference library
└── assets/
    └── dashboard_template.html  # Interactive dark-theme results dashboard
```

---

## Module Reference

### 1. `orchestrator.py` — Master Engine
Central coordinator. Accepts a target (email, domain, URL, company name) and dispatches
to the appropriate modules. Merges all findings into a unified `ResultStore` and hands off
to `report_generator.py` for output.

```bash
python3 scripts/orchestrator.py --target "example.com.au" --modules all
python3 scripts/orchestrator.py --email "user@corp.com.au" --modules breach,paste
python3 scripts/orchestrator.py --url "https://target.com.au" --modules exploit
```

---

### 2. `breach_search.py` — Breach Database Search
Queries multiple breach intelligence APIs for email addresses, domains, usernames, and IPs.

| Source | Type | Auth Required |
|--------|------|---------------|
| Have I Been Pwned | Email breach lookup | API key |
| DeHashed | Full-text breach search | API key + email |
| LeakCheck | Email/domain/IP/username | API key |
| Intelligence X | Archive search | API key |
| Snusbase | Email/hash/IP/username | API key |
| BreachDirectory | RapidAPI breach lookup | RapidAPI key |
| ProxyNova COMB | COMB combo list search | Free |
| Hudson Rock Cavalier | Infostealer victim lookup | Free |

**AU domain filtering** — automatically flags `.com.au`, `.gov.au`, `.edu.au`, `.org.au` results.

---

### 3. `osint_australia.py` — Australian OSINT
Specialised module for Australian corporate and government intelligence.

- **ABN Lookup** — Australian Business Register (ABR) API
- **ASIC Search** — Company register, director names, ACN
- **WHOIS** — `.com.au` / `.net.au` domain registration data
- **BSB Database** — Bank-State-Branch to institution mapping
- **Phone Validation** — AU mobile / landline format + carrier inference
- **Medicare / TFN Pattern Detection** — Regex-based PII detection in leaks
- **APNIC IP Ranges** — Identify Australian IP allocations
- **Government Employee Directories** — Scrape public gov.au staff listings

---

### 4. `darkweb_crawler.py` — Dark Web Intelligence
Tor-routed crawler for .onion sites, forums, and marketplaces.

- Ahmia.fi search engine integration
- Marketplace listing monitoring (databases, credentials, AU-tagged data)
- Forum post scraping (breach announcements, AU data lots)
- Paste .onion site monitoring
- Pricing intelligence for AU data listings
- Requires: `TOR_PROXY=socks5://127.0.0.1:9050`

---

### 5. `telegram_monitor.py` — Telegram Leak Monitor
MTProto-based Telegram client for real-time leak channel monitoring.

- Channel/group discovery for AU leak channels
- Keyword-filtered message scraping
- Combo list and database file download + auto-parse
- Bot interaction for breach lookup services
- Known AU leak channel database: `@ausleaks`, `@ozleaks`, `@breachforums_official`
- Requires: `TELEGRAM_API_ID` + `TELEGRAM_API_HASH`

---

### 6. `exploit_scanner.py` — Vulnerability Scanner
Comprehensive web application vulnerability scanner.

| Category | Techniques |
|----------|-----------|
| **SQL Injection** | Union-based, blind boolean, time-based, error-based, stacked, second-order |
| **XSS** | Reflected, stored, DOM-based, polyglot, CSP bypass |
| **SSRF** | Internal network scan, AWS/GCP/Azure metadata extraction |
| **LFI/RFI** | Path traversal, PHP wrapper, log poisoning |
| **RCE** | Command injection, deserialization, SSTI |
| **Auth Bypass** | JWT manipulation, IDOR, privilege escalation |
| **API Abuse** | GraphQL introspection, REST fuzzing, rate limit bypass |
| **Novel** | HTTP request smuggling, cache poisoning, prototype pollution, WebSocket hijack |

---

### 7. `paste_scraper.py` — Paste Site Monitor
Monitors public paste sites for Australian data exposure.

- Pastebin API + scraping
- GitHub Gist search
- Ghostbin, Rentry, dpaste, hastebin
- Regex-based AU data classification (credentials, PII, financial)
- Auto-classification and severity tagging

---

### 8. `credential_parser.py` — Credential Normalizer
Processes raw credential dumps into structured, deduplicated output.

- Multi-format: `email:pass`, `user:pass`, `hash:pass`, tab-separated, SQL dumps
- Hash identification: MD5, SHA1, SHA256, bcrypt, NTLM, Argon2
- Hash cracking integration (hashcat / john command generation)
- AU email domain extraction and filtering
- Password pattern analysis (complexity, reuse detection)
- Combo list merging and export

---

### 9. `report_generator.py` — Report Engine
Produces three output formats from a unified findings payload.

- **HTML** — Interactive dark-theme dashboard with severity tabs, timeline, risk score
- **JSON** — Structured API-consumable report with metadata and risk breakdown
- **CSV** — Flat spreadsheet export for further analysis
- Risk scoring: weighted severity × category multiplier, normalised 0–100, grade A–F
- Executive summary generation
- Timeline visualisation sorted by `date_found`

---

### 10. `pdf_extractor.py` — PDF Data Extractor
Extracts and classifies sensitive data from PDF files (leaked documents, reports, dumps).

**Extraction engine:** PyMuPDF (primary) → pypdf (fallback)

**Detected pattern types:**

| Category | Patterns |
|----------|---------|
| Credentials | `email:password` pairs, password fields |
| AU Identifiers | TFN, ABN, ACN, BSB, Medicare, drivers licence |
| Contact | AU mobile, landline, postcode |
| Financial | Credit cards (Visa/MC/Amex), bank accounts, IBAN, SWIFT |
| Secrets | AWS access keys, JWT tokens, private keys, API keys |
| Hashes | MD5, SHA1, SHA256, bcrypt, NTLM |
| Network | IPv4, URLs, .onion addresses, AU domains |

```bash
# Scan single PDF
python3 scripts/pdf_extractor.py --file leaked_doc.pdf --target corp.com.au

# Scan entire directory
python3 scripts/pdf_extractor.py --dir /path/to/pdfs/ --target corp.com.au --au-only
```

---

### 11. `infostealer_parser.py` — Infostealer Log Parser
Parses infostealer log bundles with date-range filtering and AU credential targeting.

**Supported stealer formats:**

| Stealer | Detection Method |
|---------|----------------|
| Redline | `Passwords.txt` + `System Info.txt` signature |
| Raccoon | `passwords.txt` + `system.txt` signature |
| Vidar | `passwords.txt` + `information.txt` signature |
| Aurora | `Passwords.txt` + `Wallets/` directory |
| Lumma | `All Passwords.txt` + `System Information.txt` |
| MetaStealer | Generic fallback parser |

**Date inference priority:**
1. Directory name (e.g. `2024-03-15_victim/`)
2. Archive filename
3. System info file (`Date:` field)
4. File modification timestamp

```bash
# Parse directory of logs, filter by date range
python3 scripts/infostealer_parser.py \
    --dir /path/to/logs/ \
    --start 2024-01-01 \
    --end 2024-12-31 \
    --au-only \
    --target corp.com.au

# Bank credentials only
python3 scripts/infostealer_parser.py --dir /logs/ --bank
```

**AU-targeted filters:**
- `.com.au`, `.gov.au`, `.edu.au`, `.org.au`, `.net.au`
- Banks: Westpac, CommBank, ANZ, NAB, Macquarie, Bendigo, Suncorp, BankWest, ING, UBank
- Government: myGov, ATO, Centrelink, Medicare, ASIC, AFP, ASD, Defence
- Crypto wallets: MetaMask, Exodus, Electrum, Coinbase, Binance, Kraken, Trust Wallet

---

### 12. `leaked_db_hunter.py` — Leaked DB & Combo Market Hunter
Multi-source breach discovery with paid combo market intelligence.

**Free sources (no key required):**
- ProxyNova COMB — largest public combo list index
- Hudson Rock Cavalier — infostealer victim lookup

**Paid API sources:**
- HIBP, DeHashed, LeakCheck, Snusbase, IntelX, BreachDirectory

**Combo Market Intelligence:**

| Market Type | Sources |
|-------------|---------|
| Telegram | @breachforums_official, @leakbase_io, @ausleaks, @ozleaks, @combolist |
| Forums | BreachForums, Cracked.io, Nulled.to, XSS.is, Exploit.in |
| Dark Web | Russian Market, 2easy Shop, Genesis Market, Stealc Market |

**AU Pricing Intelligence (observed market rates):**

| Data Type | Price Range | Unit |
|-----------|------------|------|
| Generic AU combo | $5–$50 | per 1M lines |
| AU banking creds | $100–$500 | per 10k creds |
| AU gov creds | $200–$1,000 | per 1k creds |
| Stealer log (AU) | $1–$10 | per log |
| Full AU database | $500–$5,000 | per database |
| AU CC fullz | $20–$80 | per card |

---

### 13. `ai_modules.py` — AI Intelligence Analysis
HuggingFace-powered analysis layer. See [AI Module section](#ai-module--huggingface-integration) for full details.

---

## Installation

### Requirements
- Python 3.10+
- Tor (for dark web modules): `apt install tor`
- Optional: CUDA toolkit for GPU inference (not required — CPU/RAM priority)

```bash
# Clone the repository
git clone https://github.com/steelai-bot/Aegis-OSINT-AI.git
cd Aegis-OSINT-AI/

# Install all dependencies
pip install -r requirements.txt

# Install Tor (dark web modules)
sudo apt install tor
sudo systemctl start tor

# Verify setup
python3 scripts/orchestrator.py --check-config
```

### Quick Install (single command)
```bash
pip install -r requirements.txt && python3 scripts/ai_modules.py --detect-hardware
```

---

## Configuration

Set API keys as environment variables or in a `.env` file in the project root:

```env
# ── Breach APIs ──────────────────────────────────────────────
HIBP_API_KEY=your_hibp_key
DEHASHED_API_KEY=your_dehashed_key
DEHASHED_EMAIL=your@email.com
LEAKCHECK_API_KEY=your_leakcheck_key
INTELX_API_KEY=your_intelx_key
SNUSBASE_API_KEY=your_snusbase_key
RAPIDAPI_KEY=your_rapidapi_key

# ── Telegram ─────────────────────────────────────────────────
TELEGRAM_API_ID=your_api_id
TELEGRAM_API_HASH=your_api_hash

# ── Network ──────────────────────────────────────────────────
TOR_PROXY=socks5://127.0.0.1:9050
HTTP_PROXY=                        # optional upstream proxy

# ── AI / HuggingFace ─────────────────────────────────────────
HF_TOKEN=your_huggingface_token    # optional, for gated models
HF_MODEL=                          # override auto-selected model
HF_CACHE_DIR=./models              # local model cache directory
```

---

## Usage Examples

### Email Hunt (all sources)
```bash
python3 scripts/orchestrator.py \
    --email "target@company.com.au" \
    --modules breach,paste,telegram,darkweb
```

### Domain Recon
```bash
python3 scripts/orchestrator.py \
    --target "company.com.au" \
    --modules all \
    --output ./reports/
```

### PDF Batch Scan
```bash
python3 scripts/pdf_extractor.py \
    --dir /mnt/leaked_docs/ \
    --target company.com.au \
    --au-only \
    --output ./reports/
```

### Infostealer Logs — Date Filtered
```bash
python3 scripts/infostealer_parser.py \
    --dir /mnt/stealer_logs/ \
    --start 2024-01-01 \
    --end 2024-06-30 \
    --au-only \
    --bank \
    --output ./reports/
```

### Exploit Scan
```bash
python3 scripts/orchestrator.py \
    --url "https://target.com.au" \
    --modules exploit \
    --scan-type full
```

### Combo Market Intel Report
```bash
python3 scripts/leaked_db_hunter.py --market --output ./reports/
```

### AI Analysis of Findings
```bash
python3 scripts/ai_modules.py \
    --input ./reports/findings.json \
    --task summarise \
    --model auto
```

---

## AI Module — HuggingFace Integration

The `ai_modules.py` module integrates local HuggingFace models for intelligence analysis.
No data leaves the machine — all inference runs locally.

### Capabilities
- **Finding summarisation** — Condense raw findings into executive-ready summaries
- **Credential pattern analysis** — Identify password patterns, reuse, and weak credentials
- **Entity extraction** — Pull names, organisations, ABNs, emails from unstructured text
- **Threat classification** — Classify findings by MITRE ATT&CK technique
- **Report generation** — Natural language threat narrative from structured findings
- **Uncensored analysis** — Prioritises uncensored models for unrestricted security analysis

### Model Selection
Run hardware detection first — the system recommends the best model for your hardware:

```bash
python3 scripts/ai_modules.py --detect-hardware
```

Then select a model interactively or pass `--model auto` to use the recommendation.

### Supported Model Families
| Family | Example Models | Best For |
|--------|---------------|---------|
| Mistral | Mistral-7B, Mixtral-8x7B | General analysis, fast |
| LLaMA 3 | Meta-LLaMA-3-8B | Balanced quality/speed |
| Phi-3 | Phi-3-mini, Phi-3-medium | Low RAM systems |
| Qwen2 | Qwen2-7B, Qwen2-72B | Long context analysis |
| Gemma | Gemma-2-9B | Instruction following |
| WizardLM | WizardLM-2-7B | Uncensored, red team |
| Dolphin | Dolphin-2.9-Mistral | Uncensored, unrestricted |
| OpenHermes | OpenHermes-2.5-Mistral | Uncensored, fast |

---

## Hardware Auto-Detection & Model Recommender

Before loading any model, run the hardware scanner. It checks your CPU, RAM, and
available disk space, then recommends uncensored models that will actually fit and run.
GPU is detected but **not required** — RAM and CPU are the primary selection criteria.

```bash
python3 scripts/ai_modules.py --detect-hardware
```

### Example Output
```
══════════════════════════════════════════════════
  AU-OSINT-RECON — Hardware Detection
══════════════════════════════════════════════════
  CPU     : AMD EPYC 7502 (32 cores / 64 threads)
  RAM     : 62.8 GB total / 58.1 GB available
  Disk    : 480 GB free
  GPU     : None detected (CPU inference mode)
  OS      : Ubuntu 22.04 LTS

  Recommended tier: HIGH (32GB+ RAM)

  ┌─────────────────────────────────────────────┐
  │  RECOMMENDED UNCENSORED MODELS              │
  ├─────────────────────────────────────────────┤
  │  1. dolphin-2.9-llama3-70b-q4 (38 GB)      │ ← best fit
  │  2. WizardLM-2-8x22B-q3 (28 GB)            │
  │  3. Mixtral-8x7B-Dolphin-q4 (26 GB)        │
  │  4. openhermes-2.5-mistral-7b (4.1 GB)     │ ← fast option
  └─────────────────────────────────────────────┘

  Select model [1-4] or enter HuggingFace model ID:
```

### RAM Tiers
| Available RAM | Tier | Recommended Models |
|--------------|------|-------------------|
| < 4 GB | MINIMAL | Phi-3-mini (Q4), TinyLlama |
| 4–8 GB | LOW | Mistral-7B (Q4), OpenHermes-7B (Q4) |
| 8–16 GB | MEDIUM | Mistral-7B (Q8), LLaMA-3-8B, Dolphin-7B |
| 16–32 GB | HIGH | Mixtral-8x7B (Q4), WizardLM-13B, Dolphin-13B |
| 32–64 GB | VERY HIGH | LLaMA-3-70B (Q4), Dolphin-70B (Q4) |
| 64 GB+ | EXTREME | Full precision 70B models, Mixtral-8x22B |

---

## API Keys Reference

| Variable | Service | URL | Free Tier |
|----------|---------|-----|-----------|
| `HIBP_API_KEY` | Have I Been Pwned | haveibeenpwned.com/API/v3 | No |
| `DEHASHED_API_KEY` | DeHashed | dehashed.com | No |
| `LEAKCHECK_API_KEY` | LeakCheck | leakcheck.io | Limited |
| `INTELX_API_KEY` | Intelligence X | intelx.io | Limited |
| `SNUSBASE_API_KEY` | Snusbase | snusbase.com | No |
| `RAPIDAPI_KEY` | BreachDirectory (RapidAPI) | rapidapi.com | Limited |
| `TELEGRAM_API_ID` | Telegram MTProto | my.telegram.org | Free |
| `TELEGRAM_API_HASH` | Telegram MTProto | my.telegram.org | Free |
| `HF_TOKEN` | HuggingFace (gated models) | huggingface.co/settings/tokens | Free |

---

## Output Formats

All modules feed findings into `report_generator.py` which produces:

### HTML Dashboard
Interactive dark-theme dashboard with:
- Risk score (0–100) with grade (A–F)
- Severity stat cards (Critical / High / Medium / Low)
- Filterable findings table with expandable detail rows
- Event timeline sorted by discovery date
- Category breakdown bar chart
- Executive summary

### JSON Report
```json
{
  "meta": { "target": "...", "generated_at": "...", "modules_run": [...] },
  "risk": { "score": 87.3, "grade": "F", "breakdown": { ... } },
  "summary": "...",
  "timeline": [ { "date": "...", "title": "...", "severity": "..." } ],
  "findings": [ { "title": "...", "severity": "critical", ... } ]
}
```

### CSV Export
Flat spreadsheet with columns: `title, severity, category, source, date_found, summary, target, raw_data`

---

*AU-OSINT-RECON — built for red team operations and Australian threat intelligence.*
