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
Aegis-OSINT-AI/
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
│   ├── eni_signature.py         # Session watermarking
│   └── utils.py                 # Shared utilities, rate limiting, proxy management
├── references/
│   ├── australian_sources.md    # Known AU data sources, endpoints, registries
│   └── exploit_payloads.md      # SQLi / XSS / SSRF payload reference library
├── assets/
│   └── dashboard_template.html  # Interactive dark-theme results dashboard
├── requirements.txt
└── README.md
```

---

## Installation

```bash
git clone https://github.com/steelai-bot/Aegis-OSINT-AI
cd Aegis-OSINT-AI
pip install -r requirements.txt

# Detect hardware & select AI model
python3 scripts/ai_modules.py --detect-hardware
```

---

## Configuration

```env
HIBP_API_KEY=your_hibp_key
DEHASHED_API_KEY=your_dehashed_key
DEHASHED_EMAIL=your@email.com
LEAKCHECK_API_KEY=your_leakcheck_key
INTELX_API_KEY=your_intelx_key
SNUSBASE_API_KEY=your_snusbase_key
TELEGRAM_API_ID=your_api_id
TELEGRAM_API_HASH=your_api_hash
TOR_PROXY=socks5://127.0.0.1:9050
HF_TOKEN=your_huggingface_token
HF_CACHE_DIR=./models
```

---

## Usage Examples

```bash
# Full domain recon
python3 scripts/orchestrator.py --target company.com.au --modules all

# Email breach hunt
python3 scripts/orchestrator.py --email user@corp.com.au --modules breach,paste

# PDF batch scan
python3 scripts/pdf_extractor.py --dir /mnt/leaked_docs/ --au-only

# Infostealer logs — date filtered
python3 scripts/infostealer_parser.py --dir /logs/ --start 2024-01-01 --end 2024-12-31 --au-only --bank

# Exploit scan
python3 scripts/orchestrator.py --url https://target.com.au --modules exploit

# Combo market intel
python3 scripts/leaked_db_hunter.py --market

# AI analysis
python3 scripts/ai_modules.py --input reports/findings.json --task summarise --model auto

# Hardware detection
python3 scripts/ai_modules.py --detect-hardware
```

---

## AI Module — HuggingFace Integration

Runs fully local — no data leaves the machine. Prioritises uncensored models.

```bash
python3 scripts/ai_modules.py --detect-hardware
```

### RAM Tiers
| Available RAM | Tier | Recommended Models |
|--------------|------|-------------------|
| < 4 GB | MINIMAL | Phi-3-mini (Q4), TinyLlama |
| 4–8 GB | LOW | Mistral-7B (Q4), OpenHermes-7B (Q4) |
| 8–16 GB | MEDIUM | Mistral-7B (Q8), LLaMA-3-8B, Dolphin-7B |
| 16–32 GB | HIGH | Mixtral-8x7B (Q4), WizardLM-13B |
| 32–64 GB | VERY HIGH | LLaMA-3-70B (Q4), Dolphin-70B (Q4) |
| 64 GB+ | EXTREME | Full precision 70B, Mixtral-8x22B |

---

## API Keys Reference

| Variable | Service | Free Tier |
|----------|---------|----------|
| `HIBP_API_KEY` | Have I Been Pwned | No |
| `DEHASHED_API_KEY` | DeHashed | No |
| `LEAKCHECK_API_KEY` | LeakCheck | Limited |
| `INTELX_API_KEY` | Intelligence X | Limited |
| `SNUSBASE_API_KEY` | Snusbase | No |
| `TELEGRAM_API_ID/HASH` | Telegram MTProto | Free |
| `HF_TOKEN` | HuggingFace | Free |

---

*Aegis-OSINT-AI — Australian threat intelligence platform.*