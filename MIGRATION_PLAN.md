# Aegis v2 Migration Plan

This migration is incremental. Every phase must keep the application runnable and end with tests, documentation updates, and a commit.

## Legacy Inventory

| Legacy area | Current examples | Decision | Notes |
| --- | --- | --- | --- |
| Reporting | `scripts/report_generator.py`, `assets/dashboard_template.html` | Preserve and refactor | Move safe rendering logic to `backend/reports/` and frontend dashboard components. |
| Passive breach intelligence | `scripts/breach_search.py` | Preserve selectively | Keep authorized breach metadata lookups. Do not retain credential replay or password handling. |
| Search APIs | `scripts/api_search_engine.py` | Preserve selectively | Convert API lookups to async plugins/providers with environment-backed keys. |
| Australian public-source OSINT | `scripts/osint_australia.py`, `references/australian_sources.md` | Preserve selectively | Retain public registry lookup patterns where legally appropriate and configurable. |
| PDF and data classification | `scripts/pdf_extractor.py`, `scripts/au_data_classifier.py` | Preserve selectively | Convert to passive evidence extraction services with redaction support. |
| Dark web and Telegram collection | `legacy/quarantine/darkweb_crawler.py`, `legacy/quarantine/telegram_monitor.py` | Isolated pending review | Legal and policy boundaries must be documented before enabling. |
| OAuth helper utilities | `scripts/oauth_manager.py` | Preserve selectively | Keep only generic token lifecycle helpers if needed; never store secrets in code. |
| Offensive exploit scanners | `legacy/quarantine/exploit_scanner.py`, `legacy/quarantine/advanced_exploits.py`, `legacy/quarantine/pre_exploit.py`, `legacy/quarantine/sneaky_recon.py` | Removed from v2 runtime | Not compatible with OSINT-only framework scope. |
| Session and fingerprint tooling | `legacy/quarantine/session_hijacker.py`, `legacy/quarantine/eni_signature.py` | Removed from v2 runtime | Explicitly prohibited by the v2 requirements. |
| Credential dump tooling | `legacy/quarantine/credential_parser.py`, `legacy/quarantine/infostealer_parser.py`, `legacy/quarantine/leaked_db_hunter.py` | Isolated pending review | Do not process credentials for replay. Retain only high-level exposure metadata if legally approved. |
| Pivot/lateral movement mapping | `legacy/quarantine/pivot_chain.py` | Removed from v2 runtime | Offensive workflow semantics conflict with v2 goals. |
| Legacy all-in-one entrypoints | `legacy/quarantine/orchestrator.py`, `legacy/quarantine/tui.py` | Removed from v2 runtime | These entrypoints enabled prohibited modules and must not be used as v2 quick starts. |
| Exploit payload references | `legacy/quarantine/references/exploit_payloads.md` | Removed from v2 runtime/docs | Not part of a defensive OSINT framework. |

## Phase 0 — Planning and Guardrails

1. Add `ARCHITECTURE.md`, `MIGRATION_PLAN.md`, and `TODO.md`.
2. Define legacy isolation rules.
3. Update dependency intent for the v2 stack.
4. Add first runnable backend health surface.

## Phase 1 — Backend Foundation

1. Create `backend/` package structure.
2. Add FastAPI app factory and health/metrics routes.
3. Add Pydantic v2 settings.
4. Add async HTTP client wrapper with timeouts, retries, and TLS verification enabled.
5. Add SQLAlchemy base models and Alembic skeleton.
6. Add basic tests for health and architectural contracts.

## Phase 2 — Persistence and Investigation API

1. Implement PostgreSQL models for investigations, targets, findings, reports, and embeddings.
2. Add Alembic migration with pgvector extension support.
3. Add CRUD services and API schemas.
4. Add API tests for investigations and findings.

## Phase 3 — Agent Framework

1. Implement `BaseAgent` and independent agent classes.
2. Implement event bus integration.
3. Add investigation engine workflow orchestration.
4. Persist task results and findings.

## Phase 4 — Plugin Framework

1. Implement `BasePlugin` and plugin registry auto-discovery.
2. Add WHOIS, DNS, crt.sh, Shodan, VirusTotal, SecurityTrails, and HIBP plugins.
3. Convert safe legacy logic to async plugins.
4. Add plugin configuration tests.

## Phase 5 — AI Provider Layer

1. Implement provider factory.
2. Add OpenAI, Anthropic, Gemini, and Ollama providers.
3. Use provider abstraction for report summaries and finding correlation.

## Phase 6 — Reporting and Correlation

1. Add Markdown, HTML, JSON, and PDF report renderers.
2. Add executive summary generation.
3. Add relationship graph generation for findings.
4. Add report API endpoints.

## Phase 7 — Frontend Dashboard

1. Create Next.js app structure.
2. Add dashboard, investigations, targets, findings, reports, settings, and plugins pages.
3. Add live websocket timeline.
4. Add searchable findings UI.

## Phase 8 — Docker, Security, and Operations

1. Add Dockerfiles and compose stack.
2. Add secrets management documentation.
3. Add RBAC preparation and audit logging.
4. Add deployment and migration documentation.

## Validation Rules

- No API keys, tokens, or credentials in source code.
- No `verify=False` in v2 runtime code.
- No direct agent-to-agent calls.
- No provider-specific logic outside `backend/providers/`.
- Tests must pass after each phase.
