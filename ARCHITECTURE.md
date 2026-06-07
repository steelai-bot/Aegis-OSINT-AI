# Aegis v2 Architecture

Aegis v2 is a production-grade OSINT Investigation Framework built around clear service boundaries, asynchronous execution, persistent evidence storage, and configurable integrations. The migration intentionally does **not** preserve the legacy monolithic script architecture.

## Target Runtime

- Python 3.12+
- Kali Linux 2026.1+ supported for operator workstations
- FastAPI and Uvicorn
- PostgreSQL with SQLAlchemy 2.x async sessions
- Alembic migrations
- Pydantic v2 settings and schemas
- httpx for async HTTP integrations
- pgvector for embeddings
- Docker-based deployment
- Next.js 16, TypeScript, Tailwind, and shadcn/ui for the frontend

## Repository Layout

```text
backend/
├── api/          # FastAPI app, routers, schemas, OpenAPI surface
├── core/         # configuration, logging, HTTP client, event bus, security primitives
├── agents/       # independent investigation agents
├── plugins/      # auto-discovered OSINT integrations
├── providers/    # LLM provider abstraction and concrete implementations
├── scanners/     # passive scanners and reusable collection utilities
├── reports/      # report renderers and templates
├── storage/      # database engine/session lifecycle and persistence helpers
├── models/       # SQLAlchemy domain models
├── services/     # application workflows and orchestration
├── workers/      # background execution entrypoints
└── tests/        # unit, integration, and API tests

frontend/
├── src/app/        # Next.js App Router pages
├── src/components/ # reusable UI components
└── src/lib/        # API clients, sample data, utilities, TypeScript contracts

Dockerfile and compose support live in `backend/`, `frontend/`, and `docker-compose.yml`
docs/             # technical documentation and operator guides
legacy/quarantine/ # pre-v2 modules retained only for extraction review
```

## Architectural Boundaries

### API Layer

The API layer exposes investigation, target, finding, report, agent-run, passive
collection, health, and metrics endpoints. It validates requests with Pydantic
schemas and delegates business workflows to services. It does not call plugins or
LLM providers directly; passive collection endpoints delegate through the
collection orchestration service boundary.

### Services

Services coordinate persistence, agent execution, passive collection, report
generation, and graph correlation. Services own transaction boundaries and
application workflows.

`CollectionOrchestrator` runs approved passive collectors, normalizes plugin
results, optionally enriches and scores findings, deduplicates evidence, and
persists findings when an investigation context is provided. Collection workflows
can run ad hoc without persistence or against existing targets/investigations
with persistence after the required finding metadata migration is applied.

Collection endpoints also support `async_mode` using FastAPI background tasks and
a persisted `collection_runs` status table. This is an in-process MVP execution
model for operator visibility, not a durable distributed queue. The architecture
keeps this replaceable with the existing `workers/` boundary, Redis, PostgreSQL
LISTEN/NOTIFY, or another message broker when explicitly approved.

### Agents

Agents are independent task processors. Agents must communicate only through:

1. investigation context,
2. persisted task results and findings,
3. the event bus.

Agents must never call other agents directly. The investigation engine decides the workflow order.

Initial agents:

- `ReconAgent`
- `DomainAgent`
- `EmailAgent`
- `SocialAgent`
- `BreachAgent`
- `ThreatIntelAgent`
- `ReportAgent`

### Plugins

Plugins encapsulate external OSINT integrations. They are auto-discovered from
`backend/plugins/`, enabled or disabled by configuration, and return normalized
findings. Provider API keys are read from environment variables only.

Initial plugins:

- WHOIS
- DNS
- crt.sh
- Shodan
- VirusTotal
- SecurityTrails
- HaveIBeenPwned

Additional passive collection plugins support defensive threat-intelligence,
brand/domain monitoring, phishing infrastructure detection, and authorized public
source monitoring:

- `certstream_monitor`
- `s3_scanner`
- `ransomware_blog_scraper`
- `telegram_channel_monitor`

Plugins must remain passive and must not perform exploitation, credential replay,
payload execution, phishing operations, browser fingerprint cloning, or session
hijacking.

### Tool Execution Layer
The Tool Execution Layer in `backend/services/tool_execution.py` is the single
policy gate before plugins/tools are invoked. It enforces runtime modes,
per-plugin execution modes, approval tokens, scoped approval metadata, and a
process-local rate limit before orchestration can call a plugin. Persistent
approval records live in `tool_execution_approvals` and are managed through
`POST/GET/DELETE /tool-execution/approvals`; only token hashes and target hashes
are stored. Decisions and outcomes are written as sanitized `tool.execution.*`
audit events when an audit DB session is available, and operators can review
that trail through `GET /audit/events` or the frontend `/tool-execution` page.

The default runtime mode is `passive`. Future active, crawl, or offensive-adjacent
capabilities should not be removed from the roadmap; they must be gated by stricter
modes, explicit operator approval, scoped authorization notes, audit logs, rate
limits, and operator control.

### Providers

LLM provider-specific code is isolated behind `BaseLLMProvider`. Provider selection is configuration-driven. No agent, service, or API route should import a vendor SDK directly.

Initial providers:

- OpenAI
- Anthropic
- Gemini
- Hugging Face Inference Providers
- Ollama

### Storage

PostgreSQL is the production database. SQLAlchemy async sessions are used by services and repositories. Alembic owns schema migration. Embeddings use pgvector.

### Event Bus

The event bus publishes lifecycle and investigation events such as:

- `workflow.started`
- `workflow.step.ready`
- `workflow.step.completed`
- `workflow.completed`
- `agent.started`
- `agent.completed`
- `collection.started`
- `collection.completed`
- `finding.created`
- `report.created`

The investigation engine dispatches agents through ordered workflow steps and publishes step events before and after each agent run. Agents still communicate only through persisted context, findings, and events; direct agent-to-agent calls remain prohibited. The first implementation is in-process and async; it is intentionally replaceable with Redis, PostgreSQL LISTEN/NOTIFY, or a message broker later.

### Kali Tool Compatibility

Kali-specific tooling is described by `backend/core/kali_tools.py` and checked
by `scripts/kali_compatibility.py`. The registry tracks the recent Kali 2026.1
and 2025.4 additions requested for operator workstations, but it is not an
autonomous execution layer. Tools with exploitation, post-exploitation,
credential access, or autonomous MCP behavior remain disabled by default and
require explicit human approval outside the normal OSINT pipeline.

## Legacy Isolation Policy

Legacy offensive workflows are not part of Aegis v2. Session hijacking, credential replay, browser fingerprint cloning, exploit payload execution, banking-target-specific workflows, hardcoded targets, and offensive exploitation modules must be removed or isolated from the runnable v2 application. Files under `legacy/quarantine/` are migration inventory only and must not be imported by `backend/`, exposed by API routes, or referenced by setup quick-start paths. Passive OSINT parsing or normalization code may be extracted only after review.
