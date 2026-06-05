# Aegis v2 Architecture

Aegis v2 is a production-grade OSINT Investigation Framework built around clear service boundaries, asynchronous execution, persistent evidence storage, and configurable integrations. The migration intentionally does **not** preserve the legacy monolithic script architecture.

## Target Runtime

- Python 3.12+
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
├── app/          # Next.js routes and pages
├── components/   # reusable UI components
├── lib/          # API clients, utilities, websocket clients
└── types/        # shared TypeScript contracts

docker/           # deployment manifests and container support
docs/             # technical documentation and operator guides
```

## Architectural Boundaries

### API Layer

The API layer exposes investigation, target, finding, report, agent-run, health, and metrics endpoints. It validates requests with Pydantic schemas and delegates business workflows to services. It does not call plugins or LLM providers directly.

### Services

Services coordinate persistence, agent execution, report generation, and graph correlation. Services own transaction boundaries and application workflows.

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

Plugins encapsulate external OSINT integrations. They are auto-discovered from `backend/plugins/`, enabled or disabled by configuration, and return normalized findings. Provider API keys are read from environment variables only.

Initial plugins:

- WHOIS
- DNS
- crt.sh
- Shodan
- VirusTotal
- SecurityTrails
- HaveIBeenPwned

### Providers

LLM provider-specific code is isolated behind `BaseLLMProvider`. Provider selection is configuration-driven. No agent, service, or API route should import a vendor SDK directly.

Initial providers:

- OpenAI
- Anthropic
- Gemini
- Ollama

### Storage

PostgreSQL is the production database. SQLAlchemy async sessions are used by services and repositories. Alembic owns schema migration. Embeddings use pgvector.

### Event Bus

The event bus publishes lifecycle and investigation events such as:

- `agent.started`
- `agent.completed`
- `finding.created`
- `report.created`

The first implementation is in-process and async; it is intentionally replaceable with Redis, PostgreSQL LISTEN/NOTIFY, or a message broker later.

## Legacy Isolation Policy

Legacy offensive workflows are not part of Aegis v2. Session hijacking, credential replay, browser fingerprint cloning, exploit payload execution, banking-target-specific workflows, hardcoded targets, and offensive exploitation modules must be removed or isolated from the runnable v2 application. Passive OSINT parsing or normalization code may be extracted only after review.
