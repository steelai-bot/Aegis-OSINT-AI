# Aegis v2 - OSINT Investigation Framework

Aegis v2 is a defensive OSINT investigation framework for authorized,
passive evidence collection, investigation workflow tracking, and reporting.
The migration does not preserve the legacy monolithic script runtime.

Offensive exploitation, session replay, credential replay, browser fingerprint
cloning, payload execution, hardcoded target workflows, and banking-specific
automation are excluded from the runnable v2 application.

## Migration Status

The current branch contains the v2 backend foundation, API skeleton,
provider abstraction, initial OSINT plugins, passive collection orchestration,
report renderers, Next.js frontend console, Docker stack, and Kali operator
compatibility checks. See `ARCHITECTURE.md`, `MIGRATION_PLAN.md`, and `TODO.md`
for the phased migration plan.

Legacy modules that conflict with the v2 scope have been moved to
`legacy/quarantine/` for extraction review. They are not imported by the
backend and are not part of the supported runtime.

## Current Runtime

- Python 3.12+
- FastAPI and Uvicorn
- PostgreSQL with SQLAlchemy async sessions
- Alembic migrations
- Pydantic v2 settings and schemas
- httpx for async integrations
- Configurable LLM providers: OpenAI, Anthropic, Gemini, Hugging Face, Ollama
- Passive threat-intelligence collection for authorized targets and investigations
- Next.js 16 frontend console
- Docker Compose stack for local API, frontend, and PostgreSQL pgvector
- Kali Linux 2026.1+ supported for operator workstations

## Backend API

Create the backend app from `backend.api.app:create_app`.

```bash
uvicorn backend.api.app:create_app --factory --reload
```

Implemented route groups:

- `/health`
- `/metrics`
- `/investigations`
- `/targets`
- `/findings`
- `/reports`
- `/agents/run`
- `/collections/run`
- `/targets/{target_id}/collect`
- `/investigations/{investigation_id}/collect`

When the API is run with `AEGIS_API_PREFIX=/api/v1`, these routes are exposed
under `/api/v1`.

Persisted passive collection workflows require the database schema to include the
threat-intelligence finding metadata columns from migration
`0003_finding_threat_intel_metadata`. See `MIGRATION_PLAN.md` for apply,
verification, and rollback guidance before enabling collection persistence in an
environment.

## Frontend

The frontend lives in `frontend/` and uses Next.js 16, TypeScript, Tailwind,
and `lucide-react`.

```bash
cd frontend
npm install
npm run dev
```

Set `NEXT_PUBLIC_AEGIS_API_URL=http://localhost:8000` to connect server-rendered
pages to the backend. Without it, the console renders deterministic sample data.

## Local Lifecycle CLI

Use the lifecycle helper for local setup and dev server management:

```bash
python scripts/dev_lifecycle.py setup
python scripts/dev_lifecycle.py start
python scripts/dev_lifecycle.py status
python scripts/dev_lifecycle.py stop
```

The helper creates `.venv`, installs backend runtime dependencies, installs
frontend dependencies, writes safe local defaults to `.env` and
`frontend/.env.local`, and stores dev server process state in `.aegis/`.
`stop` only terminates the backend and frontend processes that were started by
this helper. It does not kill unrelated localhost processes.

Run diagnostics without starting servers:

```bash
python scripts/dev_lifecycle.py doctor
```

## Docker Compose

Run the local stack:

```bash
docker compose up --build
```

Run migrations:

```bash
docker compose run --rm backend alembic upgrade head
```

Local service URLs:

- Frontend: `http://localhost:3000`
- Backend: `http://localhost:8000/api/v1`
- PostgreSQL: `localhost:5432`

See `docs/operator_guide.md`, `docs/security_model.md`, and
`docs/legacy_migration_notes.md` before shared deployments.

## Reporting

### v2 Render API

The v2 render API can render persisted investigation findings without writing
files:

```http
POST /investigations/{investigation_id}/reports/render
```

Request:

```json
{ "format": "markdown" }
```

Supported render formats are `html`, `json`, `markdown`, `briefing`, and `pdf`. PDF render responses return base64-encoded PDF bytes in `content`. `csv` remains a report record format until its v2 renderer is implemented.

## Kali Linux Compatibility

Aegis v2 is compatible with Kali Linux 2026.1+ for the backend runtime and
operator-guided tool discovery. Run the compatibility check on Kali before an
engagement:

```bash
python3 scripts/kali_compatibility.py
python3 scripts/kali_compatibility.py --json
```

The check covers recent Kali 2026.1 and 2025.4 tool additions. See
`docs/kali_compatibility.md` for the package registry, install command, and
safety policies. Offensive or autonomous tools are detected only and remain
disabled by default in the Aegis OSINT pipeline.

## Configuration

Provider keys are read from environment variables only. Do not commit `.env`
files or paste API keys into source code.

```env
AEGIS_LLM_PROVIDER=openai
AEGIS_OPENAI_API_KEY=sk-...
AEGIS_ANTHROPIC_API_KEY=sk-ant-...
AEGIS_GEMINI_API_KEY=...
AEGIS_HUGGINGFACE_API_KEY=hf_...
AEGIS_OLLAMA_BASE_URL=http://localhost:11434
```

Supported `AEGIS_LLM_PROVIDER` values are `disabled`, `openai`, `anthropic`,
`gemini`, `huggingface`, and `ollama`.

## Setup

Install dependencies with the lifecycle helper:

```bash
python scripts/dev_lifecycle.py setup
```

Or install dependencies manually and run local checks:

```bash
pip install -r requirements.txt
python3 scripts/kali_compatibility.py --json
python3 -m pytest backend/tests
```

Frontend checks:

```bash
cd frontend
npm run lint
npm run build
```

If pytest is not installed, the static architecture tests can be imported
directly by a Python runner as part of the migration workflow.

## Legacy Isolation

The quarantined legacy files are retained only as migration inventory. Safe
logic may be extracted into `backend/` after review, tests, and documentation.
Do not run quarantined files as part of normal v2 operation.
