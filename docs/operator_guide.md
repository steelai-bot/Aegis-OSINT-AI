# Operator Guide

This guide covers local operation for Aegis v2. It assumes authorized,
defensive OSINT work only.

## Local Backend

Recommended local setup:

```bash
python scripts/dev_lifecycle.py setup
python scripts/dev_lifecycle.py start
python scripts/dev_lifecycle.py status
```

Stop only the lifecycle-managed backend and frontend processes:

```bash
python scripts/dev_lifecycle.py stop
```

The lifecycle helper creates `.venv`, installs backend runtime dependencies,
installs frontend dependencies, creates safe local env defaults, and stores
process state in `.aegis/devserver.json`.

Manual backend setup remains available:

1. Create a Python 3.12 virtual environment.
2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Set required runtime configuration:

   ```bash
   AEGIS_API_PREFIX=/api/v1
   AEGIS_DATABASE_URL=postgresql+asyncpg://aegis:aegis@localhost:5432/aegis
   AEGIS_LLM_PROVIDER=disabled
   ```

4. Run migrations:

   ```bash
   alembic upgrade head
   ```

5. Start the API:

   ```bash
   uvicorn backend.api.app:app --reload --host 0.0.0.0 --port 8000
   ```

Health checks:

```bash
curl http://localhost:8000/api/v1/health
curl http://localhost:8000/api/v1/metrics
```

## Optional Backend API Authentication

Backend API authentication is disabled by default for local MVP development and
single-operator demos. To require bearer-token authentication for protected API
endpoints, set runtime environment variables before starting the backend:

```bash
AEGIS_AUTH_ENABLED=true
AEGIS_API_AUTH_TOKEN=<set-a-long-random-token-outside-source-control>
```

When authentication is enabled, direct API clients must send the token in the
`Authorization` header:

```bash
curl http://localhost:8000/api/v1/investigations \
  -H "Authorization: Bearer <TOKEN>"
```

`<TOKEN>` is a placeholder. Do not paste real bearer tokens into source files,
commits, screenshots, tickets, or shared logs.

Health checks remain public by default so local and deployment probes continue to
work. To require authentication for `/health` as well, set:

```bash
AEGIS_AUTH_ALLOW_UNAUTHENTICATED_HEALTH=false
```

`/metrics` is protected when backend authentication is enabled:

```bash
curl http://localhost:8000/api/v1/metrics \
  -H "Authorization: Bearer <TOKEN>"
```

Do not expose the backend bearer token through `NEXT_PUBLIC_*` frontend
variables. Values with that prefix are visible in browser-delivered JavaScript.
If the frontend must access an authenticated backend later, add a server-side
proxy or a real browser login flow first.

## Local Frontend

The lifecycle helper starts the frontend automatically. Manual frontend setup:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:3000`.

Optional frontend configuration:

```bash
NEXT_PUBLIC_AEGIS_API_URL=http://localhost:8000
NEXT_PUBLIC_AEGIS_WS_URL=ws://localhost:8000/api/v1/events
```

The frontend renders sample data when the backend URL is not configured or the
backend is unavailable.

## Docker Stack

Use Docker Compose for a local API, frontend, and PostgreSQL pgvector database:

```bash
docker compose up --build
```

Services:

- Frontend: `http://localhost:3000`
- Backend: `http://localhost:8000/api/v1`
- PostgreSQL: `localhost:5432`

Run migrations after the backend image is available:

```bash
docker compose run --rm backend alembic upgrade head
```

The compose file uses development credentials for PostgreSQL. Change them
before any shared or persistent deployment.

## API Workflow

Create an investigation:

```bash
curl -X POST http://localhost:8000/api/v1/investigations \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d "{\"title\":\"Authorized domain review\"}"
```

Omit the `Authorization` header only when backend API authentication is disabled.
When auth is enabled, include `-H "Authorization: Bearer <TOKEN>"` on protected
investigation, target, finding, report, collection, and agent requests.

Create a target:

```bash
curl -X POST http://localhost:8000/api/v1/targets \
  -H "Content-Type: application/json" \
  -d "{\"investigation_id\":\"INVESTIGATION_ID\",\"type\":\"domain\",\"value\":\"example.com\"}"
```

Run agents:

```bash
curl -X POST http://localhost:8000/api/v1/agents/run \
  -H "Content-Type: application/json" \
  -d "{\"investigation_id\":\"INVESTIGATION_ID\",\"target\":\"example.com\",\"target_type\":\"domain\"}"
```

Run passive collection for one ad-hoc target without persistence:

```bash
curl -X POST http://localhost:8000/api/v1/collections/run \
  -H "Content-Type: application/json" \
  -d "{\"target\":\"example.com\",\"target_type\":\"domain\",\"plugin_name\":\"crtsh\"}"
```

Queue the same collection workflow in the current API process and poll run
status:

```bash
curl -X POST http://localhost:8000/api/v1/collections/run \
  -H "Content-Type: application/json" \
  -d "{\"target\":\"example.com\",\"target_type\":\"domain\",\"plugin_name\":\"crtsh\",\"async_mode\":true}"

curl http://localhost:8000/api/v1/collections/runs/RUN_ID
```

`async_mode` uses FastAPI background tasks as an in-process MVP queue. It is not
a durable distributed worker; if the API process restarts, queued or running work
may stop. The persisted run status remains available for operator review.

Run passive collection for an existing target and persist findings to its
investigation:

```bash
curl -X POST http://localhost:8000/api/v1/targets/TARGET_ID/collect \
  -H "Content-Type: application/json" \
  -d "{\"plugin_name\":\"crtsh\",\"enrich\":false,\"async_mode\":true}"
```

Run passive collection for every target in an investigation:

```bash
curl -X POST http://localhost:8000/api/v1/investigations/INVESTIGATION_ID/collect \
  -H "Content-Type: application/json" \
  -d "{\"plugin_name\":\"certstream_monitor\",\"enrich\":false,\"async_mode\":true}"
```

When `plugin_name` is omitted, collection runs all enabled passive plugins that
support the target type. If `plugin_name` is set, `config` is passed only to that
plugin. If `plugin_name` is omitted, `config` should be a mapping of plugin name
to plugin-specific config object.

Example request-scoped plugin configuration for configured public sources:

```bash
curl -X POST http://localhost:8000/api/v1/collections/run \
  -H "Content-Type: application/json" \
  -d "{\"target\":\"Example Brand\",\"target_type\":\"keyword\",\"plugin_name\":\"ransomware_blog_scraper\",\"config\":{\"sources\":[\"https://authorized-public-source.example/leaks\"]}}"
```

Example request-scoped S3 bucket candidates:

```bash
curl -X POST http://localhost:8000/api/v1/collections/run \
  -H "Content-Type: application/json" \
  -d "{\"target\":\"example.com\",\"target_type\":\"domain\",\"plugin_name\":\"s3_scanner\",\"config\":{\"bucket_names\":[\"example-assets\",\"example-logs\"]}}"
```

Example request-scoped Telegram public-channel metadata check. Prefer setting
the bot token through runtime environment/configuration rather than placing it
in request logs; `config.channels` should only include authorized public
channels:

```bash
curl -X POST http://localhost:8000/api/v1/collections/run \
  -H "Content-Type: application/json" \
  -d "{\"target\":\"Example Brand\",\"target_type\":\"keyword\",\"plugin_name\":\"telegram_channel_monitor\",\"config\":{\"channels\":[\"@authorized_public_channel\"]}}"
```

Do not commit provider keys or paste real secrets into tickets, source files, or
shared logs. Runtime collection persistence requires the current database schema
to include the threat-intelligence finding metadata columns. Background run
tracking also requires the `collection_runs` table from migration `0004`.

Render a report:

```bash
curl -X POST http://localhost:8000/api/v1/investigations/INVESTIGATION_ID/reports/render \
  -H "Content-Type: application/json" \
  -d "{\"format\":\"markdown\"}"
```

## Operating Rules

- Confirm authorization before adding targets.
- Prefer passive sources and API-backed enrichment.
- Do not run quarantined legacy modules.
- Do not paste secrets into source files, reports, screenshots, or tickets.
- Keep backend bearer tokens environment-backed and out of browser-visible
  frontend configuration.
- Treat findings as unverified until an operator reviews source, timestamp,
  confidence, and legal handling restrictions.
- Keep provider keys scoped to the minimum permissions required.
