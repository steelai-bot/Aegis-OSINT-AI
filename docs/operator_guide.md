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
  -H "Content-Type: application/json" \
  -d "{\"title\":\"Authorized domain review\"}"
```

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
- Treat findings as unverified until an operator reviews source, timestamp,
  confidence, and legal handling restrictions.
- Keep provider keys scoped to the minimum permissions required.
