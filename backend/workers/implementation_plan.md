# Implementation Plan

Add a durable distributed worker/queue for long-running investigation-wide passive collection, replacing the current in-process `BackgroundTasks` approach.

## [Overview]

Replace the current in-process `BackgroundTasks`-based collection queue with a Redis-backed durable queue (`arq`) and a separate long-lived worker process. The change keeps the existing FastAPI routes, schemas, and `CollectionRunService` untouched, adds a Redis service to the Docker stack, and introduces a new worker entrypoint that reads jobs from Redis, executes them using the existing `CollectionOrchestrator`, and persists results via the existing `CollectionRunService`.

Currently when `POST /collections/run?async_mode=true` is called, the route schedules execution via `BackgroundTasks.add_task(...)`. If the API process dies, the queued run is lost. Queue items are not visible, not retriable, and not distributable. By moving the queue to Redis/`arq`, we gain: persistence across restarts, retry logic, visibility into queue depth, and multi-worker support.

## [Types]

No new Pydantic models. No new SQLAlchemy models. No new API schemas.

The existing `CollectionRunRequest` and `CollectionWorkflowRunRequest` are already serializable using `.model_dump(mode="json")` and can be enqueued as JSON.

A new configuration group will be added to `backend/core/config.py`:

```python
# Arq/Redis
redis_url: str = "redis://localhost:6379/0"
arq_job_timeout_seconds: int = 600
arq_max_retries: int = 3
```

## [Files]

Single sentence: Three new files and edits to four existing files.

**New files:**
1. `backend/workers/collection_worker.py` — The `arq` worker definition (async function `run_collection_job_worker(ctx, run_id, payload_dict)`) and the CLI entrypoint (`poll_queue`) that starts the `arq.Worker`. The function deserializes the payload, opens a DB session, calls `CollectionRunService` to mark running, runs `collection_workflows.run_collection_job`, and marks completed/failed.
2. `backend/workers/__init__.py` — Make the workers dir importable.
3. `backend/requirements.worker.txt` — Worker-only dependencies: `arq>=0.26.0`, `redis>=5.0.0`.

**Existing files to modify:**
4. `docker-compose.yml` — Add `redis` service and `worker` service (depends on db + redis, build from same Dockerfile, entrypoint runs the worker poll command).
5. `backend/requirements.txt` or `backend/requirements.runtime.txt` — Add `arq>=0.26.0`, `redis>=5.0.0`.
6. `backend/core/config.py` — Add Redis/arq settings group.
7. `backend/services/collection_workflows.py` — Change `queue_collection_run`, `queue_investigation_collection_run` to enqueue via `arq` Redis pool instead of `background_tasks.add_task()`. Or alternatively keep both paths (legacy in-process + arq) behind a feature flag. **Approach chosen:** add a new async helper `enqueue_collection_run_via_arq` and a `AEGIS_QUEUE_BACKEND` setting (`in_process` vs `arq`). Default stays `in_process` so existing behavior is preserved. When set to `arq`, enqueue via Redis.
8. `backend/api/routes/collections.py` — The `background_tasks` parameter in route signatures can remain; the queue helpers no longer use it when `AEGIS_QUEUE_BACKEND=arq`.
9. `backend/Dockerfile` — Ensure the Dockerfile copies the workers directory and installs the additional requirements.

## [Functions]

Single sentence: One new worker function, one new queue enqueue helper, and modifications to two existing queue helper functions.

**New functions:**
- `backend/workers/collection_worker.py`: `async def run_collection_job_worker(ctx, run_id: str, payload_dict: dict) -> None` — the arq job function. Opens session, deserializes `payload_dict` into `CollectionRunRequest`, marks run running, calls `run_collection_job`, marks completed/failed.
- `backend/workers/collection_worker.py`: `async def poll_queue() -> None` — CLI entrypoint. Creates `arq.Worker`, runs it forever.
- `backend/services/collection_workflows.py`: `async def enqueue_collection_run_via_arq(payload_dict, arq_pool) -> str` — pushes job to arq, returns job ID.

**Modified functions:**
- `backend/services/collection_workflows.py`: `queue_collection_run` — add conditional: if `settings.queue_backend == "arq"`, create arq pool, enqueue, close pool; else fall through to existing `background_tasks.add_task`.
- `backend/services/collection_workflows.py`: `queue_investigation_collection_run` — same conditional pattern.

## [Classes]

No new classes. The existing `CollectionOrchestrator`, `CollectionRunService`, and `CollectionRun` model remain unchanged.

## [Dependencies]

Single sentence: Add `arq>=0.26.0` and `redis>=5.0.0` to runtime requirements, and add a Redis container to Docker Compose.

- `backend/requirements.runtime.txt`: add `arq>=0.26.0` and `redis>=5.0.0`
- `docker-compose.yml`: add `redis: { image: redis:7-alpine, ports: ["6379:6379"] }` and a `worker` service

## [Testing]

Single sentence: One new integration test verifying end-to-end queue/worker flow, plus a unit test for the arq pool helper.

- `backend/tests/test_workers.py`: 
  1. `test_queue_and_process_collection_run_via_arq` — creates a CollectionRunRequest, enqueues via arq pool (mock Redis), verifies run is persisted and status is not "queued" after "worker" marks it.
  2. `test_worker_executes_failed_collection` — simulate exception, verify run is marked "failed".
- For CI without Redis, the tests can mock `arq.connections.ArqRedis` using `unittest.mock.patch`.

## [Implementation Order]

Single sentence: Add Redis config, add dependencies, write the worker, modify the queue helpers, update Docker Compose, and finally write tests.

1. Add Redis/arq settings to `backend/core/config.py`
2. Add `arq` and `redis` to `backend/requirements.runtime.txt`
3. Create `backend/workers/__init__.py` (empty)
4. Create `backend/workers/collection_worker.py` with job function + CLI
5. Modify `backend/services/collection_workflows.py` — add arq enqueue path + settings check
6. Update `docker-compose.yml` — add redis + worker services
7. Update `backend/Dockerfile` if needed for workers
8. Write tests in `backend/tests/test_workers.py`
9. Run full test suite to verify nothing is broken
10. Commit and push