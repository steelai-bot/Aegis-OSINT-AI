"""arq-based durable background worker for collection runs.

This module provides:
* ``run_collection_job_worker`` — the arq job function that executes a single
  collection run in the worker process.
* ``poll_queue`` — a CLI entrypoint that starts the arq worker so the
  ``docker-compose worker`` service can run ``python -m ... poll_queue``.
"""

from __future__ import annotations

import asyncio
import logging
from uuid import UUID

import arq
from arq.connections import ArqRedis, create_pool

from backend.core.config import get_settings
from backend.services.collection_workflows import (
    execute_collection_run_background,
    execute_investigation_collection_background,
)
from backend.services.collection_runs import CollectionRunService
from backend.storage.database import AsyncSessionLocal

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# arq job functions
# ---------------------------------------------------------------------------

async def run_collection_job_worker(ctx: dict, run_id: str, payload_dict: dict) -> None:
    """Execute a single collection run inside the arq worker.

    Parameters
    ----------
    ctx :
        arq worker context (not used directly).
    run_id :
        UUID of the ``CollectionRun`` row to process.
    payload_dict :
        Serialised ``CollectionRunRequest`` fields.
    """
    async with AsyncSessionLocal() as session:
        service = CollectionRunService(session)
        await service.mark_running(UUID(run_id))
        try:
            # Reuse the existing background helper — it opens its own session
            # and calls run_collection_job internally.
            from backend.api.schemas.collections import CollectionRunRequest

            payload = CollectionRunRequest(**payload_dict)
            await execute_collection_run_background(UUID(run_id), payload)
        except Exception as exc:
            logger.exception("Worker failed for run %s", run_id)
            await session.rollback()
            await service.mark_failed(UUID(run_id), error={"message": str(exc)})


async def run_investigation_job_worker(ctx: dict, run_id: str, investigation_id: str, payload_dict: dict) -> None:
    """Execute an investigation-wide collection run inside the arq worker.

    Parameters
    ----------
    ctx :
        arq worker context (not used directly).
    run_id :
        UUID of the ``CollectionRun`` row to process.
    investigation_id :
        UUID of the investigation whose targets should be collected.
    payload_dict :
        Serialised ``CollectionWorkflowRunRequest`` fields.
    """
    async with AsyncSessionLocal() as session:
        service = CollectionRunService(session)
        await service.mark_running(UUID(run_id))
        try:
            from backend.api.schemas.collections import CollectionWorkflowRunRequest

            payload = CollectionWorkflowRunRequest(**payload_dict)
            await execute_investigation_collection_background(
                UUID(run_id), UUID(investigation_id), payload,
            )
        except Exception as exc:
            logger.exception("Investigation worker failed for run %s", run_id)
            await session.rollback()
            await service.mark_failed(UUID(run_id), error={"message": str(exc)})


# ---------------------------------------------------------------------------
# arq WorkerSettings
# ---------------------------------------------------------------------------

class WorkerSettings:
    """Settings object that arq uses to configure the worker."""

    functions: list = [run_collection_job_worker, run_investigation_job_worker]
    redis_settings: arq.connections.RedisSettings | None = None

    @classmethod
    def from_settings(cls) -> type[WorkerSettings]:
        """Build a ``WorkerSettings`` class configured from the application settings."""
        s = get_settings()
        cls.redis_settings = arq.connections.RedisSettings.from_dsn(s.redis_url)
        cls.job_timeout = s.arq_job_timeout_seconds
        cls.max_retries = s.arq_max_retries
        cls.keep_result = 3600  # keep results for 1 hour
        cls.keep_result_failed = 86400  # keep failed results for 24 hours
        return cls


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

async def _run_worker_forever() -> None:
    """Start the arq worker and run until interrupted."""
    settings = WorkerSettings.from_settings()
    worker = arq.Worker(
        functions=settings.functions,
        redis_settings=settings.redis_settings,
        job_timeout=settings.job_timeout,  # type: ignore[attr-defined]
        max_retries=settings.max_retries,  # type: ignore[attr-defined]
        keep_result=settings.keep_result,  # type: ignore[attr-defined]
        keep_result_failed=settings.keep_result_failed,  # type: ignore[attr-defined]
    )
    logger.info("Starting arq worker …")
    await worker.main()


def poll_queue() -> None:
    """CLI entrypoint: ``python -m backend.workers.collection_worker poll_queue``."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    asyncio.run(_run_worker_forever())


# ---------------------------------------------------------------------------
# Enqueue helper (used by collection_workflows.py)
# ---------------------------------------------------------------------------

async def enqueue_collection_run_via_arq(
    run_id: str,
    payload_dict: dict,
    *,
    investigation_id: str | None = None,
) -> str | None:
    """Push a collection run job into the arq Redis queue.

    Parameters
    ----------
    run_id :
        UUID string of the persisted ``CollectionRun`` row.
    payload_dict :
        Serialised request payload.
    investigation_id :
        If set, enqueue the investigation-wide job variant.

    Returns
    -------
    The arq job ID, or ``None`` if enqueueing failed.
    """
    settings = get_settings()
    pool: ArqRedis | None = None
    try:
        pool = await create_pool(arq.connections.RedisSettings.from_dsn(settings.redis_url))
        if investigation_id:
            job = await pool.enqueue_job(
                "run_investigation_job_worker",
                run_id,
                investigation_id,
                payload_dict,
                _job_timeout_seconds=settings.arq_job_timeout_seconds,
            )
        else:
            job = await pool.enqueue_job(
                "run_collection_job_worker",
                run_id,
                payload_dict,
                _job_timeout_seconds=settings.arq_job_timeout_seconds,
            )
        return job.job_id if job else None
    except Exception:
        logger.exception("Failed to enqueue run %s via arq", run_id)
        return None
    finally:
        if pool is not None:
            await pool.close()