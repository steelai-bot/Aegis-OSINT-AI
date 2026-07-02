"""Distributed worker monitoring API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from backend.api.security import require_permission
from backend.core.config import get_settings

router = APIRouter(prefix="/workers", tags=["worker-monitor"])


# ── Schemas ────────────────────────────────────────────────────────────────


class WorkerStatus(BaseModel):
    queue_backend: str
    redis_url: str | None = None
    job_timeout_seconds: int
    max_retries: int
    worker_count: int = 0
    queue_depth: int = 0
    active_jobs: int = 0
    failed_jobs: int = 0
    completed_jobs: int = 0
    status: str = "healthy"


class WorkerMetrics(BaseModel):
    total_jobs: int = 0
    successful_jobs: int = 0
    failed_jobs: int = 0
    avg_job_duration_seconds: float = 0
    active_workers: int = 0
    queue_health: str = "healthy"


class WorkerJob(BaseModel):
    job_id: str
    status: str = "unknown"
    created_at: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    duration_seconds: float | None = None
    error_message: str | None = None


class WorkerStatusResponse(BaseModel):
    status: WorkerStatus
    metrics: WorkerMetrics


# ── Routes ─────────────────────────────────────────────────────────────────


@router.get(
    "/status",
    response_model=WorkerStatusResponse,
    dependencies=[Depends(require_permission("agent:run"))],
)
async def worker_status():
    """Return current worker queue status and metrics."""
    settings = get_settings()
    backend = settings.queue_backend
    redis_url = settings.redis_url if backend == "arq" else None

    worker_status_obj = WorkerStatus(
        queue_backend=backend,
        redis_url=redis_url,
        job_timeout_seconds=settings.arq_job_timeout_seconds,
        max_retries=settings.arq_max_retries,
        status="healthy" if backend == "in_process" else "waiting_for_redis",
    )

    metrics = WorkerMetrics()

    return WorkerStatusResponse(status=worker_status_obj, metrics=metrics)


@router.get(
    "/health",
    dependencies=[Depends(require_permission("agent:run"))],
)
async def worker_health():
    """Quick health check for worker infrastructure."""
    settings = get_settings()
    return {
        "queue_backend": settings.queue_backend,
        "status": "healthy",
        "redis_configured": bool(settings.redis_url),
    }