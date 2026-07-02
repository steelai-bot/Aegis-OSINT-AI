"""Health and readiness endpoints."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends

from backend.api.security import require_health_auth
from backend.core.config import Settings, get_settings

router = APIRouter(tags=["system"])


@router.get("/health", dependencies=[Depends(require_health_auth)])
async def health(settings: Settings = Depends(get_settings)) -> dict[str, Any]:
    """Health check endpoint with service status."""
    return {
        "status": "ok",
        "service": settings.app_name,
        "environment": settings.environment,
        "timestamp": datetime.now(UTC).isoformat(),
        "services": {
            "database": "ok",
        },
    }


@router.get("/metrics", dependencies=[Depends(require_health_auth)])
async def metrics() -> dict[str, Any]:
    """Basic metrics endpoint for monitoring."""
    return {
        "status": "ok",
        "metrics": {
            "requests_total": 0,
            "events_buffered": 0,
            "active_investigations": 0,
        },
    }