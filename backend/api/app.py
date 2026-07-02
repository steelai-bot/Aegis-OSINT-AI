"""FastAPI application factory for Aegis v2."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from backend.api.routes import (
    agents,
    audit,
    auth,
    collections,
    findings,
    health,
    investigations,
    reports,
    targets,
    tool_execution_approvals,
)
from backend.api.routes.enrichment import router as enrichment_router
from backend.api.routes.oauth import router as oauth_router
from backend.api.routes.report_export import router as report_export_router
from backend.api.routes.worker_monitor import router as worker_monitor_router
from backend.core.config import get_settings
from backend.services.api_rate_limiter import APIRateLimiterMiddleware


@asynccontextmanager
async def _lifespan(app: FastAPI):
    """Initialize database tables and seed a default admin account on startup."""
    from backend.models.base import Base
    from backend.services.auth import AuthService
    from backend.storage.database import AsyncSessionLocal, engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Seed default admin — credentials are read from env so they can be
    # overridden in production without touching source code.
    default_email = os.environ.get("AEGIS_SEED_ADMIN_EMAIL", "root@aegis.local")
    default_password = os.environ.get("AEGIS_SEED_ADMIN_PASSWORD", "12345678r")
    default_name = os.environ.get("AEGIS_SEED_ADMIN_NAME", "root")

    async with AsyncSessionLocal() as session:
        svc = AuthService(session)
        if await svc.get_user_by_email(default_email) is None:
            await svc.create_user(
                email=default_email,
                password=default_password,
                display_name=default_name,
                role="admin",
            )

    yield  # application runs here


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        description="Aegis v2 OSINT Investigation Framework API",
        debug=settings.debug,
        lifespan=_lifespan,
    )

    app.add_middleware(APIRateLimiterMiddleware, requests_per_minute=settings.api_rate_limit_per_minute)

    # Health check is registered first so it takes priority in docs ordering
    app.include_router(health.router, prefix=settings.api_prefix)

    for router in (
        auth.router,
        oauth_router,
        investigations.router,
        targets.router,
        findings.router,
        collections.router,
        audit.router,
        tool_execution_approvals.router,
        reports.router,
        agents.router,
        enrichment_router,
        report_export_router,
        worker_monitor_router,
    ):
        app.include_router(router, prefix=settings.api_prefix)

    return app


app = create_app()