"""FastAPI application factory for Aegis v2."""

from fastapi import FastAPI

from backend.api.routes import agents, audit, auth, collections, findings, health, investigations, reports, targets, tool_execution_approvals
from backend.api.routes.oauth import router as oauth_router
from backend.api.routes.enrichment import router as enrichment_router
from backend.api.routes.report_export import router as report_export_router
from backend.api.routes.worker_monitor import router as worker_monitor_router
from backend.core.config import get_settings
from backend.services.api_rate_limiter import APIRateLimiterMiddleware


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        description="Aegis v2 OSINT Investigation Framework API",
        debug=settings.debug,
    )

    # Rate limiting middleware
    app.add_middleware(APIRateLimiterMiddleware, requests_per_minute=120)

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