"""FastAPI application factory for Aegis v2."""

from fastapi import FastAPI

from backend.api.routes import agents, collections, findings, health, investigations, reports, targets
from backend.core.config import get_settings


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        description="Aegis v2 OSINT Investigation Framework API",
        debug=settings.debug,
    )
    app.include_router(health.router, prefix=settings.api_prefix)
    for router in (
        investigations.router,
        targets.router,
        findings.router,
        collections.router,
        reports.router,
        agents.router,
    ):
        app.include_router(router, prefix=settings.api_prefix)
    return app


app = create_app()
