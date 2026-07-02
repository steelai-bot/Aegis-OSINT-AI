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

    @app.on_event("startup")
    async def startup_event():
        """
        Initialize database tables and ensure a default admin user exists.
        """
        from backend.services.auth import AuthService
        from backend.storage.database import AsyncSessionLocal, engine
        from backend.models.base import Base

        # Create tables if they don't exist
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        # Ensure default admin user exists
        async with AsyncSessionLocal() as session:
            auth_service = AuthService(session)
            # Check if a user with email 'root@aegis.local' already exists
            existing = await auth_service.get_user_by_email("root@aegis.local")
            if existing is None:
                await auth_service.create_user(
                    email="root@aegis.local",
                    password="12345678r",
                    display_name="root",
                    role="admin",
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