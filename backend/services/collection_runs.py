"""Persistence service for passive collection run tracking."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.collection_run import CollectionRun


class CollectionRunService:
    """CRUD operations for process-local background collection run status."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create_run(
        self,
        *,
        run_scope: str,
        target: str | None = None,
        target_type: str | None = None,
        investigation_id: UUID | None = None,
        target_id: UUID | None = None,
        plugin_name: str | None = None,
        priority: int = 100,
        config: dict[str, Any] | None = None,
        enrich: bool = False,
    ) -> CollectionRun:
        run = CollectionRun(
            run_scope=run_scope,
            target=target,
            target_type=target_type,
            investigation_id=investigation_id,
            target_id=target_id,
            plugin_name=plugin_name,
            status="queued",
            priority=priority,
            config_json=config or {},
            result_json={},
            error_json={},
            enrich=enrich,
            persisted_count=0,
        )
        self.session.add(run)
        await self.session.commit()
        await self.session.refresh(run)
        return run

    async def get_run(self, run_id: UUID) -> CollectionRun | None:
        return await self.session.get(CollectionRun, run_id)

    async def mark_running(self, run_id: UUID) -> CollectionRun | None:
        run = await self.get_run(run_id)
        if run is None:
            return None
        run.status = "running"
        run.started_at = datetime.now(UTC)
        await self.session.commit()
        await self.session.refresh(run)
        return run

    async def mark_completed(
        self,
        run_id: UUID,
        *,
        result: dict[str, Any],
        persisted_count: int,
    ) -> CollectionRun | None:
        run = await self.get_run(run_id)
        if run is None:
            return None
        run.status = "completed"
        run.result_json = result
        run.error_json = {}
        run.persisted_count = persisted_count
        run.completed_at = datetime.now(UTC)
        await self.session.commit()
        await self.session.refresh(run)
        return run

    async def mark_failed(self, run_id: UUID, *, error: dict[str, Any]) -> CollectionRun | None:
        run = await self.get_run(run_id)
        if run is None:
            return None
        run.status = "failed"
        run.error_json = error
        run.completed_at = datetime.now(UTC)
        await self.session.commit()
        await self.session.refresh(run)
        return run
