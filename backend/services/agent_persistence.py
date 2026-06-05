"""Persistence helpers for agent workflow state."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from backend.agents import AgentResult, InvestigationContext
from backend.models import AgentContextSnapshot, AgentTaskResult


class AgentPersistenceService:
    """Stores investigation context snapshots and per-agent task results."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create_context_snapshot(
        self,
        context: InvestigationContext,
        *,
        status: str = "started",
    ) -> AgentContextSnapshot:
        snapshot = AgentContextSnapshot(
            investigation_id=context.investigation_id,
            target=context.target,
            target_type=context.target_type,
            status=status,
            metadata_json=context.metadata,
            findings_json=context.findings,
        )
        self.session.add(snapshot)
        await self.session.commit()
        await self.session.refresh(snapshot)
        return snapshot

    async def update_context_snapshot(
        self,
        snapshot: AgentContextSnapshot,
        context: InvestigationContext,
        *,
        status: str,
    ) -> AgentContextSnapshot:
        snapshot.status = status
        snapshot.metadata_json = context.metadata
        snapshot.findings_json = context.findings
        await self.session.commit()
        await self.session.refresh(snapshot)
        return snapshot

    async def create_task_result(
        self,
        result: AgentResult,
        *,
        investigation_id: UUID | None,
        context_snapshot_id: UUID | None,
    ) -> AgentTaskResult:
        task_result = AgentTaskResult(
            investigation_id=investigation_id,
            context_snapshot_id=context_snapshot_id,
            agent_name=result.agent_name,
            status=result.status,
            findings_json=result.findings,
            metadata_json=result.metadata,
        )
        self.session.add(task_result)
        await self.session.commit()
        await self.session.refresh(task_result)
        return task_result
