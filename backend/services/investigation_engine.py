"""Investigation workflow orchestration."""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from backend.agents import (
    AgentResult,
    BaseAgent,
    DomainAgent,
    InvestigationContext,
    ReconAgent,
    ReportAgent,
    ThreatIntelAgent,
)
from backend.services.agent_persistence import AgentPersistenceService


class InvestigationEngine:
    """Runs agents in a controlled workflow without direct agent-to-agent calls."""

    def __init__(self, agents: Sequence[BaseAgent] | None = None, session: AsyncSession | None = None) -> None:
        self.agents = list(agents or [ReconAgent(), DomainAgent(), ThreatIntelAgent(), ReportAgent()])
        self.persistence = AgentPersistenceService(session) if session is not None else None

    async def run(self, context: InvestigationContext) -> list[AgentResult]:
        context_snapshot = None
        if self.persistence is not None:
            context_snapshot = await self.persistence.create_context_snapshot(context, status="started")

        results: list[AgentResult] = []
        for agent in self.agents:
            result = await agent.execute(context)
            if self.persistence is not None:
                task_result = await self.persistence.create_task_result(
                    result,
                    investigation_id=context.investigation_id,
                    context_snapshot_id=context_snapshot.id if context_snapshot is not None else None,
                )
                result.metadata = {**result.metadata, "task_result_id": str(task_result.id)}
            results.append(result)
            context.findings.extend(result.findings)
        if self.persistence is not None and context_snapshot is not None:
            await self.persistence.update_context_snapshot(context_snapshot, context, status="completed")
        return results
