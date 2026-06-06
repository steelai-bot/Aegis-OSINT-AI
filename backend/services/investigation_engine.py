"""Investigation workflow orchestration."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from backend.agents import (
    AgentResult,
    BaseAgent,
    DomainAgent,
    InvestigationContext,
    ReconAgent,
    ReportAgent,
    SocialAgent,
    ThreatIntelAgent,
)
from backend.core.events import EventBus, event_bus
from backend.services.agent_persistence import AgentPersistenceService


@dataclass(frozen=True, slots=True)
class WorkflowStep:
    """A single event-driven workflow dispatch step."""

    agent: BaseAgent
    depends_on: tuple[str, ...] = ()


class InvestigationEngine:
    """Runs agents in a controlled workflow without direct agent-to-agent calls."""

    def __init__(
        self,
        agents: Sequence[BaseAgent] | None = None,
        session: AsyncSession | None = None,
        bus: EventBus | None = None,
    ) -> None:
        self.event_bus = bus or event_bus
        self.agents = list(
            agents
            or [
                ReconAgent(bus=self.event_bus),
                DomainAgent(bus=self.event_bus),
                SocialAgent(bus=self.event_bus),
                ThreatIntelAgent(bus=self.event_bus),
                ReportAgent(bus=self.event_bus),
            ]
        )
        for agent in self.agents:
            agent.event_bus = self.event_bus
        self.workflow = self._build_workflow(self.agents)
        self.persistence = AgentPersistenceService(session) if session is not None else None

    def _build_workflow(self, agents: Sequence[BaseAgent]) -> list[WorkflowStep]:
        completed_dependency = ""
        steps: list[WorkflowStep] = []
        for agent in agents:
            dependencies = (completed_dependency,) if completed_dependency else ()
            steps.append(WorkflowStep(agent=agent, depends_on=dependencies))
            completed_dependency = agent.name
        return steps

    async def run(self, context: InvestigationContext) -> list[AgentResult]:
        context_snapshot = None
        if self.persistence is not None:
            context_snapshot = await self.persistence.create_context_snapshot(context, status="started")

        await self.event_bus.publish(
            "workflow.started",
            {
                "investigation_id": str(context.investigation_id) if context.investigation_id else None,
                "target": context.target,
                "target_type": context.target_type,
                "agents": [step.agent.name for step in self.workflow],
            },
        )

        results: list[AgentResult] = []
        completed_agents: set[str] = set()
        for step in self.workflow:
            missing_dependencies = [dependency for dependency in step.depends_on if dependency not in completed_agents]
            if missing_dependencies:
                raise RuntimeError(f"Workflow dependencies not satisfied for {step.agent.name}: {missing_dependencies}")

            await self.event_bus.publish(
                "workflow.step.ready",
                {
                    "agent": step.agent.name,
                    "depends_on": list(step.depends_on),
                    "target": context.target,
                    "existing_findings": len(context.findings),
                },
            )

            result = await step.agent.execute(context)
            if self.persistence is not None:
                task_result = await self.persistence.create_task_result(
                    result,
                    investigation_id=context.investigation_id,
                    context_snapshot_id=context_snapshot.id if context_snapshot is not None else None,
                )
                result.metadata = {**result.metadata, "task_result_id": str(task_result.id)}
            results.append(result)
            context.findings.extend(result.findings)
            completed_agents.add(step.agent.name)

            await self.event_bus.publish(
                "workflow.step.completed",
                {
                    "agent": step.agent.name,
                    "status": result.status,
                    "target": context.target,
                    "finding_count": len(result.findings),
                    "total_findings": len(context.findings),
                    "task_result_id": result.metadata.get("task_result_id"),
                },
            )

        if self.persistence is not None and context_snapshot is not None:
            await self.persistence.update_context_snapshot(context_snapshot, context, status="completed")
        await self.event_bus.publish(
            "workflow.completed",
            {
                "investigation_id": str(context.investigation_id) if context.investigation_id else None,
                "target": context.target,
                "status": "completed",
                "agents": [result.agent_name for result in results],
                "total_findings": len(context.findings),
            },
        )
        return results
