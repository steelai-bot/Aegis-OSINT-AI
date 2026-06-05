"""Unit tests for agent contracts and event-driven workflow orchestration."""

from uuid import uuid4

import pytest

from backend.agents import AgentResult, BaseAgent, DomainAgent, InvestigationContext, ReconAgent, ReportAgent
from backend.core.events import EventBus
from backend.services.investigation_engine import InvestigationEngine

pytestmark = pytest.mark.asyncio


class StubAgent(BaseAgent):
    name = "stub"

    async def run(self, context: InvestigationContext) -> AgentResult:
        return AgentResult(
            agent_name=self.name,
            status="completed",
            findings=[{"source": self.name, "type": "stub.finding", "value": context.target}],
        )


async def test_base_agent_publishes_lifecycle_events() -> None:
    bus = EventBus()
    context = InvestigationContext(investigation_id=None, target="example.com", target_type="domain")
    agent = StubAgent(bus=bus)

    result = await agent.execute(context)
    events = await bus.history()

    assert result.status == "completed"
    assert [event.name for event in events] == ["agent.started", "agent.completed"]
    assert events[0].payload == {"agent": "stub", "target": "example.com"}
    assert events[1].payload["status"] == "completed"


async def test_domain_agent_only_emits_domain_findings_for_domain_targets() -> None:
    agent = DomainAgent(bus=EventBus())

    domain_result = await agent.run(
        InvestigationContext(investigation_id=None, target="example.com", target_type="domain")
    )
    email_result = await agent.run(
        InvestigationContext(investigation_id=None, target="person@example.com", target_type="email")
    )

    assert domain_result.findings == [
        {"source": "domain", "type": "domain.queued", "value": "example.com", "confidence": 0.8}
    ]
    assert email_result.findings == []


async def test_report_agent_counts_findings_from_context() -> None:
    context = InvestigationContext(
        investigation_id=uuid4(),
        target="example.com",
        target_type="domain",
        findings=[
            {"source": "recon", "type": "target.observed"},
            {"source": "domain", "type": "domain.queued"},
        ],
    )

    result = await ReportAgent(bus=EventBus()).run(context)

    assert result.metadata["finding_count"] == 2
    assert result.findings == []


async def test_investigation_engine_emits_workflow_events_in_agent_order() -> None:
    bus = EventBus()
    context = InvestigationContext(investigation_id=uuid4(), target="example.com", target_type="domain")
    engine = InvestigationEngine(agents=[ReconAgent(), DomainAgent(), ReportAgent()], bus=bus)

    results = await engine.run(context)
    events = await bus.history()

    assert [result.agent_name for result in results] == ["recon", "domain", "report"]
    assert [finding["source"] for finding in context.findings] == ["recon", "domain"]
    assert [event.name for event in events] == [
        "workflow.started",
        "workflow.step.ready",
        "agent.started",
        "agent.completed",
        "workflow.step.completed",
        "workflow.step.ready",
        "agent.started",
        "agent.completed",
        "workflow.step.completed",
        "workflow.step.ready",
        "agent.started",
        "agent.completed",
        "workflow.step.completed",
        "workflow.completed",
    ]

    ready_events = [event for event in events if event.name == "workflow.step.ready"]
    assert [event.payload["agent"] for event in ready_events] == ["recon", "domain", "report"]
    assert ready_events[1].payload["depends_on"] == ["recon"]
    assert ready_events[2].payload["depends_on"] == ["domain"]

    completed = events[-1]
    assert completed.payload["status"] == "completed"
    assert completed.payload["agents"] == ["recon", "domain", "report"]
    assert completed.payload["total_findings"] == 2
