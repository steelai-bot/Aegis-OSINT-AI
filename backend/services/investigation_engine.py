"""Investigation workflow orchestration."""

from __future__ import annotations

from collections.abc import Sequence

from backend.agents import (
    AgentResult,
    BaseAgent,
    DomainAgent,
    InvestigationContext,
    ReconAgent,
    ReportAgent,
    ThreatIntelAgent,
)


class InvestigationEngine:
    """Runs agents in a controlled workflow without direct agent-to-agent calls."""

    def __init__(self, agents: Sequence[BaseAgent] | None = None) -> None:
        self.agents = list(agents or [ReconAgent(), DomainAgent(), ThreatIntelAgent(), ReportAgent()])

    async def run(self, context: InvestigationContext) -> list[AgentResult]:
        results: list[AgentResult] = []
        for agent in self.agents:
            result = await agent.execute(context)
            results.append(result)
            context.findings.extend(result.findings)
        return results
