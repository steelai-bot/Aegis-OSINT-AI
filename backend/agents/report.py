"""Report preparation agent."""

from backend.agents.base import AgentResult, BaseAgent, InvestigationContext


class ReportAgent(BaseAgent):
    name = "report"

    async def run(self, context: InvestigationContext) -> AgentResult:
        return AgentResult(
            agent_name=self.name,
            status="completed",
            findings=[],
            metadata={"finding_count": len(context.findings)},
        )
