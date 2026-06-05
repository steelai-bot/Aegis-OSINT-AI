"""Breach exposure metadata agent."""

from backend.agents.base import AgentResult, BaseAgent, InvestigationContext


class BreachAgent(BaseAgent):
    name = "breach"

    async def run(self, context: InvestigationContext) -> AgentResult:
        return AgentResult(agent_name=self.name, status="completed", findings=[])
