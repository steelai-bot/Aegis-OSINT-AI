"""Social OSINT investigation agent."""

from backend.agents.base import AgentResult, BaseAgent, InvestigationContext


class SocialAgent(BaseAgent):
    name = "social"

    async def run(self, context: InvestigationContext) -> AgentResult:
        return AgentResult(agent_name=self.name, status="completed", findings=[])
