"""Initial reconnaissance agent."""

from backend.agents.base import AgentResult, BaseAgent, InvestigationContext


class ReconAgent(BaseAgent):
    name = "recon"

    async def run(self, context: InvestigationContext) -> AgentResult:
        finding = {"source": self.name, "type": "target.observed", "value": context.target, "confidence": 1.0}
        return AgentResult(agent_name=self.name, status="completed", findings=[finding])
