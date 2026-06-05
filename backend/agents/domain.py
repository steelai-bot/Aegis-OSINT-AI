"""Domain-focused investigation agent."""

from backend.agents.base import AgentResult, BaseAgent, InvestigationContext


class DomainAgent(BaseAgent):
    name = "domain"

    async def run(self, context: InvestigationContext) -> AgentResult:
        findings = []
        if context.target_type == "domain":
            findings.append({"source": self.name, "type": "domain.queued", "value": context.target, "confidence": 0.8})
        return AgentResult(agent_name=self.name, status="completed", findings=findings)
