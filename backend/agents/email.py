"""Email-focused investigation agent."""

from backend.agents.base import AgentResult, BaseAgent, InvestigationContext


class EmailAgent(BaseAgent):
    name = "email"

    async def run(self, context: InvestigationContext) -> AgentResult:
        findings = []
        if context.target_type == "email":
            domain = context.target.split("@")[-1]
            findings.append({"source": self.name, "type": "email.domain", "value": domain, "confidence": 0.9})
        return AgentResult(agent_name=self.name, status="completed", findings=findings)
