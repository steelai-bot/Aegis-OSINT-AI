"""Threat intelligence enrichment agent."""

from backend.agents.base import AgentResult, BaseAgent, InvestigationContext


class ThreatIntelAgent(BaseAgent):
    name = "threat_intel"

    async def run(self, context: InvestigationContext) -> AgentResult:
        return AgentResult(agent_name=self.name, status="completed", findings=[])
