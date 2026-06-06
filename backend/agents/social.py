"""Social OSINT investigation agent."""

import httpx
from backend.agents.base import AgentResult, BaseAgent, InvestigationContext
from backend.core.config import get_settings

class SocialAgent(BaseAgent):
    name = "social"

    async def run(self, context: InvestigationContext) -> AgentResult:
        settings = get_settings()
        findings = []
        
        if not settings.serus_ai_api_key:
            return AgentResult(agent_name=self.name, status="failed", findings=[])

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://api.serus.ai/v1/search/accounts",
                    params={"query": context.target},
                    headers={"Authorization": f"Bearer {settings.serus_ai_api_key}"},
                    timeout=10.0
                )
                
                if response.status_code == 200:
                    data = response.json()
                    accounts = data.get("accounts", [])
                    for acc in accounts:
                        findings.append({
                            "source": "serus.ai",
                            "type": "social.account",
                            "value": acc.get("username", context.target),
                            "confidence": acc.get("confidence", 0.85),
                            "platform": acc.get("platform", "unknown"),
                            "url": acc.get("url", "")
                        })
                else:
                    # Fallback stub for when API endpoint doesn't exist but we want to simulate
                    findings.append({
                        "source": "serus.ai", 
                        "type": "social.account",
                        "value": f"[{response.status_code}] serus.ai query returned no accounts",
                        "confidence": 0.0
                    })
        except Exception as e:
            findings.append({
                "source": "serus.ai",
                "type": "error",
                "value": str(e),
                "confidence": 0.0
            })

        return AgentResult(agent_name=self.name, status="completed", findings=findings)
