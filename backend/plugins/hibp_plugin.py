import logging
import os

import httpx

from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin

logger = logging.getLogger(__name__)


class HaveIBeenPwnedPlugin(BasePlugin):
    """
    Have I Been Pwned (HIBP) Plugin for checking email breaches.
    Requires HIBP_API_KEY environment variable.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="hibp",
            description="Checks if email addresses have been involved in known data breaches.",
            version="1.0.0",
            supported_entity_types=[TargetType.EMAIL],
            required_api_keys=["HIBP_API_KEY"],
            tags=["hibp", "breach", "email"],
            execution_cost=1.0,
            estimated_time=5
        )

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        api_key = os.getenv("HIBP_API_KEY")
        if not api_key:
            logger.warning("HIBP_API_KEY not configured")
            return []

        findings = []
        headers = {
            "hibp-api-key": api_key,
            "user-agent": "Aegis-OSINT-AI"
        }

        async with httpx.AsyncClient(timeout=15.0, headers=headers) as client:
            try:
                if target_type == TargetType.EMAIL:
                    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{query}"
                    resp = await client.get(url)

                    if resp.status_code == 200:
                        breaches = resp.json()
                        evidence = []

                        for breach in breaches[:10]:  # Limit results
                            evidence.append({
                                "name": breach.get("Name"),
                                "title": breach.get("Title"),
                                "domain": breach.get("Domain"),
                                "breach_date": breach.get("BreachDate"),
                                "added_date": breach.get("AddedDate"),
                                "pwn_count": breach.get("PwnCount"),
                                "data_classes": breach.get("DataClasses", [])
                            })

                        findings.append(PluginResponse(
                            provider=self.metadata.name,
                            entity_type=target_type,
                            confidence=0.95,
                            evidence=evidence,
                            raw={"breaches": breaches}
                        ))
                    elif resp.status_code == 404:
                        # No breaches found - still valid result
                        findings.append(PluginResponse(
                            provider=self.metadata.name,
                            entity_type=target_type,
                            confidence=0.99,
                            evidence=[{"breaches_found": 0}],
                            raw={"message": "No breaches found"}
                        ))
                    else:
                        logger.warning(f"HIBP returned status {resp.status_code}")

            except Exception as e:
                logger.error(f"HIBPPlugin error for query '{query}': {e}")

        return findings
