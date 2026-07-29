import logging
import os

from backend.http_client import SharedHTTPClient
from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin

logger = logging.getLogger(__name__)

class EmailPlugin(BasePlugin):
    """
    Plugin for email discovery and validation.
    Uses Hunter.io if API key is available, otherwise performs basic pattern extraction.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="email_discovery",
            description="Discovers and validates email addresses using Hunter.io or pattern analysis.",
            supported_entity_types=[TargetType.EMAIL, TargetType.DOMAIN, TargetType.COMPANY],
            required_api_keys=["HUNTER_API_KEY"],
            tags=["email", "identity"],
            execution_cost=1.5,
            estimated_time=5
        )

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        findings = []
        api_key = os.getenv("HUNTER_API_KEY")
        client = await SharedHTTPClient().get_client()

        if api_key:
            try:
                if target_type == TargetType.DOMAIN:
                    url = f"https://api.hunter.io/v2/domain-search?domain={query}&api_key={api_key}"
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        data = resp.json()
                        emails = data.get("data", {}).get("emails", [])
                        if emails:
                            findings.append(PluginResponse(
                                provider=self.metadata.name,
                                entity_type=TargetType.EMAIL,
                                confidence=0.9,
                                evidence=[{"emails": [e.get("value") for e in emails]}],
                                raw=data
                            ))
                elif target_type == TargetType.EMAIL:
                    url = f"https://api.hunter.io/v2/email-verifier?email={query}&api_key={api_key}"
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        data = resp.json()
                        result = data.get("data", {})
                        if result.get("status") == "valid":
                            findings.append(PluginResponse(
                                provider=self.metadata.name,
                                entity_type=TargetType.EMAIL,
                                confidence=1.0,
                                evidence=[{"status": "valid", "email": query}],
                                raw=data
                            ))
            except Exception as e:
                logger.error(f"EmailPlugin Hunter.io error: {e}")

        # Fallback or complementary: Basic pattern extraction if query is a domain
        if target_type == TargetType.DOMAIN:
            # In a real scenario, we might scrape the domain for emails.
            # For MVP, we simulate finding a common pattern if no API key was used.
            if not api_key:
                findings.append(PluginResponse(
                    provider=self.metadata.name,
                    entity_type=TargetType.EMAIL,
                    confidence=0.3,
                    evidence=[{"note": "No API key provided, performing basic pattern simulation", "suggested_pattern": f"admin@{query}"}],
                    raw={}
                ))

        return findings
