import logging
import os

from backend.http_client import SharedHTTPClient
from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin

logger = logging.getLogger(__name__)

class GooglePlugin(BasePlugin):
    """
    Plugin for Google Dorking and search-based discovery.
    Uses Google Custom Search API if key is available.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="google_dorking",
            description="Performs Google dorking and search-based discovery.",
            supported_entity_types=[TargetType.DOMAIN, TargetType.PERSON, TargetType.COMPANY, TargetType.EMAIL],
            required_api_keys=["GOOGLE_SEARCH_API_KEY", "GOOGLE_SEARCH_CX"],
            tags=["google", "search"],
            execution_cost=2.5,
            estimated_time=6
        )

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        findings = []
        api_key = os.getenv("GOOGLE_SEARCH_API_KEY")
        cx = os.getenv("GOOGLE_SEARCH_CX")
        client = await SharedHTTPClient().get_client()

        if api_key and cx:
            try:
                dork = query
                if target_type == TargetType.DOMAIN:
                    dork = f"site:{query}"
                elif target_type == TargetType.EMAIL:
                    dork = f'"{query}"'

                url = "https://www.googleapis.com/customsearch/v1"
                params = {
                    "q": dork,
                    "key": api_key,
                    "cx": cx
                }

                resp = await client.get(url, params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    items = data.get("items", [])
                    if items:
                        results = []
                        for item in items:
                            results.append({
                                "title": item.get("title"),
                                "link": item.get("link"),
                                "snippet": item.get("snippet")
                            })

                        findings.append(PluginResponse(
                            provider=self.metadata.name,
                            entity_type=target_type,
                            confidence=0.8,
                            evidence=[{"search_results": results}],
                            raw=data
                        ))
                else:
                    logger.error(f"GooglePlugin error: {resp.status_code} - {resp.text}")
            except Exception as e:
                logger.error(f"GooglePlugin error: {e}")
        else:
            logger.warning("GooglePlugin: API key or CX not configured. Skipping.")
            if not api_key:
                findings.append(PluginResponse(
                    provider=self.metadata.name,
                    entity_type=target_type,
                    confidence=0.1,
                    evidence=[{"note": "Google Search API not configured. Skipping actual search."}],
                    raw={}
                ))

        return findings
