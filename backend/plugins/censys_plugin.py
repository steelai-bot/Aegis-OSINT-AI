import logging
import os

import httpx

from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin

logger = logging.getLogger(__name__)


class CensysPlugin(BasePlugin):
    """
    Censys Plugin for internet-wide scanning data and certificate/host intelligence.
    Requires CENSYS_API_ID and CENSYS_API_SECRET environment variables.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="censys",
            description="Censys search for hosts, certificates, and internet-wide scanning data.",
            version="1.0.0",
            supported_entity_types=[
                TargetType.IP,
                TargetType.DOMAIN,
                TargetType.NZ_DOMAIN
            ],
            required_api_keys=["CENSYS_API_ID", "CENSYS_API_SECRET"],
            tags=["censys", "passive", "infrastructure", "certificates"],
            execution_cost=3.0,
            estimated_time=12
        )

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        api_id = os.getenv("CENSYS_API_ID")
        api_secret = os.getenv("CENSYS_API_SECRET")
        if not api_id or not api_secret:
            logger.warning("CENSYS_API_ID or CENSYS_API_SECRET not configured")
            return []

        findings = []

        async with httpx.AsyncClient(timeout=20.0) as client:
            try:
                auth = (api_id, api_secret)

                # Search hosts
                if target_type in (TargetType.IP, TargetType.DOMAIN, TargetType.NZ_DOMAIN):
                    search_url = "https://search.censys.io/api/v2/hosts/search"
                    params: dict[str, str | int] = {"q": query, "per_page": 5}

                    resp = await client.get(search_url, params=params, auth=auth)

                    if resp.status_code == 200:
                        data = resp.json()
                        results = data.get("result", {}).get("hits", [])

                        if results:
                            evidence = []
                            for hit in results[:5]:
                                evidence.append({
                                    "ip": hit.get("ip"),
                                    "services": [
                                        {"port": s.get("port"), "service_name": s.get("service_name")}
                                        for s in hit.get("services", [])[:3]
                                    ],
                                    "location": hit.get("location", {}),
                                    "autonomous_system": hit.get("autonomous_system", {}),
                                    "operating_system": hit.get("operating_system", {})
                                })

                            findings.append(PluginResponse(
                                provider=self.metadata.name,
                                entity_type=target_type,
                                confidence=0.90,
                                evidence=evidence,
                                raw=data
                            ))
                    else:
                        logger.warning(f"Censys API returned status {resp.status_code}")

            except Exception as e:
                logger.error(f"CensysPlugin error for query '{query}': {e}")

        return findings
