import logging
import os

import httpx

from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin

logger = logging.getLogger(__name__)


class ShodanPlugin(BasePlugin):
    """
    Shodan Plugin for IP, domain and service reconnaissance.
    Requires SHODAN_API_KEY environment variable.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="shodan",
            description="Shodan search engine for IPs, domains, services, and vulnerabilities.",
            version="1.0.0",
            supported_entity_types=[
                TargetType.IP,
                TargetType.DOMAIN,
                TargetType.NZ_DOMAIN
            ],
            required_api_keys=["SHODAN_API_KEY"],
            tags=["shodan", "passive", "infrastructure"],
            execution_cost=2.0,
            estimated_time=8
        )

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        api_key = os.getenv("SHODAN_API_KEY")
        if not api_key:
            logger.warning("SHODAN_API_KEY not configured")
            return []

        findings = []

        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                # Search by IP or hostname
                if target_type in (TargetType.IP, TargetType.DOMAIN, TargetType.NZ_DOMAIN):
                    url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={query}"
                    resp = await client.get(url)

                    if resp.status_code == 200:
                        data = resp.json()
                        matches = data.get("matches", [])

                        if matches:
                            evidence = []
                            for match in matches[:5]:  # Limit to top 5 results
                                evidence.append({
                                    "ip": match.get("ip_str"),
                                    "port": match.get("port"),
                                    "org": match.get("org"),
                                    "os": match.get("os"),
                                    "product": match.get("product"),
                                    "version": match.get("version"),
                                    "location": {
                                        "country": match.get("location", {}).get("country_name"),
                                        "city": match.get("location", {}).get("city")
                                    },
                                    "hostnames": match.get("hostnames", []),
                                    "vulns": list(match.get("vulns", {}).keys()) if match.get("vulns") else []
                                })

                            findings.append(PluginResponse(
                                provider=self.metadata.name,
                                entity_type=target_type,
                                confidence=0.92,
                                evidence=evidence,
                                raw=data
                            ))
                    else:
                        logger.warning(f"Shodan API returned status {resp.status_code}")

            except Exception as e:
                logger.error(f"ShodanPlugin error for query '{query}': {e}")

        return findings
