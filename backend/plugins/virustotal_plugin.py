import logging
import os

import httpx

from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin

logger = logging.getLogger(__name__)


class VirusTotalPlugin(BasePlugin):
    """
    VirusTotal Plugin for domain/IP reputation and malware analysis.
    Requires VIRUSTOTAL_API_KEY environment variable.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="virustotal",
            description="VirusTotal reputation and malware analysis for domains and IPs.",
            version="1.0.0",
            supported_entity_types=[
                TargetType.DOMAIN,
                TargetType.IP,
                TargetType.NZ_DOMAIN
            ],
            required_api_keys=["VIRUSTOTAL_API_KEY"],
            tags=["virustotal", "reputation", "malware"],
            execution_cost=1.5,
            estimated_time=6
        )

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not api_key:
            logger.warning("VIRUSTOTAL_API_KEY not configured")
            return []

        findings = []
        headers = {"x-apikey": api_key}

        async with httpx.AsyncClient(timeout=15.0, headers=headers) as client:
            try:
                if target_type in (TargetType.DOMAIN, TargetType.NZ_DOMAIN):
                    url = f"https://www.virustotal.com/api/v3/domains/{query}"
                elif target_type == TargetType.IP:
                    url = f"https://www.virustotal.com/api/v3/ip_addresses/{query}"
                else:
                    return []

                resp = await client.get(url)

                if resp.status_code == 200:
                    data = resp.json()
                    attributes = data.get("data", {}).get("attributes", {})

                    evidence = [{
                        "reputation": attributes.get("reputation"),
                        "last_analysis_stats": attributes.get("last_analysis_stats"),
                        "categories": attributes.get("categories"),
                        "total_votes": attributes.get("total_votes"),
                        "whois": attributes.get("whois", "")[:500] if attributes.get("whois") else None
                    }]

                    findings.append(PluginResponse(
                        provider=self.metadata.name,
                        entity_type=target_type,
                        confidence=0.90,
                        evidence=evidence,
                        raw=data
                    ))
                else:
                    logger.warning(f"VirusTotal returned status {resp.status_code}")

            except Exception as e:
                logger.error(f"VirusTotalPlugin error for query '{query}': {e}")

        return findings
