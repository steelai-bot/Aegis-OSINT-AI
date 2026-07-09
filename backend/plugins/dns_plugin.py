import httpx
import logging
from typing import List
from urllib.parse import quote
from backend.plugins.base import BasePlugin
from backend.models import PluginMetadata, PluginResponse, TargetType

logger = logging.getLogger(__name__)

class DNSPlugin(BasePlugin):
    """
    Plugin for performing DNS record lookups using Google DNS.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="dns_lookup",
            description="Performs DNS record lookups (A, AAAA, MX, TXT, NS, CNAME, SOA) using Google DNS.",
            supported_entity_types=[TargetType.DOMAIN, TargetType.NZ_DOMAIN],
            tags=["dns", "passive"],
            execution_cost=1.0,
            estimated_time=3
        )

    async def execute(self, query: str, target_type: TargetType) -> List[PluginResponse]:
        findings = []
        domain = query
        
        # Basic validation for domain-like strings
        if "." not in domain:
            return []

        async with httpx.AsyncClient(timeout=10.0) as client:
            for rtype in ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']:
                try:
                    url = f'https://dns.google/resolve?name={quote(domain)}&type={rtype}'
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        data = resp.json()
                        answers = data.get('Answer', [])
                        if answers:
                            findings.append(PluginResponse(
                                provider=self.metadata.name,
                                entity_type=target_type,
                                confidence=0.95,
                                evidence=[{
                                    "record_type": rtype,
                                    "records": [a.get('data', '') for a in answers]
                                }],
                                raw=data
                            ))
                except Exception as e:
                    logger.error(f"DNSPlugin error during {rtype} lookup for {domain}: {e}")
                    continue
        
        return findings