import logging
from urllib.parse import quote

from backend.http_client import SharedHTTPClient
from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin

logger = logging.getLogger(__name__)

class CertTransparencyPlugin(BasePlugin):
    """
    Plugin for searching Certificate Transparency logs via crt.sh.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="cert_transparency",
            description="Searches Certificate Transparency logs for subdomains and certificates.",
            supported_entity_types=[TargetType.DOMAIN, TargetType.NZ_DOMAIN],
            tags=["cert", "subdomain", "passive"],
            execution_cost=1.5,
            estimated_time=5
        )

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        domain = query
        if "." not in domain:
            return []

        try:
            client = await SharedHTTPClient().get_client()
            url = f'https://crt.sh/?q=%.{quote(domain)}&output=json'
            resp = await client.get(url)
            if resp.status_code == 200:
                certs = resp.json()
                subdomains = set()
                for cert in certs:
                    name = cert.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub and sub.endswith(domain) and '*' not in sub:
                            subdomains.add(sub)

                if subdomains:
                    return [PluginResponse(
                        provider=self.metadata.name,
                        entity_type=target_type,
                        confidence=0.9,
                        evidence=[{
                            "domain": domain,
                            "subdomains": sorted(subdomains)[:100],
                            "count": len(subdomains)
                        }],
                        raw={"total_certs": len(certs)}
                    )]
        except Exception as e:
            logger.error(f"CertTransparencyPlugin error for {domain}: {e}")

        return []
