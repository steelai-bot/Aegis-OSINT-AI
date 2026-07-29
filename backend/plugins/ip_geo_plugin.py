import logging

from backend.http_client import SharedHTTPClient
from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin

logger = logging.getLogger(__name__)

class IPGeoPlugin(BasePlugin):
    """
    Plugin for IP geolocation using ip-api.com.
    Optimized with shared HTTP client for connection reuse.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="ip_geolocation",
            description="Provides geolocation and ISP information for an IP address.",
            supported_entity_types=[TargetType.IP],
            tags=["ip", "geo", "network"],
            execution_cost=1.0,
            estimated_time=2
        )

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        ip = query
        try:
            client = await SharedHTTPClient().get_client()
            url = f'http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as'
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('status') == 'success':
                    return [PluginResponse(
                        provider=self.metadata.name,
                        entity_type=target_type,
                        confidence=0.8,
                        evidence=[{
                            "ip": ip,
                            "country": data.get('country', ''),
                            "country_code": data.get('countryCode', ''),
                            "region": data.get('regionName', ''),
                            "city": data.get('city', ''),
                            "isp": data.get('isp', ''),
                            "org": data.get('org', ''),
                            "as_number": data.get('as', ''),
                            "is_australian": data.get('countryCode') == 'AU',
                            "is_nz": data.get('countryCode') == 'NZ'
                        }],
                        raw=data
                    )]
        except Exception as e:
            logger.error(f"IPGeoPlugin error for {ip}: {e}")

        return []
