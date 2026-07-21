import asyncio
import logging
from typing import List
from backend.plugins.base import BasePlugin
from backend.models import PluginMetadata, PluginResponse, TargetType

logger = logging.getLogger(__name__)

class WHOISPlugin(BasePlugin):
    """
    Plugin for performing WHOIS lookups.
    Requires the 'whois' command-line tool to be installed on the system.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="whois_lookup",
            description="Performs WHOIS lookups for domains to find registration details.",
            supported_entity_types=[TargetType.DOMAIN, TargetType.NZ_DOMAIN],
            tags=["whois", "registration"],
            execution_cost=2.0,
            estimated_time=10
        )

    async def execute(self, query: str, target_type: TargetType) -> List[PluginResponse]:
        domain = query
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                ['whois', domain],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if result.returncode == 0 and result.stdout:
                return [PluginResponse(
                    provider=self.metadata.name,
                    entity_type=target_type,
                    confidence=0.9,
                    evidence=[{
                        "raw_whois": result.stdout[:5000]
                    }],
                    raw={"stdout": result.stdout}
                )]
        except Exception as e:
            logger.error(f"WHOISPlugin error for {domain}: {e}")
        
        return []