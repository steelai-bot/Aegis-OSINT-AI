import asyncio
import logging

from backend.http_client import SharedHTTPClient
from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin

logger = logging.getLogger(__name__)

PLATFORMS = [
    {"name": "GitHub", "url": "https://github.com/{username}"},
    {"name": "Twitter", "url": "https://twitter.com/{username}"},
    {"name": "Instagram", "url": "https://instagram.com/{username}"},
    {"name": "Reddit", "url": "https://reddit.com/user/{username}"},
    {"name": "LinkedIn", "url": "https://linkedin.com/in/{username}"},
    {"name": "YouTube", "url": "https://youtube.com/@{username}"},
    {"name": "Medium", "url": "https://medium.com/@{username}"},
    {"name": "Dev.to", "url": "https://dev.to/{username}"},
    {"name": "GitLab", "url": "https://gitlab.com/{username}"},
    {"name": "StackOverflow", "url": "https://stackoverflow.com/users/{username}"},
]

class UsernamePlugin(BasePlugin):
    """
    Plugin for username enumeration across multiple platforms.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="username_enumeration",
            description="Checks for username presence across common social and developer platforms.",
            supported_entity_types=[TargetType.USERNAME, TargetType.PERSON],
            tags=["username", "social"],
            execution_cost=2.0,
            estimated_time=8
        )

    async def _check_platform(self, client, platform: dict, username: str) -> dict:
        url = platform["url"].format(username=username)
        try:
            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                return {
                    "platform": platform["name"],
                    "url": url,
                    "status": "found"
                }
        except Exception as e:
            logger.debug(f"UsernamePlugin error checking {platform['name']}: {e}")
        return None

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        found = []
        client = await SharedHTTPClient().get_client()

        tasks = [self._check_platform(client, platform, query) for platform in PLATFORMS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, dict):
                found.append(result)

        if found:
            return [PluginResponse(
                provider=self.metadata.name,
                entity_type=TargetType.USERNAME,
                confidence=0.7,
                evidence=[{"profiles": found}],
                raw={"query": query, "results": found}
            )]

        return []
