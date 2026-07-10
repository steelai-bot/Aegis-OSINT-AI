import logging

import httpx

from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin

logger = logging.getLogger(__name__)

# Common platforms to check for username presence
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

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        found = []

        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
            for platform in PLATFORMS:
                url = platform["url"].format(username=query)
                try:
                    resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                    # Basic check: 200 OK and not a generic "not found" page (heuristic)
                    if resp.status_code == 200:
                        # Some sites return 200 for not found pages, but for MVP we accept 200
                        found.append({
                            "platform": platform["name"],
                            "url": url,
                            "status": "found"
                        })
                except Exception as e:
                    logger.debug(f"UsernamePlugin error checking {platform['name']}: {e}")
                    continue

        if found:
            return [PluginResponse(
                provider=self.metadata.name,
                entity_type=TargetType.USERNAME,
                confidence=0.7,
                evidence=[{"profiles": found}],
                raw={"query": query, "results": found}
            )]

        return []
