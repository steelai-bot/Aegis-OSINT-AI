import logging
import os
from typing import List
from backend.plugins.base import BasePlugin
from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.http_client import SharedHTTPClient

logger = logging.getLogger(__name__)

class GithubPlugin(BasePlugin):
    """
    Plugin for GitHub user and repository discovery.
    Uses GitHub API if token is available.
    Optimized with shared HTTP client for connection reuse.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="github_discovery",
            description="Discovers GitHub users and repositories associated with a query.",
            supported_entity_types=[TargetType.GITHUB, TargetType.USERNAME, TargetType.PERSON],
            required_api_keys=["GITHUB_TOKEN"],
            tags=["github", "social"],
            execution_cost=1.2,
            estimated_time=4
        )

    async def execute(self, query: str, target_type: TargetType) -> List[PluginResponse]:
        findings = []
        token = os.getenv("GITHUB_TOKEN")
        headers = {"Authorization": f"token {token}"} if token else {}

        try:
            client = await SharedHTTPClient.get_client()
            # Search for users matching the query
            url = f"https://api.github.com/search/users?q={query}"
            resp = await client.get(url, headers=headers)

            if resp.status_code == 200:
                data = resp.json()
                users = data.get("items", [])
                if users:
                    user_list = []
                    for u in users:
                        user_list.append({
                            "login": u.get("login"),
                            "html_url": u.get("html_url"),
                            "type": u.get("type")
                        })

                    findings.append(PluginResponse(
                        provider=self.metadata.name,
                        entity_type=TargetType.GITHUB,
                        confidence=0.8,
                        evidence=[{"users": user_list}],
                        raw=data
                    ))
            elif resp.status_code == 401:
                logger.warning("GithubPlugin: Unauthorized. Check GITHUB_TOKEN.")
            else:
                logger.error(f"GithubPlugin error: {resp.status_code} - {resp.text}")

        except Exception as e:
            logger.error(f"GithubPlugin error: {e}")

        return findings