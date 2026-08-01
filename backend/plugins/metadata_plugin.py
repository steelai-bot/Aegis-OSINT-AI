import logging
import re
from typing import Any

from backend.http_client import SharedHTTPClient
from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin

logger = logging.getLogger(__name__)


class MetadataPlugin(BasePlugin):
    """
    Plugin for metadata extraction from files or URLs.
    For MVP, it extracts basic metadata from HTML pages or simulates file metadata.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="metadata_extraction",
            description="Extracts metadata from URLs or files (HTML title, generator, etc.).",
            supported_entity_types=[TargetType.DOMAIN, TargetType.UNKNOWN],
            tags=["metadata", "passive"],
            execution_cost=1.0,
            estimated_time=4,
        )

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        findings: list[PluginResponse] = []

        if query.startswith("http://") or query.startswith("https://"):
            url = query
        elif target_type == TargetType.DOMAIN:
            url = f"https://{query}"
        else:
            return findings

        try:
            client = await SharedHTTPClient().get_client()
            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                content = resp.text
                metadata: dict[str, Any] = {}

                title_match = re.search(r"<title>(.*?)</title>", content, re.IGNORECASE | re.DOTALL)
                if title_match:
                    metadata["title"] = title_match.group(1).strip()

                gen_match = re.search(
                    r'name=["\']generator["\'] content=["\'](.*?)["\']', content, re.IGNORECASE
                )
                if gen_match:
                    metadata["generator"] = gen_match.group(1).strip()

                desc_match = re.search(
                    r'name=["\']description["\'] content=["\'](.*?)["\']', content, re.IGNORECASE
                )
                if desc_match:
                    metadata["description"] = desc_match.group(1).strip()

                emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", content)
                if emails:
                    metadata["emails_found"] = list(set(emails))

                if metadata:
                    findings.append(
                        PluginResponse(
                            provider=self.metadata.name,
                            entity_type=TargetType.DOMAIN,
                            confidence=0.6,
                            evidence=[metadata],
                            raw={"url": url, "metadata": metadata},
                        )
                    )
        except Exception as e:
            logger.error(f"MetadataPlugin error for {url}: {e}")

        return findings
