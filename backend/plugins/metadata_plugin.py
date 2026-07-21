import logging
import re
from typing import Any

import httpx

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
            estimated_time=4
        )

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        findings = []

        # If query looks like a URL, fetch it
        if query.startswith("http://") or query.startswith("https://"):
            url = query
        elif target_type == TargetType.DOMAIN:
            url = f"https://{query}"
        else:
            # For MVP, we only handle URLs/Domains
            return findings

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    content = resp.text
                    metadata: dict[str, Any] = {}

                    # Extract title
                    title_match = re.search(r'<title>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
                    if title_match:
                        metadata["title"] = title_match.group(1).strip()

                    # Extract generator
                    gen_match = re.search(r'name=["\']generator["\'] content=["\'](.*?)["\']', content, re.IGNORECASE)
                    if gen_match:
                        metadata["generator"] = gen_match.group(1).strip()

                    # Extract meta description
                    desc_match = re.search(r'name=["\']description["\'] content=["\'](.*?)["\']', content, re.IGNORECASE)
                    if desc_match:
                        metadata["description"] = desc_match.group(1).strip()

                    # Extract emails found in page
                    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content)
                    if emails:
                        metadata["emails_found"] = list(set(emails))

                    if metadata:
                        findings.append(PluginResponse(
                            provider=self.metadata.name,
                            entity_type=TargetType.DOMAIN,
                            confidence=0.6,
                            evidence=[metadata],
                            raw={"url": url, "metadata": metadata}
                        ))
        except Exception as e:
            logger.error(f"MetadataPlugin error for {url}: {e}")

        return findings
