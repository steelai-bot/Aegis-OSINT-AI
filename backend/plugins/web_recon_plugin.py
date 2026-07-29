import asyncio
import logging
import re

import httpx

from backend.http_client import SharedHTTPClient
from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin

logger = logging.getLogger(__name__)

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
MAX_PATHS = 50


class WebReconPlugin(BasePlugin):
    """
    Plugin for passive web reconnaissance of a domain.
    Fetches and parses robots.txt, .well-known/security.txt, and sitemap.xml
    to discover hidden paths, sitemaps, and security contacts.
    No API key required.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="web_recon",
            description="Parses robots.txt, security.txt, and sitemap.xml to discover paths, sitemaps, and security contacts.",
            supported_entity_types=[TargetType.DOMAIN, TargetType.NZ_DOMAIN, TargetType.SUBDOMAIN],
            tags=["web", "passive", "recon"],
            execution_cost=1.0,
            estimated_time=4,
        )

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        domain = query.strip().lower()
        if "." not in domain:
            return []

        base_url = f"https://{domain}"
        client = await SharedHTTPClient().get_client()

        robots_task = self._fetch(client, f"{base_url}/robots.txt")
        security_task = self._fetch(client, f"{base_url}/.well-known/security.txt")
        security_fallback_task = self._fetch(client, f"{base_url}/security.txt")
        sitemap_task = self._fetch(client, f"{base_url}/sitemap.xml")

        robots, security, security_fallback, sitemap = await asyncio.gather(
            robots_task, security_task, security_fallback_task, sitemap_task
        )
        if not security:
            security = security_fallback

        evidence: list[dict] = []
        raw: dict = {"query": domain}

        if robots:
            parsed = self._parse_robots(robots)
            evidence.append({
                "type": "robots_txt",
                "disallowed_paths": parsed["disallowed"][:MAX_PATHS],
                "sitemaps": parsed["sitemaps"],
            })
            raw["robots_txt"] = robots[:5000]

        if security:
            contacts = EMAIL_RE.findall(security)
            evidence.append({
                "type": "security_txt",
                "contacts": sorted(set(contacts)),
            })
            raw["security_txt"] = security[:5000]
            if contacts:
                raw.setdefault("emails", [])
                raw["emails"].extend(sorted(set(contacts)))

        if sitemap:
            urls = re.findall(r"<loc>(.*?)</loc>", sitemap)
            evidence.append({
                "type": "sitemap_xml",
                "url_count": len(urls),
                "urls": urls[:MAX_PATHS],
            })
            raw["sitemap_url_count"] = len(urls)

        if not evidence:
            return []

        return [PluginResponse(
            provider=self.metadata.name,
            entity_type=target_type,
            confidence=0.8,
            evidence=evidence,
            raw=raw,
        )]

    async def _fetch(self, client: httpx.AsyncClient, url: str) -> str | None:

        """Fetch a URL and return its text body on success, else None."""
        try:
            resp = await client.get(url)
            if resp.status_code == 200 and resp.text:
                return resp.text
        except Exception as e:
            logger.debug(f"WebReconPlugin fetch failed for {url}: {e}")
        return None

    def _parse_robots(self, text: str) -> dict:
        """Extract Disallow paths and Sitemap entries from robots.txt."""
        disallowed: list[str] = []
        sitemaps: list[str] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, sep, value = line.partition(":")
            if not sep:
                continue
            key = key.strip().lower()
            value = value.strip()
            if key == "disallow" and value:
                disallowed.append(value)
            elif key == "sitemap" and value:
                sitemaps.append(value)
        return {"disallowed": disallowed, "sitemaps": sitemaps}
