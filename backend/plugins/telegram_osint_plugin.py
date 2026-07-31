import asyncio
import logging

from backend.http_client import SharedHTTPClient
from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin
from backend.plugins.darkweb_helpers import (
    OSINT_CHANNELS,
    STEALER_CHANNELS,
    _attr_str,
    make_hit,
    search_telegram_channel,
)

logger = logging.getLogger(__name__)

_DDG_HTML_URL = "https://html.duckduckgo.com/html/?q=site%3At.me+{query}"


class TelegramOSINTPlugin(BasePlugin):
    """
    Searches public Telegram channels/groups for mentions of the query.

    Uses t.me/s/{channel} HTML previews for a curated list of OSINT and
    stealer-log channels, plus a best-effort DuckDuckGo site:t.me search
    (clearnet, no API key required).
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="telegram_osint",
            description="Searches public Telegram channels and groups for mentions of the target.",
            version="1.0.0",
            supported_entity_types=[
                TargetType.EMAIL,
                TargetType.USERNAME,
                TargetType.PHONE,
                TargetType.DOMAIN,
                TargetType.PERSON,
            ],
            required_api_keys=[],
            tags=["telegram", "chat", "social", "passive"],
            execution_cost=2.5,
            estimated_time=15,
        )

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        client = await SharedHTTPClient().get_client()

        results = await asyncio.gather(
            self._run_channel_previews(client, query),
            self._run_ddg_search(client, query),
            return_exceptions=True,
        )

        responses: list[PluginResponse] = []
        for res in results:
            if isinstance(res, Exception):
                logger.debug(f"telegram_osint source failed: {res}")
            elif isinstance(res, PluginResponse):
                responses.append(res)
        return responses

    async def _run_channel_previews(self, client, query: str) -> PluginResponse | None:
        channels = OSINT_CHANNELS + STEALER_CHANNELS
        channel_results = await asyncio.gather(
            *(search_telegram_channel(client, ch, query) for ch in channels),
            return_exceptions=True,
        )
        hits: list[dict] = []
        for res in channel_results:
            if isinstance(res, list):
                hits.extend(res)
        if not hits:
            return None
        return PluginResponse(
            provider=self.metadata.name,
            entity_type=TargetType.USERNAME,
            confidence=0.75,
            evidence=hits,
            raw={"source": "telegram_channel_previews", "query": query, "hits": len(hits)},
        )

    async def _run_ddg_search(self, client, query: str) -> PluginResponse | None:
        try:
            from bs4 import BeautifulSoup

            resp = await client.get(
                _DDG_HTML_URL.format(query=query),
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
            )
            if resp.status_code != 200:
                return None

            soup = BeautifulSoup(resp.text, "html.parser")
            hits: list[dict] = []
            for result in soup.select(".result")[:10]:
                link_el = result.select_one("a.result__a")
                if not link_el:
                    continue
                title = link_el.get_text(" ", strip=True)
                url = _attr_str(link_el.get("href"))
                snippet_el = result.select_one(".result__snippet")
                snippet = snippet_el.get_text(" ", strip=True) if snippet_el else ""
                if not title or not url or "t.me" not in url:
                    continue
                hits.append(
                    make_hit(
                        source="duckduckgo_tme",
                        category="telegram",
                        title=title,
                        snippet=snippet,
                        url=url,
                        severity="info",
                    )
                )
            if not hits:
                return None
            return PluginResponse(
                provider=self.metadata.name,
                entity_type=TargetType.USERNAME,
                confidence=0.5,
                evidence=hits,
                raw={"source": "duckduckgo_site_tme", "query": query, "hits": len(hits)},
            )
        except Exception as e:
            logger.debug(f"DuckDuckGo t.me search failed: {e}")
            return None
