import asyncio
import logging
import os

from backend.http_client import SharedHTTPClient
from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin
from backend.plugins.darkweb_helpers import (
    AHMIA_CLEARNET_URL,
    AHMIA_ONION_URL,
    _attr_str,
    make_hit,
    parse_ahmia_results,
)
from backend.tor_client import TorClient, TorUnavailableError

logger = logging.getLogger(__name__)

_ONION_LIVE_SEARCH = "https://onion.live/?s={query}"


class DarkWebMonitorPlugin(BasePlugin):
    """
    Monitors dark-web forums and breach chatter for mentions of the query.

    Always searches clearnet-reachable sources (Ahmia clearnet, onion.live
    index, Google dorks when GOOGLE_SEARCH_API_KEY is set). When a local Tor
    proxy is reachable, also queries the Ahmia .onion endpoint for deeper
    forum coverage.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="darkweb_monitor",
            description="Searches dark-web forums, onion indexes and breach chatter for target mentions.",
            version="1.0.0",
            supported_entity_types=[
                TargetType.EMAIL,
                TargetType.USERNAME,
                TargetType.DOMAIN,
                TargetType.PHONE,
                TargetType.PERSON,
                TargetType.LEAK,
            ],
            required_api_keys=[],
            tags=["darkweb", "forums", "monitoring", "passive"],
            execution_cost=4.0,
            estimated_time=25,
        )

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        client = await SharedHTTPClient().get_client()
        tor = TorClient.get_instance()

        tasks = [
            self._run_ahmia_clearnet(client, query),
            self._run_onion_live(client, query),
            self._run_google_dorks(client, query),
        ]
        if await tor.is_available():
            tasks.append(self._run_ahmia_onion(query))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        responses: list[PluginResponse] = []
        for res in results:
            if isinstance(res, Exception):
                logger.debug(f"darkweb_monitor source failed: {res}")
            elif isinstance(res, PluginResponse):
                responses.append(res)
        return responses

    async def _run_ahmia_clearnet(self, client, query: str) -> PluginResponse | None:
        try:
            resp = await client.get(AHMIA_CLEARNET_URL.format(query=query))
            if resp.status_code != 200:
                return None
            hits = parse_ahmia_results(resp.text, source="ahmia", tor=False)
            if not hits:
                return None
            return PluginResponse(
                provider=self.metadata.name,
                entity_type=TargetType.LEAK,
                confidence=0.6,
                evidence=hits,
                raw={"source": "ahmia_clearnet", "query": query, "hits": len(hits)},
            )
        except Exception as e:
            logger.debug(f"Ahmia clearnet search failed: {e}")
            return None

    async def _run_ahmia_onion(self, query: str) -> PluginResponse | None:
        tor = TorClient.get_instance()
        try:
            async with await tor.get_client() as client:
                resp = await client.get(AHMIA_ONION_URL.format(query=query))
                if resp.status_code != 200:
                    return None
                hits = parse_ahmia_results(resp.text, source="ahmia_onion", tor=True)
                if not hits:
                    return None
                return PluginResponse(
                    provider=self.metadata.name,
                    entity_type=TargetType.LEAK,
                    confidence=0.75,
                    evidence=hits,
                    raw={"source": "ahmia_onion", "query": query, "hits": len(hits)},
                )
        except TorUnavailableError:
            return None
        except Exception as e:
            logger.debug(f"Ahmia onion search failed: {e}")
            return None

    async def _run_onion_live(self, client, query: str) -> PluginResponse | None:
        try:
            from bs4 import BeautifulSoup

            resp = await client.get(
                _ONION_LIVE_SEARCH.format(query=query),
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
            )
            if resp.status_code != 200:
                return None
            soup = BeautifulSoup(resp.text, "html.parser")
            hits: list[dict] = []
            for item in soup.select("div.list-group-item, article, .search-result")[:10]:
                link_el = item.select_one("a")
                if not link_el:
                    continue
                title = link_el.get_text(" ", strip=True)
                url = _attr_str(link_el.get("href"))
                if not title:
                    continue
                snippet_el = item.select_one("p")
                hits.append(make_hit(
                    source="onion_live",
                    category="forum_mention",
                    title=title,
                    snippet=snippet_el.get_text(" ", strip=True) if snippet_el else "",
                    url=url,
                    severity="info",
                ))
            if not hits:
                return None
            return PluginResponse(
                provider=self.metadata.name,
                entity_type=TargetType.LEAK,
                confidence=0.5,
                evidence=hits,
                raw={"source": "onion_live", "query": query, "hits": len(hits)},
            )
        except Exception as e:
            logger.debug(f"onion.live search failed: {e}")
            return None

    async def _run_google_dorks(self, client, query: str) -> PluginResponse | None:
        api_key = os.getenv("GOOGLE_SEARCH_API_KEY")
        cx = os.getenv("GOOGLE_SEARCH_CX")
        if not api_key or not cx:
            return None
        try:
            hits: list[dict] = []
            for dork in (f'"{query}" darknet forum', f'"{query}" breachforums OR "onion"'):
                try:
                    resp = await client.get(
                        "https://www.googleapis.com/customsearch/v1",
                        params={"key": api_key, "cx": cx, "q": dork, "num": 5},
                    )
                    if resp.status_code != 200:
                        continue
                    data = resp.json()
                    for item in data.get("items", [])[:5]:
                        if not isinstance(item, dict):
                            continue
                        hits.append(make_hit(
                            source="google_dork",
                            category="forum_mention",
                            title=item.get("title") or "",
                            snippet=item.get("snippet") or "",
                            url=item.get("link"),
                            severity="info",
                        ))
                except Exception as e:
                    logger.debug(f"Google dork '{dork}' failed: {e}")
            if not hits:
                return None
            return PluginResponse(
                provider=self.metadata.name,
                entity_type=TargetType.LEAK,
                confidence=0.5,
                evidence=hits,
                raw={"source": "google_darkweb_dorks", "query": query, "hits": len(hits)},
            )
        except Exception as e:
            logger.debug(f"Google dark-web dorks failed: {e}")
            return None
