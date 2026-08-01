import asyncio
import logging

from backend.http_client import SharedHTTPClient
from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin
from backend.plugins.darkweb_helpers import (
    AHMIA_ONION_URL,
    LEAK_INDEX_URLS,
    _attr_str,
    make_hit,
    parse_ahmia_results,
    search_psbdmp,
)
from backend.tor_client import TorClient, TorUnavailableError

logger = logging.getLogger(__name__)


class LeakedDBPlugin(BasePlugin):
    """
    Searches for leaked databases / dumps referencing the query.

    Sources: psbdmp dump index (with direct download links), clearnet leak
    listing indexes (onion.live), and - when a Tor proxy is available - Ahmia
    .onion searches for '{query} database dump' / '{query} combolist'.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="leaked_db",
            description="Searches leaked database and dump indexes for the target, with download links when published.",
            version="1.0.0",
            supported_entity_types=[
                TargetType.DOMAIN,
                TargetType.EMAIL,
                TargetType.USERNAME,
                TargetType.LEAK,
                TargetType.COMPANY,
            ],
            required_api_keys=[],
            tags=["database", "dumps", "leak", "darkweb", "passive"],
            execution_cost=3.5,
            estimated_time=20,
        )

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        client = await SharedHTTPClient().get_client()
        tor = TorClient.get_instance()

        tasks = [
            self._run_psbdmp_dumps(client, query),
            self._run_leak_indexes(client, query),
        ]
        if await tor.is_available():
            tasks.append(self._run_ahmia_dumps(query))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        responses: list[PluginResponse] = []
        for res in results:
            if isinstance(res, Exception):
                logger.debug(f"leaked_db source failed: {res}")
            elif isinstance(res, PluginResponse):
                responses.append(res)
        return responses

    async def _run_psbdmp_dumps(self, client, query: str) -> PluginResponse | None:
        hits = await search_psbdmp(client, query)
        if not hits:
            return None
        for hit in hits:
            hit["type"] = "database_dump"
            if query.lower() in (hit.get("title") or "").lower():
                hit["severity"] = "critical"
        return PluginResponse(
            provider=self.metadata.name,
            entity_type=TargetType.LEAK,
            confidence=0.8,
            evidence=hits,
            raw={"source": "psbdmp_dumps", "query": query, "hits": len(hits)},
        )

    async def _run_leak_indexes(self, client, query: str) -> PluginResponse | None:
        try:
            from bs4 import BeautifulSoup

            hits: list[dict] = []
            for url_template in LEAK_INDEX_URLS:
                try:
                    resp = await client.get(
                        url_template.format(query=query),
                        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
                    )
                    if resp.status_code != 200:
                        continue
                    soup = BeautifulSoup(resp.text, "html.parser")
                    for item in soup.select("div.list-group-item, article, .search-result")[:10]:
                        link_el = item.select_one("a")
                        if not link_el:
                            continue
                        title = link_el.get_text(" ", strip=True)
                        url = _attr_str(link_el.get("href"))
                        if not title:
                            continue
                        if url and url.startswith("/"):
                            from urllib.parse import urlparse

                            base = urlparse(url_template)
                            url = f"{base.scheme}://{base.netloc}{url}"
                        snippet_el = item.select_one("p")
                        hits.append(
                            make_hit(
                                source="leak_index",
                                category="database_dump",
                                title=title,
                                snippet=snippet_el.get_text(" ", strip=True) if snippet_el else "",
                                url=url,
                                severity="warning",
                            )
                        )
                except Exception as e:
                    logger.debug(f"Leak index {url_template} failed: {e}")
            if not hits:
                return None
            return PluginResponse(
                provider=self.metadata.name,
                entity_type=TargetType.LEAK,
                confidence=0.6,
                evidence=hits[:15],
                raw={"source": "leak_indexes", "query": query, "hits": len(hits)},
            )
        except Exception as e:
            logger.debug(f"Leak index search failed: {e}")
            return None

    async def _run_ahmia_dumps(self, query: str) -> PluginResponse | None:
        tor = TorClient.get_instance()
        try:
            async with await tor.get_client() as client:
                hits: list[dict] = []
                for term in (f'"{query}" database dump', f'"{query}" combolist'):
                    try:
                        resp = await client.get(AHMIA_ONION_URL.format(query=term))
                        if resp.status_code == 200:
                            hits.extend(
                                parse_ahmia_results(
                                    resp.text,
                                    source="ahmia_onion",
                                    tor=True,
                                    category="database_dump",
                                )
                            )
                    except Exception as e:
                        logger.debug(f"Ahmia dump search '{term}' failed: {e}")
                if not hits:
                    return None
                for hit in hits:
                    if query.lower() in (hit.get("title") or "").lower():
                        hit["severity"] = "critical"
                return PluginResponse(
                    provider=self.metadata.name,
                    entity_type=TargetType.LEAK,
                    confidence=0.7,
                    evidence=hits[:15],
                    raw={"source": "ahmia_onion_dumps", "query": query, "hits": len(hits)},
                )
        except TorUnavailableError:
            return None
        except Exception as e:
            logger.debug(f"Ahmia onion dump search failed: {e}")
            return None
