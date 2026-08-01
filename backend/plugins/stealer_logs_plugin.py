import asyncio
import logging

from backend.http_client import SharedHTTPClient
from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin
from backend.plugins.darkweb_helpers import (
    AHMIA_CLEARNET_URL,
    AHMIA_ONION_URL,
    STEALER_CHANNELS,
    make_hit,
    parse_ahmia_results,
    search_paid_apis,
    search_psbdmp,
    search_telegram_channel,
)
from backend.tor_client import TorClient, TorUnavailableError

logger = logging.getLogger(__name__)


class StealerLogsPlugin(BasePlugin):
    """
    Searches info-stealer log sources for a query (email, username, phone, domain).

    Clearnet sources always run (psbdmp paste index, public Telegram stealer-log
    channel previews, Ahmia clearnet search, paid breach APIs when keys exist).
    When a local Tor proxy is reachable, the Ahmia .onion endpoint is queried too.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="stealer_logs",
            description="Searches info-stealer log aggregators, Telegram log channels and paste indexes for exposed credentials.",
            version="1.0.0",
            supported_entity_types=[
                TargetType.EMAIL,
                TargetType.USERNAME,
                TargetType.PHONE,
                TargetType.DOMAIN,
                TargetType.PERSON,
            ],
            required_api_keys=[],
            tags=["stealer-logs", "darkweb", "credentials", "passive"],
            execution_cost=3.0,
            estimated_time=20,
        )

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        client = await SharedHTTPClient().get_client()
        tor = TorClient.get_instance()
        tor_available = await tor.is_available()

        tasks = [
            self._run_psbdmp(client, query),
            self._run_telegram(client, query),
            self._run_ahmia_clearnet(client, query),
            self._run_paid(client, query),
        ]
        if tor_available:
            tasks.append(self._run_ahmia_onion(query))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        responses: list[PluginResponse] = []
        for res in results:
            if isinstance(res, Exception):
                logger.debug(f"stealer_logs source failed: {res}")
            elif isinstance(res, PluginResponse):
                responses.append(res)
        return responses

    async def _run_psbdmp(self, client, query: str) -> PluginResponse | None:
        hits = await search_psbdmp(client, query)
        if not hits:
            return None
        for hit in hits:
            hit["type"] = "stealer_log"
        return PluginResponse(
            provider=self.metadata.name,
            entity_type=TargetType.LEAK,
            confidence=0.8,
            evidence=hits,
            raw={"source": "psbdmp", "query": query, "hits": len(hits)},
        )

    async def _run_telegram(self, client, query: str) -> PluginResponse | None:
        channel_results = await asyncio.gather(
            *(
                search_telegram_channel(client, ch, query, source="stealer_channel")
                for ch in STEALER_CHANNELS
            ),
            return_exceptions=True,
        )
        hits: list[dict] = []
        for res in channel_results:
            if isinstance(res, list):
                hits.extend(res)
        if not hits:
            return None
        for hit in hits:
            hit["type"] = "stealer_log"
            hit["severity"] = "critical"
        return PluginResponse(
            provider=self.metadata.name,
            entity_type=TargetType.LEAK,
            confidence=0.85,
            evidence=hits,
            raw={"source": "telegram_stealer_channels", "query": query, "hits": len(hits)},
        )

    async def _run_ahmia_clearnet(self, client, query: str) -> PluginResponse | None:
        try:
            resp = await client.get(AHMIA_CLEARNET_URL.format(query=query))
            if resp.status_code != 200:
                return None
            hits = parse_ahmia_results(resp.text, source="ahmia", tor=False, category="stealer_log")
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
                hits = parse_ahmia_results(
                    resp.text, source="ahmia_onion", tor=True, category="stealer_log"
                )
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

    async def _run_paid(self, client, query: str) -> PluginResponse | None:
        hits = await search_paid_apis(client, query)
        if not hits:
            return None
        return PluginResponse(
            provider=self.metadata.name,
            entity_type=TargetType.LEAK,
            confidence=0.95,
            evidence=hits,
            raw={"source": "paid_breach_apis", "query": query, "hits": len(hits)},
        )

    # Keep make_hit import referenced for external users of this module
    _ = make_hit
