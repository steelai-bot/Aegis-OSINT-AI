import asyncio
import hashlib
import logging
import os

from backend.http_client import SharedHTTPClient
from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin
from backend.plugins.darkweb_helpers import (
    STEALER_CHANNELS,
    make_hit,
    normalize_phone_digits,
    search_paid_apis,
    search_psbdmp,
    search_telegram_channel,
)

logger = logging.getLogger(__name__)

_HIBP_BASE = "https://haveibeenpwned.com/api/v3"
_HIBP_UA = "Aegis-OSINT-AI/2.0"


class ExposedCredentialsPlugin(BasePlugin):
    """
    Finds exposed credentials (emails, passwords, phone numbers) in breach
    databases, paste sites and stealer-log channels.

    Works with zero API keys (psbdmp, Telegram channel previews, k-anonymity
    password check) and automatically enriches results when HIBP_API_KEY or
    paid aggregator keys (Dehashed/LeakCheck/Snusbase) are configured.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="exposed_credentials",
            description="Scans breach databases, paste sites and stealer channels for exposed credentials (emails, passwords, phones).",
            version="1.1.0",
            supported_entity_types=[TargetType.EMAIL, TargetType.PHONE, TargetType.USERNAME],
            required_api_keys=[],
            tags=["credentials", "passive", "dark_web", "breached"],
            execution_cost=3.0,
            estimated_time=15,
        )

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        client = await SharedHTTPClient().get_client()

        tasks = [
            self._run_psbdmp(client, query),
            self._run_paid(client, query),
        ]
        if target_type == TargetType.EMAIL:
            tasks.append(self._run_kanonymity(client, query))
            if os.getenv("HIBP_API_KEY"):
                tasks.append(self._run_hibp_pastes(client, query))
        if target_type in (TargetType.USERNAME, TargetType.EMAIL):
            tasks.append(self._run_telegram(client, query))
        if target_type == TargetType.PHONE:
            tasks.append(self._run_phone_info(query))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        responses: list[PluginResponse] = []
        for res in results:
            if isinstance(res, Exception):
                logger.debug(f"exposed_credentials source failed: {res}")
            elif isinstance(res, PluginResponse):
                responses.append(res)
        return responses

    async def _run_psbdmp(self, client, query: str) -> PluginResponse | None:
        hits = await search_psbdmp(client, query)
        if not hits:
            return None
        return PluginResponse(
            provider=self.metadata.name,
            entity_type=TargetType.LEAK,
            confidence=0.8,
            evidence=hits,
            raw={"source": "psbdmp", "query": query, "hits": len(hits)},
        )

    async def _run_telegram(self, client, query: str) -> PluginResponse | None:
        channel_results = await asyncio.gather(
            *(search_telegram_channel(client, ch, query, source="stealer_channel") for ch in STEALER_CHANNELS),
            return_exceptions=True,
        )
        hits: list[dict] = []
        for res in channel_results:
            if isinstance(res, list):
                hits.extend(res)
        if not hits:
            return None
        for hit in hits:
            hit["severity"] = "critical"
        return PluginResponse(
            provider=self.metadata.name,
            entity_type=TargetType.LEAK,
            confidence=0.85,
            evidence=hits,
            raw={"source": "telegram_stealer_channels", "query": query, "hits": len(hits)},
        )

    async def _run_hibp_pastes(self, client, email: str) -> PluginResponse | None:
        try:
            resp = await client.get(
                f"{_HIBP_BASE}/pasteaccount/{email}",
                headers={"hibp-api-key": os.getenv("HIBP_API_KEY", ""), "User-Agent": _HIBP_UA},
            )
            if resp.status_code != 200:
                return None
            pastes = resp.json()
            if not isinstance(pastes, list) or not pastes:
                return None
            hits = []
            for paste in pastes[:20]:
                if not isinstance(paste, dict):
                    continue
                source = paste.get("Source") or "unknown"
                paste_id = paste.get("Id") or ""
                hits.append(make_hit(
                    source="hibp_pastes",
                    category="paste",
                    title=f"Paste on {source}: {paste.get('Title') or paste_id}",
                    snippet=f"Email found in {source} paste ({paste.get('EmailCount', '?')} emails).",
                    url=f"https://pastebin.com/{paste_id}" if source == "Pastebin" else None,
                    download_url=f"https://pastebin.com/raw/{paste_id}" if source == "Pastebin" and paste_id else None,
                    date=paste.get("Date"),
                    severity="warning",
                ))
            return PluginResponse(
                provider=self.metadata.name,
                entity_type=TargetType.EMAIL,
                confidence=0.85,
                evidence=hits,
                raw={"source": "hibp_pasteaccount", "email": email, "paste_count": len(hits)},
            )
        except Exception as e:
            logger.debug(f"HIBP pastes lookup failed: {e}")
            return None

    async def _run_kanonymity(self, client, email: str) -> PluginResponse | None:
        try:
            digest = hashlib.sha1(email.encode()).hexdigest().upper()
            prefix, suffix = digest[:5], digest[5:]
            resp = await client.get(f"https://api.pwnedpasswords.com/range/{prefix}")
            if resp.status_code != 200:
                return None
            for line in resp.text.splitlines():
                parts = line.split(":")
                if len(parts) == 2 and parts[0] == suffix:
                    count = int(parts[1])
                    return PluginResponse(
                        provider=self.metadata.name,
                        entity_type=TargetType.EMAIL,
                        confidence=0.8,
                        evidence=[make_hit(
                            source="pwnedpasswords",
                            category="breach",
                            title=f"Email hash seen {count:,} times in breach corpus",
                            snippet="Credential material associated with this email appears in known breach password lists.",
                            url="https://haveibeenpwned.com/",
                            severity="critical" if count > 100 else "warning",
                        )],
                        raw={"source": "pwnedpasswords_range", "count": count},
                    )
            return None
        except Exception as e:
            logger.debug(f"k-anonymity check failed: {e}")
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

    async def _run_phone_info(self, phone: str) -> PluginResponse | None:
        normalized = normalize_phone_digits(phone)
        if not normalized:
            return None
        return PluginResponse(
            provider=self.metadata.name,
            entity_type=TargetType.PHONE,
            confidence=0.3,
            evidence=[make_hit(
                source="exposed_credentials",
                category="breach",
                title="Phone breach scan limited without paid keys",
                snippet=(
                    f"Normalized number: {normalized}. Free sources do not index phone breaches; "
                    "configure DEHASHED_API_KEY, LEAKCHECK_API_KEY or SNUSBASE_API_KEY for deep phone lookup."
                ),
                severity="info",
            )],
            raw={"phone": normalized, "limited": True},
        )
