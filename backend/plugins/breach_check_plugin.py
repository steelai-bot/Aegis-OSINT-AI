import asyncio
import hashlib
import logging
import os

from backend.http_client import SharedHTTPClient
from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin
from backend.plugins.darkweb_helpers import make_hit, search_paid_apis

logger = logging.getLogger(__name__)

_HIBP_BASE = "https://haveibeenpwned.com/api/v3"
_HIBP_UA = "Aegis-OSINT-AI/2.0"


class BreachCheckPlugin(BasePlugin):
    """
    Checks whether an email/phone/username appears in known data breaches.

    With HIBP_API_KEY: full HaveIBeenPwned v3 breachedaccount + pasteaccount
    lookups (breach names, dates, data classes, paste links with raw download
    URLs for Pastebin). Without a key: falls back to the free k-anonymity
    password-range check and paid aggregators (Dehashed/LeakCheck/Snusbase)
    when their keys are configured.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="breach_check",
            description="Checks emails, phones and usernames against HaveIBeenPwned and breach aggregators.",
            version="1.0.0",
            supported_entity_types=[TargetType.EMAIL, TargetType.PHONE, TargetType.USERNAME],
            required_api_keys=[],
            tags=["breach", "hibp", "credentials", "passive"],
            execution_cost=2.0,
            estimated_time=15,
        )

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        client = await SharedHTTPClient().get_client()
        responses: list[PluginResponse] = []

        tasks = []
        if target_type == TargetType.EMAIL:
            if os.getenv("HIBP_API_KEY"):
                tasks.extend([
                    self._run_hibp_breaches(client, query),
                    self._run_hibp_pastes(client, query),
                ])
            else:
                tasks.append(self._run_kanonymity(client, query))
        tasks.append(self._run_paid(client, query))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, Exception):
                logger.debug(f"breach_check source failed: {res}")
            elif isinstance(res, PluginResponse):
                responses.append(res)

        if not responses and target_type in (TargetType.PHONE, TargetType.USERNAME):
            responses.append(PluginResponse(
                provider=self.metadata.name,
                entity_type=target_type,
                confidence=0.3,
                evidence=[make_hit(
                    source="breach_check",
                    category="breach",
                    title="No free breach source available for this target type",
                    snippet=(
                        "Phone/username breach lookups need HIBP_API_KEY (email only), "
                        "DEHASHED_API_KEY, LEAKCHECK_API_KEY or SNUSBASE_API_KEY. "
                        "Configure one in Settings to enable deep breach search."
                    ),
                    severity="info",
                )],
                raw={"query": query, "target_type": target_type.value, "limited": True},
            ))

        return responses

    async def _run_hibp_breaches(self, client, email: str) -> PluginResponse | None:
        try:
            resp = await client.get(
                f"{_HIBP_BASE}/breachedaccount/{email}",
                params={"truncateResponse": "false"},
                headers={"hibp-api-key": os.getenv("HIBP_API_KEY", ""), "User-Agent": _HIBP_UA},
            )
            if resp.status_code == 404:
                return None  # not pwned
            if resp.status_code == 401:
                return PluginResponse(
                    provider=self.metadata.name,
                    entity_type=TargetType.EMAIL,
                    confidence=0.3,
                    evidence=[make_hit(
                        source="hibp",
                        category="breach",
                        title="HIBP API key rejected (401)",
                        snippet="The configured HIBP_API_KEY was rejected. Check the key in Settings.",
                        severity="warning",
                    )],
                    raw={"error": "unauthorized"},
                )
            if resp.status_code != 200:
                logger.debug(f"HIBP breaches returned {resp.status_code}")
                return None

            breaches = resp.json()
            if not isinstance(breaches, list) or not breaches:
                return None

            hits = []
            for breach in breaches[:25]:
                if not isinstance(breach, dict):
                    continue
                name = breach.get("Name") or breach.get("Title") or "Unknown breach"
                data_classes = breach.get("DataClasses") or []
                hits.append(make_hit(
                    source="hibp",
                    category="breach",
                    title=f"HIBP breach: {name}",
                    snippet=(
                        f"Exposed data: {', '.join(data_classes[:8])}. "
                        f"Accounts affected: {breach.get('PwnCount', '?'):,}"
                        if isinstance(breach.get("PwnCount"), int)
                        else f"Exposed data: {', '.join(data_classes[:8])}"
                    ),
                    url=f"https://haveibeenpwned.com/PwnedWebsites#{name}",
                    date=breach.get("BreachDate"),
                    severity="critical",
                    domain=breach.get("Domain"),
                    verified=breach.get("IsVerified"),
                ))
            return PluginResponse(
                provider=self.metadata.name,
                entity_type=TargetType.EMAIL,
                confidence=0.95,
                evidence=hits,
                raw={"source": "hibp_breachedaccount", "email": email, "breach_count": len(hits)},
            )
        except Exception as e:
            logger.debug(f"HIBP breaches lookup failed: {e}")
            return None

    async def _run_hibp_pastes(self, client, email: str) -> PluginResponse | None:
        try:
            # HIBP rate limit: 1 request per 1.5s across the account endpoints
            await asyncio.sleep(1.6)
            resp = await client.get(
                f"{_HIBP_BASE}/pasteaccount/{email}",
                headers={"hibp-api-key": os.getenv("HIBP_API_KEY", ""), "User-Agent": _HIBP_UA},
            )
            if resp.status_code in (404, 401):
                return None
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
                url = paste.get("Source") and f"https://pastebin.com/{paste_id}" if source == "Pastebin" else None
                download_url = f"https://pastebin.com/raw/{paste_id}" if source == "Pastebin" and paste_id else None
                hits.append(make_hit(
                    source="hibp_pastes",
                    category="paste",
                    title=f"Paste on {source}: {paste.get('Title') or paste_id}",
                    snippet=f"Email found in {source} paste ({paste.get('EmailCount', '?')} emails in paste).",
                    url=url,
                    download_url=download_url,
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
        """Free k-anonymity check: is the email's SHA1 in the pwned-passwords corpus."""
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
                            title=f"Email hash appears {count:,} times in pwned-passwords corpus",
                            snippet=(
                                "Free k-anonymity check (no HIBP_API_KEY configured). "
                                "Add HIBP_API_KEY in Settings for full breach names, dates and paste links."
                            ),
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
        for hit in hits:
            hit["type"] = "breach"
        return PluginResponse(
            provider=self.metadata.name,
            entity_type=TargetType.EMAIL,
            confidence=0.95,
            evidence=hits,
            raw={"source": "paid_breach_apis", "query": query, "hits": len(hits)},
        )
