import logging

from backend.http_client import SharedHTTPClient
from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin

logger = logging.getLogger(__name__)


class EmailRepPlugin(BasePlugin):
    """
    Email reputation and leak attribution via emailrep.io (free, no API key).

    Reports reputation, suspicious/malicious flags, breach & credential-leak
    references (WHERE the address leaked) and linked online profiles - key
    pivot material for person-centric investigations.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="emailrep_lookup",
            description=(
                "Queries emailrep.io for email reputation, breach/leak attribution "
                "and linked online profiles (free, keyless)."
            ),
            supported_entity_types=[TargetType.EMAIL, TargetType.PERSON],
            tags=["email", "identity", "breach", "passive"],
            execution_cost=0.5,
            estimated_time=3,
        )

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        email = query.strip().lower()
        if "@" not in email:
            return []

        client = await SharedHTTPClient().get_client()
        try:
            resp = await client.get(
                f"https://emailrep.io/{email}",
                headers={
                    "User-Agent": "Aegis-OSINT/1.0",
                    "Accept": "application/json",
                },
            )
            if resp.status_code == 429:
                logger.info("EmailRepPlugin rate-limited by emailrep.io")
                return []
            if resp.status_code != 200:
                return []
            data = resp.json()
        except Exception as e:
            logger.debug(f"EmailRepPlugin request error: {e}")
            return []

        details = data.get("details", {}) or {}
        profiles = data.get("profiles", []) or []

        leaked_sources: list[str] = []
        if details.get("data_breach"):
            leaked_sources.append("data_breach")
        if details.get("credentials_leaked"):
            leaked_sources.append("credentials_leaked")
        if details.get("credentials_leaked_recent"):
            leaked_sources.append("credentials_leaked_recent")
        if details.get("malicious_activity"):
            leaked_sources.append("malicious_activity")

        evidence: list[dict] = [
            {
                "type": "email_reputation",
                "email": email,
                "reputation": data.get("reputation"),
                "suspicious": data.get("suspicious"),
                "references": data.get("references"),
                "first_seen": data.get("first_seen"),
                "last_seen": data.get("last_seen"),
                "domain_reputation": details.get("domain_reputation"),
                "domain_exists": details.get("domain_exists"),
                "disposable": details.get("disposable"),
                "free_provider": details.get("free_provider"),
                "deliverable": details.get("deliverable"),
                "leaked_in": leaked_sources,
                "profiles": profiles,
            }
        ]

        severity_confidence = 0.8
        return [
            PluginResponse(
                provider=self.metadata.name,
                entity_type=TargetType.EMAIL,
                confidence=severity_confidence,
                evidence=evidence,
                raw=data,
            )
        ]
