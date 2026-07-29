import asyncio
import logging
from urllib.parse import quote

from backend.http_client import SharedHTTPClient
from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin

logger = logging.getLogger(__name__)


class WaybackPlugin(BasePlugin):
    """
    Plugin for querying the Internet Archive Wayback Machine.
    Discovers historical snapshots and recent captures for a domain.
    Uses the public CDX and Availability APIs - no API key required.
    """

    CDX_URL = "https://web.archive.org/cdx/search/cdx"
    AVAILABILITY_URL = "https://archive.org/wayback/available"
    MAX_CAPTURES = 25

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="wayback_machine",
            description="Retrieves historical snapshots and recent captures of a domain from the Wayback Machine.",
            supported_entity_types=[TargetType.DOMAIN, TargetType.NZ_DOMAIN, TargetType.SUBDOMAIN],
            tags=["archive", "passive", "history"],
            execution_cost=1.5,
            estimated_time=6,
        )

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        domain = query.strip().lower()
        if "." not in domain:
            return []

        client = await SharedHTTPClient().get_client()

        latest_task = self._get_latest_snapshot(client, domain)
        captures_task = self._get_recent_captures(client, domain)
        latest, captures = await asyncio.gather(latest_task, captures_task)

        evidence: list[dict] = []
        raw: dict = {"query": domain}

        if latest:
            evidence.append({
                "type": "latest_snapshot",
                "url": latest.get("url"),
                "timestamp": latest.get("timestamp"),
                "status": latest.get("status"),
            })
            raw["latest_snapshot"] = latest

        if captures:
            evidence.append({
                "type": "recent_captures",
                "capture_count": len(captures),
                "captures": captures,
            })
            raw["recent_captures"] = captures

        if not evidence:
            return []

        return [PluginResponse(
            provider=self.metadata.name,
            entity_type=target_type,
            confidence=0.85,
            evidence=evidence,
            raw=raw,
        )]

    async def _get_latest_snapshot(self, client, domain: str) -> dict | None:
        """Query the Availability API for the closest snapshot."""
        try:
            resp = await client.get(f"{self.AVAILABILITY_URL}?url={quote(domain)}")
            if resp.status_code == 200:
                data = resp.json()
                snapshot = data.get("archived_snapshots", {}).get("closest", {})
                if snapshot.get("available"):
                    return {
                        "url": snapshot.get("url"),
                        "timestamp": snapshot.get("timestamp"),
                        "status": snapshot.get("status"),
                    }
        except Exception as e:
            logger.error(f"WaybackPlugin availability lookup failed for {domain}: {e}")
        return None

    async def _get_recent_captures(self, client, domain: str) -> list[dict]:
        """Query the CDX API for the most recent captures of the domain."""
        params = (
            f"url={quote(domain)}&output=json&fl=timestamp,original,statuscode,mimetype"
            f"&filter=statuscode:200&collapse=digest&limit={self.MAX_CAPTURES}&from=2015"
        )
        try:
            resp = await client.get(f"{self.CDX_URL}?{params}")
            if resp.status_code == 200:
                data = resp.json()
                if not isinstance(data, list) or len(data) < 2:
                    return []
                header, rows = data[0], data[1:]
                captures = []
                for row in rows[-self.MAX_CAPTURES:]:
                    if isinstance(row, list) and len(row) == len(header):
                        captures.append(dict(zip(header, row, strict=False)))
                return captures
        except Exception as e:
            logger.error(f"WaybackPlugin CDX lookup failed for {domain}: {e}")
        return []
