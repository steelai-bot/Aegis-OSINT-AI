import hashlib
import logging

from backend.http_client import SharedHTTPClient
from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin

logger = logging.getLogger(__name__)


class GravatarPlugin(BasePlugin):
    """
    Email -> Gravatar profile lookup (free, no API key).

    Gravatar profiles frequently reveal the owner's display name, location,
    short bio and linked accounts (WordPress, GitHub, X, etc.) - high-value
    pivots for person-centric investigations.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="gravatar_lookup",
            description=(
                "Resolves an email address to its public Gravatar profile "
                "(display name, location, linked accounts)."
            ),
            supported_entity_types=[TargetType.EMAIL, TargetType.PERSON],
            tags=["email", "identity", "social", "passive"],
            execution_cost=0.5,
            estimated_time=3,
        )

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        email = query.strip().lower()
        if "@" not in email:
            return []

        # Gravatar uses SHA-256 for new profiles; MD5 remains for legacy lookups
        sha256 = hashlib.sha256(email.encode()).hexdigest()
        client = await SharedHTTPClient().get_client()

        profile = None
        for digest in (sha256, hashlib.md5(email.encode()).hexdigest()):  # noqa: S324
            try:
                resp = await client.get(
                    f"https://www.gravatar.com/{digest}.json",
                    headers={"User-Agent": "Aegis-OSINT/1.0"},
                )
                if resp.status_code == 200:
                    entries = resp.json().get("entry", [])
                    if entries:
                        profile = entries[0]
                        break
            except Exception as e:
                logger.debug(f"GravatarPlugin request error: {e}")

        if not profile:
            return []

        accounts = [
            {"platform": a.get("name"), "username": a.get("username"), "url": a.get("url")}
            for a in profile.get("accounts", [])
            if isinstance(a, dict)
        ]
        urls = [u.get("value") for u in profile.get("urls", []) if isinstance(u, dict)]

        evidence: list[dict] = [
            {
                "type": "gravatar_profile",
                "display_name": profile.get("displayName"),
                "preferred_username": profile.get("preferredUsername"),
                "location": profile.get("currentLocation"),
                "about": (profile.get("aboutMe") or "")[:500],
                "profile_url": profile.get("profileUrl"),
                "avatar_url": profile.get("thumbnailUrl"),
                "accounts": accounts,
                "urls": [u for u in urls if u],
            }
        ]

        return [
            PluginResponse(
                provider=self.metadata.name,
                entity_type=TargetType.EMAIL,
                confidence=0.85,
                evidence=evidence,
                raw={"email": email, "profile": profile},
            )
        ]
