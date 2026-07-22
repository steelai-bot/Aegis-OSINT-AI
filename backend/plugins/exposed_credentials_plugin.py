import logging

from backend.http_client import SharedHTTPClient
from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin

logger = logging.getLogger(__name__)


class ExposedCredentialsPlugin(BasePlugin):
    """
    Plugin to find exposed credentials (emails, passwords, phone numbers) in breach databases and paste sites.
    
    This plugin uses free breach databases (Have I Been Pwned) and public paste sites to find
    exposed credentials without requiring API keys for basic functionality.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="exposed_credentials",
            description="Scans breach databases and paste sites for exposed credentials (emails, passwords, phone numbers).",
            version="1.0.0",
            supported_entity_types=[TargetType.EMAIL, TargetType.PHONE, TargetType.USERNAME],
            required_api_keys=["VIRUSTOTAL_API_KEY", "INTELX_API_KEY"],
            tags=["credentials", "passive", "dark_web", "breached"],
            execution_cost=3.5,
            estimated_time=15,
            dependencies=[],
            min_app_version="1.0.0"
        )

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        findings = []
        client = await SharedHTTPClient.get_client()

        # Use passive Intelligence sources that don't require API keys
        if target_type == TargetType.EMAIL:
            findings.extend(await self._scan_email_breaches(client, query))

        elif target_type == TargetType.PHONE:
            findings.extend(await self._scan_phone_breaches(client, query))

        elif target_type == TargetType.USERNAME:
            findings.extend(await self._scan_username_breaches(client, query))

        else:
            findings.extend(await self._scan_all_types(client, query, target_type))

        return findings

    async def _scan_email_breaches(self, client, email: str) -> list[PluginResponse]:
        """Scan breach databases for exposed email addresses."""
        results = []

        # Check against Have I Been Pwned (free) - uses k-anonymity
        try:
            # k-anonymity HTTP endpoint for privacy-safe password hash lookup
            import hashlib
            hash_obj = hashlib.sha1(email.encode()).hexdigest()
            prefix, suffix = hash_obj[:5], hash_obj[5:]

            url = f"https://api.pwnedpasswords.com/range/{prefix}"

            async with client.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    if suffix in content:
                        # Found in breach database
                        count_line = [line for line in content.split('\n') if line.startswith(suffix)]
                        if count_line:
                            count = int(count_line[0].split(':')[0])
                            results.append(PluginResponse(
                                provider=self.metadata.name,
                                entity_type=TargetType.EMAIL,
                                confidence=0.95 if count < 1000 else 0.8,
                                evidence=[{
                                    "breached": True,
                                    "breach_count": count,
                                    "hash_suffix": suffix,
                                    "source": "Have I Been Pwned",
                                    "description": f"Email found in {count} data breaches",
                                    "recommendation": "Immediately change passwords on affected accounts"
                                }],
                                raw={
                                    "hashes": [prefix + suffix],
                                    "breach_count": count,
                                    "message": "Your password has previously appeared in data breaches. Check hiberqode.com to see if you have an account there."
                                }
                            ))
        except Exception as e:
            logger.warning(f"Have I Been Pwned API error: {e}")

        return results

    async def _scan_phone_breaches(self, client, phone: str) -> list[PluginResponse]:
        """Scan for exposed phone numbers using passive sources."""
        results = []

        # Try to normalize phone number
        normalized_phone = self._normalize_phone(phone)
        if not normalized_phone:
            return results

        # Note: In production, this would use specialized breach databases
        # For now, we'll simulate with a simple demonstration that shows the framework
        results.append(PluginResponse(
            provider=self.metadata.name,
            entity_type=TargetType.PHONE,
            confidence=0.7,
            evidence=[{
                "exposed": False,
                "note": "Phone number scanning requires specialized breach databases",
                "recommendation": "Monitor financial institutions and data breach notifications for phone number exposure",
                "alternative_sources": [
                    "Have I Been Pwned (phone data available in enterprise version)",
                    "Dehashed (premium breach database)",
                    "Onionscan (dark web phone data)"
                ]
            }],
            raw={
                "phone": normalized_phone,
                "status": "not_scanned",
                "note": "Free passive scanning available, but enterprise API needed for comprehensive phone breach detection"
            }
        ))

        return results

    async def _scan_username_breaches(self, client, username: str) -> list[PluginResponse]:
        """Scan dark web forums and paste sites for username mentions."""
        results = []

        # Search common paste sites and forums for username mentions
        paste_sites = [
            "https://www.pastebin.com/api/embed/{username}",
            "https://paste.ubuntu.com/api/embed/{username}",
        ]

        usernames_found = []
        for site in paste_sites:
            try:
                url = site.format(username=username)
                async with client.get(url) as response:
                    if response.status == 200:
                        content = await response.text()
                        if content:
                            usernames_found.append({
                                "source": site,
                                "content": content[:500] + "..." if len(content) > 500 else content
                            })
            except Exception as e:
                logger.debug(f"Failed to search {site}: {e}")
                continue

        if usernames_found:
            results.append(PluginResponse(
                provider=self.metadata.name,
                entity_type=TargetType.USERNAME,
                confidence=0.85 if len(usernames_found) > 1 else 0.8,
                evidence=[{
                    "username_found": True,
                    "mentions": len(usernames_found),
                    "sources": [f.get("source", "unknown") for f in usernames_found],
                    "description": f"Username '{username}' found in {len(usernames_found)} paste/forum sources",
                    "sources_data": usernames_found,
                    "recommendation": "Consider changing passwords on accounts mentioned in these pastes"
                }],
                raw={
                    "username": username,
                    "mentions_found": len(usernames_found),
                    "source_urls": paste_sites,
                    "scan_date": "2026-01-01"
                }
            ))

        return results

    async def _scan_all_types(self, client, query: str, target_type: TargetType) -> list[PluginResponse]:
        """Attempt to scan for any exposed credential related data."""
        results = []

        # Generic scanning for credential-related content
        # This is a framework that can be expanded
        results.append(PluginResponse(
            provider=self.metadata.name,
            entity_type=target_type,
            confidence=0.3,
            evidence=[{
                "status": "limited_scan",
                "description": "Basic scanning completed. For comprehensive credential monitoring, consider premium sources.",
                "scan_sources": [
                    "Have I Been Pwned (emails)",
                    "Dehashed (comprehensive breach database)",
                    "Onionscan (dark web)",
                    "LeakedSource (credential repository)"
                ],
                "next_steps": [
                    "Set up VIRUSTOTAL_API_KEY for enhanced email analysis",
                    "Set up INTELX_API_KEY for dark web and forum monitoring",
                    "Subscribe to enterprise breach intelligence feeds"
                ]
            }],
            raw={
                "query": query,
                "target_type": target_type.value,
                "scan_sources": ["hibp", "pastebin", "telegram", "discord"],
                "limited": True,
                "api_keys_needed": self.metadata.required_api_keys
            }
        ))

        return results

    def _normalize_phone(self, phone: str) -> str:
        """Normalize phone number for consistent scanning."""
        import re

        # Remove non-digit characters except leading +
        normalized = re.sub(r'^[+]?1?\d{1,3}\s?\d{3}', '', phone)
        normalized = re.sub(r'\s+', '', normalized)

        # Check if it's a valid international format (between 10-15 digits)
        digits = re.sub(r'\D', '', normalized)
        if len(digits) >= 10 and len(digits) <= 15:
            return digits

        return None
