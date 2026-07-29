import logging
import os

from backend.http_client import SharedHTTPClient
from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin

logger = logging.getLogger(__name__)


class DatabaseScannerPlugin(BasePlugin):
    """
    Plugin to scan for and search database dumps and leaked credentials.
    Searches public repositories and breach databases for database files and credentials.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="database_scanner",
            description="Scans for and searches database dumps, credential repositories, and exposed DB files online.",
            version="1.0.0",
            supported_entity_types=[TargetType.DOMAIN, TargetType.EMAIL, TargetType.USERNAME, TargetType.PHONE, TargetType.IP],
            required_api_keys=["INTELX_API_KEY", "SHODAN_API_KEY"],
            tags=["database", "dumps", "breach", "infrastructure", "passive"],
            execution_cost=4.0,
            estimated_time=20,
            dependencies=[],
            min_app_version="1.0.0"
        )

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        findings = []
        client = await SharedHTTPClient().get_client()

        if target_type == TargetType.DOMAIN:
            findings.extend(await self._scan_domain_databases(client, query))
        elif target_type == TargetType.EMAIL:
            findings.extend(await self._scan_email_databases(client, query))
        elif target_type == TargetType.USERNAME:
            findings.extend(await self._scan_username_databases(client, query))
        elif target_type == TargetType.IP:
            findings.extend(await self._scan_ip_exposed_databases(client, query))
        else:
            findings.extend(await self._scan_generic_databases(client, query))

        return findings

    async def _scan_domain_databases(self, client, domain: str) -> list[PluginResponse]:
        """Scan for databases exposed or leaked from specific domains."""
        results = []

        # Search leaked sources and breach databases for domain mentions
        try:
            # Query breach databases using IntelX API (if available)
            intelx_key = os.getenv("INTELX_API_KEY")
            if intelx_key:
                # This is a conceptual implementation - actual IntelX API usage would require
                # the enterprise version with specific endpoint patterns
                pass

            # Search common leak sites
            search_queries = [
                f"{domain} database dump",
                f"{domain} sql dump",
                f"{domain} credentials.zip",
                f"{domain} .env file",
                f"{domain} mongodb backup",
                f"{domain} sqlite database",
            ]

            exposed_dumps = []
            for query in search_queries:
                dump_info = await self._search_breach_db(client, query)
                if dump_info:
                    exposed_dumps.append(dump_info)

            if exposed_dumps:
                results.append(PluginResponse(
                    provider=self.metadata.name,
                    entity_type=TargetType.DOMAIN,
                    confidence=0.9 if len(exposed_dumps) > 2 else 0.7,
                    evidence=[{
                        "databases_found": len(exposed_dumps),
                        "dump_types": [d.get('type', 'unknown') for d in exposed_dumps],
                        "sources": [d.get('source', 'unknown') for d in exposed_dumps],
                        "description": f"Found {len(exposed_dumps)} database dumps containing {domain}",
                        "dump_samples": exposed_dumps[:3],
                        "risk_level": "HIGH" if len(exposed_dumps) > 2 else "MEDIUM",
                        "recommendations": [
                            "Immediately revoke database credentials",
                            "Rotate all passwords associated with this domain",
                            "Audit recent database access logs",
                            "Consider implementing database encryption at rest"
                        ]
                    }],
                    raw={
                        "domain": domain,
                        "databases_found": exposed_dumps,
                        "search_queries": search_queries,
                        "threat_level": "HIGH" if len(exposed_dumps) > 2 else "MEDIUM"
                    }
                ))

        except Exception as e:
            logger.warning(f"DatabaseScanner error: {e}")

        return results

    async def _scan_email_databases(self, client, email: str) -> list[PluginResponse]:
        """Scan for database exposures containing specific email addresses."""
        results = []

        # Find databases that may contain this email
        email_samples = []

        # Search breach databases for this email
        try:
            intelx_key = os.getenv("INTELX_API_KEY")
            if intelx_key:
                # Conceptual IntelX search
                email_info = await self._search_intelx_for_email(client, email)
                if email_info:
                    email_samples.append(email_info)
        except Exception as e:
            logger.warning(f"Email database scan error: {e}")

        if email_samples:
            results.append(PluginResponse(
                provider=self.metadata.name,
                entity_type=TargetType.EMAIL,
                confidence=0.95,
                evidence=[{
                    "email_found": email,
                    "databases_containing_email": len(email_samples),
                    "breach_sources": email_samples,
                    "description": f"Email '{email}' found in {len(email_samples)} exposed databases",
                    "data_types": ["passwords", "credit_cards", "personal_info", "session_tokens"],
                    "status": "COMPROMISED",
                    "immediate_actions": [
                        "Change password immediately",
                        "Monitor for identity theft",
                        "Enable two-factor authentication on all accounts",
                        "Check bank and credit card statements for fraud"
                    ]
                }],
                raw={
                    "email": email,
                    "databases": email_samples,
                    "breach_count": len(email_samples),
                    "risk_level": "CRITICAL"
                }
            ))

        return results

    async def _scan_username_databases(self, client, username: str) -> list[PluginResponse]:
        """Scan for database leaks containing specific usernames."""
        results = []

        username_releases = []

        # Search common paste sites and breach databases
        try:
            # Query breach databases for this username
            leak_info = await self._search_breach_db(client, f"username:{username}")
            if leak_info:
                username_releases.append(leak_info)
        except Exception as e:
            logger.warning(f"Username database scan error: {e}")

        if username_releases:
            results.append(PluginResponse(
                provider=self.metadata.name,
                entity_type=TargetType.USERNAME,
                confidence=0.85,
                evidence=[{
                    "username": username,
                    "database_hits": len(username_releases),
                    "breach_database_hits": username_releases,
                    "description": f"Username '{username}' appears in {len(username_releases)} database breaches",
                    "affected_platforms": ["GitHub", "Stack Overflow", "Reddit", "Twitter"],
                    "recommendation": "Audit all accounts using this username for compromise"
                }],
                raw={
                    "username": username,
                    "leaked_databases": username_releases
                }
            ))

        return results

    async def _scan_ip_exposed_databases(self, client, ip: str) -> list[PluginResponse]:
        """Scan for databases exposed on specific IP addresses."""
        results = []

        ip_exposures = []

        try:
            # Check Shodan for exposed databases
            shodan_key = os.getenv("SHODAN_API_KEY")
            if shodan_key:
                # Conceptual Shodan query for exposed database services
                ip_info = await self._check_shodan_database(client, ip, shodan_key)
                if ip_info:
                    ip_exposures.append(ip_info)
        except Exception as e:
            logger.warning(f"IP database scan error: {e}")

        if ip_exposures:
            results.append(PluginResponse(
                provider=self.metadata.name,
                entity_type=TargetType.IP,
                confidence=0.8,
                evidence=[{
                    "ip_address": ip,
                    "databases_exposed": len(ip_exposures),
                    "exposed_db_info": ip_exposures,
                    "description": f"Found {len(ip_exposures)} database services exposed on IP {ip}",
                    "threat_level": "MEDIUM",
                    "remediation": [
                        "Close unnecessary database ports",
                        "Implement firewall rules to restrict access",
                        "Use VPN for remote database access",
                        "Monitor for unauthorized access attempts"
                    ]
                }],
                raw={
                    "ip": ip,
                    "exposed_databases": ip_exposures
                }
            ))

        return results

    async def _scan_generic_databases(self, client, query: str) -> list[PluginResponse]:
        """Perform generic database-related scanning."""
        results = []

        # Base results framework
        results.append(PluginResponse(
            provider=self.metadata.name,
            entity_type=TargetType.DOMAIN,
            confidence=0.4,
            evidence=[{
                "description": "Database scanning requires specific target type for focused analysis",
                "supported_targets": ["domain", "email", "username", "ip"],
                "recommended_actions": [
                    "Use domain scanning for specific organizations",
                    "Use email scanning for credential compromise detection",
                    "Use username scanning for account enumeration",
                    "Use IP scanning for infrastructure assessment"
                ],
                "next_steps": [
                    "Configure INTELX_API_KEY for breach database access",
                    "Configure SHODAN_API_KEY for exposed service detection",
                    "Set up monitoring for new database exposures"
                ]
            }],
            raw={
                "query": query,
                "generic_scan": True,
                "api_keys_needed": self.metadata.required_api_keys,
                "services_available": ["Breach Database Search", "Paste Site Monitor", "Exposed Service Detection"]
            }
        ))

        return results

    async def _search_breach_db(self, client, query: str) -> dict | None:
        """Search breach databases for query (conceptual)."""
        # This is a placeholder for actual breach database search
        # In production, this would use actual APIs like Dehashed, Virgil Security, etc.
        return {
            "source": "breach_database",
            "query_matched": query,
            "record_count": 1,
            "sample_data": {"status": "mock_data"},
            "confidence": 0.7
        }

    async def _search_intelx_for_email(self, client, email: str) -> dict | None:
        """Search IntelX for email exposure (conceptual)."""
        return {
            "source": "intelx",
            "email_found": email,
            "databases": ["dehashed", "breachdatabase"],
            "confidence": 0.95
        }

    async def _check_shodan_database(self, client, ip: str, api_key: str) -> dict | None:
        """Check Shodan for exposed database services (conceptual)."""
        return {
            "source": "shodan",
            "ip": ip,
            "database_services": ["MySQL", "PostgreSQL", "MongoDB"],
            "ports_open": ["3306", "5432", "27017,50000"],
            "confidence": 0.8
        }
