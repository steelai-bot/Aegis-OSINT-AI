"""
Shodan OSINT Plugin - Internet-wide scanner for IoT devices, servers, and services
Provides comprehensive device discovery, vulnerability detection, and service enumeration
"""

import logging
import os

from backend.http_client import EnhancedHTTPClient
from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin

logger = logging.getLogger(__name__)


class ShodanPlugin(BasePlugin):
    """
    Advanced Shodan integration for comprehensive internet scanning.
    Supports device search, host lookup, vulnerability search, and CVE matching.
    Uses enhanced HTTP client with caching and rate limiting.
    """

    def __init__(self):
        self._client: EnhancedHTTPClient | None = None
        self._api_key: str | None = None

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="shodan_scanner",
            description="Comprehensive Shodan scanner for IoT devices, open ports, vulnerabilities, and services",
            supported_entity_types=[TargetType.IP, TargetType.DOMAIN, TargetType.COMPANY],
            required_api_keys=["SHODAN_API_KEY"],
            tags=["shodan", "iot", "vulnerability", "passive"],
            execution_cost=2.0,
            estimated_time=8,
            version="2.0.0",
            min_app_version="1.5.0"
        )

    async def _get_client(self) -> EnhancedHTTPClient:
        """Get or initialize HTTP client"""
        if self._client is None:
            self._client = EnhancedHTTPClient()
            await self._client.initialize()
        return self._client

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        findings = []
        self._api_key = os.getenv("SHODAN_API_KEY")

        if not self._api_key:
            logger.warning("ShodanPlugin: SHODAN_API_KEY not configured")
            return []

        try:
            client = await self._get_client()
            base_url = "https://api.shodan.io"
            headers = {"Authorization": f"Bearer {self._api_key}"}

            if target_type == TargetType.IP:
                # Host lookup for specific IP
                findings.extend(await self._host_lookup(client, base_url, headers, query))
                # Search for related devices
                findings.extend(await self._ip_search(client, base_url, headers, query))

            elif target_type == TargetType.DOMAIN:
                # DNS resolution and domain search
                findings.extend(await self._domain_search(client, base_url, headers, query))

            elif target_type == TargetType.COMPANY:
                # Organization search
                findings.extend(await self._org_search(client, base_url, headers, query))

            # Vulnerability scan if CVEs found
            if any(f.evidence for f in findings if 'vulns' in str(f.raw)):
                findings.extend(await self._vuln_scan(client, base_url, headers, query))

        except Exception as e:
            logger.error(f"ShodanPlugin error: {e}", exc_info=True)

        return findings

    async def _host_lookup(
        self,
        client: EnhancedHTTPClient,
        base_url: str,
        headers: dict,
        ip: str
    ) -> list[PluginResponse]:
        """Detailed host information lookup"""
        try:
            url = f"{base_url}/shodan/host/{ip}"
            params = {"minify": False}

            resp = await client.get(
                url,
                headers=headers,
                params=params,
                use_cache=True,
                cache_ttl=3600.0  # Cache for 1 hour
            )

            if resp.status_code == 200:
                data = resp.json()
                evidence = {
                    "ip": data.get("ip_str"),
                    "ports": data.get("ports", []),
                    "hostnames": data.get("hostnames", []),
                    "country": data.get("country_name"),
                    "city": data.get("city"),
                    "org": data.get("org"),
                    "isp": data.get("isp"),
                    "os": data.get("os"),
                    "last_update": data.get("last_update"),
                    "vulnerabilities": data.get("vulns", {}).keys() if data.get("vulns") else []
                }

                # Extract services with details
                services = []
                for banner in data.get("data", []):
                    services.append({
                        "port": banner.get("port"),
                        "protocol": banner.get("transport"),
                        "service": banner.get("product"),
                        "version": banner.get("version"),
                        "banner": banner.get("data", "")[:500]  # Truncate long banners
                    })

                evidence["services"] = services

                confidence = 0.95 if data.get("ports") else 0.7

                return [PluginResponse(
                    provider=self.metadata.name,
                    entity_type=TargetType.IP,
                    confidence=confidence,
                    evidence=[evidence],
                    raw=data
                )]

        except Exception as e:
            logger.error(f"Shodan host lookup failed for {ip}: {e}")

        return []

    async def _ip_search(
        self,
        client: EnhancedHTTPClient,
        base_url: str,
        headers: dict,
        ip: str
    ) -> list[PluginResponse]:
        """Search for devices matching IP pattern"""
        try:
            url = f"{base_url}/shodan/host/search"
            params = {
                "query": f"ip:{ip}",
                "page": 1,
                "minify": False
            }

            resp = await client.get(
                url,
                headers=headers,
                params=params,
                use_cache=True,
                cache_ttl=1800.0
            )

            if resp.status_code == 200:
                data = resp.json()
                total = data.get("total", 0)

                evidence = {
                    "search_type": "ip",
                    "query": ip,
                    "total_results": total,
                    "matches": []
                }

                for match in data.get("matches", [])[:10]:  # Limit to 10 results
                    evidence["matches"].append({
                        "ip": match.get("ip_str"),
                        "ports": match.get("ports", []),
                        "country": match.get("geo", {}).get("country_name"),
                        "org": match.get("org")
                    })

                if total > 0:
                    return [PluginResponse(
                        provider=self.metadata.name,
                        entity_type=TargetType.IP,
                        confidence=0.85,
                        evidence=[evidence],
                        raw=data
                    )]

        except Exception as e:
            logger.error(f"Shodan IP search failed for {ip}: {e}")

        return []

    async def _domain_search(
        self,
        client: EnhancedHTTPClient,
        base_url: str,
        headers: dict,
        domain: str
    ) -> list[PluginResponse]:
        """Search for domain-related hosts"""
        try:
            url = f"{base_url}/dns/domain/{domain}"

            resp = await client.get(
                url,
                headers=headers,
                use_cache=True,
                cache_ttl=3600.0
            )

            if resp.status_code == 200:
                data = resp.json()

                evidence = {
                    "domain": domain,
                    "subdomains": [],
                    "record_types": set()
                }

                for record in data.get("data", []):
                    evidence["subdomains"].append(record.get("subdomain"))
                    evidence["record_types"].add(record.get("type"))

                evidence["record_types"] = list(evidence["record_types"])
                evidence["total_records"] = len(data.get("data", []))

                if evidence["subdomains"]:
                    return [PluginResponse(
                        provider=self.metadata.name,
                        entity_type=TargetType.DOMAIN,
                        confidence=0.9,
                        evidence=[evidence],
                        raw=data
                    )]

        except Exception as e:
            logger.error(f"Shodan domain search failed for {domain}: {e}")

        return []

    async def _org_search(
        self,
        client: EnhancedHTTPClient,
        base_url: str,
        headers: dict,
        org_name: str
    ) -> list[PluginResponse]:
        """Search for organization's internet presence"""
        try:
            url = f"{base_url}/shodan/host/search"
            params = {
                "query": f'org:"{org_name}"',
                "page": 1,
                "minify": False
            }

            resp = await client.get(
                url,
                headers=headers,
                params=params,
                use_cache=True,
                cache_ttl=1800.0
            )

            if resp.status_code == 200:
                data = resp.json()

                evidence = {
                    "organization": org_name,
                    "total_hosts": data.get("total", 0),
                    "unique_ports": set(),
                    "countries": set(),
                    "top_services": {}
                }

                for match in data.get("matches", [])[:20]:
                    for port in match.get("ports", []):
                        evidence["unique_ports"].add(port)

                    country = match.get("geo", {}).get("country_name", "Unknown")
                    evidence["countries"].add(country)

                    # Count services
                    for banner in match.get("data", []):
                        service = banner.get("product", "unknown")
                        evidence["top_services"][service] = evidence["top_services"].get(service, 0) + 1

                evidence["unique_ports"] = sorted(evidence["unique_ports"])
                evidence["countries"] = list(evidence["countries"])
                evidence["top_services"] = dict(
                    sorted(
                        evidence["top_services"].items(),
                        key=lambda x: x[1],
                        reverse=True
                    )[:10]
                )

                if data.get("total", 0) > 0:
                    return [PluginResponse(
                        provider=self.metadata.name,
                        entity_type=TargetType.COMPANY,
                        confidence=0.88,
                        evidence=[evidence],
                        raw=data
                    )]

        except Exception as e:
            logger.error(f"Shodan org search failed for {org_name}: {e}")

        return []

    async def _vuln_scan(
        self,
        client: EnhancedHTTPClient,
        base_url: str,
        headers: dict,
        query: str
    ) -> list[PluginResponse]:
        """Search for vulnerabilities associated with target"""
        try:
            url = f"{base_url}/shodan/host/search"
            params = {
                "query": f'vuln:{query}',
                "page": 1
            }

            resp = await client.get(
                url,
                headers=headers,
                params=params,
                use_cache=True,
                cache_ttl=900.0
            )

            if resp.status_code == 200:
                data = resp.json()

                evidence = {
                    "vulnerability_search": query,
                    "affected_hosts": data.get("total", 0),
                    "cve_details": []
                }

                for match in data.get("matches", [])[:5]:
                    vulns = match.get("vulns", {})
                    for cve, details in vulns.items():
                        evidence["cve_details"].append({
                            "cve": cve,
                            "verified": details.get("verified", False),
                            "references": details.get("references", [])[:3]
                        })

                if evidence["affected_hosts"] > 0:
                    return [PluginResponse(
                        provider=self.metadata.name,
                        entity_type=TargetType.UNKNOWN,
                        confidence=0.82,
                        evidence=[evidence],
                        raw=data
                    )]

        except Exception as e:
            logger.error(f"Shodan vulnerability scan failed: {e}")

        return []
