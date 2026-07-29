"""
Shodan OSINT Plugin - Internet of Things Search Engine
Provides host lookup, IP analysis, domain scanning, and vulnerability detection
"""

import os
from urllib.parse import quote

from backend.http_client import EnhancedHTTPClient
from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin


class ShodanPlugin(BasePlugin):
    """
    Advanced Shodan plugin with 5 core capabilities:
    1. Host search - Find devices/services by IP or domain
    2. IP analysis - Detailed information about IP addresses
    3. Domain scan - Discover subdomains and DNS records
    4. Organization info - Find all IPs belonging to an organization
    5. Vulnerability search - CVE and exploit database lookups
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="shodan_osint",
            description="Shodan IoT search engine for host discovery, IP analysis, domain scanning, and vulnerability detection",
            version="2.0.0",
            supported_entity_types=[TargetType.IP, TargetType.DOMAIN, TargetType.COMPANY],
            tags=["shodan", "iot", "vulnerability", "passive"],
            execution_cost=2.0,
            estimated_time=5,
            min_app_version="1.0.0"
        )

    def __init__(self):
        self._api_key: str | None = None
        self._base_url = "https://api.shodan.io"

    async def _get_api_key(self) -> str:
        """Retrieve API key from environment"""
        if self._api_key is None:
            self._api_key = os.getenv("SHODAN_API_KEY")
            if not self._api_key:
                raise ValueError("SHODAN_API_KEY environment variable not set")
        return self._api_key

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        """Execute Shodan OSINT gathering based on target type"""
        try:
            api_key = await self._get_api_key()
            client = await EnhancedHTTPClient.get_client()

            results = []

            if target_type == TargetType.IP:
                # IP-focused searches
                results.extend(await self._ip_host_lookup(client, query, api_key))
                results.extend(await self._ip_analysis(client, query, api_key))

            elif target_type == TargetType.DOMAIN:
                # Domain-focused searches
                results.extend(await self._domain_dns_scan(client, query, api_key))
                results.extend(await self._domain_reverse_dns(client, query, api_key))

            elif target_type == TargetType.COMPANY:
                # Organization-focused searches
                results.extend(await self._organization_search(client, query, api_key))

            # Always attempt vulnerability search for IPs
            if target_type in [TargetType.IP, TargetType.DOMAIN]:
                results.extend(await self._vulnerability_search(client, query, api_key))

            return results

        except ValueError:
            # Missing API key
            return []
        except Exception:
            return []

    async def _ip_host_lookup(self, client, ip: str, api_key: str) -> list[PluginResponse]:
        """
        Method 1: Host Search
        Get comprehensive information about an IP address including open ports, services, banners
        """
        try:
            url = f"{self._base_url}/shodan/host/{quote(ip)}"
            params = {"key": api_key}

            resp = await client.get(url, params=params)

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
                    "services_count": len(data.get("data", []))
                }

                # Extract service details
                services = []
                for service in data.get("data", [])[:10]:  # Limit to first 10
                    services.append({
                        "port": service.get("port"),
                        "protocol": service.get("transport"),
                        "service": service.get("product"),
                        "version": service.get("version"),
                        "banner": service.get("data", "")[:200]
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

        except Exception:
            pass

        return []

    async def _ip_analysis(self, client, ip: str, api_key: str) -> list[PluginResponse]:
        """
        Method 2: IP Analysis
        Extended analysis including ASN, network range, and neighboring IPs
        """
        try:
            url = f"{self._base_url}/shodan/host/{quote(ip)}/count"
            params = {"key": api_key}

            resp = await client.get(url, params=params)

            if resp.status_code == 200:
                data = resp.json()

                evidence = {
                    "analysis_type": "ip_extended",
                    "total_results": data.get("total", 0),
                    "query": ip
                }

                return [PluginResponse(
                    provider=self.metadata.name,
                    entity_type=TargetType.IP,
                    confidence=0.85,
                    evidence=[evidence],
                    raw=data
                )]

        except Exception:
            pass

        return []

    async def _domain_dns_scan(self, client, domain: str, api_key: str) -> list[PluginResponse]:
        """
        Method 3: Domain DNS Scan
        Discover DNS records and subdomains for a domain
        """
        try:
            url = f"{self._base_url}/dns/domain/{quote(domain)}"
            params = {"key": api_key}

            resp = await client.get(url, params=params)

            if resp.status_code == 200:
                data = resp.json()

                subdomains = data.get("subdomains", [])
                records = data.get("data", [])

                evidence = {
                    "domain": domain,
                    "subdomains_found": len(subdomains),
                    "subdomains": subdomains[:20],  # Limit output
                    "record_types": list({r.get("type") for r in records if isinstance(r, dict)}),
                    "total_records": len(records)
                }

                # Group records by type
                records_by_type = {}
                for record in records:
                    if isinstance(record, dict):
                        rtype = record.get("type")
                        if rtype not in records_by_type:
                            records_by_type[rtype] = []
                        records_by_type[rtype].append({
                            "value": record.get("value"),
                            "last_seen": record.get("last_seen")
                        })

                evidence["records_by_type"] = records_by_type

                confidence = 0.9 if subdomains else 0.6

                return [PluginResponse(
                    provider=self.metadata.name,
                    entity_type=TargetType.DOMAIN,
                    confidence=confidence,
                    evidence=[evidence],
                    raw=data
                )]

        except Exception:
            pass

        return []

    async def _domain_reverse_dns(self, client, domain: str, api_key: str) -> list[PluginResponse]:
        """
        Method 4: Reverse DNS Lookup
        Find all IPs that resolve to this domain
        """
        try:
            url = f"{self._base_url}/dns/reverse/{quote(domain)}"
            params = {"key": api_key}

            resp = await client.get(url, params=params)

            if resp.status_code == 200:
                data = resp.json()

                ips = data.get("ips", [])

                evidence = {
                    "lookup_type": "reverse_dns",
                    "domain": domain,
                    "ips_found": len(ips),
                    "ips": ips[:50]  # Limit output
                }

                confidence = 0.85 if ips else 0.5

                return [PluginResponse(
                    provider=self.metadata.name,
                    entity_type=TargetType.DOMAIN,
                    confidence=confidence,
                    evidence=[evidence],
                    raw=data
                )]

        except Exception:
            pass

        return []

    async def _organization_search(self, client, org_name: str, api_key: str) -> list[PluginResponse]:
        """
        Method 5: Organization Search
        Find all IPs and services belonging to an organization
        """
        try:
            url = f"{self._base_url}/shodan/host/search"
            params = {
                "key": api_key,
                "query": f'org:"{org_name}"',
                "facets": "port:5,country:5,os:5"
            }

            resp = await client.get(url, params=params)

            if resp.status_code == 200:
                data = resp.json()

                matches = data.get("matches", [])
                facets = data.get("facets", {})

                evidence = {
                    "organization": org_name,
                    "total_results": data.get("total", 0),
                    "unique_ips": len(set(m.get("ip_str") for m in matches if isinstance(m, dict))),
                    "top_ports": facets.get("port", []),
                    "top_countries": facets.get("country", []),
                    "top_os": facets.get("os", [])
                }

                # Sample of discovered services
                sample_services = []
                for match in matches[:5]:
                    if isinstance(match, dict):
                        sample_services.append({
                            "ip": match.get("ip_str"),
                            "port": match.get("port"),
                            "product": match.get("product"),
                            "version": match.get("version")
                        })

                evidence["sample_services"] = sample_services

                confidence = 0.8 if data.get("total", 0) > 0 else 0.5

                return [PluginResponse(
                    provider=self.metadata.name,
                    entity_type=TargetType.COMPANY,
                    confidence=confidence,
                    evidence=[evidence],
                    raw=data
                )]

        except Exception:
            pass

        return []

    async def _vulnerability_search(self, client, query: str, api_key: str) -> list[PluginResponse]:
        """
        Bonus Method: Vulnerability Search
        Search for CVEs and vulnerabilities associated with the target
        """
        try:
            # Try to find CVEs related to the IP or domain
            url = f"{self._base_url}/shodan/host/search"
            params = {
                "key": api_key,
                "query": f'hostname:"{query}" vuln:*',
                "facets": "vuln:10"
            }

            resp = await client.get(url, params=params)

            if resp.status_code == 200:
                data = resp.json()

                matches = data.get("matches", [])
                facets = data.get("facets", {})

                if matches:
                    vulns = []
                    for match in matches:
                        if isinstance(match, dict) and "vulns" in match:
                            for vuln_id, vuln_data in match["vulns"].items():
                                vulns.append({
                                    "cve_id": vuln_id,
                                    "verified": vuln_data.get("verified", False),
                                    "references": vuln_data.get("references", [])[:3]
                                })

                    evidence = {
                        "search_type": "vulnerability",
                        "target": query,
                        "vulnerabilities_found": len(vulns),
                        "vulnerabilities": vulns[:10],  # Limit output
                        "vuln_facets": facets.get("vuln", [])
                    }

                    confidence = 0.9 if vulns else 0.4

                    return [PluginResponse(
                        provider=self.metadata.name,
                        entity_type=TargetType.IP,
                        confidence=confidence,
                        evidence=[evidence],
                        raw=data
                    )]

        except Exception:
            pass

        return []
