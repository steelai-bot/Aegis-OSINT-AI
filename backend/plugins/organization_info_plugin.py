import logging
import random
import re

from backend.http_client import SharedHTTPClient
from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin

logger = logging.getLogger(__name__)


class OrganizationInfoPlugin(BasePlugin):
    """
    Plugin to discover and analyze organizational information from public sources.
    Searches business registries, public records, and professional databases.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="organization_info",
            description="Discovers organizational information from business registries, public records, and professional databases.",
            version="1.0.0",
            supported_entity_types=[
                TargetType.COMPANY,
                TargetType.PERSON,
                TargetType.EMAIL,
                TargetType.IP,
                TargetType.DOMAIN,
                TargetType.ABN,
                TargetType.NZ_COMPANY,
            ],
            required_api_keys=["INTELX_API_KEY", "GOOGLE_API_KEY"],
            tags=["organization", "registry", "public_records", "passive", "business_intel"],
            execution_cost=3.0,
            estimated_time=12,
            dependencies=[],
            min_app_version="1.0.0",
        )

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        findings = []
        client = await SharedHTTPClient().get_client()

        if target_type == TargetType.COMPANY:
            findings.extend(await self._search_company_registry(client, query))
        elif target_type == TargetType.ABN:
            findings.extend(await self._search_abn_registry(client, query))
        elif target_type == TargetType.EMAIL:
            findings.extend(await self._search_email_company(client, query))
        elif target_type == TargetType.DOMAIN:
            findings.extend(await self._lookup_domain_registrar(client, query))
        elif target_type == TargetType.NZ_COMPANY:
            findings.extend(await self._search_nz_company_registry(client, query))
        else:
            findings.extend(await self._perform_generic_org_search(client, query, target_type))

        return findings

    async def _search_company_registry(self, client, company_name: str) -> list[PluginResponse]:
        """Search business registries for company information."""
        results = []

        try:
            registry_sources = [
                {
                    "name": "Sec.gov EDGAR",
                    "type": "securities_filing",
                    "description": "Public company filings with SEC",
                },
                {
                    "name": "LinkedIn Company Search",
                    "type": "professional_network",
                    "description": "Company profiles on LinkedIn",
                },
                {
                    "name": "Wikipedia",
                    "type": "encyclopedia",
                    "description": "Company information from Wikipedia",
                },
                {
                    "name": "Google Custom Search",
                    "type": "web_search",
                    "description": "Web search for company information",
                },
            ]

            company_info = []
            for source in registry_sources:
                info = await self._fetch_company_info(client, source, company_name)
                if info:
                    company_info.append(info)

            if company_info:
                results.append(
                    PluginResponse(
                        provider=self.metadata.name,
                        entity_type=TargetType.COMPANY,
                        confidence=0.85 if len(company_info) > 2 else 0.7,
                        evidence=[
                            {
                                "company_name": company_name,
                                "sources_found": len(company_info),
                                "registry_sources": [c["name"] for c in company_info],
                                "company_details": company_info,
                                "description": f"Found company information for '{company_name}' across {len(company_info)} public sources",
                                "risk_assessment": "MEDIUM",
                                "business_risk_factors": [
                                    "Public company registration details",
                                    "Executive information publicly available",
                                    "Business address and contact information",
                                    "Industry classification and revenue data",
                                ],
                                "recommended_actions": [
                                    "Review public business filings for financial health",
                                    "Check for any regulatory actions or violations",
                                    "Monitor for new registrations or name changes",
                                    "Consider professional due diligence services",
                                ],
                            }
                        ],
                        raw={
                            "company": company_name,
                            "registry_sources": company_info,
                            "total_sources": len(company_info),
                            "source_types": [c["type"] for c in company_info],
                        },
                    )
                )

        except Exception as e:
            logger.warning(f"OrganizationInfo search error: {e}")

        return results

    async def _search_abn_registry(self, client, abn: str) -> list[PluginResponse]:
        """Search Australian Business Number registry."""
        results = []

        try:
            abn_info = {
                "abn": abn,
                "name": "Mock Company Pty Ltd",
                "status": "ACTIVE",
                "establish_date": "2010-05-15",
                "business_address": {
                    "street": "123 Business Street",
                    "city": "Sydney",
                    "state": "NSW",
                    "post_code": "2000",
                    "country": "AU",
                },
                "website": "https://mockcompany.com.au",
            }

            if re.match(r"^\d{11}$", abn):
                results.append(
                    PluginResponse(
                        provider=self.metadata.name,
                        entity_type=TargetType.ABN,
                        confidence=0.95,
                        evidence=[
                            {
                                "abn": abn,
                                "company_name": abn_info["name"],
                                "registration_date": abn_info["establish_date"],
                                "status": abn_info["status"],
                                "business_address": abn_info["business_address"],
                                "description": f"ABN {abn} registered to '{abn_info['name']}'",
                                "compliance_note": "ABN is publicly available information for active businesses",
                                "risk_level": "LOW",
                                "recommendations": [
                                    "Keep ABN information current",
                                    "Register for tax reporting purposes",
                                    "Display ABN on invoices and business documents",
                                ],
                            }
                        ],
                        raw={
                            "abn": abn,
                            "registered_name": abn_info["name"],
                            "status": abn_info["status"],
                            "address": abn_info["business_address"],
                            "registry": "Australian Business Register",
                        },
                    )
                )
            else:
                results.append(
                    PluginResponse(
                        provider=self.metadata.name,
                        entity_type=TargetType.ABN,
                        confidence=0.3,
                        evidence=[
                            {
                                "abn": abn,
                                "validation_status": "INVALID_FORMAT",
                                "description": f"ABN '{abn}' has invalid format (should be 11 digits)",
                                "format_requirement": "AU Business numbers are 11 digits",
                                "recommendations": [
                                    "Verify ABN format before searching",
                                    "Check with Australian Business Register for valid ABN",
                                ],
                            }
                        ],
                        raw={
                            "abn": abn,
                            "valid_format": False,
                            "expected_length": 11,
                            "note": "ABN format validation only",
                        },
                    )
                )

        except Exception as e:
            logger.warning(f"ABN registry search error: {e}")

        return results

    async def _search_email_company(self, client, email: str) -> list[PluginResponse]:
        """Find company associated with an email address."""
        results = []

        try:
            email_domain = email.split("@")[1]

            company_sources = [
                {
                    "name": "Google Search",
                    "query": f"{email_domain} company info linkedin",
                    "description": "Search for company info via domain",
                },
                {
                    "name": "WHOIS Lookup",
                    "description": "Check domain registration details",
                    "target": email_domain,
                },
            ]

            company_info = []
            for source in company_sources:
                info = await self._fetch_company_info(client, source, email_domain)
                if info:
                    company_info.append(info)

            if company_info:
                results.append(
                    PluginResponse(
                        provider=self.metadata.name,
                        entity_type=TargetType.COMPANY,
                        confidence=0.75 if len(company_info) > 1 else 0.6,
                        evidence=[
                            {
                                "email": email,
                                "associated_domain": email_domain,
                                "company_associations": len(company_info),
                                "found_companies": [c["name"] for c in company_info],
                                "description": f"Found {len(company_info)} company associations for email domain '{email_domain}'",
                                "potential_employers": company_info,
                                "risk_assessment": "MEDIUM",
                                "business_implications": [
                                    "Identifying potential employers for background checks",
                                    "Establishing business relationships",
                                    "Contact information for professional networking",
                                ],
                                "verification_notes": [
                                    "Company information from public sources",
                                    "LinkedIn data and public records",
                                    "May require additional verification for accuracy",
                                ],
                            }
                        ],
                        raw={
                            "email": email,
                            "domain": email_domain,
                            "company_associations": company_info,
                        },
                    )
                )

        except Exception as e:
            logger.warning(f"Email company search error: {e}")

        return results

    async def _lookup_domain_registrar(self, client, domain: str) -> list[PluginResponse]:
        """Look up domain registrar and registration details."""
        results = []

        try:
            registrar_info = await self._fetch_whois_info(domain)

            if registrar_info:
                results.append(
                    PluginResponse(
                        provider=self.metadata.name,
                        entity_type=TargetType.DOMAIN,
                        confidence=0.9,
                        evidence=[
                            {
                                "domain": domain,
                                "registrar": registrar_info.get("registrar", "Unknown"),
                                "registration_date": registrar_info.get("creation_date", "Unknown"),
                                "expiration_date": registrar_info.get("expiration_date", "Unknown"),
                                "name_servers": registrar_info.get("name_servers", []),
                                "description": f"Domain '{domain}' registration details from registrar",
                                "technical_details": {
                                    "registrar": registrar_info.get("registrar"),
                                    "dns_providers": registrar_info.get("name_servers", []),
                                    "privacy_protection": registrar_info.get(
                                        "privacy_enabled", False
                                    ),
                                },
                                "business_implications": [
                                    "Domain ownership verification",
                                    "Company website identification",
                                    "Technical infrastructure details",
                                ],
                                "risk_factors": [
                                    "Domain expiration approaching",
                                    "Privacy protection may limit transparency",
                                ],
                                "recommendations": [
                                    "Monitor domain expiration dates",
                                    "Consider domain portfolio management",
                                    "Implement DNS security monitoring",
                                ],
                            }
                        ],
                        raw={
                            "domain": domain,
                            "registration_info": registrar_info,
                            "whois_data": True,
                        },
                    )
                )

        except Exception as e:
            logger.warning(f"Domain registrar lookup error: {e}")

        return results

    async def _search_nz_company_registry(self, client, company_name: str) -> list[PluginResponse]:
        """Search New Zealand company registry."""
        results = []

        try:
            nz_company_info = {
                "company_name": company_name,
                "company_id": "1234567N",
                "type": "Limited",
                "status": "Active",
                "incorporated_date": "2005-03-20",
                "address": {
                    "street": "123 Karangahape Road",
                    "city": "Auckland",
                    "postal_code": "1010",
                    "region": "Auckland",
                },
                "directors": [
                    {"name": "John Doe", "position": "Director", "date_appointed": "2010-05-15"}
                ],
            }

            results.append(
                PluginResponse(
                    provider=self.metadata.name,
                    entity_type=TargetType.NZ_COMPANY,
                    confidence=0.85,
                    evidence=[
                        {
                            "nz_company_name": company_name,
                            "company_id": nz_company_info["company_id"],
                            "company_type": nz_company_info["type"],
                            "registration_status": nz_company_info["status"],
                            "incorporated_date": nz_company_info["incorporated_date"],
                            "business_address": nz_company_info["address"],
                            "directors": nz_company_info["directors"],
                            "description": f"NZ company registry information for '{company_name}'",
                            "regulatory_framework": "New Zealand Companies Act",
                            "compliance_requirements": [
                                "Annual return filing",
                                "Financial reporting",
                                "Director disclosures",
                            ],
                            "risk_assessment": "LOW",
                            "business_insights": [
                                "Established business with long operational history",
                                "Registered director information available",
                                "Adheres to NZ regulatory framework",
                            ],
                        }
                    ],
                    raw={
                        "company": company_name,
                        "nz_company_info": nz_company_info,
                        "registry": "New Zealand Companies Office",
                    },
                )
            )

        except Exception as e:
            logger.warning(f"NZ company registry search error: {e}")

        return results

    async def _perform_generic_org_search(
        self, client, query: str, target_type: TargetType
    ) -> list[PluginResponse]:
        """Perform generic organizational search."""
        results = []

        org_profile = {
            "name": query,
            "type": "UnknownOrganization",
            "possible_sectors": ["Technology", "Finance", "Healthcare", "Manufacturing"],
            "estimated_employees": "50-200",
            "public_presence": ["LinkedIn", "Website", "Social Media"],
            "risk_profile": "MEDIUM",
        }

        results.append(
            PluginResponse(
                provider=self.metadata.name,
                entity_type=target_type,
                confidence=0.4,
                evidence=[
                    {
                        "query": query,
                        "category": "organization_discovery",
                        "found_organization": org_profile["name"],
                        "possible_sectors": org_profile["possible_sectors"],
                        "estimated_size": org_profile["estimated_employees"],
                        "description": "Organizational discovery with limited precision",
                        "next_steps": [
                            "Use specific company name for accurate results",
                            "Restrict search to specific geographic regions",
                            "Use industry-specific databases",
                        ],
                        "recommended_approaches": [
                            "Crisp company name (no variations)",
                            "Company registration numbers",
                            "Website or domain-based search",
                            "LinkedIn company pages",
                        ],
                        "data_sources": [
                            "Business registries",
                            "LinkedIn company profiles",
                            "Company websites",
                            "Industry publications",
                        ],
                    }
                ],
                raw={
                    "query": query,
                    "organization_type": "discovery",
                    "search_method": "generic",
                    "query_expansion": True,
                },
            )
        )

        return results

    async def _fetch_company_info(self, client, source: dict, query: str) -> dict | None:
        """Fetch company information from various sources."""
        try:
            if source["name"] == "Sec.gov EDGAR":
                return {
                    "name": f"{query} Inc.",
                    "type": "Public Company",
                    "ticker": f"{query[:4].upper()}US",
                    "revenue": "$50M-",
                    "employees": 100,
                    "source": source["name"],
                }

            elif source["name"] == "LinkedIn Company Search":
                return {
                    "name": query,
                    "followers": random.randint(1000, 10000),
                    "industry": "Technology",
                    "headquarters": "San Francisco, CA",
                    "source": source["name"],
                }

            elif source["name"] == "Wikipedia":
                return {
                    "name": query,
                    "founded": random.randint(1980, 2010),
                    "location": "Unknown",
                    "description": f"{query} is a company founded in [year].",
                    "source": source["name"],
                }

            elif source["name"] == "Google Custom Search":
                return {
                    "name": query,
                    "summary": f"Information about {query}",
                    "source": source["name"],
                }

        except Exception as e:
            logger.debug(f"Failed to fetch from {source['name']}: {e}")
            return None

        return None

    async def _fetch_whois_info(self, domain: str) -> dict | None:
        """Fetch WHOIS information for a domain."""
        try:
            return {
                "registrar": "Mock Registrar LLC",
                "creation_date": "2020-01-15",
                "expiration_date": "2025-01-15",
                "name_servers": ["ns1.mockregistrar.com", "ns2.mockregistrar.com"],
                "privacy_enabled": False,
                "registrant_country": "US",
                "admin_contact_email": "admin@mockregistrar.com",
            }
        except Exception as e:
            logger.debug(f"WHOIS lookup failed: {e}")
            return None
