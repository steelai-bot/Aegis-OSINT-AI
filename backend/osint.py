"""
OSINT Search Module
Supports Australian, New Zealand, and custom searches.
"""

import os
import re
import json
import httpx
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.parse import quote, urlencode

class OSINTClient:
    """OSINT search client for AU, NZ, and custom targets."""
    
    def __init__(self):
        self.session = httpx.Client(timeout=30.0)
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
    
    def search_sync(self, query: str, target_type: str = "auto", custom_search: str = None) -> Dict[str, Any]:
        """Synchronous search for use in FastAPI."""
        findings = []
        
        # Auto-detect target type
        if target_type == "auto":
            target_type = self._detect_type(query)
        
        # Route to appropriate search method
        if target_type == "abn":
            findings.extend(self._search_abn(query))
        elif target_type == "domain":
            findings.extend(self._search_domain(query))
        elif target_type == "phone":
            findings.extend(self._search_phone(query))
        elif target_type == "ip":
            findings.extend(self._search_ip(query))
        elif target_type == "company":
            findings.extend(self._search_company(query))
        elif target_type == "nz_company":
            findings.extend(self._search_nz_company(query))
        elif target_type == "nz_domain":
            findings.extend(self._search_nz_domain(query))
        elif target_type == "custom" and custom_search:
            findings.extend(self._search_custom(query, custom_search))
        else:
            # General search
            findings.extend(self._search_general(query))
        
        return {"findings": findings, "target_type": target_type}
    
    def _detect_type(self, query: str) -> str:
        """Auto-detect target type from query."""
        query_clean = re.sub(r'\D', '', query)
        
        # ABN (11 digits)
        if len(query_clean) == 11 and query_clean.isdigit():
            return "abn"
        
        # Domain
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', query):
            if query.endswith('.nz') or query.endswith('.co.nz') or query.endswith('.org.nz'):
                return "nz_domain"
            return "domain"
        
        # Email
        if '@' in query:
            domain = query.split('@')[1]
            if domain.endswith('.nz'):
                return "nz_domain"
            return "domain"
        
        # Phone
        if re.match(r'^[\d\s\-\+\(\)]+$', query) and len(query_clean) >= 8:
            return "phone"
        
        # IP
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', query):
            return "ip"
        
        # NZ company (check for NZ indicators)
        if any(term in query.lower() for term in ['nz', 'new zealand', 'aotearoa']):
            return "nz_company"
        
        return "company"
    
    # Australian searches
    def _search_abn(self, abn: str) -> List[Dict[str, Any]]:
        """Search Australian Business Register."""
        findings = []
        abn_clean = re.sub(r'\D', '', abn)
        
        if len(abn_clean) != 11:
            return findings
        
        # Try ABR API (requires GUID)
        guid = os.getenv('ABR_GUID', '')
        if guid:
            try:
                url = 'https://abr.business.gov.au/abrxmlsearch/AbrXmlSearch.asmx/SearchByABNv202001'
                params = {
                    'searchString': abn_clean,
                    'includeHistoricalDetails': 'Y',
                    'authenticationGuid': guid
                }
                resp = self.session.get(url, params=params, headers=self.headers)
                if resp.status_code == 200:
                    findings.append({
                        "source": "ABR",
                        "category": "business_registration",
                        "severity": "info",
                        "confidence": 0.95,
                        "data": {"abn": abn_clean, "raw_xml": resp.text[:2000]}
                    })
            except Exception:
                pass
        
        # Fallback: scrape ABN Lookup
        try:
            url = f'https://abr.business.gov.au/ABN/View?id={abn_clean}'
            resp = self.session.get(url, headers=self.headers)
            if resp.status_code == 200:
                findings.append({
                    "source": "ABR-Web",
                    "category": "business_registration",
                    "severity": "info",
                    "confidence": 0.8,
                    "data": {"abn": abn_clean, "url": url, "html_length": len(resp.text)}
                })
        except Exception:
            pass
        
        return findings
    
    def _search_domain(self, domain: str) -> List[Dict[str, Any]]:
        """Search domain intelligence (AU + general)."""
        findings = []
        
        # DNS records via Google DNS
        for rtype in ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']:
            try:
                resp = self.session.get(
                    f'https://dns.google/resolve?name={quote(domain)}&type={rtype}',
                    headers=self.headers
                )
                if resp.status_code == 200:
                    data = resp.json()
                    answers = data.get('Answer', [])
                    if answers:
                        findings.append({
                            "source": "DNS-Google",
                            "category": "dns_record",
                            "severity": "info",
                            "confidence": 0.95,
                            "data": {
                                "domain": domain,
                                "record_type": rtype,
                                "records": [a.get('data', '') for a in answers]
                            }
                        })
            except Exception:
                pass
        
        # Certificate Transparency
        try:
            resp = self.session.get(
                f'https://crt.sh/?q=%.{quote(domain)}&output=json',
                headers=self.headers
            )
            if resp.status_code == 200:
                certs = resp.json()
                subdomains = set()
                for cert in certs:
                    name = cert.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub and sub.endswith(domain) and '*' not in sub:
                            subdomains.add(sub)
                
                if subdomains:
                    findings.append({
                        "source": "CertTransparency",
                        "category": "subdomain_enum",
                        "severity": "info",
                        "confidence": 0.9,
                        "data": {
                            "domain": domain,
                            "subdomains": sorted(list(subdomains))[:100],
                            "count": len(subdomains)
                        }
                    })
        except Exception:
            pass
        
        # WHOIS for .au domains
        if domain.endswith('.au'):
            try:
                import subprocess
                result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=15)
                if result.returncode == 0 and result.stdout:
                    findings.append({
                        "source": "WHOIS-AU",
                        "category": "domain_registration",
                        "severity": "info",
                        "confidence": 0.9,
                        "data": {"domain": domain, "raw": result.stdout[:3000]}
                    })
            except Exception:
                pass
        
        return findings
    
    def _search_phone(self, phone: str) -> List[Dict[str, Any]]:
        """Search Australian phone number."""
        findings = []
        phone_clean = re.sub(r'\D', '', phone)
        
        # Normalize to +61
        if phone_clean.startswith('0') and len(phone_clean) == 10:
            phone_clean = '61' + phone_clean[1:]
        elif phone_clean.startswith('0061'):
            phone_clean = phone_clean[2:]
        
        if not phone_clean.startswith('61'):
            return findings
        
        # Carrier detection
        mobile_prefix = phone_clean[2:5] if len(phone_clean) >= 5 else ''
        carrier_map = {
            '400': 'Telstra', '401': 'Telstra', '402': 'Telstra', '403': 'Telstra',
            '404': 'Telstra', '405': 'Telstra', '410': 'Telstra', '411': 'Telstra',
            '412': 'Telstra', '413': 'Telstra', '414': 'Telstra', '415': 'Telstra',
            '416': 'Telstra', '417': 'Telstra', '418': 'Telstra', '419': 'Telstra',
            '427': 'Telstra', '428': 'Telstra', '429': 'Telstra', '437': 'Telstra',
            '438': 'Telstra', '447': 'Telstra', '448': 'Telstra', '449': 'Telstra',
            '457': 'Telstra', '458': 'Telstra', '459': 'Telstra', '467': 'Telstra',
            '468': 'Telstra', '469': 'Telstra', '477': 'Telstra', '478': 'Telstra',
            '479': 'Telstra', '487': 'Telstra', '488': 'Telstra', '497': 'Telstra',
            '498': 'Telstra', '499': 'Telstra',
            '420': 'Optus', '421': 'Optus', '422': 'Optus', '423': 'Optus',
            '430': 'Optus', '431': 'Optus', '432': 'Optus', '433': 'Optus',
            '434': 'Optus', '435': 'Optus', '439': 'Optus', '440': 'Optus',
            '441': 'Optus', '450': 'Optus', '451': 'Optus', '452': 'Optus',
            '453': 'Optus', '466': 'Optus', '476': 'Optus',
            '406': 'Vodafone', '407': 'Vodafone', '408': 'Vodafone', '424': 'Vodafone',
            '425': 'Vodafone', '426': 'Vodafone', '436': 'Vodafone', '442': 'Vodafone',
            '443': 'Vodafone', '444': 'Vodafone', '445': 'Vodafone', '446': 'Vodafone',
            '454': 'Vodafone', '455': 'Vodafone', '456': 'Vodafone', '464': 'Vodafone',
            '465': 'Vodafone',
        }
        
        carrier = carrier_map.get(mobile_prefix, 'Unknown')
        phone_type = 'mobile' if phone_clean[2] == '4' else 'landline'
        
        findings.append({
            "source": "AU-Phone-Lookup",
            "category": "phone_info",
            "severity": "info",
            "confidence": 0.7,
            "data": {
                "phone": f'+{phone_clean}',
                "phone_type": phone_type,
                "carrier": carrier,
                "country": "Australia"
            }
        })
        
        return findings
    
    def _search_ip(self, ip: str) -> List[Dict[str, Any]]:
        """Search IP geolocation."""
        findings = []
        
        try:
            resp = self.session.get(
                f'http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as',
                headers=self.headers
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get('status') == 'success':
                    findings.append({
                        "source": "IP-Geolocation",
                        "category": "ip_info",
                        "severity": "info",
                        "confidence": 0.8,
                        "data": {
                            "ip": ip,
                            "country": data.get('country', ''),
                            "country_code": data.get('countryCode', ''),
                            "region": data.get('regionName', ''),
                            "city": data.get('city', ''),
                            "isp": data.get('isp', ''),
                            "org": data.get('org', ''),
                            "as_number": data.get('as', ''),
                            "is_australian": data.get('countryCode') == 'AU',
                            "is_nz": data.get('countryCode') == 'NZ'
                        }
                    })
        except Exception:
            pass
        
        return findings
    
    def _search_company(self, company: str) -> List[Dict[str, Any]]:
        """Search Australian company (ASIC)."""
        findings = []
        
        try:
            url = f'https://connectonline.asic.gov.au/RegistrySearch/faces/landing/bySearchRegisters.jspx?searchText={quote(company)}&searchType=OrgAndBusNm'
            resp = self.session.get(url, headers=self.headers)
            if resp.status_code == 200:
                findings.append({
                    "source": "ASIC",
                    "category": "company_registration",
                    "severity": "info",
                    "confidence": 0.7,
                    "data": {"company": company, "url": url, "html_length": len(resp.text)}
                })
        except Exception:
            pass
        
        return findings
    
    # New Zealand searches
    def _search_nz_company(self, company: str) -> List[Dict[str, Any]]:
        """Search NZ Companies Office."""
        findings = []
        
        try:
            url = f'https://www.companiesoffice.govt.nz/companies/search?q={quote(company)}'
            resp = self.session.get(url, headers=self.headers)
            if resp.status_code == 200:
                findings.append({
                    "source": "NZ-Companies-Office",
                    "category": "company_registration",
                    "severity": "info",
                    "confidence": 0.8,
                    "data": {"company": company, "url": url, "html_length": len(resp.text)}
                })
        except Exception:
            pass
        
        return findings
    
    def _search_nz_domain(self, domain: str) -> List[Dict[str, Any]]:
        """Search NZ domain (.nz)."""
        findings = []
        
        # Use same DNS logic as AU
        findings.extend(self._search_domain(domain))
        
        # NZ-specific WHOIS
        try:
            import subprocess
            result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=15)
            if result.returncode == 0 and result.stdout:
                findings.append({
                    "source": "WHOIS-NZ",
                    "category": "domain_registration",
                    "severity": "info",
                    "confidence": 0.9,
                    "data": {"domain": domain, "raw": result.stdout[:3000]}
                })
        except Exception:
            pass
        
        return findings
    
    def _search_custom(self, query: str, custom_search: str) -> List[Dict[str, Any]]:
        """Custom search using specified engine."""
        findings = []
        
        # Support for custom search engines
        if custom_search == "google":
            try:
                url = f'https://www.google.com/search?q={quote(query)}'
                resp = self.session.get(url, headers=self.headers)
                if resp.status_code == 200:
                    findings.append({
                        "source": "Google-Search",
                        "category": "web_search",
                        "severity": "info",
                        "confidence": 0.6,
                        "data": {"query": query, "url": url, "html_length": len(resp.text)}
                    })
            except Exception:
                pass
        
        elif custom_search == "bing":
            try:
                url = f'https://www.bing.com/search?q={quote(query)}'
                resp = self.session.get(url, headers=self.headers)
                if resp.status_code == 200:
                    findings.append({
                        "source": "Bing-Search",
                        "category": "web_search",
                        "severity": "info",
                        "confidence": 0.6,
                        "data": {"query": query, "url": url, "html_length": len(resp.text)}
                    })
            except Exception:
                pass
        
        elif custom_search == "duckduckgo":
            try:
                url = f'https://duckduckgo.com/html/?q={quote(query)}'
                resp = self.session.get(url, headers=self.headers)
                if resp.status_code == 200:
                    findings.append({
                        "source": "DuckDuckGo-Search",
                        "category": "web_search",
                        "severity": "info",
                        "confidence": 0.6,
                        "data": {"query": query, "url": url, "html_length": len(resp.text)}
                    })
            except Exception:
                pass
        
        return findings
    
    def _search_general(self, query: str) -> List[Dict[str, Any]]:
        """General search fallback."""
        findings = []
        
        # Try multiple search engines
        for engine in ["duckduckgo", "bing"]:
            findings.extend(self._search_custom(query, engine))
        
        return findings