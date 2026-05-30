"""
au-osint-recon :: osint_australia.py
Australia-specific OSINT — ABN lookup, ASIC, WHOIS, gov directories, telecom, banking.
"""

import os
import re
import json
import time
from typing import Optional, Dict, List, Any
from urllib.parse import quote, urlencode

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    requests = None
    BeautifulSoup = None

from utils import (
    logger, safe_request, Finding, ResultStore,
    AU_PATTERNS, AU_MAJOR_BANKS, AU_TELCOS, AU_GOV_DOMAINS,
    AU_STATES, DataClassifier, random_ua
)


class AustralianOSINT:
    """Australia-specific OSINT gathering engine."""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.results = ResultStore()
        self.session = requests.Session() if requests else None

    # ── ABN Lookup (Australian Business Register) ────────────────────────

    def lookup_abn(self, abn: str) -> List[Finding]:
        """Look up Australian Business Number via ABR."""
        findings = []
        abn_clean = re.sub(r'\D', '', abn)

        if len(abn_clean) != 11:
            logger.warning(f'Invalid ABN length: {abn_clean}')
            return findings

        # ABR web service (GUID required for production)
        guid = self.config.get('ABR_GUID', os.getenv('ABR_GUID', ''))

        if guid:
            url = 'https://abr.business.gov.au/abrxmlsearch/AbrXmlSearch.asmx/SearchByABNv202001'
            params = {
                'searchString': abn_clean,
                'includeHistoricalDetails': 'Y',
                'authenticationGuid': guid,
            }
            resp = safe_request(f'{url}?{urlencode(params)}', timeout=15)
            if resp and resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'lxml-xml') if BeautifulSoup else None
                if soup:
                    entity = soup.find('businessEntity')
                    if entity:
                        data = {
                            'abn': abn_clean,
                            'entity_status': entity.find('entityStatusCode').text if entity.find('entityStatusCode') else '',
                            'entity_type': entity.find('entityTypeCode').text if entity.find('entityTypeCode') else '',
                            'main_name': entity.find('mainName', {'organisationName': True}),
                            'state': entity.find('stateCode').text if entity.find('stateCode') else '',
                            'postcode': entity.find('postcode').text if entity.find('postcode') else '',
                            'gst_registered': bool(entity.find('goodsAndServicesTax')),
                        }
                        # Extract all name variations
                        names = entity.find_all('organisationName')
                        data['all_names'] = [n.text for n in names]

                        findings.append(Finding(
                            source='ABR',
                            category='business_registration',
                            data=data,
                            confidence=0.95,
                        ))

        # Fallback: scrape ABN Lookup website
        else:
            url = f'https://abr.business.gov.au/ABN/View?id={abn_clean}'
            resp = safe_request(url, timeout=15)
            if resp and resp.status_code == 200 and BeautifulSoup:
                soup = BeautifulSoup(resp.text, 'html.parser')
                data = {'abn': abn_clean}

                # Parse the results table
                tables = soup.find_all('table')
                for table in tables:
                    rows = table.find_all('tr')
                    for row in rows:
                        cells = row.find_all(['th', 'td'])
                        if len(cells) >= 2:
                            key = cells[0].get_text(strip=True).lower()
                            val = cells[1].get_text(strip=True)
                            if 'entity name' in key:
                                data['entity_name'] = val
                            elif 'abn status' in key:
                                data['status'] = val
                            elif 'entity type' in key:
                                data['entity_type'] = val
                            elif 'goods' in key and 'services' in key:
                                data['gst'] = val
                            elif 'main business location' in key:
                                data['location'] = val

                if 'entity_name' in data:
                    findings.append(Finding(
                        source='ABR-Web',
                        category='business_registration',
                        data=data,
                        confidence=0.9,
                    ))

        return findings

    # ── ASIC Company Search ──────────────────────────────────────────────

    def search_asic(self, company_name: str) -> List[Finding]:
        """Search ASIC Connect for company information."""
        findings = []

        url = 'https://connectonline.asic.gov.au/RegistrySearch/faces/landing/SearchRegisters.jspx'
        search_url = f'https://connectonline.asic.gov.au/RegistrySearch/faces/landing/bySearchRegisters.jspx'

        # Scrape ASIC search (note: ASIC has rate limiting and CAPTCHA)
        resp = safe_request(
            f'https://connectonline.asic.gov.au/RegistrySearch/faces/landing/bySearchRegisters.jspx?searchText={quote(company_name)}&searchType=OrgAndBusNm',
            timeout=20,
        )
        if resp and resp.status_code == 200 and BeautifulSoup:
            soup = BeautifulSoup(resp.text, 'html.parser')
            results_table = soup.find('table', class_='search-results')
            if results_table:
                rows = results_table.find_all('tr')[1:]  # skip header
                for row in rows[:20]:
                    cells = row.find_all('td')
                    if len(cells) >= 4:
                        findings.append(Finding(
                            source='ASIC',
                            category='company_registration',
                            data={
                                'company_name': cells[0].get_text(strip=True),
                                'acn': cells[1].get_text(strip=True),
                                'status': cells[2].get_text(strip=True),
                                'type': cells[3].get_text(strip=True),
                            },
                            confidence=0.9,
                        ))

        return findings

    # ── Australian Domain WHOIS ──────────────────────────────────────────

    def whois_au_domain(self, domain: str) -> List[Finding]:
        """WHOIS lookup for .au domains."""
        findings = []

        # Use auDA/aunic WHOIS
        import subprocess
        try:
            result = subprocess.run(
                ['whois', domain],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0 and result.stdout:
                whois_data = {}
                for line in result.stdout.splitlines():
                    if ':' in line:
                        key, _, val = line.partition(':')
                        key = key.strip().lower()
                        val = val.strip()
                        if val:
                            whois_data[key] = val

                if whois_data:
                    findings.append(Finding(
                        source='WHOIS-AU',
                        category='domain_registration',
                        data={
                            'domain': domain,
                            'registrant': whois_data.get('registrant', ''),
                            'registrant_id': whois_data.get('registrant id', ''),
                            'tech_contact': whois_data.get('tech contact', ''),
                            'name_servers': [
                                v for k, v in whois_data.items()
                                if 'name server' in k
                            ],
                            'registrar': whois_data.get('registrar name', ''),
                            'status': whois_data.get('status', ''),
                            'last_modified': whois_data.get('last modified', ''),
                            'raw': result.stdout[:2000],
                        },
                        confidence=0.9,
                    ))
        except Exception as e:
            logger.warning(f'WHOIS failed for {domain}: {e}')

        return findings

    # ── Australian Phone Number Lookup ───────────────────────────────────

    def lookup_phone_au(self, phone: str) -> List[Finding]:
        """Lookup Australian phone number carrier and type."""
        findings = []
        phone_clean = re.sub(r'\D', '', phone)

        # Normalize to +61
        if phone_clean.startswith('0') and len(phone_clean) == 10:
            phone_clean = '61' + phone_clean[1:]
        elif phone_clean.startswith('0061'):
            phone_clean = phone_clean[2:]

        if not phone_clean.startswith('61'):
            return findings

        # Determine carrier by prefix
        mobile_prefix = phone_clean[2:5] if len(phone_clean) >= 5 else ''
        carrier_map = {
            # Telstra
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
            # Optus
            '420': 'Optus', '421': 'Optus', '422': 'Optus', '423': 'Optus',
            '430': 'Optus', '431': 'Optus', '432': 'Optus', '433': 'Optus',
            '434': 'Optus', '435': 'Optus', '439': 'Optus', '440': 'Optus',
            '441': 'Optus', '450': 'Optus', '451': 'Optus', '452': 'Optus',
            '453': 'Optus', '466': 'Optus', '476': 'Optus',
            # Vodafone
            '406': 'Vodafone', '407': 'Vodafone', '408': 'Vodafone', '424': 'Vodafone',
            '425': 'Vodafone', '426': 'Vodafone', '436': 'Vodafone', '442': 'Vodafone',
            '443': 'Vodafone', '444': 'Vodafone', '445': 'Vodafone', '446': 'Vodafone',
            '454': 'Vodafone', '455': 'Vodafone', '456': 'Vodafone', '464': 'Vodafone',
            '465': 'Vodafone',
        }

        carrier = carrier_map.get(mobile_prefix, 'Unknown')
        phone_type = 'mobile' if phone_clean[2] == '4' else 'landline'

        # Area code mapping for landlines
        area_codes = {
            '2': 'NSW/ACT (Sydney, Canberra)',
            '3': 'VIC/TAS (Melbourne, Hobart)',
            '7': 'QLD (Brisbane)',
            '8': 'SA/WA/NT (Adelaide, Perth, Darwin)',
        }
        area = area_codes.get(phone_clean[2], 'Unknown') if phone_type == 'landline' else ''

        data = {
            'phone': f'+{phone_clean}',
            'phone_type': phone_type,
            'carrier': carrier,
            'country': 'Australia',
        }
        if area:
            data['area'] = area

        findings.append(Finding(
            source='AU-Phone-Lookup',
            category='phone_info',
            data=data,
            confidence=0.7,
        ))

        # Try reverse lookup services
        reverse_urls = [
            f'https://www.reversephonelookup.com.au/{phone_clean}',
            f'https://www.whitepages.com.au/phone/{phone_clean}',
        ]
        for url in reverse_urls:
            resp = safe_request(url, timeout=15)
            if resp and resp.status_code == 200 and BeautifulSoup:
                soup = BeautifulSoup(resp.text, 'html.parser')
                # Extract any name/address data
                name_elem = soup.find(['h1', 'h2', 'span'], class_=re.compile(r'name|owner|person', re.I))
                if name_elem:
                    name_text = name_elem.get_text(strip=True)
                    if name_text and len(name_text) > 2:
                        findings.append(Finding(
                            source='ReversePhone-AU',
                            category='pii',
                            data={
                                'phone': f'+{phone_clean}',
                                'possible_name': name_text,
                                'lookup_url': url,
                            },
                            confidence=0.5,
                        ))

        return findings

    # ── BSB Database ─────────────────────────────────────────────────────

    def lookup_bsb(self, bsb: str) -> List[Finding]:
        """Look up BSB (Bank-State-Branch) number."""
        findings = []
        bsb_clean = re.sub(r'\D', '', bsb)

        if len(bsb_clean) != 6:
            return findings

        # BSB prefix → bank mapping
        bsb_bank_map = {
            '01': 'ANZ Banking Group',
            '03': 'Westpac Banking Corporation',
            '06': 'Commonwealth Bank of Australia',
            '08': 'National Australia Bank',
            '09': 'Reserve Bank of Australia',
            '10': 'BankSA',
            '11': 'St. George Bank',
            '12': 'Bank of Queensland',
            '13': 'Rabobank',
            '14': 'Rabobank',
            '15': 'Town & Country Bank',
            '18': 'Macquarie Bank',
            '19': 'Bank of Melbourne',
            '21': 'JP Morgan Chase',
            '22': 'BNP Paribas',
            '23': 'Bank of America',
            '25': 'BNP Paribas',
            '26': 'Bankers Trust',
            '29': 'Bank of Tokyo-Mitsubishi',
            '30': 'Bankwest',
            '33': 'St. George Bank',
            '34': 'HSBC Bank Australia',
            '35': 'OCBC Bank',
            '40': 'AMP Bank',
            '48': 'Macquarie Bank',
            '55': 'Bank of China',
            '57': 'ING DIRECT',
            '61': 'Adelaide Bank',
            '63': 'Greater Building Society',
            '64': 'Suncorp-Metway',
            '73': 'Westpac Banking Corporation',
            '76': 'Commonwealth Bank of Australia',
            '80': 'Cuscal (Credit Unions)',
            '81': 'Cuscal (Credit Unions)',
            '82': 'Cuscal (Credit Unions)',
            '83': 'Credit Union Australia',
            '84': 'ME Bank',
            '88': 'Citibank',
            '92': 'NAB',
        }

        # State from BSB
        state_map = {
            '2': 'NSW', '3': 'VIC', '4': 'QLD',
            '5': 'SA', '6': 'WA', '7': 'TAS',
            '8': 'NT', '9': 'ACT',
        }

        prefix = bsb_clean[:2]
        bank = bsb_bank_map.get(prefix, 'Unknown Bank')
        state_digit = bsb_clean[2]
        state = state_map.get(state_digit, 'Unknown State')

        findings.append(Finding(
            source='BSB-Database',
            category='banking_info',
            data={
                'bsb': f'{bsb_clean[:3]}-{bsb_clean[3:]}',
                'bank': bank,
                'state': state,
                'branch_code': bsb_clean[3:],
            },
            confidence=0.85,
        ))

        return findings

    # ── Australian Gov Employee Directory ────────────────────────────────

    def search_gov_directory(self, name: str) -> List[Finding]:
        """Search Australian government directories."""
        findings = []

        # Directory of Australian Government bodies
        directories = [
            ('https://www.directory.gov.au/search', {'q': name, 'type': 'people'}),
            ('https://www.directory.gov.au/search', {'q': name, 'type': 'organisations'}),
        ]

        for url, params in directories:
            resp = safe_request(f'{url}?{urlencode(params)}', timeout=15)
            if resp and resp.status_code == 200 and BeautifulSoup:
                soup = BeautifulSoup(resp.text, 'html.parser')
                results = soup.find_all('div', class_='search-result')
                for result in results[:10]:
                    title = result.find(['h3', 'h4', 'a'])
                    desc = result.find(['p', 'span'], class_=re.compile(r'desc|summary', re.I))

                    if title:
                        findings.append(Finding(
                            source='AuGov-Directory',
                            category='gov_employee',
                            data={
                                'name': title.get_text(strip=True),
                                'description': desc.get_text(strip=True) if desc else '',
                                'source_url': url,
                            },
                            confidence=0.6,
                        ))

        return findings

    # ── Australian IP Range Lookup ───────────────────────────────────────

    def is_australian_ip(self, ip: str) -> Dict[str, Any]:
        """Check if an IP is in Australian ranges via APNIC/RIPE."""
        result = {'ip': ip, 'is_australian': False}

        # Use ip-api.com (free)
        resp = safe_request(
            f'http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as',
            timeout=10,
        )
        if resp and resp.status_code == 200:
            data = resp.json()
            if data.get('status') == 'success':
                result.update({
                    'is_australian': data.get('countryCode') == 'AU',
                    'country': data.get('country', ''),
                    'region': data.get('regionName', ''),
                    'city': data.get('city', ''),
                    'isp': data.get('isp', ''),
                    'org': data.get('org', ''),
                    'as_number': data.get('as', ''),
                })

        return result

    # ── Australian Email Domain Intelligence ─────────────────────────────

    def domain_intel(self, domain: str) -> List[Finding]:
        """Gather intelligence on Australian domain — DNS, subdomains, tech stack."""
        findings = []

        # DNS records via Google DNS
        for rtype in ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']:
            resp = safe_request(
                f'https://dns.google/resolve?name={quote(domain)}&type={rtype}',
                timeout=10,
            )
            if resp and resp.status_code == 200:
                data = resp.json()
                answers = data.get('Answer', [])
                if answers:
                    findings.append(Finding(
                        source='DNS-Google',
                        category='dns_record',
                        data={
                            'domain': domain,
                            'record_type': rtype,
                            'records': [a.get('data', '') for a in answers],
                            'ttl': answers[0].get('TTL', 0),
                        },
                        confidence=0.95,
                    ))

        # Certificate Transparency via crt.sh
        resp = safe_request(
            f'https://crt.sh/?q=%.{quote(domain)}&output=json',
            timeout=20,
        )
        if resp and resp.status_code == 200:
            try:
                certs = resp.json()
                subdomains = set()
                for cert in certs:
                    name = cert.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub and sub.endswith(domain) and '*' not in sub:
                            subdomains.add(sub)

                if subdomains:
                    findings.append(Finding(
                        source='CertTransparency',
                        category='subdomain_enum',
                        data={
                            'domain': domain,
                            'subdomains': sorted(list(subdomains))[:200],
                            'count': len(subdomains),
                        },
                        confidence=0.9,
                    ))
            except Exception:
                pass

        # SecurityTrails (if key available)
        st_key = self.config.get('SECURITYTRAILS_KEY', os.getenv('SECURITYTRAILS_KEY', ''))
        if st_key:
            resp = safe_request(
                f'https://api.securitytrails.com/v1/domain/{domain}',
                headers={'APIKEY': st_key},
                timeout=15,
            )
            if resp and resp.status_code == 200:
                data = resp.json()
                findings.append(Finding(
                    source='SecurityTrails',
                    category='domain_intel',
                    data={
                        'domain': domain,
                        'alexa_rank': data.get('alexa_rank', 0),
                        'apex_domain': data.get('apex_domain', ''),
                        'hostname': data.get('hostname', ''),
                        'current_dns': data.get('current_dns', {}),
                    },
                    confidence=0.9,
                ))

        return findings

    # ── Full Australian Recon ────────────────────────────────────────────

    def full_recon(self, target: str, target_type: str = 'auto') -> ResultStore:
        """Full Australian OSINT recon on target."""
        logger.info(f'Starting Australian OSINT for: {target}')

        # Auto-detect target type
        if target_type == 'auto':
            if re.match(r'\d{11}', re.sub(r'\D', '', target)):
                target_type = 'abn'
            elif '.au' in target and '@' not in target:
                target_type = 'domain'
            elif '@' in target:
                target_type = 'email'
            elif re.match(r'[\d\s\-+]+$', target):
                target_type = 'phone'
            elif re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', target):
                target_type = 'ip'
            else:
                target_type = 'company'

        logger.info(f'  Target type detected: {target_type}')

        if target_type == 'abn':
            self.results.add_many(self.lookup_abn(target))

        elif target_type == 'domain':
            self.results.add_many(self.whois_au_domain(target))
            self.results.add_many(self.domain_intel(target))

        elif target_type == 'phone':
            self.results.add_many(self.lookup_phone_au(target))

        elif target_type == 'company':
            self.results.add_many(self.search_asic(target))
            self.results.add_many(self.search_gov_directory(target))

        elif target_type == 'ip':
            ip_info = self.is_australian_ip(target)
            if ip_info:
                self.results.add(Finding(
                    source='IP-Geolocation',
                    category='ip_info',
                    data=ip_info,
                    confidence=0.8,
                ))

        elif target_type == 'email':
            domain = target.split('@')[1] if '@' in target else ''
            if domain:
                self.results.add_many(self.domain_intel(domain))

        logger.info(f'Australian OSINT complete: {len(self.results)} findings')
        return self.results


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Australian OSINT Module')
    parser.add_argument('--target', '-t', required=True)
    parser.add_argument('--type', default='auto', choices=['auto', 'abn', 'domain', 'phone', 'company', 'ip', 'email'])
    parser.add_argument('--output', '-o', default='au_osint_results.json')
    args = parser.parse_args()

    osint = AustralianOSINT()
    results = osint.full_recon(args.target, args.type)
    with open(args.output, 'w') as f:
        f.write(results.to_json())
    print(json.dumps(results.summary(), indent=2))
