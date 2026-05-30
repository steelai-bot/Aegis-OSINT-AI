"""
au-osint-recon :: darkweb_crawler.py
Dark web crawler — .onion search, marketplace monitoring, forum scraping.
Requires Tor proxy (SOCKS5 on port 9050) for .onion access.
"""

import os
import re
import json
import time
from typing import Optional, Dict, List, Any
from urllib.parse import quote, urlencode, urlparse

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    requests = None
    BeautifulSoup = None

from utils import (
    logger, safe_request, Finding, ResultStore,
    DataClassifier, random_ua, AU_PATTERNS
)


# Known search engines and indexes for .onion
ONION_SEARCH_ENGINES = {
    'ahmia': 'https://ahmia.fi/search/?q=',
    'torch_clearnet': 'https://torchsearch.xyz/search?query=',
    'haystak_clearnet': 'https://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion.ly/search?q=',
    'darkSearch': 'https://darksearch.io/api/search?query=',
    'onionland': 'https://onionlandsearchengine.net/search?q=',
}

# Known dark web forums & marketplaces with AU data
DARKWEB_SOURCES = {
    'forums': [
        {'name': 'BreachForums', 'clearnet': 'https://breachforums.st', 'search_path': '/search.php?action=results&keywords='},
        {'name': 'XSS.is', 'clearnet': 'https://xss.is', 'search_path': '/search/?q='},
        {'name': 'Exploit.in', 'clearnet': 'https://exploit.in', 'search_path': '/search/?q='},
        {'name': 'RaidForums Archive', 'clearnet': None, 'note': 'Seized, archives exist on mirrors'},
        {'name': 'Nulled.to', 'clearnet': 'https://nulled.to', 'search_path': '/search/?q='},
        {'name': 'Cracked.io', 'clearnet': 'https://cracked.io', 'search_path': '/search/?q='},
        {'name': 'LeakBase', 'clearnet': 'https://leakbase.io', 'search_path': '/search/?q='},
        {'name': 'Sinisterly', 'clearnet': 'https://sinisterly.net', 'search_path': '/search/?q='},
    ],
    'marketplaces': [
        {'name': 'Genesis Market', 'type': 'credentials/bots', 'note': 'Browser fingerprints + credentials'},
        {'name': 'Russian Market', 'type': 'credentials/logs', 'note': 'Stealer logs, RDP, SSH'},
        {'name': '2easy Shop', 'type': 'stealer_logs', 'note': 'Redline/Raccoon/Vidar logs'},
        {'name': 'BidenCash', 'type': 'credit_cards', 'note': 'Free CC dumps periodically'},
        {'name': 'BriansClub', 'type': 'credit_cards', 'note': 'Massive CC marketplace'},
        {'name': 'Joker Stash (legacy)', 'type': 'credit_cards', 'note': 'Closed but data persists'},
    ],
    'paste_onions': [
        {'name': 'StrongHold Paste', 'note': '.onion paste site'},
        {'name': 'DeepPaste', 'note': '.onion paste site'},
        {'name': 'ZeroBin Onion', 'note': 'Encrypted paste'},
    ],
}

# Australian-specific search keywords
AU_DARKWEB_KEYWORDS = [
    'australia database',
    'australian leak',
    'aussie combo',
    'com.au credentials',
    'com.au database',
    'australian credit card',
    'aussie fullz',
    'australian bank',
    'commbank leak',
    'westpac leak',
    'anz dump',
    'nab database',
    'optus breach',
    'medibank hack',
    'medicare data',
    'centrelink leak',
    'mygov breach',
    'australian passport',
    'australian driver license',
    'au identity',
    'telstra dump',
    'aus gov leak',
    '.gov.au breach',
    '.edu.au dump',
    'sydney database',
    'melbourne leak',
    'brisbane dump',
    'perth breach',
    'adelaide data',
    'queensland leak',
    'victoria database',
    'nsw breach',
]


class DarkWebCrawler:
    """Dark web intelligence gathering for Australian data."""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.results = ResultStore()
        self.tor_proxy = self.config.get('TOR_PROXY', os.getenv('TOR_PROXY', 'socks5h://127.0.0.1:9050'))
        self.use_tor = self.config.get('USE_TOR', False)
        self.session = requests.Session() if requests else None
        self.classifier = DataClassifier()

    def _check_tor(self) -> bool:
        """Verify Tor connectivity."""
        try:
            resp = safe_request(
                'https://check.torproject.org/api/ip',
                use_tor=True,
                timeout=15,
            )
            if resp and resp.status_code == 200:
                data = resp.json()
                is_tor = data.get('IsTor', False)
                logger.info(f'Tor check: {"Connected" if is_tor else "NOT connected"} (IP: {data.get("IP", "?")})')
                return is_tor
        except Exception as e:
            logger.warning(f'Tor check failed: {e}')
        return False

    # ── Ahmia Search ─────────────────────────────────────────────────────

    def search_ahmia(self, query: str, max_pages: int = 3) -> List[Finding]:
        """Search Ahmia.fi — clearnet gateway to .onion sites."""
        findings = []
        logger.info(f'  Searching Ahmia for: {query}')

        for page in range(max_pages):
            url = f'https://ahmia.fi/search/?q={quote(query)}&page={page}'
            resp = safe_request(url, timeout=20)

            if not resp or resp.status_code != 200:
                break

            if not BeautifulSoup:
                break

            soup = BeautifulSoup(resp.text, 'html.parser')
            results = soup.find_all('li', class_='result')

            if not results:
                break

            for result in results:
                title_elem = result.find('a')
                desc_elem = result.find('p')
                cite_elem = result.find('cite')

                if title_elem:
                    title = title_elem.get_text(strip=True)
                    link = title_elem.get('href', '')
                    desc = desc_elem.get_text(strip=True) if desc_elem else ''
                    onion_url = cite_elem.get_text(strip=True) if cite_elem else ''

                    # Check Australian relevance
                    combined = f'{title} {desc} {onion_url}'.lower()
                    is_au = self.classifier.is_australian(combined) or any(
                        kw in combined for kw in ['australia', 'aussie', '.com.au', 'au ']
                    )

                    findings.append(Finding(
                        source='Ahmia',
                        category='darkweb_listing',
                        data={
                            'title': title,
                            'onion_url': onion_url,
                            'description': desc[:500],
                            'search_query': query,
                            'is_australian': is_au,
                            'page': page,
                        },
                        confidence=0.6 if is_au else 0.3,
                    ))

            time.sleep(2)

        return findings

    # ── DarkSearch API ───────────────────────────────────────────────────

    def search_darksearch(self, query: str, max_pages: int = 3) -> List[Finding]:
        """Search DarkSearch.io API."""
        findings = []
        logger.info(f'  Searching DarkSearch for: {query}')

        for page in range(1, max_pages + 1):
            url = f'https://darksearch.io/api/search?query={quote(query)}&page={page}'
            resp = safe_request(url, timeout=20)

            if not resp or resp.status_code != 200:
                break

            try:
                data = resp.json()
                results = data.get('data', [])

                for item in results:
                    title = item.get('title', '')
                    link = item.get('link', '')
                    desc = item.get('description', '')

                    combined = f'{title} {desc}'.lower()
                    is_au = self.classifier.is_australian(combined)

                    findings.append(Finding(
                        source='DarkSearch',
                        category='darkweb_listing',
                        data={
                            'title': title,
                            'onion_url': link,
                            'description': desc[:500],
                            'search_query': query,
                            'is_australian': is_au,
                        },
                        confidence=0.6 if is_au else 0.3,
                    ))

                if not data.get('next'):
                    break

            except Exception as e:
                logger.error(f'DarkSearch parse error: {e}')
                break

            time.sleep(2)

        return findings

    # ── Clearnet Forum Search ────────────────────────────────────────────

    def search_forums_clearnet(self, query: str) -> List[Finding]:
        """Search known forums via clearnet mirrors."""
        findings = []

        for forum in DARKWEB_SOURCES['forums']:
            if not forum.get('clearnet') or not forum.get('search_path'):
                continue

            logger.info(f'  Searching {forum["name"]}...')
            url = f'{forum["clearnet"]}{forum["search_path"]}{quote(query)}'

            resp = safe_request(url, timeout=20)
            if not resp or resp.status_code != 200:
                continue

            if not BeautifulSoup:
                continue

            soup = BeautifulSoup(resp.text, 'html.parser')

            # Generic thread extraction
            threads = soup.find_all(['a', 'div', 'tr'], class_=re.compile(
                r'thread|topic|result|post|listing', re.I
            ))

            for thread in threads[:20]:
                title_elem = thread.find('a') if thread.name != 'a' else thread
                if not title_elem:
                    continue

                title = title_elem.get_text(strip=True)
                link = title_elem.get('href', '')

                if not title or len(title) < 5:
                    continue

                combined = f'{title}'.lower()
                is_au = self.classifier.is_australian(combined) or any(
                    kw.lower() in combined for kw in AU_DARKWEB_KEYWORDS[:10]
                )

                # Look for sale/dump indicators
                is_sale = any(w in combined for w in [
                    'sell', 'sale', 'dump', 'combo', 'leak', 'breach',
                    'database', 'fullz', 'credit card', 'cc', 'cvv',
                    'fresh', 'valid', 'hq', 'private', 'exclusive',
                ])

                if is_au or is_sale:
                    findings.append(Finding(
                        source=f'Forum-{forum["name"]}',
                        category='forum_listing',
                        data={
                            'forum': forum['name'],
                            'title': title[:200],
                            'url': link if link.startswith('http') else f'{forum["clearnet"]}{link}',
                            'search_query': query,
                            'is_australian': is_au,
                            'is_sale_listing': is_sale,
                        },
                        confidence=0.5 if is_au else 0.2,
                    ))

            time.sleep(3)

        return findings

    # ── Stealer Log Intelligence ─────────────────────────────────────────

    def generate_stealer_log_queries(self, target: str) -> Dict[str, List[str]]:
        """Generate queries for finding stealer logs (Redline, Raccoon, Vidar, etc.)."""
        return {
            'telegram_keywords': [
                f'"{target}" stealer logs',
                f'"{target}" redline logs',
                f'"{target}" raccoon logs',
                f'"{target}" vidar logs',
                f'"{target}" aurora stealer',
                f'"{target}" mars stealer',
                f'"{target}" meta stealer',
                f'"{target}" stealc logs',
                f'"{target}" risepro logs',
                f'cloud of logs "{target}"',
                f'"{target}" cookies autofill',
            ],
            'forum_keywords': [
                f'[SALE] {target} stealer logs',
                f'{target} fresh logs',
                f'{target} redline cloud',
                f'{target} bot logs',
                f'{target} browser data',
            ],
            'marketplace_queries': [
                f'domain:{target}',
                f'url:*{target}*',
            ],
        }

    # ── Ransomware Leak Site Monitoring ──────────────────────────────────

    def check_ransomware_sites(self, company: str) -> List[Finding]:
        """Check known ransomware group leak sites for Australian victims."""
        findings = []

        # Known ransomware groups with Australian victims
        ransomware_groups = [
            {'name': 'LockBit', 'note': 'Most active, has hit AU companies'},
            {'name': 'ALPHV/BlackCat', 'note': 'Hit multiple AU healthcare orgs'},
            {'name': 'Royal', 'note': 'Active in APAC'},
            {'name': 'BianLian', 'note': 'Data exfil focused'},
            {'name': 'Clop', 'note': 'MOVEit attacks hit AU orgs'},
            {'name': 'Play', 'note': 'Active in Australia'},
            {'name': 'Akira', 'note': 'New, targeting AU SMBs'},
            {'name': 'Rhysida', 'note': 'Government/education targets'},
            {'name': '8Base', 'note': 'SMB focused'},
            {'name': 'Medusa', 'note': 'Active globally'},
        ]

        # Check ransomware.live API (aggregator)
        url = f'https://ransomware.live/api/v1/victims'
        resp = safe_request(url, timeout=30)

        if resp and resp.status_code == 200:
            try:
                victims = resp.json()
                for victim in victims:
                    victim_name = victim.get('victim', '').lower()
                    victim_country = victim.get('country', '').lower()

                    if 'australia' in victim_country or 'au' == victim_country:
                        # Australian victim
                        if company.lower() in victim_name or victim_name in company.lower():
                            confidence = 0.9
                        else:
                            confidence = 0.6

                        findings.append(Finding(
                            source='RansomwareLeaks',
                            category='ransomware_victim',
                            data={
                                'victim_name': victim.get('victim', ''),
                                'group': victim.get('group', ''),
                                'date': victim.get('date', ''),
                                'country': victim.get('country', ''),
                                'url': victim.get('url', ''),
                                'description': victim.get('description', '')[:500],
                                'searched_company': company,
                            },
                            confidence=confidence,
                        ))
            except Exception as e:
                logger.error(f'Ransomware.live parse error: {e}')

        return findings

    # ── Known Australian Breaches Database ───────────────────────────────

    def get_known_au_breaches(self) -> List[Dict]:
        """Database of significant known Australian data breaches."""
        return [
            {'name': 'Optus', 'date': '2022-09', 'records': '9.8M', 'data': 'names, DOB, phone, email, passport, drivers license, medicare',
             'type': 'telecom', 'severity': 'critical'},
            {'name': 'Medibank', 'date': '2022-10', 'records': '9.7M', 'data': 'names, DOB, phone, email, medicare, health claims',
             'type': 'health_insurance', 'severity': 'critical'},
            {'name': 'Canva', 'date': '2019-05', 'records': '137M', 'data': 'email, username, name, city, password hash (bcrypt)',
             'type': 'tech', 'severity': 'high'},
            {'name': 'Latitude Financial', 'date': '2023-03', 'records': '14M', 'data': 'names, DOB, address, phone, passport, drivers license',
             'type': 'financial', 'severity': 'critical'},
            {'name': 'HWL Ebsworth', 'date': '2023-04', 'records': '65K+', 'data': 'legal documents, client data, government data',
             'type': 'legal', 'severity': 'critical'},
            {'name': 'Telstra', 'date': '2022-10', 'records': '30K', 'data': 'employee names, email',
             'type': 'telecom', 'severity': 'medium'},
            {'name': 'Woolworths/MyDeal', 'date': '2022-10', 'records': '2.2M', 'data': 'names, email, phone, DOB, address',
             'type': 'retail', 'severity': 'high'},
            {'name': 'Vinomofo', 'date': '2022-10', 'records': '500K', 'data': 'names, DOB, email, phone, address, gender',
             'type': 'retail', 'severity': 'medium'},
            {'name': 'Australian Clinical Labs', 'date': '2022-02', 'records': '223K', 'data': 'names, medicare, pathology results',
             'type': 'healthcare', 'severity': 'critical'},
            {'name': 'FlexBooker', 'date': '2022-01', 'records': '3.7M', 'data': 'names, email, phone, password hash',
             'type': 'tech', 'severity': 'high'},
            {'name': 'TIO Networks (Telstra)', 'date': '2017', 'records': '1.6M', 'data': 'names, address, DOB, bank details',
             'type': 'telecom', 'severity': 'critical'},
            {'name': 'Australian National University', 'date': '2019-11', 'records': '200K', 'data': 'names, DOB, address, phone, email, tax, bank, academic records',
             'type': 'education', 'severity': 'critical'},
            {'name': 'Service NSW', 'date': '2020-04', 'records': '186K', 'data': 'names, email, phone, address, drivers license, bank',
             'type': 'government', 'severity': 'critical'},
            {'name': 'Singtel/Optus (via Accellion)', 'date': '2021-02', 'records': 'Unknown', 'data': 'customer data',
             'type': 'telecom', 'severity': 'high'},
            {'name': 'Eastern Health', 'date': '2021-03', 'records': 'Unknown', 'data': 'patient records, health data',
             'type': 'healthcare', 'severity': 'critical'},
            {'name': 'Ambulance Victoria', 'date': '2023-06', 'records': '28K', 'data': 'employee data',
             'type': 'healthcare', 'severity': 'medium'},
            {'name': 'DP World Australia', 'date': '2023-11', 'records': 'Unknown', 'data': 'employee data, port operations',
             'type': 'logistics', 'severity': 'high'},
            {'name': 'Court Services Victoria', 'date': '2024-01', 'records': 'Unknown', 'data': 'court recordings, hearing records',
             'type': 'government', 'severity': 'critical'},
            {'name': 'MediSecure', 'date': '2024-05', 'records': '12.9M', 'data': 'prescriptions, personal data, medicare',
             'type': 'healthcare', 'severity': 'critical'},
            {'name': 'Ticketmaster AU', 'date': '2024-05', 'records': '560M (global)', 'data': 'names, email, phone, payment partial',
             'type': 'entertainment', 'severity': 'high'},
        ]

    def search_known_breaches(self, query: str) -> List[Finding]:
        """Search known Australian breaches for relevance to query."""
        findings = []
        query_lower = query.lower()
        breaches = self.get_known_au_breaches()

        for breach in breaches:
            if (query_lower in breach['name'].lower() or
                query_lower in breach.get('data', '').lower() or
                query_lower in breach.get('type', '').lower()):
                findings.append(Finding(
                    source='KnownBreaches-AU',
                    category='known_breach',
                    data=breach,
                    confidence=0.95,
                ))

        return findings

    # ── Full Dark Web Search ─────────────────────────────────────────────

    def full_search(self, target: str, include_tor: bool = False) -> ResultStore:
        """Complete dark web intelligence gathering."""
        logger.info(f'Starting dark web search for: {target}')

        # Known breaches first
        logger.info('[1] Checking known Australian breaches...')
        known = self.search_known_breaches(target)
        self.results.add_many(known)
        logger.info(f'  → Known breaches: {len(known)} matches')

        # Ahmia search
        logger.info('[2] Searching Ahmia.fi...')
        for kw in [f'{target} australia', f'{target} .com.au', f'{target} database leak']:
            ahmia = self.search_ahmia(kw, max_pages=2)
            self.results.add_many(ahmia)
        logger.info(f'  → Ahmia: {len(self.results)} total')

        # DarkSearch
        logger.info('[3] Searching DarkSearch...')
        for kw in [f'{target} australia', f'{target} breach']:
            ds = self.search_darksearch(kw, max_pages=2)
            self.results.add_many(ds)
        logger.info(f'  → DarkSearch: {len(self.results)} total')

        # Forum search
        logger.info('[4] Searching clearnet forum mirrors...')
        forums = self.search_forums_clearnet(f'{target} australia')
        self.results.add_many(forums)
        logger.info(f'  → Forums: {len(forums)} listings')

        # Ransomware check
        logger.info('[5] Checking ransomware leak sites...')
        ransom = self.check_ransomware_sites(target)
        self.results.add_many(ransom)
        logger.info(f'  → Ransomware: {len(ransom)} matches')

        # Stealer log queries
        logger.info('[6] Generating stealer log queries...')
        stealer_queries = self.generate_stealer_log_queries(target)
        self.results.add(Finding(
            source='StealerLogIntel',
            category='search_queries',
            data=stealer_queries,
            confidence=1.0,
        ))

        logger.info(f'Dark web search complete: {len(self.results)} total findings')
        return self.results


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Dark Web Crawler Module')
    parser.add_argument('--target', '-t', required=True)
    parser.add_argument('--tor', action='store_true')
    parser.add_argument('--output', '-o', default='darkweb_results.json')
    args = parser.parse_args()

    crawler = DarkWebCrawler({'USE_TOR': args.tor})
    results = crawler.full_search(args.target, include_tor=args.tor)
    with open(args.output, 'w') as f:
        f.write(results.to_json())
    print(json.dumps(results.summary(), indent=2))
