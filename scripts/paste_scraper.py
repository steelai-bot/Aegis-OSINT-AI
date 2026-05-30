"""
au-osint-recon :: paste_scraper.py
Scrape paste sites (Pastebin, Ghostbin, Rentry, dpaste, GitHub Gists)
for Australian leaked data.
"""

import os
import re
import json
import time
from typing import Optional, Dict, List, Any
from urllib.parse import quote

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    requests = None
    BeautifulSoup = None

from utils import (
    logger, safe_request, Finding, ResultStore,
    DataClassifier, AU_PATTERNS, AU_EMAIL_DOMAINS, random_ua
)


class PasteScraper:
    """Scrape paste sites for Australian leaked data."""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.results = ResultStore()
        self.classifier = DataClassifier()
        self.session = requests.Session() if requests else None

    # ── Pastebin Scraping ────────────────────────────────────────────────

    def search_pastebin(self, query: str) -> List[Finding]:
        """Search Pastebin via Google dorking (Pastebin API requires pro)."""
        findings = []

        # Pastebin scrape API (if available)
        pb_key = self.config.get('PASTEBIN_API_KEY', os.getenv('PASTEBIN_API_KEY', ''))

        if pb_key:
            # Use Pastebin scraping API
            url = 'https://scrape.pastebin.com/api_scraping.php'
            params = {'limit': 250}
            resp = safe_request(f'{url}?{params}', timeout=30)

            if resp and resp.status_code == 200:
                try:
                    pastes = resp.json()
                    for paste in pastes:
                        title = paste.get('title', '').lower()
                        # Fetch paste content for AU check
                        paste_url = paste.get('scrape_url', '')
                        if paste_url:
                            content_resp = safe_request(paste_url, timeout=10)
                            if content_resp and content_resp.status_code == 200:
                                content = content_resp.text
                                if self.classifier.is_australian(content) or query.lower() in content.lower():
                                    classified = self.classifier.classify(content)
                                    findings.append(Finding(
                                        source='Pastebin',
                                        category='paste_leak',
                                        data={
                                            'title': paste.get('title', ''),
                                            'url': paste.get('full_url', ''),
                                            'date': paste.get('date', ''),
                                            'size': paste.get('size', 0),
                                            'detected_data': classified,
                                            'content_preview': content[:500],
                                        },
                                        confidence=0.7,
                                    ))
                            time.sleep(1)  # Rate limit
                except Exception as e:
                    logger.error(f'Pastebin API error: {e}')

        # Google dork fallback
        google_queries = [
            f'site:pastebin.com "{query}"',
            f'site:pastebin.com "{query}" password',
            f'site:pastebin.com "{query}" .com.au',
            f'site:pastebin.com "{query}" database',
        ]

        for gq in google_queries:
            # Note: Direct Google scraping is rate-limited
            # Using pastebin search instead
            search_url = f'https://pastebin.com/search?q={quote(query)}'
            resp = safe_request(search_url, timeout=15)

            if resp and resp.status_code == 200 and BeautifulSoup:
                soup = BeautifulSoup(resp.text, 'html.parser')
                results = soup.find_all('a', href=re.compile(r'^/[a-zA-Z0-9]{8}$'))

                for result in results[:20]:
                    paste_id = result.get('href', '').strip('/')
                    title = result.get_text(strip=True)

                    # Fetch paste content
                    raw_url = f'https://pastebin.com/raw/{paste_id}'
                    content_resp = safe_request(raw_url, timeout=10)

                    if content_resp and content_resp.status_code == 200:
                        content = content_resp.text
                        is_au = self.classifier.is_australian(content)

                        if is_au or query.lower() in content.lower():
                            classified = self.classifier.classify(content)
                            findings.append(Finding(
                                source='Pastebin',
                                category='paste_leak',
                                data={
                                    'paste_id': paste_id,
                                    'title': title,
                                    'url': f'https://pastebin.com/{paste_id}',
                                    'detected_data': classified,
                                    'is_australian': is_au,
                                    'content_preview': content[:500],
                                    'content_length': len(content),
                                },
                                confidence=0.7 if is_au else 0.4,
                            ))

                    time.sleep(1.5)

            time.sleep(3)

        return findings

    # ── GitHub Gist Search ───────────────────────────────────────────────

    def search_github_gists(self, query: str) -> List[Finding]:
        """Search GitHub Gists for leaked AU data."""
        findings = []

        gh_token = self.config.get('GITHUB_TOKEN', os.getenv('GITHUB_TOKEN', ''))
        headers = {}
        if gh_token:
            headers['Authorization'] = f'token {gh_token}'
        headers['Accept'] = 'application/vnd.github.v3+json'

        # Search GitHub code
        search_queries = [
            f'{query} password site:gist.github.com',
            f'{query} .com.au credential',
            f'"{query}" filename:combo',
            f'"{query}" filename:dump',
        ]

        for sq in search_queries:
            url = f'https://api.github.com/search/code?q={quote(sq)}&per_page=30'
            resp = safe_request(url, headers=headers, timeout=15)

            if resp and resp.status_code == 200:
                data = resp.json()
                items = data.get('items', [])

                for item in items:
                    repo = item.get('repository', {})
                    findings.append(Finding(
                        source='GitHub-Gist',
                        category='code_leak',
                        data={
                            'name': item.get('name', ''),
                            'path': item.get('path', ''),
                            'url': item.get('html_url', ''),
                            'repo': repo.get('full_name', ''),
                            'repo_url': repo.get('html_url', ''),
                            'score': item.get('score', 0),
                        },
                        confidence=0.5,
                    ))

            time.sleep(2)

        return findings

    # ── GitHub Code Search for Secrets ───────────────────────────────────

    def search_github_secrets(self, domain: str) -> List[Finding]:
        """Search GitHub for accidentally committed secrets for AU domains."""
        findings = []

        gh_token = self.config.get('GITHUB_TOKEN', os.getenv('GITHUB_TOKEN', ''))
        headers = {'Accept': 'application/vnd.github.v3+json'}
        if gh_token:
            headers['Authorization'] = f'token {gh_token}'

        secret_patterns = [
            f'"{domain}" password',
            f'"{domain}" api_key',
            f'"{domain}" secret_key',
            f'"{domain}" access_token',
            f'"{domain}" AWS_SECRET',
            f'"{domain}" PRIVATE_KEY',
            f'"{domain}" jdbc:mysql',
            f'"{domain}" mongodb+srv',
            f'"{domain}" smtp_password',
            f'filename:.env "{domain}"',
            f'filename:.npmrc "{domain}"',
            f'filename:wp-config.php "{domain}"',
            f'filename:settings.py "{domain}" SECRET',
            f'filename:application.yml "{domain}" password',
            f'filename:docker-compose.yml "{domain}"',
        ]

        for pattern in secret_patterns[:10]:
            url = f'https://api.github.com/search/code?q={quote(pattern)}&per_page=10'
            resp = safe_request(url, headers=headers, timeout=15)

            if resp and resp.status_code == 200:
                data = resp.json()
                for item in data.get('items', []):
                    findings.append(Finding(
                        source='GitHub-Secrets',
                        category='exposed_secret',
                        data={
                            'file': item.get('name', ''),
                            'path': item.get('path', ''),
                            'url': item.get('html_url', ''),
                            'repo': item.get('repository', {}).get('full_name', ''),
                            'search_pattern': pattern,
                        },
                        confidence=0.6,
                    ))

            time.sleep(3)  # GitHub rate limit

        return findings

    # ── Other Paste Sites ────────────────────────────────────────────────

    def search_other_pastes(self, query: str) -> List[Finding]:
        """Search alternative paste sites."""
        findings = []

        paste_sites = [
            {'name': 'Rentry', 'search': f'https://rentry.co/search?q={quote(query)}'},
            {'name': 'dpaste', 'search': f'https://dpaste.org/search?q={quote(query)}'},
            {'name': 'PrivateBin', 'search': None, 'note': 'Encrypted, requires link'},
            {'name': 'PasteBin.pl', 'search': f'https://pastebin.pl/search?q={quote(query)}'},
            {'name': 'ControlC', 'search': f'https://controlc.com/search?q={quote(query)}'},
            {'name': 'JustPaste', 'search': f'https://justpaste.it/search/{quote(query)}'},
        ]

        for site in paste_sites:
            if not site.get('search'):
                continue

            logger.info(f'  Searching {site["name"]}...')
            resp = safe_request(site['search'], timeout=15)

            if resp and resp.status_code == 200 and BeautifulSoup:
                soup = BeautifulSoup(resp.text, 'html.parser')

                # Generic result extraction
                links = soup.find_all('a', href=True)
                for link in links[:20]:
                    href = link.get('href', '')
                    text = link.get_text(strip=True)

                    if not text or len(text) < 5:
                        continue

                    if query.lower() in text.lower() or self.classifier.is_australian(text):
                        findings.append(Finding(
                            source=f'Paste-{site["name"]}',
                            category='paste_leak',
                            data={
                                'site': site['name'],
                                'title': text[:200],
                                'url': href if href.startswith('http') else f'{site["search"].split("/search")[0]}{href}',
                            },
                            confidence=0.4,
                        ))

            time.sleep(2)

        return findings

    # ── Full Paste Search ────────────────────────────────────────────────

    def full_search(self, target: str) -> ResultStore:
        """Search all paste sites for target."""
        logger.info(f'Starting paste site search for: {target}')

        # Pastebin
        logger.info('[1] Searching Pastebin...')
        pb = self.search_pastebin(target)
        self.results.add_many(pb)
        logger.info(f'  → Pastebin: {len(pb)} findings')

        # GitHub
        logger.info('[2] Searching GitHub Gists...')
        gists = self.search_github_gists(target)
        self.results.add_many(gists)
        logger.info(f'  → GitHub Gists: {len(gists)} findings')

        # GitHub Secrets
        if '.' in target:
            logger.info('[3] Searching GitHub for exposed secrets...')
            secrets = self.search_github_secrets(target)
            self.results.add_many(secrets)
            logger.info(f'  → GitHub Secrets: {len(secrets)} findings')

        # Other paste sites
        logger.info('[4] Searching other paste sites...')
        others = self.search_other_pastes(target)
        self.results.add_many(others)
        logger.info(f'  → Other pastes: {len(others)} findings')

        logger.info(f'Paste search complete: {len(self.results)} findings')
        return self.results


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Paste Scraper Module')
    parser.add_argument('--target', '-t', required=True)
    parser.add_argument('--output', '-o', default='paste_results.json')
    args = parser.parse_args()

    scraper = PasteScraper()
    results = scraper.full_search(args.target)
    with open(args.output, 'w') as f:
        f.write(results.to_json())
    print(json.dumps(results.summary(), indent=2))
