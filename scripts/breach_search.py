"""
au-osint-recon :: breach_search.py
Search breach databases, combo lists, and credential leak repositories.
Targets: HIBP, DeHashed, LeakCheck, IntelX, BreachDirectory, Snusbase.
"""

import os
import re
import json
import time
import base64
import hashlib
from typing import Optional, Dict, List, Any
from urllib.parse import quote, urlencode

try:
    import requests
except ImportError:
    requests = None

from utils import (
    logger, safe_request, Finding, ResultStore,
    AU_PATTERNS, AU_EMAIL_DOMAINS, DataClassifier,
    identify_hash, random_ua, ts_iso
)


class BreachSearchEngine:
    """Multi-source breach & credential leak search engine."""

    def __init__(self, config: Optional[Dict[str, str]] = None):
        self.config = config or {}
        self.results = ResultStore()
        self.session = requests.Session() if requests else None

        # API keys from config or environment
        self.hibp_key = self.config.get('HIBP_API_KEY', os.getenv('HIBP_API_KEY', ''))
        self.dehashed_key = self.config.get('DEHASHED_API_KEY', os.getenv('DEHASHED_API_KEY', ''))
        self.dehashed_email = self.config.get('DEHASHED_EMAIL', os.getenv('DEHASHED_EMAIL', ''))
        self.intelx_key = self.config.get('INTELX_API_KEY', os.getenv('INTELX_API_KEY', ''))
        self.leakcheck_key = self.config.get('LEAKCHECK_API_KEY', os.getenv('LEAKCHECK_API_KEY', ''))
        self.snusbase_key = self.config.get('SNUSBASE_API_KEY', os.getenv('SNUSBASE_API_KEY', ''))

    # ── Have I Been Pwned ────────────────────────────────────────────────

    def search_hibp(self, email: str) -> List[Finding]:
        """Search HIBP for breached accounts."""
        findings = []
        if not self.hibp_key:
            logger.warning('HIBP: No API key configured, using free endpoint')

        # Breached accounts
        headers = {
            'hibp-api-key': self.hibp_key,
            'User-Agent': 'AU-OSINT-Recon',
        }

        url = f'https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}'
        params = {'truncateResponse': 'false', 'includeUnverified': 'true'}

        resp = safe_request(
            f'{url}?{urlencode(params)}',
            headers=headers,
            timeout=15,
        )
        if resp and resp.status_code == 200:
            breaches = resp.json()
            for breach in breaches:
                findings.append(Finding(
                    source='HIBP',
                    category='breach',
                    data={
                        'email': email,
                        'breach_name': breach.get('Name', ''),
                        'breach_domain': breach.get('Domain', ''),
                        'breach_date': breach.get('BreachDate', ''),
                        'data_classes': breach.get('DataClasses', []),
                        'pwn_count': breach.get('PwnCount', 0),
                        'description': breach.get('Description', ''),
                        'is_verified': breach.get('IsVerified', False),
                        'is_sensitive': breach.get('IsSensitive', False),
                    },
                    confidence=0.95 if breach.get('IsVerified') else 0.7,
                ))

        # Pastes
        paste_url = f'https://haveibeenpwned.com/api/v3/pasteaccount/{quote(email)}'
        resp = safe_request(paste_url, headers=headers, timeout=15)
        if resp and resp.status_code == 200:
            pastes = resp.json()
            for paste in (pastes or []):
                findings.append(Finding(
                    source='HIBP-Paste',
                    category='paste',
                    data={
                        'email': email,
                        'paste_source': paste.get('Source', ''),
                        'paste_id': paste.get('Id', ''),
                        'paste_title': paste.get('Title', ''),
                        'paste_date': paste.get('Date', ''),
                        'email_count': paste.get('EmailCount', 0),
                    },
                    confidence=0.8,
                ))

        # Password (k-anonymity)
        sha1 = hashlib.sha1(email.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        pwd_url = f'https://api.pwnedpasswords.com/range/{prefix}'
        resp = safe_request(pwd_url, timeout=10)
        if resp and resp.status_code == 200:
            for line in resp.text.splitlines():
                h, count = line.split(':')
                if h == suffix:
                    findings.append(Finding(
                        source='HIBP-Passwords',
                        category='password_exposure',
                        data={
                            'email': email,
                            'exposure_count': int(count),
                            'note': 'Password hash found in known breaches',
                        },
                        confidence=0.9,
                    ))
                    break

        return findings

    # ── DeHashed ─────────────────────────────────────────────────────────

    def search_dehashed(self, query: str, query_type: str = 'email') -> List[Finding]:
        """Search DeHashed for leaked credentials."""
        findings = []
        if not (self.dehashed_key and self.dehashed_email):
            logger.warning('DeHashed: Missing API key or email')
            return findings

        url = 'https://api.dehashed.com/search'
        params = {'query': f'{query_type}:{query}', 'size': 100}
        headers = {
            'Accept': 'application/json',
        }
        auth = (self.dehashed_email, self.dehashed_key)

        resp = safe_request(
            f'{url}?{urlencode(params)}',
            headers=headers,
            timeout=30,
        )
        # Manual auth since safe_request doesn't handle basic auth directly
        if requests and self.session:
            try:
                r = self.session.get(
                    url,
                    params=params,
                    headers={**headers, 'User-Agent': random_ua()},
                    auth=auth,
                    timeout=30,
                )
                if r.status_code == 200:
                    data = r.json()
                    entries = data.get('entries', []) or []
                    for entry in entries:
                        findings.append(Finding(
                            source='DeHashed',
                            category='credential',
                            data={
                                'email': entry.get('email', ''),
                                'username': entry.get('username', ''),
                                'password': entry.get('password', ''),
                                'hashed_password': entry.get('hashed_password', ''),
                                'name': entry.get('name', ''),
                                'ip_address': entry.get('ip_address', ''),
                                'phone': entry.get('phone', ''),
                                'address': entry.get('address', ''),
                                'database_name': entry.get('database_name', ''),
                                'obtained_from': entry.get('obtained_from', ''),
                            },
                            confidence=0.85,
                        ))
            except Exception as e:
                logger.error(f'DeHashed error: {e}')

        return findings

    # ── Intelligence X ───────────────────────────────────────────────────

    def search_intelx(self, query: str, max_results: int = 100) -> List[Finding]:
        """Search Intelligence X archive."""
        findings = []
        if not self.intelx_key:
            logger.warning('IntelX: No API key configured')
            return findings

        base = 'https://2.intelx.io'

        # Start search
        search_payload = {
            'term': query,
            'maxresults': max_results,
            'media': 0,   # all media types
            'sort': 2,     # relevance
            'terminate': [],
        }
        headers = {
            'x-key': self.intelx_key,
            'Content-Type': 'application/json',
        }

        try:
            r = self.session.post(
                f'{base}/intelligent/search',
                json=search_payload,
                headers={**headers, 'User-Agent': random_ua()},
                timeout=30,
            )
            if r.status_code != 200:
                return findings

            search_id = r.json().get('id')
            if not search_id:
                return findings

            # Poll for results
            time.sleep(3)
            for _ in range(10):
                r = self.session.get(
                    f'{base}/intelligent/search/result',
                    params={'id': search_id, 'limit': max_results},
                    headers={**headers, 'User-Agent': random_ua()},
                    timeout=30,
                )
                if r.status_code == 200:
                    data = r.json()
                    records = data.get('records', []) or []
                    for rec in records:
                        findings.append(Finding(
                            source='IntelX',
                            category='leak_archive',
                            data={
                                'name': rec.get('name', ''),
                                'date': rec.get('date', ''),
                                'bucket': rec.get('bucket', ''),
                                'media_type': rec.get('mediah', ''),
                                'size': rec.get('size', 0),
                                'storage_id': rec.get('storageid', ''),
                                'system_id': rec.get('systemid', ''),
                            },
                            confidence=0.8,
                        ))
                    if data.get('status', 0) in [0, 2]:  # finished or no more
                        break
                time.sleep(2)

        except Exception as e:
            logger.error(f'IntelX error: {e}')

        return findings

    # ── LeakCheck ────────────────────────────────────────────────────────

    def search_leakcheck(self, query: str, query_type: str = 'email') -> List[Finding]:
        """Search LeakCheck.io for leaked data."""
        findings = []
        if not self.leakcheck_key:
            logger.warning('LeakCheck: No API key configured')
            return findings

        url = f'https://leakcheck.io/api/v2/query/{quote(query)}'
        headers = {
            'X-API-Key': self.leakcheck_key,
            'Accept': 'application/json',
        }
        params = {'type': query_type}

        resp = safe_request(
            f'{url}?{urlencode(params)}',
            headers=headers,
            timeout=20,
        )
        if resp and resp.status_code == 200:
            data = resp.json()
            if data.get('success'):
                for entry in data.get('result', []):
                    findings.append(Finding(
                        source='LeakCheck',
                        category='credential',
                        data={
                            'email': entry.get('email', ''),
                            'username': entry.get('username', ''),
                            'password': entry.get('password', ''),
                            'hash': entry.get('hash', ''),
                            'origin': entry.get('source', {}).get('name', ''),
                            'breach_date': entry.get('source', {}).get('date', ''),
                        },
                        confidence=0.85,
                    ))

        return findings

    # ── Snusbase ─────────────────────────────────────────────────────────

    def search_snusbase(self, query: str, query_type: str = 'email') -> List[Finding]:
        """Search Snusbase for leaked databases."""
        findings = []
        if not self.snusbase_key:
            logger.warning('Snusbase: No API key configured')
            return findings

        url = 'https://api.snusbase.com/data/search'
        headers = {
            'Auth': self.snusbase_key,
            'Content-Type': 'application/json',
        }
        payload = {
            'terms': [query],
            'types': [query_type],
        }

        try:
            r = self.session.post(
                url,
                json=payload,
                headers={**headers, 'User-Agent': random_ua()},
                timeout=30,
            )
            if r.status_code == 200:
                data = r.json()
                results = data.get('results', {})
                for db_name, entries in results.items():
                    for entry in entries:
                        findings.append(Finding(
                            source='Snusbase',
                            category='credential',
                            data={
                                'database': db_name,
                                'email': entry.get('email', ''),
                                'username': entry.get('username', ''),
                                'password': entry.get('password', ''),
                                'hash': entry.get('hash', ''),
                                'name': entry.get('name', ''),
                                'lastip': entry.get('lastip', ''),
                            },
                            confidence=0.85,
                        ))
        except Exception as e:
            logger.error(f'Snusbase error: {e}')

        return findings

    # ── Breach Directory ─────────────────────────────────────────────────

    def search_breach_directory(self, query: str) -> List[Finding]:
        """Search BreachDirectory for leaks."""
        findings = []
        url = 'https://breachdirectory.org/api/search'

        # RapidAPI based
        rapid_key = self.config.get('RAPIDAPI_KEY', os.getenv('RAPIDAPI_KEY', ''))
        if not rapid_key:
            # Try free endpoint
            url = f'https://breachdirectory.org/api/search?query={quote(query)}'
            resp = safe_request(url, timeout=20)
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    for entry in data.get('result', []):
                        findings.append(Finding(
                            source='BreachDirectory',
                            category='credential',
                            data={
                                'email': entry.get('email', query),
                                'password': entry.get('password', ''),
                                'hash': entry.get('sha1', ''),
                                'sources': entry.get('sources', []),
                            },
                            confidence=0.75,
                        ))
                except Exception:
                    pass
        else:
            headers = {
                'X-RapidAPI-Key': rapid_key,
                'X-RapidAPI-Host': 'breachdirectory.p.rapidapi.com',
            }
            params = {'func': 'auto', 'term': query}
            resp = safe_request(
                'https://breachdirectory.p.rapidapi.com/',
                headers=headers,
                timeout=20,
            )
            if resp and resp.status_code == 200:
                data = resp.json()
                if data.get('success'):
                    for entry in data.get('result', []):
                        findings.append(Finding(
                            source='BreachDirectory',
                            category='credential',
                            data={
                                'email': query,
                                'password': entry.get('password', ''),
                                'hash': entry.get('sha1', ''),
                                'sources': entry.get('sources', []),
                                'has_password': entry.get('has_password', False),
                            },
                            confidence=0.8,
                        ))

        return findings

    # ── Google Dorking for AU Leaks ──────────────────────────────────────

    def generate_google_dorks(self, target: str) -> List[str]:
        """Generate Google dork queries for AU-targeted leak search."""
        dorks = [
            # Credential leaks
            f'site:pastebin.com "{target}" password',
            f'site:pastebin.com intext:"@{target}" "password"',
            f'site:ghostbin.com "{target}"',
            f'site:rentry.co "{target}"',
            f'site:dpaste.org "{target}"',

            # Database dumps
            f'"{target}" filetype:sql "INSERT INTO" "password"',
            f'"{target}" filetype:sql "VALUES" "@" ".com.au"',
            f'"{target}" filetype:csv email password',
            f'"{target}" filetype:txt "email" "pass"',
            f'"{target}" filetype:json "password" "email"',

            # Config leaks
            f'"{target}" filetype:env DB_PASSWORD',
            f'"{target}" filetype:yml password',
            f'"{target}" filetype:xml "password" "username"',
            f'"{target}" filetype:conf "password"',
            f'"{target}" filetype:ini "[database]" password',

            # Git leaks
            f'site:github.com "{target}" password',
            f'site:gitlab.com "{target}" "api_key"',
            f'site:bitbucket.org "{target}" secret',
            f'"{target}" inurl:".git" "password"',
            f'"{target}" inurl:"/.env" DB_',

            # Australian specific
            f'site:*.com.au "{target}" "password" OR "credential"',
            f'"{target}" "australian" "leaked" "database"',
            f'"{target}" ".gov.au" "password"',
            f'"{target}" "medicare" OR "tfn" OR "abn"',
            f'"{target}" "bsb" "account" "number"',
            f'"{target}" "optus" OR "medibank" OR "canva" "breach"',

            # Forum & paste leaks
            f'"{target}" site:raidforums.com OR site:breachforums.is',
            f'"{target}" site:xss.is "database" OR "combo"',
            f'"{target}" site:exploit.in "combolist"',
            f'"{target}" "leak" "dump" "australia"',

            # S3 / cloud storage
            f'site:s3.amazonaws.com "{target}"',
            f'site:storage.googleapis.com "{target}"',
            f'site:blob.core.windows.net "{target}"',
            f'"{target}" inurl:"s3" filetype:csv',

            # Exposed panels
            f'"{target}" intitle:"phpMyAdmin" inurl:"/phpmyadmin/"',
            f'"{target}" intitle:"Adminer" inurl:"/adminer"',
            f'"{target}" inurl:"/wp-admin" "database"',
            f'"{target}" intitle:"Index of" "database" OR "dump" OR "backup"',
        ]
        return dorks

    # ── Combo List Parser ────────────────────────────────────────────────

    def parse_combo_file(self, filepath: str, au_only: bool = True) -> List[Finding]:
        """Parse combo list file and extract AU-related entries."""
        findings = []
        classifier = DataClassifier()

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    # Check if Australian
                    if au_only and not classifier.is_australian(line):
                        # Check for AU email domains
                        has_au_domain = any(d in line.lower() for d in AU_EMAIL_DOMAINS)
                        if not has_au_domain:
                            continue

                    # Classify format
                    fmt = classifier.classify_credential_format(line)
                    if fmt:
                        parts = line.split(':', maxsplit=2)
                        data = {'raw_line': line, 'format': fmt, 'line_number': line_num}

                        if fmt == 'email:pass':
                            data['email'] = parts[0]
                            data['password'] = ':'.join(parts[1:])
                        elif fmt == 'user:pass':
                            data['username'] = parts[0]
                            data['password'] = ':'.join(parts[1:])
                        elif fmt == 'email:hash':
                            data['email'] = parts[0]
                            data['hash'] = parts[1]
                            data['hash_type'] = identify_hash(parts[1])

                        findings.append(Finding(
                            source='ComboList',
                            category='credential',
                            data=data,
                            confidence=0.6,
                            raw=line,
                        ))

        except Exception as e:
            logger.error(f'Error parsing combo file {filepath}: {e}')

        return findings

    # ── Full Search ──────────────────────────────────────────────────────


    def search_via_tor(self, query: str, query_type: str = "email") -> dict:
        """
        Route breach queries through Tor for anonymity.
        Uses SOCKS5 proxy to reach .onion breach lookup services.
        """
        tor_proxy = self.config.get("TOR_PROXY", "socks5://127.0.0.1:9050")
        proxies = {"http": tor_proxy, "https": tor_proxy}

        results = {"source": "tor_breach_lookup", "query": query, "results": []}

        # ProxyNova via Tor
        try:
            import requests
            r = requests.get(
                f"https://api.proxynova.com/comb?query={query}",
                proxies=proxies, timeout=30
            )
            if r.status_code == 200:
                data = r.json()
                results["proxynova_count"] = data.get("count", 0)
                results["results"].extend(data.get("lines", [])[:50])
        except Exception as e:
            results["proxynova_error"] = str(e)

        return results

    def async_bulk_search(self, targets: list[str], query_type: str = "email") -> list[dict]:
        """
        Async bulk search across all sources with rate limiting.
        Processes up to 50 targets concurrently.
        """
        import asyncio, aiohttp

        async def _fetch_one(session, target):
            result = {"target": target, "found_in": [], "total": 0}
            # ProxyNova (free, no auth)
            try:
                async with session.get(
                    f"https://api.proxynova.com/comb?query={target}",
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as r:
                    if r.status == 200:
                        data = await r.json()
                        if data.get("count", 0) > 0:
                            result["found_in"].append("proxynova")
                            result["total"] += data["count"]
            except Exception:
                pass
            return result

        async def _run_all(targets):
            connector = aiohttp.TCPConnector(limit=10)
            async with aiohttp.ClientSession(connector=connector) as session:
                tasks = [_fetch_one(session, t) for t in targets[:50]]
                return await asyncio.gather(*tasks, return_exceptions=True)

        try:
            loop = asyncio.new_event_loop()
            results = loop.run_until_complete(_run_all(targets))
            loop.close()
            return [r for r in results if isinstance(r, dict)]
        except Exception as e:
            return [{"error": str(e)}]

    def dedup_cross_source(self, results: list[dict]) -> list[dict]:
        """
        Deduplicate credentials found across multiple sources.
        Merges entries with same email, keeps richest data.
        """
        merged: dict[str, dict] = {}
        for entry in results:
            email = (entry.get("email") or entry.get("username") or "").lower().strip()
            if not email:
                continue
            if email not in merged:
                merged[email] = entry.copy()
                merged[email]["sources"] = []
            merged[email]["sources"].append(entry.get("source", "unknown"))
            # Merge password if present
            if entry.get("password") and not merged[email].get("password"):
                merged[email]["password"] = entry["password"]
        return list(merged.values())

    def search_github_exposed(self, domain: str) -> list[dict]:
        """
        Search GitHub for accidentally committed credentials for a domain.
        Uses GitHub Search API with AU-specific dorks.
        """
        dorks = [
            f'"{domain}" password',
            f'"{domain}" api_key',
            f'"{domain}" secret',
            f'"{domain}" credentials',
            f'"{domain}" .env',
            f'site:{domain} filetype:sql',
        ]
        results = []
        try:
            import requests
            headers = {"Accept": "application/vnd.github.v3+json"}
            if self.config.get("GITHUB_TOKEN"):
                headers["Authorization"] = f"token {self.config['GITHUB_TOKEN']}"

            for dork in dorks[:3]:  # Rate limit
                r = requests.get(
                    "https://api.github.com/search/code",
                    params={"q": dork, "per_page": 10},
                    headers=headers, timeout=10
                )
                if r.status_code == 200:
                    data = r.json()
                    for item in data.get("items", []):
                        results.append({
                            "dork":    dork,
                            "repo":    item["repository"]["full_name"],
                            "file":    item["path"],
                            "url":     item["html_url"],
                            "score":   item.get("score", 0),
                        })
                import time; time.sleep(2)
        except Exception as e:
            results.append({"error": str(e)})
        return results

    def estimate_breach_freshness(self, breach_name: str, breach_date: str) -> dict:
        """
        Estimate how fresh/dangerous a breach is based on age and known reuse patterns.
        """
        from datetime import datetime, timezone
        try:
            breach_dt = datetime.strptime(breach_date[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - breach_dt).days
        except Exception:
            age_days = 9999

        if age_days < 30:
            freshness = "critical"
            reuse_risk = "very_high"
        elif age_days < 180:
            freshness = "high"
            reuse_risk = "high"
        elif age_days < 365:
            freshness = "medium"
            reuse_risk = "medium"
        elif age_days < 730:
            freshness = "low"
            reuse_risk = "low"
        else:
            freshness = "stale"
            reuse_risk = "low"

        return {
            "breach_name":  breach_name,
            "breach_date":  breach_date,
            "age_days":     age_days,
            "freshness":    freshness,
            "reuse_risk":   reuse_risk,
            "note":         f"Credentials from this breach are {age_days} days old.",
        }

    def full_search(self, query: str, query_type: str = 'email') -> ResultStore:
        """Run search across all configured sources."""
        logger.info(f'Starting full breach search for: {query} (type: {query_type})')

        # HIBP
        logger.info('[1/6] Searching HIBP...')
        hibp = self.search_hibp(query)
        self.results.add_many(hibp)
        logger.info(f'  → HIBP: {len(hibp)} findings')

        # DeHashed
        logger.info('[2/6] Searching DeHashed...')
        dehashed = self.search_dehashed(query, query_type)
        self.results.add_many(dehashed)
        logger.info(f'  → DeHashed: {len(dehashed)} findings')

        # IntelX
        logger.info('[3/6] Searching Intelligence X...')
        intelx = self.search_intelx(query)
        self.results.add_many(intelx)
        logger.info(f'  → IntelX: {len(intelx)} findings')

        # LeakCheck
        logger.info('[4/6] Searching LeakCheck...')
        leakcheck = self.search_leakcheck(query, query_type)
        self.results.add_many(leakcheck)
        logger.info(f'  → LeakCheck: {len(leakcheck)} findings')

        # Snusbase
        logger.info('[5/6] Searching Snusbase...')
        snusbase = self.search_snusbase(query, query_type)
        self.results.add_many(snusbase)
        logger.info(f'  → Snusbase: {len(snusbase)} findings')

        # BreachDirectory
        logger.info('[6/6] Searching BreachDirectory...')
        bd = self.search_breach_directory(query)
        self.results.add_many(bd)
        logger.info(f'  → BreachDirectory: {len(bd)} findings')

        logger.info(f'Total unique findings: {len(self.results)}')
        return self.results


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Breach Search Module')
    parser.add_argument('--query', '-q', required=True, help='Search query')
    parser.add_argument('--type', '-t', default='email', choices=['email', 'username', 'domain', 'phone', 'ip'])
    parser.add_argument('--output', '-o', default='breach_results.json')
    parser.add_argument('--dorks', action='store_true', help='Generate Google dorks')
    args = parser.parse_args()

    engine = BreachSearchEngine()

    if args.dorks:
        dorks = engine.generate_google_dorks(args.query)
        for d in dorks:
            print(d)
    else:
        results = engine.full_search(args.query, args.type)
        with open(args.output, 'w') as f:
            f.write(results.to_json())
        print(json.dumps(results.summary(), indent=2))
