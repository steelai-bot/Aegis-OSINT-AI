"""
au-osint-recon :: utils.py
Shared utilities — rate limiting, proxy rotation, request helpers, AU data patterns.
"""

import re
import time
import json
import hashlib
import random
import logging
import os
from typing import Optional, Dict, List, Any, Tuple
from datetime import datetime, timezone
from urllib.parse import urlparse, urlencode, quote
from collections import defaultdict

# ── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s %(name)s :: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('au-osint')


# ── Australian Regex Patterns ────────────────────────────────────────────────

AU_PATTERNS = {
    'email_au': re.compile(
        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.(?:com|net|org|gov|edu|id)\.au\b',
        re.IGNORECASE
    ),
    'phone_au': re.compile(
        r'(?:\+61|0061|0)[\s\-]?(?:'
        r'[2-478][\s\-]?\d{4}[\s\-]?\d{4}|'   # landline
        r'4\d{2}[\s\-]?\d{3}[\s\-]?\d{3}|'     # mobile 04xx
        r'1[38]00[\s\-]?\d{3}[\s\-]?\d{3}'      # toll-free
        r')'
    ),
    'abn': re.compile(r'\b\d{2}[\s\-]?\d{3}[\s\-]?\d{3}[\s\-]?\d{3}\b'),
    'acn': re.compile(r'\b\d{3}[\s\-]?\d{3}[\s\-]?\d{3}\b'),
    'tfn': re.compile(r'\b\d{3}[\s\-]?\d{3}[\s\-]?\d{3}\b'),  # same format as ACN but contextual
    'medicare': re.compile(r'\b\d{4}[\s\-]?\d{5}[\s\-]?\d{1}[\s\-]?\d{1}\b'),
    'bsb': re.compile(r'\b\d{3}[\s\-]?\d{3}\b'),
    'au_account': re.compile(r'\b\d{6,10}\b'),  # bank account numbers
    'passport_au': re.compile(r'\b[A-Z]{1,2}\d{7}\b'),
    'drivers_license_nsw': re.compile(r'\b\d{8}\b'),
    'ip_au_range': re.compile(
        r'\b(?:1\.(?:0|1[2-9]|[2-9]\d|1[0-1]\d|12[0-7])|'
        r'14\.(?:1[2-9]|[2-9]\d|1[0-1]\d)|'
        r'27\.(?:3[2-9]|[4-5]\d|6[0-3])|'
        r'43\.(?:2[4-5]\d|2[0-3]\d)|'
        r'49\.(?:1[2-9][0-9]|2[0-4]\d|25[0-5])|'
        r'101\.(?:0|1\d{1,2}|2[0-4]\d|25[0-5])|'
        r'103\.(?:[0-9]{1,3})|'
        r'110\.(?:1[4-5]\d|16[0-7])|'
        r'112\.(?:21[0-9]|2[2-4]\d|25[0-5])|'
        r'116\.(?:25[0-5]|24\d)|'
        r'120\.(?:1[5-9]\d|[2-9]\d{1,2})|'
        r'121\.(?:4[4-7]\d|48[0-9])|'
        r'122\.(?:1[4-5]\d|16[0-7])|'
        r'124\.(?:1[6-9]\d|[2-9]\d{1,2})|'
        r'175\.(?:3[2-9]|[4-5]\d|6[0-3])|'
        r'180\.(?:21[4-5])|'
        r'192\.(?:17[5-9]|1[89]\d|2[0-4]\d|25[0-5])|'
        r'203\.(?:[0-9]{1,3})|'
        r'210\.(?:[0-9]{1,3})|'
        r'211\.(?:2[6-9]|3[01]))'
        r'\.\d{1,3}\.\d{1,3}\b'
    ),
    'au_postcode': re.compile(r'\b(?:0[289]\d{2}|[1-9]\d{3})\b'),
    'domain_au': re.compile(
        r'\b[a-zA-Z0-9\-]+\.(?:com|net|org|gov|edu|id|asn)\.au\b',
        re.IGNORECASE
    ),
}

AU_EMAIL_DOMAINS = [
    '.com.au', '.net.au', '.org.au', '.gov.au', '.edu.au',
    '.id.au', '.asn.au', '.csiro.au', '.info.au',
]

BG_EMAIL_DOMAINS = [
    '@abv.bg', '@mail.bg',
]

AU_STATES = ['NSW', 'VIC', 'QLD', 'WA', 'SA', 'TAS', 'ACT', 'NT']

AU_MAJOR_BANKS = [
    'commbank', 'commonwealth', 'westpac', 'anz', 'nab',
    'macquarie', 'bendigo', 'suncorp', 'bankwest', 'ing',
    'hsbc', 'citibank', 'stgeorge', 'bankofmelbourne',
    'banksa', 'ubank', 'mebank', 'boq', 'amp',
]

AU_TELCOS = ['telstra', 'optus', 'vodafone', 'tpg', 'iinet', 'internode', 'dodo', 'amaysim']

AU_GOV_DOMAINS = [
    'services.gov.au', 'my.gov.au', 'ato.gov.au', 'centrelink.gov.au',
    'medicare.gov.au', 'defence.gov.au', 'aph.gov.au', 'police.gov.au',
    'health.gov.au', 'education.gov.au', 'border.gov.au',
]


# ── Rate Limiter ─────────────────────────────────────────────────────────────

class RateLimiter:
    """Token bucket rate limiter per domain."""

    def __init__(self, requests_per_second: float = 2.0, burst: int = 5):
        self.rps = requests_per_second
        self.burst = burst
        self._tokens: Dict[str, float] = defaultdict(lambda: float(burst))
        self._last_refill: Dict[str, float] = defaultdict(time.monotonic)

    def acquire(self, domain: str = 'default') -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill[domain]
        self._tokens[domain] = min(
            self.burst,
            self._tokens[domain] + elapsed * self.rps
        )
        self._last_refill[domain] = now

        if self._tokens[domain] < 1.0:
            wait = (1.0 - self._tokens[domain]) / self.rps
            logger.debug(f'Rate limiting {domain}: sleeping {wait:.2f}s')
            time.sleep(wait)
            self._tokens[domain] = 0.0
        else:
            self._tokens[domain] -= 1.0


# ── Proxy Rotation ───────────────────────────────────────────────────────────

class ProxyRotator:
    """Rotate through proxy list with health tracking."""

    def __init__(self, proxies: Optional[List[str]] = None):
        self.proxies = proxies or []
        self.index = 0
        self.failures: Dict[str, int] = defaultdict(int)
        self.max_failures = 3

    def add_proxy(self, proxy: str) -> None:
        self.proxies.append(proxy)

    def get_proxy(self) -> Optional[Dict[str, str]]:
        if not self.proxies:
            return None

        healthy = [p for p in self.proxies if self.failures[p] < self.max_failures]
        if not healthy:
            self.failures.clear()
            healthy = self.proxies

        proxy = healthy[self.index % len(healthy)]
        self.index += 1
        return {'http': proxy, 'https': proxy}

    def report_failure(self, proxy_url: str) -> None:
        self.failures[proxy_url] += 1
        logger.warning(f'Proxy failure #{self.failures[proxy_url]}: {proxy_url}')

    def load_from_file(self, filepath: str) -> int:
        count = 0
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.add_proxy(line)
                        count += 1
        return count


# ── User-Agent Rotation ──────────────────────────────────────────────────────

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:126.0) Gecko/20100101 Firefox/126.0',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
]

def random_ua() -> str:
    return random.choice(USER_AGENTS)


# ── Request Helper ───────────────────────────────────────────────────────────

_rate_limiter = RateLimiter()
_proxy_rotator = ProxyRotator()


def safe_request(
    url: str,
    method: str = 'GET',
    headers: Optional[Dict] = None,
    data: Optional[Any] = None,
    json_data: Optional[Dict] = None,
    timeout: int = 30,
    use_proxy: bool = False,
    use_tor: bool = False,
    rate_limit: bool = True,
    max_retries: int = 3,
    session=None,
) -> Optional[Any]:
    """Make a rate-limited, proxy-aware HTTP request with retries."""
    import requests as req

    domain = urlparse(url).netloc
    if rate_limit:
        _rate_limiter.acquire(domain)

    hdrs = {
        'User-Agent': random_ua(),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-AU,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
    }
    if headers:
        hdrs.update(headers)

    proxies = None
    if use_tor:
        tor_proxy = os.getenv('TOR_PROXY', 'socks5h://127.0.0.1:9050')
        proxies = {'http': tor_proxy, 'https': tor_proxy}
    elif use_proxy:
        proxies = _proxy_rotator.get_proxy()

    s = session or req.Session()

    for attempt in range(max_retries):
        try:
            resp = s.request(
                method=method.upper(),
                url=url,
                headers=hdrs,
                data=data,
                json=json_data,
                timeout=timeout,
                proxies=proxies,
                verify=not use_tor,
                allow_redirects=True,
            )
            resp.raise_for_status()
            return resp
        except req.exceptions.RequestException as e:
            logger.warning(f'Request failed (attempt {attempt+1}/{max_retries}): {e}')
            if proxies and use_proxy:
                proxy_url = list(proxies.values())[0]
                _proxy_rotator.report_failure(proxy_url)
                proxies = _proxy_rotator.get_proxy()
            time.sleep(2 ** attempt + random.random())

    logger.error(f'All {max_retries} attempts failed for {url}')
    return None


# ── Data Classification ──────────────────────────────────────────────────────

class DataClassifier:
    """Classify leaked data types from raw text."""

    @staticmethod
    def classify(text: str) -> Dict[str, List[str]]:
        results = {}
        for pattern_name, pattern in AU_PATTERNS.items():
            matches = list(set(pattern.findall(text)))
            if matches:
                results[pattern_name] = matches[:100]  # cap at 100 per type
        return results

    @staticmethod
    def is_australian(text: str) -> bool:
        """Heuristic: does this text contain Australian indicators?"""
        text_lower = text.lower()
        au_indicators = [
            'australia', 'aussie', '.com.au', '.gov.au', '.edu.au',
            'sydney', 'melbourne', 'brisbane', 'perth', 'adelaide',
            'canberra', 'hobart', 'darwin', 'queensland', 'victoria',
            'new south wales', 'tasmania', 'abn:', 'acn:', 'bsb:',
            'medicare', 'centrelink', 'mygov', '+61', '0061',
        ] + AU_MAJOR_BANKS + AU_TELCOS
        return any(ind in text_lower for ind in au_indicators)

    @staticmethod
    def classify_credential_format(line: str) -> Optional[str]:
        """Identify credential format in a line."""
        patterns = {
            'email:pass': re.compile(r'^[^:]+@[^:]+\.[^:]+:.+$'),
            'user:pass': re.compile(r'^[^:@]+:.+$'),
            'email:hash': re.compile(r'^[^:]+@[^:]+\.[^:]+:[a-fA-F0-9]{32,}$'),
            'hash:pass': re.compile(r'^[a-fA-F0-9]{32,}:.+$'),
            'email:pass:url': re.compile(r'^[^:]+@[^:]+\.[^:]+:.+:https?://.+$'),
            'url:email:pass': re.compile(r'^https?://[^:]+:[^:]+@[^:]+\.[^:]+:.+$'),
        }
        for fmt, pat in patterns.items():
            if pat.match(line.strip()):
                return fmt
        return None


# ── Hash Identifier ──────────────────────────────────────────────────────────

HASH_PATTERNS = {
    'MD5': re.compile(r'^[a-fA-F0-9]{32}$'),
    'SHA1': re.compile(r'^[a-fA-F0-9]{40}$'),
    'SHA256': re.compile(r'^[a-fA-F0-9]{64}$'),
    'SHA512': re.compile(r'^[a-fA-F0-9]{128}$'),
    'NTLM': re.compile(r'^[a-fA-F0-9]{32}$'),
    'bcrypt': re.compile(r'^\$2[aby]?\$\d{2}\$.{53}$'),
    'SHA512crypt': re.compile(r'^\$6\$[a-zA-Z0-9./]{8,16}\$[a-zA-Z0-9./]{86}$'),
    'MD5crypt': re.compile(r'^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}$'),
    'MySQL323': re.compile(r'^[a-fA-F0-9]{16}$'),
    'MySQL5': re.compile(r'^\*[a-fA-F0-9]{40}$'),
    'MSSQL2005': re.compile(r'^0x0100[a-fA-F0-9]{48}$'),
    'Oracle11': re.compile(r'^S:[a-fA-F0-9]{60}$'),
    'phpBB3': re.compile(r'^\$H\$[a-zA-Z0-9./]{31}$'),
    'Wordpress': re.compile(r'^\$P\$[a-zA-Z0-9./]{31}$'),
    'Argon2': re.compile(r'^\$argon2(id|i|d)\$.+$'),
}


def identify_hash(hash_str: str) -> List[str]:
    """Return possible hash types for a given string."""
    candidates = []
    for name, pattern in HASH_PATTERNS.items():
        if pattern.match(hash_str.strip()):
            candidates.append(name)
    return candidates


# ── Fingerprinting ───────────────────────────────────────────────────────────

def fingerprint_data(text: str) -> str:
    """Generate SHA256 fingerprint for deduplication."""
    return hashlib.sha256(text.encode('utf-8', errors='ignore')).hexdigest()


# ── Timestamp helpers ────────────────────────────────────────────────────────

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def ts_iso() -> str:
    return utcnow().isoformat()


# ── Result container ─────────────────────────────────────────────────────────

class Finding:
    """Single OSINT finding."""

    def __init__(
        self,
        source: str,
        category: str,
        data: Dict[str, Any],
        confidence: float = 0.5,
        raw: str = '',
    ):
        self.source = source
        self.category = category
        self.data = data
        self.confidence = min(max(confidence, 0.0), 1.0)
        self.raw = raw
        self.timestamp = ts_iso()
        self.fingerprint = fingerprint_data(json.dumps(data, sort_keys=True, default=str))

    def to_dict(self) -> Dict:
        return {
            'source': self.source,
            'category': self.category,
            'data': self.data,
            'confidence': self.confidence,
            'timestamp': self.timestamp,
            'fingerprint': self.fingerprint,
        }

    def __repr__(self):
        return f'<Finding [{self.source}] {self.category}: {self.confidence:.0%}>'


class ResultStore:
    """Deduplicated findings store."""

    def __init__(self):
        self.findings: List[Finding] = []
        self._seen: set = set()

    def add(self, finding: Finding) -> bool:
        if finding.fingerprint in self._seen:
            return False
        self._seen.add(finding.fingerprint)
        self.findings.append(finding)
        return True

    def add_many(self, findings: List[Finding]) -> int:
        return sum(1 for f in findings if self.add(f))

    def filter_by(self, source: Optional[str] = None, category: Optional[str] = None,
                  min_confidence: float = 0.0) -> List[Finding]:
        return [
            f for f in self.findings
            if (source is None or f.source == source)
            and (category is None or f.category == category)
            and f.confidence >= min_confidence
        ]

    def to_json(self) -> str:
        return json.dumps([f.to_dict() for f in self.findings], indent=2, default=str)

    def summary(self) -> Dict:
        cats = defaultdict(int)
        srcs = defaultdict(int)
        for f in self.findings:
            cats[f.category] += 1
            srcs[f.source] += 1
        return {
            'total_findings': len(self.findings),
            'by_category': dict(cats),
            'by_source': dict(srcs),
        }

    def __len__(self):
        return len(self.findings)
