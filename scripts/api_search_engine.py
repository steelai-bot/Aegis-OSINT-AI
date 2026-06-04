"""
api_search_engine.py — Aegis-OSINT-AI
Unified search engine across multiple APIs.
Aggregates results from Google, Bing, GitHub, Shodan, Censys,
GreyNoise, VirusTotal, URLScan, Dehashed, and more.
Supports authenticated (OAuth token) and API-key modes.
"""

import os
import re
import json
import time
import hashlib
import urllib.parse
from datetime import datetime, timezone
from collections import defaultdict
from typing import Any

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


# ─────────────────────────────────────────────
#  Search Engine Registry
# ─────────────────────────────────────────────

SEARCH_ENGINES = {
    # ── Web Search ──────────────────────────────────────────
    "google_cse": {
        "name":     "Google Custom Search",
        "url":      "https://www.googleapis.com/customsearch/v1",
        "auth":     "api_key",
        "env_key":  "GOOGLE_CSE_API_KEY",
        "env_cx":   "GOOGLE_CSE_CX",
        "category": "web",
        "free":     False,
        "rate":     1.0,
    },
    "bing": {
        "name":     "Bing Web Search",
        "url":      "https://api.bing.microsoft.com/v7.0/search",
        "auth":     "api_key",
        "env_key":  "BING_API_KEY",
        "category": "web",
        "free":     False,
        "rate":     1.0,
    },
    "brave": {
        "name":     "Brave Search",
        "url":      "https://api.search.brave.com/res/v1/web/search",
        "auth":     "api_key",
        "env_key":  "BRAVE_API_KEY",
        "category": "web",
        "free":     False,
        "rate":     1.0,
    },

    # ── Code / Repo Search ───────────────────────────────────
    "github_code": {
        "name":     "GitHub Code Search",
        "url":      "https://api.github.com/search/code",
        "auth":     "bearer",
        "env_key":  "GITHUB_TOKEN",
        "category": "code",
        "free":     True,
        "rate":     2.0,
    },
    "github_repos": {
        "name":     "GitHub Repository Search",
        "url":      "https://api.github.com/search/repositories",
        "auth":     "bearer",
        "env_key":  "GITHUB_TOKEN",
        "category": "code",
        "free":     True,
        "rate":     2.0,
    },
    "github_commits": {
        "name":     "GitHub Commit Search",
        "url":      "https://api.github.com/search/commits",
        "auth":     "bearer",
        "env_key":  "GITHUB_TOKEN",
        "category": "code",
        "free":     True,
        "rate":     2.0,
    },

    # ── Security / Threat Intel ──────────────────────────────
    "shodan": {
        "name":     "Shodan",
        "url":      "https://api.shodan.io/shodan/host/search",
        "auth":     "api_key",
        "env_key":  "SHODAN_API_KEY",
        "category": "security",
        "free":     False,
        "rate":     1.0,
    },
    "censys_hosts": {
        "name":     "Censys Hosts",
        "url":      "https://search.censys.io/api/v2/hosts/search",
        "auth":     "basic",
        "env_key":  "CENSYS_API_ID",
        "env_secret": "CENSYS_API_SECRET",
        "category": "security",
        "free":     False,
        "rate":     1.0,
    },
    "greynoise": {
        "name":     "GreyNoise",
        "url":      "https://api.greynoise.io/v3/community/{ip}",
        "auth":     "api_key",
        "env_key":  "GREYNOISE_API_KEY",
        "category": "security",
        "free":     True,
        "rate":     1.0,
    },
    "virustotal": {
        "name":     "VirusTotal",
        "url":      "https://www.virustotal.com/api/v3/search",
        "auth":     "api_key",
        "env_key":  "VIRUSTOTAL_API_KEY",
        "category": "security",
        "free":     False,
        "rate":     4.0,
    },
    "urlscan": {
        "name":     "URLScan.io",
        "url":      "https://urlscan.io/api/v1/search/",
        "auth":     "api_key",
        "env_key":  "URLSCAN_API_KEY",
        "category": "security",
        "free":     True,
        "rate":     1.0,
    },
    "alienvault_otx": {
        "name":     "AlienVault OTX",
        "url":      "https://otx.alienvault.com/api/v1/search/pulses",
        "auth":     "api_key",
        "env_key":  "OTX_API_KEY",
        "category": "security",
        "free":     True,
        "rate":     1.0,
    },

    # ── Breach / Credential ──────────────────────────────────
    "dehashed": {
        "name":     "DeHashed",
        "url":      "https://api.dehashed.com/search",
        "auth":     "basic",
        "env_key":  "DEHASHED_EMAIL",
        "env_secret": "DEHASHED_API_KEY",
        "category": "breach",
        "free":     False,
        "rate":     1.0,
    },
    "proxynova": {
        "name":     "ProxyNova COMB",
        "url":      "https://api.proxynova.com/comb",
        "auth":     "none",
        "category": "breach",
        "free":     True,
        "rate":     2.0,
    },
    "hudsonrock": {
        "name":     "Hudson Rock Cavalier",
        "url":      "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-login",
        "auth":     "none",
        "category": "breach",
        "free":     True,
        "rate":     2.0,
    },

    # ── OSINT / People ───────────────────────────────────────
    "hunter_io": {
        "name":     "Hunter.io (Email Finder)",
        "url":      "https://api.hunter.io/v2/domain-search",
        "auth":     "api_key",
        "env_key":  "HUNTER_API_KEY",
        "category": "osint",
        "free":     True,
        "rate":     1.0,
    },
    "fullcontact": {
        "name":     "FullContact Person API",
        "url":      "https://api.fullcontact.com/v3/person.enrich",
        "auth":     "bearer",
        "env_key":  "FULLCONTACT_API_KEY",
        "category": "osint",
        "free":     False,
        "rate":     1.0,
    },
    "intelx": {
        "name":     "Intelligence X",
        "url":      "https://2.intelx.io/intelligent/search",
        "auth":     "api_key",
        "env_key":  "INTELX_API_KEY",
        "category": "breach",
        "free":     False,
        "rate":     2.0,
    },

    # ── DNS / Network ────────────────────────────────────────
    "securitytrails": {
        "name":     "SecurityTrails",
        "url":      "https://api.securitytrails.com/v1/domain/{domain}",
        "auth":     "api_key",
        "env_key":  "SECURITYTRAILS_API_KEY",
        "category": "network",
        "free":     False,
        "rate":     1.0,
    },
    "passivedns_mnemonic": {
        "name":     "Mnemonic PassiveDNS",
        "url":      "https://api.mnemonic.no/pdns/v3/{query}",
        "auth":     "none",
        "category": "network",
        "free":     True,
        "rate":     1.0,
    },
    "crtsh": {
        "name":     "crt.sh Certificate Transparency",
        "url":      "https://crt.sh/?q={query}&output=json",
        "auth":     "none",
        "category": "network",
        "free":     True,
        "rate":     2.0,
    },
    "whoisxml": {
        "name":     "WhoisXML API",
        "url":      "https://www.whoisxmlapi.com/whoisserver/WhoisService",
        "auth":     "api_key",
        "env_key":  "WHOISXML_API_KEY",
        "category": "network",
        "free":     False,
        "rate":     1.0,
    },
}


# ─────────────────────────────────────────────
#  Search Result
# ─────────────────────────────────────────────

class SearchResult:
    __slots__ = ("engine", "query", "results", "total", "error", "timestamp", "category")

    def __init__(self, engine, query, results=None, total=0, error=None, category=""):
        self.engine    = engine
        self.query     = query
        self.results   = results or []
        self.total     = total
        self.error     = error
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.category  = category

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__slots__}

    @property
    def ok(self) -> bool:
        return self.error is None and bool(self.results)


# ─────────────────────────────────────────────
#  Engine-Specific Adapters
# ─────────────────────────────────────────────

def _search_google_cse(query: str, api_key: str, cx: str, num: int = 10) -> SearchResult:
    params = {"key": api_key, "cx": cx, "q": query, "num": min(num, 10)}
    try:
        r = requests.get(SEARCH_ENGINES["google_cse"]["url"], params=params, timeout=12)
        data = r.json()
        items = data.get("items", [])
        results = [{"title": i.get("title"), "url": i.get("link"), "snippet": i.get("snippet", "")} for i in items]
        return SearchResult("google_cse", query, results, data.get("searchInformation", {}).get("totalResults", 0), category="web")
    except Exception as e:
        return SearchResult("google_cse", query, error=str(e), category="web")


def _search_bing(query: str, api_key: str, count: int = 10) -> SearchResult:
    headers = {"Ocp-Apim-Subscription-Key": api_key}
    params  = {"q": query, "count": count, "mkt": "en-AU"}
    try:
        r = requests.get(SEARCH_ENGINES["bing"]["url"], headers=headers, params=params, timeout=12)
        data = r.json()
        items = data.get("webPages", {}).get("value", [])
        results = [{"title": i.get("name"), "url": i.get("url"), "snippet": i.get("snippet", "")} for i in items]
        return SearchResult("bing", query, results, data.get("webPages", {}).get("totalEstimatedMatches", 0), category="web")
    except Exception as e:
        return SearchResult("bing", query, error=str(e), category="web")


def _search_brave(query: str, api_key: str, count: int = 10) -> SearchResult:
    headers = {"Accept": "application/json", "Accept-Encoding": "gzip", "X-Subscription-Token": api_key}
    params  = {"q": query, "count": count, "country": "AU", "search_lang": "en"}
    try:
        r = requests.get(SEARCH_ENGINES["brave"]["url"], headers=headers, params=params, timeout=12)
        data = r.json()
        items = data.get("web", {}).get("results", [])
        results = [{"title": i.get("title"), "url": i.get("url"), "snippet": i.get("description", "")} for i in items]
        return SearchResult("brave", query, results, len(results), category="web")
    except Exception as e:
        return SearchResult("brave", query, error=str(e), category="web")


def _search_github(engine_key: str, query: str, token: str, per_page: int = 10) -> SearchResult:
    cfg = SEARCH_ENGINES[engine_key]
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    if engine_key == "github_commits":
        headers["Accept"] = "application/vnd.github.cloak-preview"

    params = {"q": query, "per_page": per_page}
    try:
        r = requests.get(cfg["url"], headers=headers, params=params, timeout=15)
        data = r.json()
        items = data.get("items", [])
        results = []
        for item in items:
            if engine_key == "github_code":
                results.append({"repo": item.get("repository", {}).get("full_name"), "file": item.get("path"), "url": item.get("html_url"), "score": item.get("score")})
            elif engine_key == "github_repos":
                results.append({"name": item.get("full_name"), "url": item.get("html_url"), "stars": item.get("stargazers_count"), "description": item.get("description", "")})
            elif engine_key == "github_commits":
                results.append({"sha": item.get("sha", "")[:7], "message": item.get("commit", {}).get("message", "")[:80], "url": item.get("html_url"), "repo": item.get("repository", {}).get("full_name")})
        return SearchResult(engine_key, query, results, data.get("total_count", 0), category="code")
    except Exception as e:
        return SearchResult(engine_key, query, error=str(e), category="code")


def _search_shodan(query: str, api_key: str) -> SearchResult:
    params = {"key": api_key, "query": query, "page": 1}
    try:
        r = requests.get(SEARCH_ENGINES["shodan"]["url"], params=params, timeout=15)
        data = r.json()
        items = data.get("matches", [])
        results = [{"ip": i.get("ip_str"), "port": i.get("port"), "org": i.get("org"), "country": i.get("location", {}).get("country_name"), "banner": i.get("data", "")[:200]} for i in items]
        return SearchResult("shodan", query, results, data.get("total", 0), category="security")
    except Exception as e:
        return SearchResult("shodan", query, error=str(e), category="security")


def _search_censys(query: str, api_id: str, api_secret: str) -> SearchResult:
    try:
        r = requests.post(
            SEARCH_ENGINES["censys_hosts"]["url"],
            json={"q": query, "per_page": 10},
            auth=(api_id, api_secret), timeout=15
        )
        data = r.json()
        items = data.get("result", {}).get("hits", [])
        results = [{"ip": i.get("ip"), "services": [s.get("service_name") for s in i.get("services", [])], "country": i.get("location", {}).get("country")} for i in items]
        return SearchResult("censys_hosts", query, results, data.get("result", {}).get("total", 0), category="security")
    except Exception as e:
        return SearchResult("censys_hosts", query, error=str(e), category="security")


def _search_urlscan(query: str, api_key: str) -> SearchResult:
    headers = {"API-Key": api_key}
    params  = {"q": query, "size": 10}
    try:
        r = requests.get(SEARCH_ENGINES["urlscan"]["url"], headers=headers, params=params, timeout=12)
        data = r.json()
        items = data.get("results", [])
        results = [{"url": i.get("page", {}).get("url"), "domain": i.get("page", {}).get("domain"), "ip": i.get("page", {}).get("ip"), "country": i.get("page", {}).get("country"), "screenshot": i.get("screenshot")} for i in items]
        return SearchResult("urlscan", query, results, data.get("total", 0), category="security")
    except Exception as e:
        return SearchResult("urlscan", query, error=str(e), category="security")


def _search_virustotal(query: str, api_key: str) -> SearchResult:
    headers = {"x-apikey": api_key}
    params  = {"query": query, "limit": 10}
    try:
        r = requests.get(SEARCH_ENGINES["virustotal"]["url"], headers=headers, params=params, timeout=15)
        data = r.json()
        items = data.get("data", [])
        results = [{"id": i.get("id"), "type": i.get("type"), "attributes": {k: v for k, v in i.get("attributes", {}).items() if k in ("name", "meaningful_name", "last_analysis_stats", "reputation")}} for i in items]
        return SearchResult("virustotal", query, results, len(results), category="security")
    except Exception as e:
        return SearchResult("virustotal", query, error=str(e), category="security")


def _search_hunter_io(domain: str, api_key: str) -> SearchResult:
    params = {"domain": domain, "api_key": api_key, "limit": 20}
    try:
        r = requests.get(SEARCH_ENGINES["hunter_io"]["url"], params=params, timeout=12)
        data = r.json()
        emails = data.get("data", {}).get("emails", [])
        results = [{"email": e.get("value"), "type": e.get("type"), "confidence": e.get("confidence"), "first_name": e.get("first_name"), "last_name": e.get("last_name"), "position": e.get("position")} for e in emails]
        return SearchResult("hunter_io", domain, results, len(results), category="osint")
    except Exception as e:
        return SearchResult("hunter_io", domain, error=str(e), category="osint")


def _search_crtsh(domain: str) -> SearchResult:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        r = requests.get(url, timeout=15)
        data = r.json()
        seen = set()
        results = []
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lstrip("*.")
                if sub not in seen and (sub.endswith(f".{domain}") or sub == domain):
                    seen.add(sub)
                    results.append({"subdomain": sub, "issuer": entry.get("issuer_name", "")[:60], "not_before": entry.get("not_before", "")})
        return SearchResult("crtsh", domain, results, len(results), category="network")
    except Exception as e:
        return SearchResult("crtsh", domain, error=str(e), category="network")


def _search_proxynova(query: str) -> SearchResult:
    try:
        r = requests.get(f"https://api.proxynova.com/comb?query={urllib.parse.quote(query)}", timeout=10)
        data = r.json()
        lines = data.get("lines", [])
        results = [{"credential": line} for line in lines[:50]]
        return SearchResult("proxynova", query, results, data.get("count", 0), category="breach")
    except Exception as e:
        return SearchResult("proxynova", query, error=str(e), category="breach")


def _search_hudsonrock(query: str) -> SearchResult:
    try:
        r = requests.get(f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-login?login={urllib.parse.quote(query)}", timeout=10)
        data = r.json()
        results = [data] if data else []
        return SearchResult("hudsonrock", query, results, len(results), category="breach")
    except Exception as e:
        return SearchResult("hudsonrock", query, error=str(e), category="breach")


def _search_securitytrails(domain: str, api_key: str) -> SearchResult:
    url = SEARCH_ENGINES["securitytrails"]["url"].replace("{domain}", domain)
    headers = {"APIKEY": api_key}
    try:
        r = requests.get(url, headers=headers, timeout=12)
        data = r.json()
        results = [{"domain": domain, "alexa_rank": data.get("alexa_rank"), "whois": data.get("whois", {}), "dns": data.get("current_dns", {})}]
        return SearchResult("securitytrails", domain, results, 1, category="network")
    except Exception as e:
        return SearchResult("securitytrails", domain, error=str(e), category="network")


# ─────────────────────────────────────────────
#  Main Search Engine Class
# ─────────────────────────────────────────────

class APISearchEngine:
    """
    Unified search across all configured engines.
    Auto-detects available engines from environment variables.
    Supports AU-specific dork generation and result deduplication.

    Usage:
        engine = APISearchEngine()
        results = engine.search("admin@company.com.au", engines=["proxynova", "github_code"])
        results = engine.search_all("company.com.au")
        results = engine.dork_search("company.com.au", dork_type="credentials")
        engine.print_results(results)
    """

    def __init__(self, oauth_manager=None):
        self.oauth  = oauth_manager
        self._cache: dict[str, SearchResult] = {}

    def available_engines(self) -> list[str]:
        """Return list of engines with credentials configured."""
        available = []
        for key, cfg in SEARCH_ENGINES.items():
            if cfg.get("auth") == "none":
                available.append(key)
            elif cfg.get("free") and cfg.get("auth") in ("none",):
                available.append(key)
            elif os.getenv(cfg.get("env_key", "")):
                available.append(key)
        return available

    def search(self, query: str, engines: list[str] | None = None, num: int = 10) -> list[SearchResult]:
        """Search across specified engines (or all available)."""
        active = engines or self.available_engines()
        results = []

        for engine_key in active:
            result = self._dispatch(engine_key, query, num)
            if result:
                results.append(result)
                time.sleep(SEARCH_ENGINES.get(engine_key, {}).get("rate", 1.0))

        return results

    def _dispatch(self, engine_key: str, query: str, num: int = 10) -> SearchResult | None:
        """Route query to correct adapter."""
        cfg = SEARCH_ENGINES.get(engine_key)
        if not cfg:
            return None

        def _key(env): return os.getenv(env, "")

        try:
            if engine_key == "google_cse":
                return _search_google_cse(query, _key("GOOGLE_CSE_API_KEY"), _key("GOOGLE_CSE_CX"), num)
            elif engine_key == "bing":
                return _search_bing(query, _key("BING_API_KEY"), num)
            elif engine_key == "brave":
                return _search_brave(query, _key("BRAVE_API_KEY"), num)
            elif engine_key in ("github_code", "github_repos", "github_commits"):
                token = _key("GITHUB_TOKEN")
                if self.oauth:
                    token = self.oauth.get_access_token("github") or token
                return _search_github(engine_key, query, token, num)
            elif engine_key == "shodan":
                return _search_shodan(query, _key("SHODAN_API_KEY"))
            elif engine_key == "censys_hosts":
                return _search_censys(query, _key("CENSYS_API_ID"), _key("CENSYS_API_SECRET"))
            elif engine_key == "urlscan":
                return _search_urlscan(query, _key("URLSCAN_API_KEY"))
            elif engine_key == "virustotal":
                return _search_virustotal(query, _key("VIRUSTOTAL_API_KEY"))
            elif engine_key == "hunter_io":
                return _search_hunter_io(query, _key("HUNTER_API_KEY"))
            elif engine_key == "crtsh":
                return _search_crtsh(query)
            elif engine_key == "proxynova":
                return _search_proxynova(query)
            elif engine_key == "hudsonrock":
                return _search_hudsonrock(query)
            elif engine_key == "securitytrails":
                return _search_securitytrails(query, _key("SECURITYTRAILS_API_KEY"))
        except Exception as e:
            return SearchResult(engine_key, query, error=str(e), category=cfg.get("category", ""))

        return None

    def search_all(self, target: str, categories: list[str] | None = None) -> dict[str, list[SearchResult]]:
        """
        Run target through all available engines, grouped by category.
        """
        results: dict[str, list[SearchResult]] = defaultdict(list)
        available = self.available_engines()

        for engine_key in available:
            cfg = SEARCH_ENGINES[engine_key]
            cat = cfg.get("category", "other")
            if categories and cat not in categories:
                continue
            result = self._dispatch(engine_key, target)
            if result:
                results[cat].append(result)
                time.sleep(cfg.get("rate", 1.0))

        return dict(results)

    def dork_search(self, target: str, dork_type: str = "credentials") -> list[SearchResult]:
        """
        Generate and run targeted dork queries for AU targets.
        dork_type: credentials | exposed_files | subdomains | emails | source_code
        """
        dorks = self._generate_dorks(target, dork_type)
        results = []

        web_engines = [k for k in self.available_engines()
                       if SEARCH_ENGINES[k].get("category") == "web"]

        for dork in dorks[:5]:
            for engine in web_engines[:2]:
                result = self._dispatch(engine, dork)
                if result and result.ok:
                    result.query = dork
                    results.append(result)
                time.sleep(2.0)

        return results

    def _generate_dorks(self, target: str, dork_type: str) -> list[str]:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        dorks = {
            "credentials": [
                f'site:pastebin.com "{domain}" password',
                f'site:github.com "{domain}" password OR secret OR api_key',
                f'"{domain}" filetype:sql "INSERT INTO" "password"',
                f'"{domain}" filetype:env "DB_PASSWORD" OR "API_KEY"',
                f'site:trello.com "{domain}" password',
                f'"{domain}" "@{domain}" filetype:txt password',
            ],
            "exposed_files": [
                f'site:{domain} filetype:pdf OR filetype:xlsx OR filetype:docx',
                f'site:{domain} intitle:"index of" "parent directory"',
                f'site:{domain} filetype:sql OR filetype:bak OR filetype:log',
                f'site:{domain} inurl:backup OR inurl:dump OR inurl:export',
            ],
            "subdomains": [
                f'site:*.{domain}',
                f'site:{domain} -www',
            ],
            "emails": [
                f'site:{domain} "@{domain}" email',
                f'"{domain}" filetype:csv email',
                f'intext:"@{domain}" site:linkedin.com',
            ],
            "source_code": [
                f'site:github.com "{domain}"',
                f'site:gitlab.com "{domain}"',
                f'site:bitbucket.org "{domain}"',
            ],
        }
        return dorks.get(dork_type, dorks["credentials"])

    def email_search(self, email: str) -> list[SearchResult]:
        """Comprehensive search for a single email address."""
        results = []
        # Breach sources
        for engine in ["proxynova", "hudsonrock"]:
            if engine in self.available_engines():
                r = self._dispatch(engine, email)
                if r:
                    results.append(r)
                time.sleep(2.0)
        # Code search
        if "github_code" in self.available_engines():
            r = self._dispatch("github_code", f'"{email}"')
            if r:
                results.append(r)
            time.sleep(2.0)
        return results

    def domain_intel(self, domain: str) -> list[SearchResult]:
        """Full domain intelligence gathering."""
        results = []
        for engine in ["crtsh", "securitytrails", "shodan", "urlscan", "hunter_io"]:
            if engine in self.available_engines():
                r = self._dispatch(engine, domain)
                if r:
                    results.append(r)
                time.sleep(1.5)
        return results

    def aggregate_findings(self, results: list[SearchResult]) -> list[dict]:
        """Convert search results to report_generator findings format."""
        findings = []
        for r in results:
            if not r.ok:
                continue
            sev = "high" if r.category == "breach" else "medium" if r.category == "security" else "low"
            findings.append({
                "title":      f"Search Result — {r.engine}: {r.query[:50]}",
                "severity":   sev,
                "category":   f"osint_{r.category}",
                "source":     f"api_search_engine:{r.engine}",
                "summary":    f"{r.total} results from {r.engine} for query: {r.query}",
                "date_found": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "raw_data":   {"engine": r.engine, "total": r.total, "sample": r.results[:3]},
                "target":     r.query,
            })
        return findings

    def print_results(self, results: list[SearchResult]) -> None:
        """Pretty-print search results."""
        try:
            from rich.console import Console
            from rich.table import Table
            from rich import box
            console = Console()
        except ImportError:
            for r in results:
                print(f"\n[{r.engine}] {r.query} — {r.total} results")
                for item in r.results[:3]:
                    print(f"  {item}")
            return

        for r in results:
            if not r.results and not r.error:
                continue
            table = Table(title=f"{r.engine} — {r.query[:60]}", box=box.SIMPLE, border_style="dim")
            if r.error:
                console.print(f"[red]✗[/red] {r.engine}: {r.error}")
                continue
            if not r.results:
                continue
            # Dynamic columns from first result
            cols = list(r.results[0].keys()) if r.results else []
            for col in cols[:5]:
                table.add_column(col, style="dim white", max_width=50)
            for item in r.results[:5]:
                table.add_row(*[str(item.get(c, ""))[:50] for c in cols[:5]])
            console.print(table)

    def status(self) -> None:
        """Show which engines are available."""
        available = self.available_engines()
        print(f"\n  {'Engine':<25} {'Category':<12} {'Free':<6} {'Status'}")
        print(f"  {'─'*25} {'─'*12} {'─'*6} {'─'*10}")
        for key, cfg in SEARCH_ENGINES.items():
            avail = "✓ ready" if key in available else "✗ no key"
            free  = "yes" if cfg.get("free") else "no"
            print(f"  {key:<25} {cfg.get('category',''):<12} {free:<6} {avail}")


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Aegis-OSINT-AI API Search Engine")
    parser.add_argument("--query",    help="Search query")
    parser.add_argument("--engines",  help="Comma-separated engine list")
    parser.add_argument("--email",    help="Search for email address")
    parser.add_argument("--domain",   help="Domain intelligence")
    parser.add_argument("--dork",     help="Dork type: credentials|exposed_files|emails|subdomains|source_code")
    parser.add_argument("--status",   action="store_true", help="Show engine availability")
    parser.add_argument("--output",   help="Save results to JSON file")
    args = parser.parse_args()

    engine = APISearchEngine()

    if args.status:
        engine.status()
    elif args.email:
        results = engine.email_search(args.email)
        engine.print_results(results)
    elif args.domain:
        if args.dork:
            results = engine.dork_search(args.domain, args.dork)
        else:
            results = engine.domain_intel(args.domain)
        engine.print_results(results)
    elif args.query:
        engines = [e.strip() for e in args.engines.split(",")] if args.engines else None
        results = engine.search(args.query, engines=engines)
        engine.print_results(results)
        if args.output:
            with open(args.output, "w") as f:
                json.dump([r.to_dict() for r in results], f, indent=2, default=str)
            print(f"\nSaved to: {args.output}")
    else:
        parser.print_help()
        print()
        engine.status()
