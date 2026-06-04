"""
leaked_db_hunter.py — AU-OSINT-RECON
Multi-source leaked account & database discovery engine.
Queries breach APIs, combo marketplaces, paste indexes, and dark web sources.
Includes paid combo list discovery with pricing intelligence.
"""

import os
import re
import json
import time
import hashlib
import urllib.parse
from datetime import datetime, timezone
from typing import Any
from collections import defaultdict

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


# ─────────────────────────────────────────────
#  Source Registry
# ─────────────────────────────────────────────

# Free / API-key sources
BREACH_API_SOURCES = {
    "hibp": {
        "name":     "Have I Been Pwned",
        "url":      "https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
        "headers":  {"hibp-api-key": "{HIBP_API_KEY}", "User-Agent": "au-osint-recon"},
        "free":     False,
        "env_key":  "HIBP_API_KEY",
        "rate":     1.5,
    },
    "dehashed": {
        "name":     "DeHashed",
        "url":      "https://api.dehashed.com/search?query={query}&size=100",
        "auth":     ("email", "DEHASHED_API_KEY"),
        "free":     False,
        "env_key":  "DEHASHED_API_KEY",
        "rate":     1.0,
    },
    "leakcheck": {
        "name":     "LeakCheck",
        "url":      "https://leakcheck.io/api/v2/query/{query}",
        "headers":  {"X-API-Key": "{LEAKCHECK_API_KEY}"},
        "free":     False,
        "env_key":  "LEAKCHECK_API_KEY",
        "rate":     1.0,
    },
    "intelx": {
        "name":     "Intelligence X",
        "url":      "https://2.intelx.io/intelligent/search",
        "headers":  {"x-key": "{INTELX_API_KEY}"},
        "free":     False,
        "env_key":  "INTELX_API_KEY",
        "rate":     2.0,
    },
    "snusbase": {
        "name":     "Snusbase",
        "url":      "https://api.snusbase.com/data/search",
        "headers":  {"Auth": "{SNUSBASE_API_KEY}", "Content-Type": "application/json"},
        "free":     False,
        "env_key":  "SNUSBASE_API_KEY",
        "rate":     1.0,
    },
    "breachdirectory": {
        "name":     "BreachDirectory",
        "url":      "https://breachdirectory.org/api?func=auto&term={query}",
        "headers":  {"X-RapidAPI-Key": "{RAPIDAPI_KEY}"},
        "free":     False,
        "env_key":  "RAPIDAPI_KEY",
        "rate":     1.0,
    },
    "proxynova": {
        "name":     "ProxyNova COMB",
        "url":      "https://api.proxynova.com/comb?query={query}",
        "free":     True,
        "rate":     2.0,
    },
    "hudsonrock": {
        "name":     "Hudson Rock (Cavalier)",
        "url":      "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-login?login={query}",
        "free":     True,
        "rate":     2.0,
    },
}

# Paid combo marketplace sources (intelligence only — pricing + availability)
PAID_COMBO_SOURCES = {
    "telegram_markets": [
        {"name": "BreachForums Telegram",  "channel": "@breachforums_official", "type": "telegram"},
        {"name": "Leakbase Telegram",      "channel": "@leakbase_io",           "type": "telegram"},
        {"name": "ComboList Telegram",     "channel": "@combolist",             "type": "telegram"},
        {"name": "AUS Leaks Telegram",     "channel": "@ausleaks",              "type": "telegram"},
        {"name": "OzLeaks",                "channel": "@ozleaks",               "type": "telegram"},
    ],
    "forums": [
        {"name": "BreachForums",           "url": "https://breachforums.st",    "type": "forum"},
        {"name": "Cracked.io",             "url": "https://cracked.io",         "type": "forum"},
        {"name": "Nulled.to",              "url": "https://nulled.to",          "type": "forum"},
        {"name": "XSS.is",                 "url": "https://xss.is",             "type": "forum"},
        {"name": "Exploit.in",             "url": "https://exploit.in",         "type": "forum"},
    ],
    "darkweb_markets": [
        {"name": "Genesis Market (mirror)", "type": "darkweb", "tags": ["stealer logs", "cookies", "fingerprints"]},
        {"name": "Russian Market",          "type": "darkweb", "tags": ["stealer logs", "CC", "RDP"]},
        {"name": "2easy Shop",              "type": "darkweb", "tags": ["stealer logs", "AU accounts"]},
        {"name": "Stealc Market",           "type": "darkweb", "tags": ["stealer logs", "crypto wallets"]},
    ],
}

# AU-specific combo list keywords for search
AU_COMBO_KEYWORDS = [
    "australia combo", "aussie combo", "com.au combo", "gov.au combo",
    "westpac combo", "commbank combo", "anz combo", "nab combo",
    "myGov combo", "centrelink combo", "ato combo", "medicare combo",
    "australia database", "AU database", "australia leak", "AU leak 2024",
    "australia stealer", "AU logs", "aussie logs",
]

# Bulgarian mail providers — searched separately, not mixed with AU
BG_COMBO_KEYWORDS = [
    "abv.bg combo", "mail.bg combo", "abv.bg leak", "mail.bg leak",
    "abv.bg database", "mail.bg database", "@abv.bg", "@mail.bg",
    "bulgaria combo", "bg combo", "bulgarian leak",
]

# Typical pricing tiers observed in markets (for intelligence reporting)
COMBO_PRICING_TIERS = {
    "generic_au":     {"price_usd": (5, 50),    "unit": "per 1M lines",  "quality": "low"},
    "au_banking":     {"price_usd": (100, 500),  "unit": "per 10k creds", "quality": "high"},
    "au_gov":         {"price_usd": (200, 1000), "unit": "per 1k creds",  "quality": "critical"},
    "au_stealer_log": {"price_usd": (1, 10),     "unit": "per log",       "quality": "medium"},
    "au_full_db":     {"price_usd": (500, 5000), "unit": "per database",  "quality": "high"},
    "au_cc_fullz":    {"price_usd": (20, 80),    "unit": "per card",      "quality": "high"},
}

# Bulgarian mail provider combo pricing (separate from AU)
BG_COMBO_PRICING = {
    "bg_mail_combo":  {"price_usd": (2, 20),  "unit": "per 100k lines", "quality": "medium",
                       "note": "abv.bg / mail.bg credential dumps. Common in EU breach markets."},
}


# ─────────────────────────────────────────────
#  API Query Helpers
# ─────────────────────────────────────────────

def _rate_sleep(seconds: float) -> None:
    time.sleep(seconds)


def _query_hibp(email: str, api_key: str) -> dict:
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}"
    headers = {"hibp-api-key": api_key, "User-Agent": "au-osint-recon/1.0"}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            return {"source": "hibp", "status": "found", "breaches": r.json()}
        elif r.status_code == 404:
            return {"source": "hibp", "status": "not_found", "breaches": []}
        else:
            return {"source": "hibp", "status": "error", "code": r.status_code}
    except Exception as e:
        return {"source": "hibp", "status": "error", "error": str(e)}


def _query_dehashed(query: str, email: str, api_key: str) -> dict:
    url = f"https://api.dehashed.com/search?query={urllib.parse.quote(query)}&size=100"
    try:
        r = requests.get(url, auth=(email, api_key), timeout=15)
        if r.status_code == 200:
            data = r.json()
            return {"source": "dehashed", "status": "found", "total": data.get("total", 0), "entries": data.get("entries", [])}
        return {"source": "dehashed", "status": "error", "code": r.status_code}
    except Exception as e:
        return {"source": "dehashed", "status": "error", "error": str(e)}


def _query_leakcheck(query: str, api_key: str) -> dict:
    url = f"https://leakcheck.io/api/v2/query/{urllib.parse.quote(query)}"
    headers = {"X-API-Key": api_key}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            return {"source": "leakcheck", "status": "found" if data.get("found") else "not_found", "data": data}
        return {"source": "leakcheck", "status": "error", "code": r.status_code}
    except Exception as e:
        return {"source": "leakcheck", "status": "error", "error": str(e)}


def _query_snusbase(query: str, query_type: str, api_key: str) -> dict:
    url = "https://api.snusbase.com/data/search"
    headers = {"Auth": api_key, "Content-Type": "application/json"}
    payload = {"terms": [query], "types": [query_type], "wildcard": False}
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=15)
        if r.status_code == 200:
            data = r.json()
            return {"source": "snusbase", "status": "found", "results": data.get("results", {}), "size": data.get("size", 0)}
        return {"source": "snusbase", "status": "error", "code": r.status_code}
    except Exception as e:
        return {"source": "snusbase", "status": "error", "error": str(e)}


def _query_proxynova(query: str) -> dict:
    url = f"https://api.proxynova.com/comb?query={urllib.parse.quote(query)}"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            return {"source": "proxynova", "status": "found", "count": data.get("count", 0), "lines": data.get("lines", [])}
        return {"source": "proxynova", "status": "error", "code": r.status_code}
    except Exception as e:
        return {"source": "proxynova", "status": "error", "error": str(e)}


def _query_hudsonrock(query: str) -> dict:
    url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-login?login={urllib.parse.quote(query)}"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            return {"source": "hudsonrock", "status": "found", "data": data}
        return {"source": "hudsonrock", "status": "error", "code": r.status_code}
    except Exception as e:
        return {"source": "hudsonrock", "status": "error", "error": str(e)}


# ─────────────────────────────────────────────
#  Combo Market Intelligence
# ─────────────────────────────────────────────

class ComboMarketIntelligence:
    """
    Generates intelligence reports on paid combo list markets.
    Does not directly scrape markets — produces structured intelligence
    on known sources, pricing, and AU-specific listings.
    """

    def __init__(self):
        self.listings: list[dict] = []

    def generate_market_report(self, target_keywords: list[str] | None = None) -> dict:
        """
        Build a structured market intelligence report for AU combo lists.
        """
        keywords = target_keywords or AU_COMBO_KEYWORDS

        report = {
            "generated_at":   datetime.now(timezone.utc).isoformat(),
            "telegram_channels": PAID_COMBO_SOURCES["telegram_markets"],
            "forums":            PAID_COMBO_SOURCES["forums"],
            "darkweb_markets":   PAID_COMBO_SOURCES["darkweb_markets"],
            "au_search_keywords": keywords,
            "pricing_intelligence": self._build_pricing_table(),
            "acquisition_guide":   self._build_acquisition_guide(),
        }
        return report

    def _build_pricing_table(self) -> list[dict]:
        rows = []
        for tier, info in COMBO_PRICING_TIERS.items():
            lo, hi = info["price_usd"]
            rows.append({
                "type":       tier.replace("_", " ").title(),
                "price_range": f"${lo}–${hi} {info['unit']}",
                "quality":    info["quality"],
                "notes":      self._tier_notes(tier),
            })
        return rows

    def _tier_notes(self, tier: str) -> str:
        notes = {
            "generic_au":     "Bulk combo lists, high dupe rate, low validity. Useful for spray attacks.",
            "au_banking":     "Westpac/CommBank/ANZ/NAB credentials. High value, frequently rotated.",
            "au_gov":         "myGov, ATO, Centrelink, Medicare. Extremely high value for fraud.",
            "au_stealer_log": "Full infostealer log per victim. Includes cookies, CC, crypto wallets.",
            "au_full_db":     "Full database dumps from AU companies. Includes PII + credentials.",
            "au_cc_fullz":    "Full credit card data with name, address, CVV. AU cards command premium.",
        }
        return notes.get(tier, "")

    def _build_acquisition_guide(self) -> list[dict]:
        return [
            {
                "step": 1,
                "action": "Monitor Telegram channels",
                "detail": "Join known AU leak channels. Use keywords: australia, aussie, com.au, gov.au, westpac, commbank",
                "channels": [s["channel"] for s in PAID_COMBO_SOURCES["telegram_markets"]],
            },
            {
                "step": 2,
                "action": "Search BreachForums / Cracked.io",
                "detail": "Use search operators: site:breachforums.st 'australia' OR 'com.au'. Filter by post date.",
                "urls": [s["url"] for s in PAID_COMBO_SOURCES["forums"][:2]],
            },
            {
                "step": 3,
                "action": "Check dark web markets",
                "detail": "Russian Market and 2easy Shop have dedicated AU stealer log sections. Filter by country=AU.",
                "markets": [s["name"] for s in PAID_COMBO_SOURCES["darkweb_markets"]],
            },
            {
                "step": 4,
                "action": "Use breach APIs for validation",
                "detail": "Cross-reference found credentials against HIBP, DeHashed, LeakCheck for breach attribution.",
                "apis": list(BREACH_API_SOURCES.keys()),
            },
            {
                "step": 5,
                "action": "Parse and filter",
                "detail": "Use credential_parser.py + infostealer_parser.py to process raw dumps. Filter AU domains.",
            },
        ]

    def add_listing(self, listing: dict) -> None:
        """Add a manually discovered listing."""
        self.listings.append({
            **listing,
            "discovered_at": datetime.now(timezone.utc).isoformat(),
        })

    def get_listings(self) -> list[dict]:
        return self.listings


# ─────────────────────────────────────────────
#  Main Hunter Class
# ─────────────────────────────────────────────

class LeakedDBHunter:
    """
    Multi-source leaked account and database discovery.
    Queries breach APIs, generates combo market intelligence,
    and builds findings for the report generator.

    Usage:
        hunter = LeakedDBHunter(config={"HIBP_API_KEY": "...", "DEHASHED_API_KEY": "..."})
        results = hunter.hunt_email("user@company.com.au")
        results = hunter.hunt_domain("company.com.au")
        market  = hunter.get_combo_market_intel()
    """

    def __init__(self, config: dict | None = None):
        self.config   = config or {}
        self.findings: list[dict] = []
        self.market   = ComboMarketIntelligence()

        # Load API keys from config or environment
        self._keys = {
            "HIBP_API_KEY":       self.config.get("HIBP_API_KEY")       or os.getenv("HIBP_API_KEY", ""),
            "DEHASHED_API_KEY":   self.config.get("DEHASHED_API_KEY")   or os.getenv("DEHASHED_API_KEY", ""),
            "DEHASHED_EMAIL":     self.config.get("DEHASHED_EMAIL")     or os.getenv("DEHASHED_EMAIL", ""),
            "LEAKCHECK_API_KEY":  self.config.get("LEAKCHECK_API_KEY")  or os.getenv("LEAKCHECK_API_KEY", ""),
            "SNUSBASE_API_KEY":   self.config.get("SNUSBASE_API_KEY")   or os.getenv("SNUSBASE_API_KEY", ""),
            "INTELX_API_KEY":     self.config.get("INTELX_API_KEY")     or os.getenv("INTELX_API_KEY", ""),
            "RAPIDAPI_KEY":       self.config.get("RAPIDAPI_KEY")       or os.getenv("RAPIDAPI_KEY", ""),
        }

    # ── Email Hunt ───────────────────────────────────────────

    def hunt_email(self, email: str) -> dict:
        """
        Query all available sources for a single email address.
        Returns aggregated results.
        """
        results = {"email": email, "sources": {}, "total_breaches": 0, "found_in": []}

        # HIBP
        if self._keys["HIBP_API_KEY"]:
            r = _query_hibp(email, self._keys["HIBP_API_KEY"])
            results["sources"]["hibp"] = r
            if r["status"] == "found":
                results["found_in"].append("hibp")
                results["total_breaches"] += len(r.get("breaches", []))
            _rate_sleep(1.5)

        # DeHashed
        if self._keys["DEHASHED_API_KEY"] and self._keys["DEHASHED_EMAIL"]:
            r = _query_dehashed(email, self._keys["DEHASHED_EMAIL"], self._keys["DEHASHED_API_KEY"])
            results["sources"]["dehashed"] = r
            if r["status"] == "found":
                results["found_in"].append("dehashed")
                results["total_breaches"] += r.get("total", 0)
            _rate_sleep(1.0)

        # LeakCheck
        if self._keys["LEAKCHECK_API_KEY"]:
            r = _query_leakcheck(email, self._keys["LEAKCHECK_API_KEY"])
            results["sources"]["leakcheck"] = r
            if r["status"] == "found":
                results["found_in"].append("leakcheck")
            _rate_sleep(1.0)

        # Snusbase
        if self._keys["SNUSBASE_API_KEY"]:
            r = _query_snusbase(email, "email", self._keys["SNUSBASE_API_KEY"])
            results["sources"]["snusbase"] = r
            if r["status"] == "found":
                results["found_in"].append("snusbase")
            _rate_sleep(1.0)

        # ProxyNova (free)
        r = _query_proxynova(email)
        results["sources"]["proxynova"] = r
        if r["status"] == "found" and r.get("count", 0) > 0:
            results["found_in"].append("proxynova")
        _rate_sleep(2.0)

        # Hudson Rock (free)
        r = _query_hudsonrock(email)
        results["sources"]["hudsonrock"] = r
        if r["status"] == "found":
            results["found_in"].append("hudsonrock")
        _rate_sleep(2.0)

        # Build finding
        if results["found_in"]:
            self._add_email_finding(email, results)

        return results

    def _add_email_finding(self, email: str, results: dict) -> None:
        is_au = bool(re.search(r"\.(?:com\.au|gov\.au|edu\.au|org\.au|net\.au)$", email))
        sev   = "critical" if is_au else "high"
        self.findings.append({
            "title":      f"Email Breach — {email}",
            "severity":   sev,
            "category":   "credential_breach",
            "source":     "leaked_db_hunter:" + ",".join(results["found_in"]),
            "summary":    (
                f"Found in {len(results['found_in'])} source(s): {', '.join(results['found_in'])}. "
                f"Total breach records: {results['total_breaches']}."
            ),
            "date_found": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "raw_data":   {"sources_found": results["found_in"], "total": results["total_breaches"]},
            "target":     email,
        })

    # ── Domain Hunt ──────────────────────────────────────────

    def hunt_domain(self, domain: str) -> dict:
        """
        Query all available sources for an entire domain.
        """
        results = {"domain": domain, "sources": {}, "found_in": []}

        if self._keys["DEHASHED_API_KEY"] and self._keys["DEHASHED_EMAIL"]:
            r = _query_dehashed(f"domain:{domain}", self._keys["DEHASHED_EMAIL"], self._keys["DEHASHED_API_KEY"])
            results["sources"]["dehashed"] = r
            if r["status"] == "found":
                results["found_in"].append("dehashed")
            _rate_sleep(1.0)

        if self._keys["LEAKCHECK_API_KEY"]:
            r = _query_leakcheck(domain, self._keys["LEAKCHECK_API_KEY"])
            results["sources"]["leakcheck"] = r
            if r["status"] == "found":
                results["found_in"].append("leakcheck")
            _rate_sleep(1.0)

        r = _query_proxynova(domain)
        results["sources"]["proxynova"] = r
        if r["status"] == "found" and r.get("count", 0) > 0:
            results["found_in"].append("proxynova")
        _rate_sleep(2.0)

        if results["found_in"]:
            self.findings.append({
                "title":      f"Domain Breach Exposure — {domain}",
                "severity":   "critical",
                "category":   "credential_breach",
                "source":     "leaked_db_hunter:" + ",".join(results["found_in"]),
                "summary":    f"Domain {domain} found in: {', '.join(results['found_in'])}.",
                "date_found": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "raw_data":   results,
                "target":     domain,
            })

        return results

    # ── Combo Market Intel ───────────────────────────────────

    def get_combo_market_intel(self, keywords: list[str] | None = None) -> dict:
        """
        Return structured combo market intelligence report.
        """
        report = self.market.generate_market_report(keywords)

        # Add as finding
        self.findings.append({
            "title":      "Paid Combo Market Intelligence — AU",
            "severity":   "high",
            "category":   "darkweb_listing",
            "source":     "leaked_db_hunter:market_intel",
            "summary":    (
                f"Intelligence gathered on {len(PAID_COMBO_SOURCES['telegram_markets'])} Telegram channels, "
                f"{len(PAID_COMBO_SOURCES['forums'])} forums, "
                f"{len(PAID_COMBO_SOURCES['darkweb_markets'])} dark web markets. "
                f"AU-specific pricing tiers documented."
            ),
            "date_found": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "raw_data":   {
                "telegram_channels": len(PAID_COMBO_SOURCES["telegram_markets"]),
                "forums":            len(PAID_COMBO_SOURCES["forums"]),
                "darkweb_markets":   len(PAID_COMBO_SOURCES["darkweb_markets"]),
                "pricing_tiers":     len(COMBO_PRICING_TIERS),
            },
            "target": "AU market",
        })

        return report

    # ── Bulk Hunt ────────────────────────────────────────────

    def hunt_email_list(self, emails: list[str], delay: float = 2.0) -> list[dict]:
        """Hunt multiple emails with rate limiting."""
        results = []
        for email in emails:
            result = self.hunt_email(email)
            results.append(result)
            time.sleep(delay)
        return results

    def get_findings(self) -> list[dict]:
        return self.findings


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AU-OSINT Leaked DB Hunter")
    parser.add_argument("--email",   help="Single email to hunt")
    parser.add_argument("--domain",  help="Domain to hunt")
    parser.add_argument("--market",  action="store_true", help="Generate combo market intel report")
    parser.add_argument("--output",  default="./reports")
    args = parser.parse_args()

    hunter = LeakedDBHunter()

    if args.email:
        result = hunter.hunt_email(args.email)
        print(json.dumps(result, indent=2, default=str))

    if args.domain:
        result = hunter.hunt_domain(args.domain)
        print(json.dumps(result, indent=2, default=str))

    if args.market:
        report = hunter.get_combo_market_intel()
        print(json.dumps(report, indent=2, default=str))
