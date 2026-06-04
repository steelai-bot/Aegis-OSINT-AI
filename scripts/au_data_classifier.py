"""
au_data_classifier.py — AU-OSINT-RECON
Deep Australian data classification engine.
Identifies, validates, and risk-scores AU-specific PII, financial,
government, and corporate identifiers from raw text or structured data.
"""

import re
import json
from datetime import datetime, timezone
from typing import Any
from collections import defaultdict


# ─────────────────────────────────────────────
#  Validation Functions
# ─────────────────────────────────────────────

def validate_tfn(tfn: str) -> bool:
    """Validate Australian Tax File Number using official algorithm."""
    digits = re.sub(r"[\s\-]", "", tfn)
    if not re.match(r"^\d{8,9}$", digits):
        return False
    if len(digits) == 8:
        digits = "0" + digits
    weights = [1, 4, 3, 7, 5, 8, 6, 9, 10]
    total = sum(int(d) * w for d, w in zip(digits, weights))
    return total % 11 == 0


def validate_abn(abn: str) -> bool:
    """Validate Australian Business Number using official algorithm."""
    digits = re.sub(r"[\s\-]", "", abn)
    if not re.match(r"^\d{11}$", digits):
        return False
    weights = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19]
    d = list(int(c) for c in digits)
    d[0] -= 1  # Subtract 1 from first digit
    total = sum(d[i] * weights[i] for i in range(11))
    return total % 89 == 0


def validate_acn(acn: str) -> bool:
    """Validate Australian Company Number."""
    digits = re.sub(r"[\s\-]", "", acn)
    if not re.match(r"^\d{9}$", digits):
        return False
    weights = [8, 7, 6, 5, 4, 3, 2, 1]
    total = sum(int(digits[i]) * weights[i] for i in range(8))
    check = (10 - (total % 10)) % 10
    return check == int(digits[8])


def validate_medicare(medicare: str) -> bool:
    """Validate Australian Medicare card number."""
    digits = re.sub(r"[\s\-]", "", medicare)
    if not re.match(r"^[2-6]\d{9}$", digits):
        return False
    weights = [1, 3, 7, 9, 1, 3, 7, 9]
    total = sum(int(digits[i]) * weights[i] for i in range(8))
    return (total % 10) == int(digits[8])


def validate_bsb(bsb: str) -> bool:
    """Validate BSB format and known institution prefix."""
    digits = re.sub(r"[\s\-]", "", bsb)
    if not re.match(r"^\d{6}$", digits):
        return False
    # Known AU bank BSB prefixes
    known_prefixes = {
        "01": "ANZ", "03": "Westpac", "06": "CommBank", "08": "NAB",
        "09": "Citibank", "10": "BankWest", "11": "St George",
        "12": "Bank of Queensland", "14": "Macquarie", "18": "Bendigo",
        "19": "Suncorp", "22": "ING", "30": "Westpac",
        "33": "St George", "73": "HSBC", "80": "Citibank",
    }
    prefix = digits[:2]
    return prefix in known_prefixes


def validate_credit_card(cc: str) -> bool:
    """Luhn algorithm validation for credit card numbers."""
    digits = re.sub(r"[\s\-]", "", cc)
    if not re.match(r"^\d{13,19}$", digits):
        return False
    total = 0
    reverse = digits[::-1]
    for i, d in enumerate(reverse):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def validate_au_phone(phone: str) -> dict:
    """Validate and classify Australian phone number."""
    cleaned = re.sub(r"[\s\-\(\)]", "", phone)
    # Normalise to local format
    if cleaned.startswith("+61"):
        cleaned = "0" + cleaned[3:]
    elif cleaned.startswith("61") and len(cleaned) == 11:
        cleaned = "0" + cleaned[2:]

    result = {"valid": False, "type": "unknown", "carrier_hint": "", "formatted": cleaned}

    if re.match(r"^04\d{8}$", cleaned):
        result["valid"] = True
        result["type"] = "mobile"
        prefix = cleaned[:4]
        carrier_map = {
            "0400": "Telstra", "0401": "Telstra", "0402": "Telstra",
            "0403": "Optus",   "0404": "Optus",   "0405": "Vodafone",
            "0406": "Vodafone","0407": "Telstra",  "0408": "Telstra",
            "0409": "Optus",   "0410": "Telstra",  "0411": "Telstra",
            "0412": "Optus",   "0413": "Vodafone", "0414": "Telstra",
            "0415": "Optus",   "0416": "Vodafone", "0417": "Telstra",
            "0418": "Telstra", "0419": "Optus",    "0420": "Vodafone",
            "0421": "Optus",   "0422": "Telstra",  "0423": "Vodafone",
            "0424": "Telstra", "0425": "Optus",    "0426": "Vodafone",
            "0427": "Telstra", "0428": "Telstra",  "0429": "Optus",
            "0430": "Vodafone","0431": "Optus",    "0432": "Telstra",
            "0433": "Vodafone","0434": "Optus",    "0435": "Telstra",
            "0436": "Vodafone","0437": "Telstra",  "0438": "Optus",
            "0439": "Telstra", "0440": "Vodafone", "0450": "Optus",
        }
        result["carrier_hint"] = carrier_map.get(prefix, "Unknown")
        result["formatted"] = f"{cleaned[:4]} {cleaned[4:7]} {cleaned[7:]}"

    elif re.match(r"^0[2-9]\d{8}$", cleaned):
        result["valid"] = True
        result["type"] = "landline"
        area_map = {"02": "NSW/ACT", "03": "VIC/TAS", "07": "QLD", "08": "WA/SA/NT"}
        result["carrier_hint"] = area_map.get(cleaned[:2], "Unknown")
        result["formatted"] = f"({cleaned[:2]}) {cleaned[2:6]} {cleaned[6:]}"

    elif re.match(r"^13\d{4,8}$", cleaned) or re.match(r"^1800\d{6}$", cleaned):
        result["valid"] = True
        result["type"] = "freecall/business"

    return result


# ─────────────────────────────────────────────
#  Classification Patterns
# ─────────────────────────────────────────────

CLASSIFICATION_PATTERNS = {
    # Government / Identity
    "tfn":              (re.compile(r"\b(\d{3}[\s\-]?\d{3}[\s\-]?\d{3})\b"), "critical", "government_id"),
    "medicare":         (re.compile(r"\b([2-6]\d{9})\b"), "critical", "government_id"),
    "abn":              (re.compile(r"\b(\d{2}[\s\-]?\d{3}[\s\-]?\d{3}[\s\-]?\d{3})\b"), "high", "corporate_id"),
    "acn":              (re.compile(r"\b(\d{3}[\s\-]?\d{3}[\s\-]?\d{3})\b"), "medium", "corporate_id"),
    "drivers_licence":  (re.compile(r"\b([A-Z]{1,2}\d{5,9})\b"), "high", "government_id"),
    "passport_au":      (re.compile(r"\b([A-Z]\d{7})\b"), "critical", "government_id"),

    # Financial
    "bsb":              (re.compile(r"\b(\d{3}[\-]\d{3})\b"), "high", "financial"),
    "bank_account":     (re.compile(r"\b(\d{6,10})\b"), "high", "financial"),
    "credit_card":      (re.compile(r"\b((?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4})\b"), "critical", "financial"),
    "cvv":              (re.compile(r"\b(?:CVV|CVC|CVV2)[:\s]*(\d{3,4})\b", re.IGNORECASE), "critical", "financial"),
    "expiry":           (re.compile(r"\b(0[1-9]|1[0-2])[/\-](\d{2,4})\b"), "high", "financial"),
    "iban":             (re.compile(r"\b([A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16})\b"), "high", "financial"),
    "swift_au":         (re.compile(r"\b([A-Z]{4}AU[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b"), "medium", "financial"),
    "crypto_btc":       (re.compile(r"\b([13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"), "high", "financial"),
    "crypto_eth":       (re.compile(r"\b(0x[a-fA-F0-9]{40})\b"), "high", "financial"),

    # Credentials
    "email_au":         (re.compile(r"\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.(?:com\.au|gov\.au|edu\.au|org\.au|net\.au|id\.au))\b"), "high", "credential"),
    "email_generic":    (re.compile(r"\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b"), "medium", "credential"),
    "password_hash_md5":(re.compile(r"\b([a-fA-F0-9]{32})\b"), "medium", "credential"),
    "password_hash_sha1":(re.compile(r"\b([a-fA-F0-9]{40})\b"), "medium", "credential"),
    "password_hash_bcrypt":(re.compile(r"(\$2[aby]\$\d{2}\$[A-Za-z0-9./]{53})"), "high", "credential"),
    "ntlm_hash":        (re.compile(r"\b([a-fA-F0-9]{32}:[a-fA-F0-9]{32})\b"), "high", "credential"),
    "jwt":              (re.compile(r"(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"), "critical", "credential"),

    # Secrets
    "aws_key":          (re.compile(r"\b((?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16})\b"), "critical", "secret"),
    "aws_secret":       (re.compile(r"(?:aws_secret|secret_access_key)[=:\s\"']+([A-Za-z0-9/+]{40})", re.IGNORECASE), "critical", "secret"),
    "private_key":      (re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "critical", "secret"),
    "api_key":          (re.compile(r"(?:api[_\-]?key|apikey|access[_\-]?token)[=:\s\"']+([A-Za-z0-9_\-\.]{20,})", re.IGNORECASE), "high", "secret"),
    "github_token":     (re.compile(r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b"), "critical", "secret"),
    "slack_token":      (re.compile(r"\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b"), "critical", "secret"),
    "stripe_key":       (re.compile(r"\b(sk_live_[A-Za-z0-9]{24,})\b"), "critical", "secret"),
    "sendgrid_key":     (re.compile(r"\b(SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43,})\b"), "critical", "secret"),

    # Network
    "ipv4_private":     (re.compile(r"\b((?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3})\b"), "low", "network"),
    "ipv4_public":      (re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"), "low", "network"),
    "onion":            (re.compile(r"([a-z2-7]{16,56}\.onion(?:/[^\s]*)?)"), "medium", "network"),
    "au_domain":        (re.compile(r"\b((?:[a-zA-Z0-9\-]+\.)+(?:com\.au|gov\.au|edu\.au|org\.au|net\.au))\b"), "medium", "network"),

    # Contact
    "au_mobile":        (re.compile(r"\b((?:\+614|04)\d{8})\b"), "medium", "contact"),
    "au_landline":      (re.compile(r"\b(0[2-9]\d{8})\b"), "low", "contact"),
    "au_postcode":      (re.compile(r"\b([0-9]{4})\b"), "info", "contact"),
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ─────────────────────────────────────────────
#  Main Classifier
# ─────────────────────────────────────────────

class AUDataClassifier:
    """
    Deep classification and validation of Australian data.
    Validates identifiers using official algorithms (TFN, ABN, Medicare, Luhn).
    Produces severity-graded findings with confidence scores.

    Usage:
        clf = AUDataClassifier()
        result = clf.classify_text(raw_text)
        result = clf.classify_file("leaked_data.txt")
        result = clf.classify_credentials(cred_list)
    """

    def __init__(self, validate: bool = True):
        self.validate  = validate   # Run checksum validation
        self._findings: list[dict] = []

    def classify_text(self, text: str, source: str = "unknown") -> dict:
        """
        Classify all AU data types found in raw text.
        Returns structured result with validated matches.
        """
        matches: dict[str, list[dict]] = defaultdict(list)
        seen = set()

        for dtype, (pattern, severity, category) in CLASSIFICATION_PATTERNS.items():
            for m in pattern.finditer(text):
                val = m.group(1) if m.lastindex else m.group(0)
                val = val.strip()
                key = f"{dtype}:{val}"
                if key in seen:
                    continue
                seen.add(key)

                # Validation
                valid = self._validate(dtype, val)
                confidence = "confirmed" if valid else "candidate"

                if valid is False and self.validate:
                    continue  # Skip invalid checksums

                context = text[max(0, m.start()-60):m.end()+60].replace("\n", " ").strip()

                matches[dtype].append({
                    "value":      val,
                    "severity":   severity,
                    "category":   category,
                    "confidence": confidence,
                    "context":    context,
                })

        # Build summary
        severity_counts = defaultdict(int)
        for dtype, items in matches.items():
            for item in items:
                severity_counts[item["severity"]] += 1

        result = {
            "source":          source,
            "total_matches":   sum(len(v) for v in matches.values()),
            "severity_counts": dict(severity_counts),
            "matches":         dict(matches),
            "highest_severity": self._highest_severity(severity_counts),
            "classified_at":   datetime.now(timezone.utc).isoformat(),
        }

        # Build findings
        self._build_findings_from_result(result, source)
        return result

    def classify_file(self, file_path: str) -> dict:
        """Classify a text file."""
        from pathlib import Path
        text = Path(file_path).read_text(encoding="utf-8", errors="replace")
        return self.classify_text(text, source=file_path)

    def classify_credentials(self, credentials: list[dict]) -> dict:
        """
        Classify a list of {email, password} credential pairs.
        Analyses password patterns, identifies AU domains, detects hash types.
        """
        au_count   = 0
        gov_count  = 0
        bank_count = 0
        patterns   = defaultdict(int)
        hashes     = defaultdict(int)

        for cred in credentials:
            email = cred.get("email", "")
            pwd   = cred.get("password", "")

            if re.search(r"\.(?:com\.au|gov\.au|edu\.au|org\.au|net\.au)$", email):
                au_count += 1
            if re.search(r"\.gov\.au$", email):
                gov_count += 1
            if re.search(r"(?:westpac|commbank|anz|nab|macquarie|suncorp|bendigo)", email, re.IGNORECASE):
                bank_count += 1

            # Password pattern analysis
            if re.match(r"^[a-fA-F0-9]{32}$", pwd):
                hashes["md5"] += 1
            elif re.match(r"^[a-fA-F0-9]{40}$", pwd):
                hashes["sha1"] += 1
            elif re.match(r"^[a-fA-F0-9]{64}$", pwd):
                hashes["sha256"] += 1
            elif re.match(r"^\$2[aby]\$", pwd):
                hashes["bcrypt"] += 1
            elif re.match(r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$", pwd):
                hashes["ntlm"] += 1
            else:
                # Plaintext pattern
                if re.match(r"^\d{4,8}$", pwd):
                    patterns["numeric_pin"] += 1
                elif re.match(r"^[a-zA-Z]+\d{1,4}$", pwd):
                    patterns["word_number"] += 1
                elif re.search(r"[A-Z].*[a-z].*\d", pwd):
                    patterns["mixed_complex"] += 1
                elif len(pwd) <= 6:
                    patterns["weak_short"] += 1
                else:
                    patterns["other_plaintext"] += 1

        return {
            "total":        len(credentials),
            "au_domain":    au_count,
            "gov_domain":   gov_count,
            "bank_domain":  bank_count,
            "hash_types":   dict(hashes),
            "pwd_patterns": dict(patterns),
            "plaintext_pct": round((sum(patterns.values()) / max(len(credentials), 1)) * 100, 1),
            "hash_pct":      round((sum(hashes.values()) / max(len(credentials), 1)) * 100, 1),
        }

    def _validate(self, dtype: str, value: str) -> bool | None:
        """Run checksum validation. Returns True/False/None (None = no validator)."""
        validators = {
            "tfn":         validate_tfn,
            "abn":         validate_abn,
            "acn":         validate_acn,
            "medicare":    validate_medicare,
            "bsb":         validate_bsb,
            "credit_card": validate_credit_card,
        }
        fn = validators.get(dtype)
        if fn:
            try:
                return fn(value)
            except Exception:
                return False
        return None  # No validator — accept as candidate

    def _highest_severity(self, counts: dict) -> str:
        for sev in ["critical", "high", "medium", "low", "info"]:
            if counts.get(sev, 0) > 0:
                return sev
        return "info"

    def _build_findings_from_result(self, result: dict, source: str) -> None:
        if result["total_matches"] == 0:
            return
        self._findings.append({
            "title":      f"AU Data Classification — {source}",
            "severity":   result["highest_severity"],
            "category":   "pii_exposure",
            "source":     f"au_data_classifier:{source}",
            "summary":    (
                f"{result['total_matches']} AU data items classified. "
                f"Severity breakdown: {result['severity_counts']}"
            ),
            "date_found": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "raw_data":   {
                "severity_counts": result["severity_counts"],
                "match_types":     list(result["matches"].keys()),
                "total":           result["total_matches"],
            },
            "target": source,
        })

    def get_findings(self) -> list[dict]:
        return self._findings

    def validate_batch(self, items: list[dict]) -> list[dict]:
        """
        Validate a batch of {type, value} items.
        Returns each item with added 'valid' and 'confidence' fields.
        """
        results = []
        for item in items:
            dtype = item.get("type", "")
            value = item.get("value", "")
            valid = self._validate(dtype, value)
            results.append({**item, "valid": valid, "confidence": "confirmed" if valid else "candidate"})
        return results


if __name__ == "__main__":
    import argparse, sys
    parser = argparse.ArgumentParser(description="AU Data Classifier")
    parser.add_argument("--file",   help="Text file to classify")
    parser.add_argument("--text",   help="Raw text to classify")
    parser.add_argument("--no-validate", action="store_true", help="Skip checksum validation")
    args = parser.parse_args()

    clf = AUDataClassifier(validate=not args.no_validate)

    if args.file:
        result = clf.classify_file(args.file)
    elif args.text:
        result = clf.classify_text(args.text)
    else:
        # Demo
        demo = """
        TFN: 123 456 782
        ABN: 51 824 753 556
        Medicare: 2123456701
        BSB: 062-000
        Card: 4532015112830366
        Email: admin@company.com.au
        Mobile: 0412 345 678
        AWS: AKIAIOSFODNN7EXAMPLE
        JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
        """
        result = clf.classify_text(demo, source="demo")

    print(json.dumps({k: v for k, v in result.items() if k != "matches"}, indent=2))
    print(f"\nMatch types found: {list(result.get('matches', {}).keys())}")
