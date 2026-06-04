"""
infostealer_parser.py — AU-OSINT-RECON
Parse, index and query infostealer log archives.
Supports Redline, Raccoon, Vidar, Aurora, MetaStealer, Lumma log formats.
Filters by date range, AU domains, and target keywords.
"""

import os
import re
import json
import zipfile
import tarfile
import hashlib
from pathlib import Path
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from typing import Any


# ─────────────────────────────────────────────
#  Stealer Log Format Signatures
# ─────────────────────────────────────────────

STEALER_SIGNATURES = {
    "redline": {
        "files":    ["Passwords.txt", "CreditCards.txt", "AutoFill.txt", "Cookies.txt", "System Info.txt"],
        "password_re": re.compile(r"URL:\s*(.+)\nUsername:\s*(.+)\nPassword:\s*(.+)", re.MULTILINE),
        "sysinfo_re":  re.compile(r"(?:IP|Country|OS|HWID|Username):\s*(.+)"),
    },
    "raccoon": {
        "files":    ["passwords.txt", "cookies.txt", "autofill.txt", "cc.txt", "system.txt"],
        "password_re": re.compile(r"Url:\s*(.+)\nLogin:\s*(.+)\nPassword:\s*(.+)", re.MULTILINE),
    },
    "vidar": {
        "files":    ["passwords.txt", "information.txt", "cc.txt", "crypto.txt"],
        "password_re": re.compile(r"URL:\s*(.+)\nUSER:\s*(.+)\nPASS:\s*(.+)", re.MULTILINE),
    },
    "aurora": {
        "files":    ["Passwords.txt", "Cookies.txt", "Wallets", "System.txt"],
        "password_re": re.compile(r"HOST:\s*(.+)\nUSER:\s*(.+)\nPASS:\s*(.+)", re.MULTILINE),
    },
    "lumma": {
        "files":    ["All Passwords.txt", "Cookies.txt", "CC.txt", "System Information.txt"],
        "password_re": re.compile(r"URL:\s*(.+)\nUsername:\s*(.+)\nPassword:\s*(.+)", re.MULTILINE),
    },

    "stealc": {
        "files":    ["Passwords.txt", "Cookies.txt", "CC.txt", "Wallets.txt", "System.txt"],
        "password_re": re.compile(r"URL:\s*(.+)\nUser:\s*(.+)\nPass:\s*(.+)", re.MULTILINE),
    },
    "whitesnake": {
        "files":    ["Passwords.txt", "Cookies.txt", "System Info.txt", "Telegram.txt"],
        "password_re": re.compile(r"Url:\s*(.+)\nUsername:\s*(.+)\nPassword:\s*(.+)", re.MULTILINE),
    },
    "meduza": {
        "files":    ["passwords.txt", "cookies.txt", "autofill.txt", "system.txt"],
        "password_re": re.compile(r"URL:\s*(.+)\nLOGIN:\s*(.+)\nPASSWORD:\s*(.+)", re.MULTILINE),
    },
    "generic": {
        "files":    ["passwords.txt", "Passwords.txt", "pass.txt", "creds.txt"],
        "password_re": re.compile(
            r"(?:URL|HOST|SITE|url|host):\s*(.+)[\r\n]+"
            r"(?:USER|USERNAME|Login|login|user):\s*(.+)[\r\n]+"
            r"(?:PASS|PASSWORD|Password|password):\s*(.+)",
            re.MULTILINE
        ),
    },
}

AU_DOMAIN_RE = re.compile(
    r"(?:\.com\.au|\.gov\.au|\.edu\.au|\.org\.au|\.net\.au|\.id\.au|"
    r"australia|\.au/|myaccount\.ato\.gov|mygov\.id|centrelink|"
    r"westpac|commbank|anz\.com|nab\.com|macquarie|bendigo|suncorp|"
    r"medicare|servicesaustralia|myhealth\.gov|ahpra\.gov|asic\.gov)",
    re.IGNORECASE
)

AU_BANK_RE = re.compile(
    r"(?:westpac|commbank|commonwealth|anz|nab|macquarie|bendigo|"
    r"suncorp|bankwest|ing\.com\.au|ubank|86400|up\.com\.au|"
    r"boq\.com\.au|mebank|cua\.com\.au|teachers\.com\.au)",
    re.IGNORECASE
)

AU_GOV_RE = re.compile(
    r"(?:\.gov\.au|ato\.gov|mygov|centrelink|medicare|servicesaustralia|"
    r"myhealth\.gov|ahpra|asic\.gov|afp\.gov|asd\.gov|defence\.gov)",
    re.IGNORECASE
)

CRYPTO_WALLET_RE = re.compile(
    r"(?:metamask|exodus|electrum|coinbase|binance|kraken|"
    r"trustwallet|phantom|solflare|ledger|trezor)",
    re.IGNORECASE
)


# ─────────────────────────────────────────────
#  Log Entry Data Classes
# ─────────────────────────────────────────────

class StealerCredential:
    __slots__ = ("url", "username", "password", "au_domain", "bank", "gov", "crypto", "source_file", "log_date", "stealer_type")

    def __init__(self, url, username, password, source_file="", log_date="", stealer_type="generic"):
        self.url          = url.strip()
        self.username     = username.strip()
        self.password     = password.strip()
        self.au_domain    = bool(AU_DOMAIN_RE.search(url))
        self.bank         = bool(AU_BANK_RE.search(url))
        self.gov          = bool(AU_GOV_RE.search(url))
        self.crypto       = bool(CRYPTO_WALLET_RE.search(url))
        self.source_file  = source_file
        self.log_date     = log_date
        self.stealer_type = stealer_type

    def to_dict(self) -> dict:
        return {
            "url":          self.url,
            "username":     self.username,
            "password":     self.password,
            "au_domain":    self.au_domain,
            "bank":         self.bank,
            "gov":          self.gov,
            "crypto":       self.crypto,
            "source_file":  self.source_file,
            "log_date":     self.log_date,
            "stealer_type": self.stealer_type,
        }


class StealerLog:
    """Represents a parsed infostealer log bundle."""

    def __init__(self, path: str, stealer_type: str = "generic", log_date: str = ""):
        self.path         = path
        self.stealer_type = stealer_type
        self.log_date     = log_date or self._infer_date(path)
        self.credentials: list[StealerCredential] = []
        self.system_info: dict = {}
        self.cookies:     list[dict] = []
        self.cc_data:     list[dict] = []
        self.wallets:     list[str] = []
        self.raw_files:   dict[str, str] = {}

    def _infer_date(self, path: str) -> str:
        """Try to extract date from directory/file name."""
        name = os.path.basename(path)
        # Common patterns: 2024-03-15, 20240315, 2024_03_15
        for pattern in [
            r"(\d{4}[-_]\d{2}[-_]\d{2})",
            r"(\d{8})",
        ]:
            m = re.search(pattern, name)
            if m:
                raw = m.group(1).replace("_", "-").replace("-", "")
                try:
                    dt = datetime.strptime(raw[:8], "%Y%m%d")
                    return dt.strftime("%Y-%m-%d")
                except ValueError:
                    pass

        # Fall back to file modification time
        try:
            mtime = os.path.getmtime(path)
            return datetime.fromtimestamp(mtime, tz=timezone.utc).strftime("%Y-%m-%d")
        except Exception:
            return ""

    @property
    def au_credentials(self) -> list[StealerCredential]:
        return [c for c in self.credentials if c.au_domain]

    @property
    def bank_credentials(self) -> list[StealerCredential]:
        return [c for c in self.credentials if c.bank]

    @property
    def gov_credentials(self) -> list[StealerCredential]:
        return [c for c in self.credentials if c.gov]

    @property
    def crypto_credentials(self) -> list[StealerCredential]:
        return [c for c in self.credentials if c.crypto]

    def to_dict(self) -> dict:
        return {
            "path":            self.path,
            "stealer_type":    self.stealer_type,
            "log_date":        self.log_date,
            "total_creds":     len(self.credentials),
            "au_creds":        len(self.au_credentials),
            "bank_creds":      len(self.bank_credentials),
            "gov_creds":       len(self.gov_credentials),
            "crypto_creds":    len(self.crypto_credentials),
            "system_info":     self.system_info,
            "credentials":     [c.to_dict() for c in self.credentials],
            "cc_data":         self.cc_data,
            "wallets":         self.wallets,
        }


# ─────────────────────────────────────────────
#  Parsers per stealer type
# ─────────────────────────────────────────────

def _parse_password_file(content: str, stealer_type: str, source_file: str, log_date: str) -> list[StealerCredential]:
    """Parse a passwords.txt file using the appropriate regex."""
    sig     = STEALER_SIGNATURES.get(stealer_type, STEALER_SIGNATURES["generic"])
    pattern = sig.get("password_re", STEALER_SIGNATURES["generic"]["password_re"])
    creds   = []
    for m in pattern.finditer(content):
        creds.append(StealerCredential(
            url          = m.group(1),
            username     = m.group(2),
            password     = m.group(3),
            source_file  = source_file,
            log_date     = log_date,
            stealer_type = stealer_type,
        ))
    return creds


def _parse_sysinfo(content: str) -> dict:
    """Parse system information file."""
    info = {}
    for line in content.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            info[key.strip().lower().replace(" ", "_")] = val.strip()
    return info


def _parse_cc_file(content: str) -> list[dict]:
    """Parse credit card data file."""
    cards = []
    cc_re = re.compile(
        r"(?:Number|CC|Card):\s*(\d[\d\s\-]{12,18}\d)[\s\S]*?"
        r"(?:Exp|Expiry|Expiration):\s*(\d{2}/\d{2,4})[\s\S]*?"
        r"(?:CVV|CVC|CVV2):\s*(\d{3,4})",
        re.IGNORECASE | re.MULTILINE
    )
    for m in cc_re.finditer(content):
        cards.append({
            "number":  m.group(1).replace(" ", "").replace("-", ""),
            "expiry":  m.group(2),
            "cvv":     m.group(3),
        })
    return cards


def _detect_stealer_type(file_list: list[str]) -> str:
    """Detect stealer type from file listing."""
    names = {os.path.basename(f).lower() for f in file_list}
    for stype, sig in STEALER_SIGNATURES.items():
        if stype == "generic":
            continue
        expected = {s.lower() for s in sig["files"]}
        if len(expected & names) >= 2:
            return stype
    return "generic"


# ─────────────────────────────────────────────
#  Archive Extraction
# ─────────────────────────────────────────────

def _extract_archive(archive_path: str, extract_to: str) -> list[str]:
    """Extract zip or tar archive, return list of extracted file paths."""
    extracted = []
    os.makedirs(extract_to, exist_ok=True)

    if zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path, "r") as zf:
            zf.extractall(extract_to)
            extracted = [os.path.join(extract_to, n) for n in zf.namelist()]
    elif tarfile.is_tarfile(archive_path):
        with tarfile.open(archive_path, "r:*") as tf:
            tf.extractall(extract_to)
            extracted = [os.path.join(extract_to, m.name) for m in tf.getmembers()]

    return extracted


# ─────────────────────────────────────────────
#  Main Parser Class
# ─────────────────────────────────────────────

class InfostealerParser:
    """
    Parse infostealer log bundles (directories or archives).
    Supports date-range filtering and AU-domain targeting.

    Usage:
        parser = InfostealerParser(target="example.com.au")
        logs   = parser.parse_directory("/path/to/logs/")
        logs   = parser.filter_by_date(logs, "2024-01-01", "2024-12-31")
        au     = parser.filter_au_only(logs)
        parser.print_summary(au)
    """

    def __init__(self, target: str = "unknown", temp_dir: str = "/tmp/stealer_extract"):
        self.target   = target
        self.temp_dir = temp_dir
        self.logs:    list[StealerLog] = []

    # ── Parse single log directory ───────────────────────────

    def parse_log_dir(self, log_dir: str) -> StealerLog:
        """Parse a single extracted log directory."""
        files = list(Path(log_dir).rglob("*"))
        file_names = [str(f) for f in files if f.is_file()]

        stealer_type = _detect_stealer_type(file_names)
        log = StealerLog(path=log_dir, stealer_type=stealer_type)

        for fpath in files:
            if not fpath.is_file():
                continue
            fname = fpath.name.lower()
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            log.raw_files[fpath.name] = content[:4096]  # Store preview

            if fname in ("passwords.txt", "all passwords.txt", "pass.txt", "creds.txt"):
                creds = _parse_password_file(content, stealer_type, str(fpath), log.log_date)
                log.credentials.extend(creds)

            elif fname in ("system info.txt", "system.txt", "information.txt", "sysinfo.txt"):
                log.system_info = _parse_sysinfo(content)
                # Try to get date from system info
                if not log.log_date:
                    for key in ("date", "time", "datetime", "install_date"):
                        if key in log.system_info:
                            log.log_date = log.system_info[key][:10]
                            break

            elif fname in ("cc.txt", "creditcards.txt", "credit_cards.txt"):
                log.cc_data = _parse_cc_file(content)

            elif "wallet" in fname or "crypto" in fname:
                log.wallets.extend(re.findall(r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}", content))

        return log

    # ── Parse archive ────────────────────────────────────────

    def parse_archive(self, archive_path: str) -> list[StealerLog]:
        """Extract and parse a zip/tar archive of logs."""
        extract_path = os.path.join(self.temp_dir, hashlib.md5(archive_path.encode()).hexdigest()[:8])
        _extract_archive(archive_path, extract_path)

        # Each subdirectory is typically one victim log
        logs = []
        base = Path(extract_path)

        # Check if top-level has password files (single log)
        top_files = [f.name.lower() for f in base.iterdir() if f.is_file()]
        if any(f in top_files for f in ["passwords.txt", "pass.txt", "creds.txt"]):
            log = self.parse_log_dir(str(base))
            logs.append(log)
        else:
            # Multiple log dirs
            for subdir in sorted(base.iterdir()):
                if subdir.is_dir():
                    log = self.parse_log_dir(str(subdir))
                    logs.append(log)

        self.logs.extend(logs)
        return logs

    # ── Parse directory of logs ──────────────────────────────

    def parse_directory(self, directory: str) -> list[StealerLog]:
        """
        Parse a directory containing multiple log bundles.
        Each subdirectory = one victim log.
        Archives (.zip, .tar.gz) are extracted automatically.
        """
        base = Path(directory)
        logs = []

        for item in sorted(base.iterdir()):
            if item.is_dir():
                log = self.parse_log_dir(str(item))
                logs.append(log)
            elif item.suffix.lower() in (".zip", ".gz", ".tar", ".7z"):
                try:
                    extracted = self.parse_archive(str(item))
                    logs.extend(extracted)
                except Exception as e:
                    pass

        self.logs.extend(logs)
        return logs

    # ── Filtering ────────────────────────────────────────────

    def filter_by_date(
        self,
        logs: list[StealerLog],
        start_date: str,
        end_date: str,
    ) -> list[StealerLog]:
        """
        Filter logs by date range (inclusive).
        Dates as ISO strings: "2024-01-01"
        """
        try:
            start = datetime.strptime(start_date, "%Y-%m-%d").date()
            end   = datetime.strptime(end_date,   "%Y-%m-%d").date()
        except ValueError:
            return logs

        filtered = []
        for log in logs:
            if not log.log_date:
                continue
            try:
                log_dt = datetime.strptime(log.log_date[:10], "%Y-%m-%d").date()
                if start <= log_dt <= end:
                    filtered.append(log)
            except ValueError:
                continue

        return filtered

    def filter_au_only(self, logs: list[StealerLog]) -> list[StealerLog]:
        """Return only logs containing AU credentials."""
        return [log for log in logs if log.au_credentials]

    def filter_by_keyword(self, logs: list[StealerLog], keyword: str) -> list[StealerLog]:
        """Filter logs where any credential URL contains keyword."""
        kw = keyword.lower()
        return [
            log for log in logs
            if any(kw in c.url.lower() or kw in c.username.lower() for c in log.credentials)
        ]

    def filter_bank_logs(self, logs: list[StealerLog]) -> list[StealerLog]:
        return [log for log in logs if log.bank_credentials]

    def filter_gov_logs(self, logs: list[StealerLog]) -> list[StealerLog]:
        return [log for log in logs if log.gov_credentials]

    # ── Timeline ─────────────────────────────────────────────

    def build_date_timeline(self, logs: list[StealerLog]) -> dict[str, dict]:
        """
        Group logs by date. Returns dict keyed by date string.
        """
        timeline: dict[str, dict] = defaultdict(lambda: {
            "log_count": 0, "total_creds": 0, "au_creds": 0,
            "bank_creds": 0, "gov_creds": 0, "stealer_types": set()
        })

        for log in logs:
            date = log.log_date or "unknown"
            timeline[date]["log_count"]    += 1
            timeline[date]["total_creds"]  += len(log.credentials)
            timeline[date]["au_creds"]     += len(log.au_credentials)
            timeline[date]["bank_creds"]   += len(log.bank_credentials)
            timeline[date]["gov_creds"]    += len(log.gov_credentials)
            timeline[date]["stealer_types"].add(log.stealer_type)

        # Convert sets to lists for JSON serialisation
        return {
            date: {**data, "stealer_types": list(data["stealer_types"])}
            for date, data in sorted(timeline.items())
        }

    # ── Summary ──────────────────────────────────────────────

    def print_summary(self, logs: list[StealerLog]) -> None:
        total_creds = sum(len(l.credentials) for l in logs)
        au_creds    = sum(len(l.au_credentials) for l in logs)
        bank_creds  = sum(len(l.bank_credentials) for l in logs)
        gov_creds   = sum(len(l.gov_credentials) for l in logs)

        print(f"\n{'='*60}")
        print(f"  INFOSTEALER LOG SUMMARY")
        print(f"{'='*60}")
        print(f"  Log bundles     : {len(logs)}")
        print(f"  Total creds     : {total_creds:,}")
        print(f"  AU creds        : {au_creds:,}")
        print(f"  Bank creds      : {bank_creds:,}")
        print(f"  Gov creds       : {gov_creds:,}")
        print(f"{'='*60}\n")

    # ── Build findings for report_generator ─────────────────


    def deduplicate_global(self, logs: list) -> list:
        """
        Global deduplication across all logs.
        Removes duplicate credentials seen in multiple log bundles.
        """
        seen = set()
        for log in logs:
            unique_creds = []
            for cred in log.credentials:
                key = f"{cred.username.lower()}:{cred.password}:{cred.url}"
                if key not in seen:
                    seen.add(key)
                    unique_creds.append(cred)
            log.credentials = unique_creds
        return logs

    def extract_crypto_wallets(self, logs: list) -> list[dict]:
        """
        Extract all cryptocurrency wallet seeds, private keys, and addresses
        from parsed stealer logs.
        """
        import re
        wallets = []
        seed_re = re.compile(
            r"\b(?:[a-z]+\s){11,23}[a-z]+\b",  # BIP39 mnemonic (12-24 words)
            re.IGNORECASE
        )
        privkey_re = re.compile(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b")  # WIF private key
        eth_re     = re.compile(r"\b0x[a-fA-F0-9]{64}\b")  # ETH private key

        for log in logs:
            for fname, content in log.raw_files.items():
                if not any(kw in fname.lower() for kw in ["wallet", "crypto", "seed", "key", "exodus", "metamask"]):
                    continue
                for m in seed_re.finditer(content):
                    words = m.group(0).split()
                    if 12 <= len(words) <= 24:
                        wallets.append({
                            "type":       "seed_phrase",
                            "value":      m.group(0),
                            "word_count": len(words),
                            "source":     log.path,
                            "date":       log.log_date,
                        })
                for m in privkey_re.finditer(content):
                    wallets.append({
                        "type":   "btc_wif_private_key",
                        "value":  m.group(0),
                        "source": log.path,
                        "date":   log.log_date,
                    })
                for m in eth_re.finditer(content):
                    wallets.append({
                        "type":   "eth_private_key",
                        "value":  m.group(0),
                        "source": log.path,
                        "date":   log.log_date,
                    })
        return wallets

    def extract_telegram_sessions(self, logs: list) -> list[dict]:
        """
        Extract Telegram session files from stealer logs.
        These allow account takeover without password.
        """
        sessions = []
        for log in logs:
            for fname, content in log.raw_files.items():
                if "telegram" in fname.lower() or "tdata" in fname.lower():
                    sessions.append({
                        "source":    log.path,
                        "file":      fname,
                        "date":      log.log_date,
                        "size":      len(content),
                        "note":      "Telegram session data — may allow account takeover",
                        "severity":  "critical",
                    })
        return sessions

    def score_log_value(self, log) -> dict:
        """
        Score a stealer log bundle by intelligence value.
        Higher score = more valuable target.
        """
        score = 0
        reasons = []

        if log.bank_credentials:
            score += len(log.bank_credentials) * 10
            reasons.append(f"{len(log.bank_credentials)} bank creds")

        if log.gov_credentials:
            score += len(log.gov_credentials) * 8
            reasons.append(f"{len(log.gov_credentials)} gov creds")

        if log.crypto_credentials:
            score += len(log.crypto_credentials) * 6
            reasons.append(f"{len(log.crypto_credentials)} crypto creds")

        if log.au_credentials:
            score += len(log.au_credentials) * 3
            reasons.append(f"{len(log.au_credentials)} AU creds")

        if log.cc_data:
            score += len(log.cc_data) * 15
            reasons.append(f"{len(log.cc_data)} CC records")

        if log.wallets:
            score += len(log.wallets) * 20
            reasons.append(f"{len(log.wallets)} crypto wallets")

        return {
            "path":    log.path,
            "score":   score,
            "reasons": reasons,
            "tier":    "critical" if score >= 50 else "high" if score >= 20 else "medium" if score >= 5 else "low",
        }

    def rank_logs_by_value(self, logs: list) -> list[dict]:
        """Rank all logs by intelligence value score."""
        scored = [self.score_log_value(log) for log in logs]
        return sorted(scored, key=lambda x: -x["score"])

    def build_findings(self, logs: list[StealerLog]) -> list[dict]:
        findings = []
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        # Per-date summary findings
        timeline = self.build_date_timeline(logs)
        for date, data in timeline.items():
            if data["au_creds"] == 0:
                continue
            sev = "critical" if data["bank_creds"] > 0 or data["gov_creds"] > 0 else "high"
            findings.append({
                "title":      f"Infostealer Logs — {date} ({data['au_creds']} AU creds)",
                "severity":   sev,
                "category":   "credential_breach",
                "source":     "infostealer_parser",
                "summary":    (
                    f"{data['log_count']} log bundles from {date}. "
                    f"AU: {data['au_creds']} | Bank: {data['bank_creds']} | Gov: {data['gov_creds']}. "
                    f"Stealer types: {', '.join(data['stealer_types'])}."
                ),
                "date_found": date if date != "unknown" else now,
                "raw_data":   data,
                "target":     self.target,
            })

        return findings

    # ── Export all AU creds ──────────────────────────────────

    def export_au_credentials(self, logs: list[StealerLog], output_path: str) -> str:
        lines = []
        for log in logs:
            for c in log.au_credentials:
                lines.append(f"{c.username}:{c.password}  # {c.url}  [{log.log_date}]")

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        return output_path


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AU-OSINT Infostealer Log Parser")
    parser.add_argument("--dir",    required=True, help="Directory of log bundles")
    parser.add_argument("--target", default="unknown")
    parser.add_argument("--start",  help="Start date filter YYYY-MM-DD")
    parser.add_argument("--end",    help="End date filter YYYY-MM-DD")
    parser.add_argument("--au-only", action="store_true")
    parser.add_argument("--bank",    action="store_true", help="Show bank credentials only")
    parser.add_argument("--output",  default="./reports")
    args = parser.parse_args()

    ip = InfostealerParser(target=args.target)
    logs = ip.parse_directory(args.dir)

    if args.start and args.end:
        logs = ip.filter_by_date(logs, args.start, args.end)
    if args.au_only:
        logs = ip.filter_au_only(logs)
    if args.bank:
        logs = ip.filter_bank_logs(logs)

    ip.print_summary(logs)

    timeline = ip.build_date_timeline(logs)
    print(json.dumps(timeline, indent=2))
