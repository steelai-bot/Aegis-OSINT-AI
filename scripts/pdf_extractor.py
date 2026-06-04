"""
pdf_extractor.py — AU-OSINT-RECON
Extract and analyse leaked data from PDF files.
Detects credentials, PII, financial data, AU-specific identifiers.
"""

import re
import os
import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Any
from collections import defaultdict

try:
    import fitz  # PyMuPDF
    PYMUPDF_OK = True
except ImportError:
    PYMUPDF_OK = False

try:
    from pypdf import PdfReader
    PYPDF_OK = True
except ImportError:
    PYPDF_OK = False


# ─────────────────────────────────────────────
#  AU-Specific Regex Patterns
# ─────────────────────────────────────────────

PATTERNS = {
    # Credentials
    "email_password":   re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\s*[:|]\s*\S+"),
    "email":            re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
    "au_email":         re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.(?:com\.au|gov\.au|edu\.au|org\.au|net\.au|id\.au)"),

    # Australian identifiers
    "tfn":              re.compile(r"\b\d{3}[\s\-]?\d{3}[\s\-]?\d{3}\b"),
    "abn":              re.compile(r"\b\d{2}[\s\-]?\d{3}[\s\-]?\d{3}[\s\-]?\d{3}\b"),
    "acn":              re.compile(r"\b\d{3}[\s\-]?\d{3}[\s\-]?\d{3}\b"),
    "bsb":              re.compile(r"\b\d{3}[\-]\d{3}\b"),
    "medicare":         re.compile(r"\b[2-6]\d{9}\b"),
    "au_phone":         re.compile(r"\b(?:\+61|0)[2-9]\d{8}\b"),
    "au_mobile":        re.compile(r"\b(?:\+614|04)\d{8}\b"),
    "au_postcode":      re.compile(r"\b(?:0[289]|[1-9]\d)\d{2}\b"),
    "au_drivers":       re.compile(r"\b[A-Z]{1,2}\d{5,9}\b"),

    # Financial
    "credit_card":      re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"),
    "bank_account":     re.compile(r"\b\d{6,10}\b"),
    "iban":             re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b"),
    "swift":            re.compile(r"\b[A-Z]{4}AU[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b"),

    # Auth tokens / secrets
    "api_key":          re.compile(r"(?:api[_\-]?key|apikey|access[_\-]?token|secret[_\-]?key)\s*[=:"\']\s*([A-Za-z0-9_\-\.]{20,})", re.IGNORECASE),
    "aws_key":          re.compile(r"(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}"),
    "aws_secret":       re.compile(r"(?:aws[_\-]?secret|secret[_\-]?access[_\-]?key)\s*[=:\"\']\s*([A-Za-z0-9/+]{40})", re.IGNORECASE),
    "jwt":              re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    "private_key":      re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "password_field":   re.compile(r"(?:password|passwd|pwd|pass)\s*[=:"\']\s*(\S{6,})", re.IGNORECASE),

    # Hashes
    "md5":              re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1":             re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256":           re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "bcrypt":           re.compile(r"\$2[aby]\$\d{2}\$[A-Za-z0-9./]{53}"),
    "ntlm":             re.compile(r"\b[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b"),

    # Network
    "ipv4":             re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
    "url":              re.compile(r"https?://[^\s<>\"']{8,}"),
    "onion":            re.compile(r"[a-z2-7]{16,56}\.onion(?:/[^\s]*)?"),
    "domain":           re.compile(r"\b(?:[a-zA-Z0-9\-]+\.)+(?:com\.au|gov\.au|edu\.au|org\.au|net\.au|com|net|org|io)\b"),
}

SEVERITY_MAP = {
    "email_password":  "critical",
    "credit_card":     "critical",
    "aws_key":         "critical",
    "aws_secret":      "critical",
    "private_key":     "critical",
    "jwt":             "critical",
    "tfn":             "critical",
    "medicare":        "critical",
    "bcrypt":          "high",
    "ntlm":            "high",
    "api_key":         "high",
    "password_field":  "high",
    "au_email":        "high",
    "bank_account":    "high",
    "bsb":             "high",
    "abn":             "medium",
    "acn":             "medium",
    "au_phone":        "medium",
    "au_mobile":       "medium",
    "md5":             "medium",
    "sha1":            "medium",
    "sha256":          "low",
    "email":           "low",
    "ipv4":            "low",
    "url":             "info",
    "domain":          "info",
    "au_postcode":     "info",
}


# ─────────────────────────────────────────────
#  PDF Text Extraction
# ─────────────────────────────────────────────

def extract_text_pymupdf(pdf_path: str) -> dict[int, str]:
    """Extract text per page using PyMuPDF (preferred — handles scanned PDFs via OCR flag)."""
    pages = {}
    doc = fitz.open(pdf_path)
    for i, page in enumerate(doc, start=1):
        pages[i] = page.get_text("text")
    doc.close()
    return pages


def extract_text_pypdf(pdf_path: str) -> dict[int, str]:
    """Fallback extraction using pypdf."""
    pages = {}
    reader = PdfReader(pdf_path)
    for i, page in enumerate(reader.pages, start=1):
        pages[i] = page.extract_text() or ""
    return pages


def extract_text(pdf_path: str) -> dict[int, str]:
    """Extract text from PDF, using best available library."""
    if PYMUPDF_OK:
        return extract_text_pymupdf(pdf_path)
    if PYPDF_OK:
        return extract_text_pypdf(pdf_path)
    raise RuntimeError("No PDF library available. Install PyMuPDF: pip install PyMuPDF")


def extract_metadata(pdf_path: str) -> dict:
    """Extract PDF metadata (author, creation date, producer, etc.)."""
    meta = {
        "file":     os.path.basename(pdf_path),
        "size_kb":  round(os.path.getsize(pdf_path) / 1024, 1),
        "sha256":   _file_hash(pdf_path),
    }
    if PYMUPDF_OK:
        doc = fitz.open(pdf_path)
        raw = doc.metadata or {}
        doc.close()
        meta.update({
            "title":        raw.get("title", ""),
            "author":       raw.get("author", ""),
            "creator":      raw.get("creator", ""),
            "producer":     raw.get("producer", ""),
            "created":      raw.get("creationDate", ""),
            "modified":     raw.get("modDate", ""),
            "page_count":   doc.page_count if hasattr(doc, "page_count") else 0,
        })
    return meta


def _file_hash(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ─────────────────────────────────────────────
#  Pattern Scanning
# ─────────────────────────────────────────────

def scan_text(text: str, page_num: int = 0) -> list[dict]:
    """
    Run all regex patterns against a text block.
    Returns list of match dicts with type, value, severity, page.
    """
    hits = []
    seen = set()

    for ptype, pattern in PATTERNS.items():
        for m in pattern.finditer(text):
            val = m.group(0).strip()
            key = f"{ptype}:{val}"
            if key in seen:
                continue
            seen.add(key)

            # For patterns with capture groups, prefer group(1)
            try:
                captured = m.group(1).strip()
                if captured:
                    val = captured
            except IndexError:
                pass

            hits.append({
                "type":     ptype,
                "value":    val,
                "severity": SEVERITY_MAP.get(ptype, "info"),
                "page":     page_num,
                "context":  _extract_context(text, m.start(), window=80),
            })

    return hits


def _extract_context(text: str, pos: int, window: int = 80) -> str:
    """Return surrounding text around a match position."""
    start = max(0, pos - window)
    end   = min(len(text), pos + window)
    snippet = text[start:end].replace("\n", " ").strip()
    return snippet


# ─────────────────────────────────────────────
#  Credential Line Extraction
# ─────────────────────────────────────────────

CRED_LINE_RE = re.compile(
    r"([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})"
    r"\s*[:|,;\t]\s*"
    r"(\S{4,})"
)

def extract_credential_lines(text: str) -> list[dict]:
    """
    Extract email:password style credential pairs from raw text.
    Returns list of {email, password, au_domain} dicts.
    """
    creds = []
    seen  = set()
    for m in CRED_LINE_RE.finditer(text):
        email = m.group(1).lower().strip()
        pwd   = m.group(2).strip()
        key   = f"{email}:{pwd}"
        if key in seen:
            continue
        seen.add(key)
        creds.append({
            "email":     email,
            "password":  pwd,
            "au_domain": bool(re.search(r"\.(?:com\.au|gov\.au|edu\.au|org\.au|net\.au)", email)),
        })
    return creds


# ─────────────────────────────────────────────
#  Main PDF Scanner Class
# ─────────────────────────────────────────────

class PDFExtractor:
    """
    Scans one or more PDF files for leaked credentials, PII,
    financial data, and AU-specific identifiers.

    Usage:
        extractor = PDFExtractor()
        result    = extractor.scan_file("/path/to/leak.pdf")
        results   = extractor.scan_directory("/path/to/pdfs/")
    """

    def __init__(self, target: str = "unknown"):
        self.target   = target
        self.findings: list[dict] = []

    # ── Single File ──────────────────────────────────────────

    def scan_file(self, pdf_path: str) -> dict:
        """
        Full scan of a single PDF. Returns structured result dict.
        """
        pdf_path = str(pdf_path)
        if not os.path.isfile(pdf_path):
            return {"error": f"File not found: {pdf_path}"}

        meta       = extract_metadata(pdf_path)
        pages      = extract_text(pdf_path)
        full_text  = "\n".join(pages.values())

        all_hits: list[dict] = []
        all_creds: list[dict] = []

        for page_num, text in pages.items():
            hits  = scan_text(text, page_num=page_num)
            creds = extract_credential_lines(text)
            all_hits.extend(hits)
            all_creds.extend(creds)

        # Deduplicate creds
        seen_creds = set()
        unique_creds = []
        for c in all_creds:
            k = f"{c['email']}:{c['password']}"
            if k not in seen_creds:
                seen_creds.add(k)
                unique_creds.append(c)

        # Severity summary
        severity_counts = defaultdict(int)
        for h in all_hits:
            severity_counts[h["severity"]] += 1

        # Build findings for report_generator
        findings = self._build_findings(pdf_path, meta, all_hits, unique_creds)
        self.findings.extend(findings)

        return {
            "file":            meta["file"],
            "sha256":          meta["sha256"],
            "metadata":        meta,
            "page_count":      len(pages),
            "total_hits":      len(all_hits),
            "credentials":     unique_creds,
            "credential_count": len(unique_creds),
            "au_credentials":  [c for c in unique_creds if c["au_domain"]],
            "hits_by_type":    self._group_hits(all_hits),
            "severity_counts": dict(severity_counts),
            "findings":        findings,
            "scanned_at":      datetime.now(timezone.utc).isoformat(),
        }

    def _group_hits(self, hits: list[dict]) -> dict[str, list]:
        grouped = defaultdict(list)
        for h in hits:
            grouped[h["type"]].append(h)
        return dict(grouped)

    def _build_findings(
        self,
        pdf_path: str,
        meta: dict,
        hits: list[dict],
        creds: list[dict],
    ) -> list[dict]:
        findings = []
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        # Credential finding
        if creds:
            au_count = sum(1 for c in creds if c["au_domain"])
            findings.append({
                "title":      f"PDF Credential Dump — {meta['file']}",
                "severity":   "critical" if au_count > 0 else "high",
                "category":   "credential_breach",
                "source":     f"pdf_extractor:{meta['file']}",
                "summary":    (
                    f"{len(creds)} credential pairs extracted. "
                    f"{au_count} with Australian domains (.com.au / .gov.au / .edu.au)."
                ),
                "date_found": now,
                "raw_data": {
                    "total_creds":   len(creds),
                    "au_creds":      au_count,
                    "sample":        creds[:5],
                    "file_sha256":   meta["sha256"],
                },
                "target": self.target,
            })

        # PII / financial findings grouped by severity
        high_types = [h for h in hits if h["severity"] in ("critical", "high") and h["type"] not in ("email_password",)]
        if high_types:
            type_summary = defaultdict(int)
            for h in high_types:
                type_summary[h["type"]] += 1
            findings.append({
                "title":      f"PDF Sensitive Data — {meta['file']}",
                "severity":   "critical" if any(h["severity"] == "critical" for h in high_types) else "high",
                "category":   "pii_exposure",
                "source":     f"pdf_extractor:{meta['file']}",
                "summary":    f"Sensitive identifiers found: {dict(type_summary)}",
                "date_found": now,
                "raw_data": {
                    "type_counts": dict(type_summary),
                    "samples":     {t: [h["value"] for h in hits if h["type"] == t][:3] for t in type_summary},
                },
                "target": self.target,
            })

        return findings

    # ── Directory Scan ───────────────────────────────────────

    def scan_directory(self, directory: str, recursive: bool = True) -> list[dict]:
        """
        Scan all PDFs in a directory. Returns list of per-file results.
        """
        base = Path(directory)
        pattern = "**/*.pdf" if recursive else "*.pdf"
        pdf_files = list(base.glob(pattern))

        results = []
        for pdf in pdf_files:
            result = self.scan_file(str(pdf))
            results.append(result)

        return results

    # ── Batch from list ──────────────────────────────────────

    def scan_files(self, paths: list[str]) -> list[dict]:
        return [self.scan_file(p) for p in paths]

    # ── Export ───────────────────────────────────────────────

    def export_credentials(self, output_path: str, au_only: bool = False) -> str:
        """
        Export all extracted credentials to a text file (email:password format).
        """
        lines = []
        for f in self.findings:
            raw = f.get("raw_data", {})
            for cred in raw.get("sample", []):
                if au_only and not cred.get("au_domain"):
                    continue
                lines.append(f"{cred['email']}:{cred['password']}")

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))

        return output_path

    def get_findings(self) -> list[dict]:
        return self.findings


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AU-OSINT PDF Extractor")
    parser.add_argument("--file",   help="Single PDF file to scan")
    parser.add_argument("--dir",    help="Directory of PDFs to scan")
    parser.add_argument("--target", default="unknown", help="Target identifier")
    parser.add_argument("--output", default="./reports", help="Output directory")
    parser.add_argument("--au-only", action="store_true", help="Export AU credentials only")
    args = parser.parse_args()

    extractor = PDFExtractor(target=args.target)

    if args.file:
        result = extractor.scan_file(args.file)
        print(json.dumps({k: v for k, v in result.items() if k != "findings"}, indent=2, default=str))
    elif args.dir:
        results = extractor.scan_directory(args.dir)
        for r in results:
            print(f"[{r.get('file', '?')}] hits={r.get('total_hits', 0)} creds={r.get('credential_count', 0)}")
    else:
        parser.print_help()
