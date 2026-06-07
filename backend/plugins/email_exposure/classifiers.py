"""PII-safe email exposure classification helpers."""

from __future__ import annotations

import hashlib
import html
import re
from dataclasses import dataclass, field


EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
CREDENTIAL_RE = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b\s*[:|;,]\s*[^\s<>'\"]{6,}",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
API_KEY_HINT_RE = re.compile(r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd)\b\s*[:=]")


@dataclass(frozen=True, slots=True)
class ExposureEvidence:
    """Classified exposure evidence ready to become an Aegis finding."""

    source_name: str
    source_url: str
    platform: str
    matched_value: str
    redacted_value: str
    email_domain: str | None
    data_types_found: tuple[str, ...]
    content_preview: str
    evidence_hash: str
    confidence: float
    severity: str
    raw_metadata: dict[str, object] = field(default_factory=dict)


def hash_value(value: str) -> str:
    """Return a stable SHA-256 hash for deduplication without storing raw PII."""

    return hashlib.sha256(value.strip().lower().encode("utf-8", errors="ignore")).hexdigest()


def redact_email(email: str) -> str:
    """Redact an email while keeping enough context for analysts."""

    local, sep, domain = email.partition("@")
    if not sep:
        return "[redacted]"
    if len(local) <= 2:
        redacted_local = local[:1] + "***"
    else:
        redacted_local = f"{local[:2]}***"
    return f"{redacted_local}@{domain.lower()}"


def redact_text(text: str, *, max_chars: int = 320) -> str:
    """Strip basic HTML entities and redact emails in evidence previews."""

    clean = html.unescape(text).replace("\x00", " ")
    clean = re.sub(r"\s+", " ", clean).strip()
    clean = EMAIL_RE.sub(lambda match: redact_email(match.group(0)), clean)
    if len(clean) <= max_chars:
        return clean
    return clean[: max_chars - 1].rstrip() + "…"


def classify_text(
    text: str,
    *,
    target: str,
    target_type: str,
    source_name: str,
    source_url: str,
    platform: str,
    max_findings: int = 25,
    preview_chars: int = 320,
) -> list[ExposureEvidence]:
    """Find target-related email exposure evidence in a public text blob."""

    lowered_target = target.strip().lower()
    if not lowered_target:
        return []

    data_types = _data_types(text)
    candidate_emails = sorted({email.lower() for email in EMAIL_RE.findall(text)})
    matched_emails = _matching_emails(candidate_emails, lowered_target, target_type)
    evidence: list[ExposureEvidence] = []

    for email in matched_emails[:max_findings]:
        email_domain = email.rsplit("@", 1)[-1]
        snippet = _snippet(text, email, fallback=target, radius=preview_chars)
        evidence.append(
            ExposureEvidence(
                source_name=source_name,
                source_url=source_url,
                platform=platform,
                matched_value=hash_value(email),
                redacted_value=redact_email(email),
                email_domain=email_domain,
                data_types_found=tuple(sorted({"email", *data_types})),
                content_preview=redact_text(snippet, max_chars=preview_chars),
                evidence_hash=hash_value(f"{source_url}|{email}|{','.join(data_types)}"),
                confidence=_confidence(data_types, exact_email=target_type == "email" and email == lowered_target),
                severity=_severity(data_types),
                raw_metadata={"match_kind": "email", "content_length": len(text)},
            )
        )

    if evidence:
        return evidence

    # For brand/domain keywords without extractable emails, keep a lower severity
    # source mention so analysts know the configured public source contained the target.
    if target_type in {"domain", "keyword"} and lowered_target in text.lower():
        snippet = _snippet(text, target, fallback=target, radius=preview_chars)
        evidence.append(
            ExposureEvidence(
                source_name=source_name,
                source_url=source_url,
                platform=platform,
                matched_value=hash_value(f"{source_url}|{lowered_target}"),
                redacted_value=target,
                email_domain=None,
                data_types_found=("target_mention",),
                content_preview=redact_text(snippet, max_chars=preview_chars),
                evidence_hash=hash_value(f"{source_url}|{lowered_target}|target_mention"),
                confidence=0.45,
                severity="low",
                raw_metadata={"match_kind": "target_mention", "content_length": len(text)},
            )
        )

    return evidence[:max_findings]


def _matching_emails(candidate_emails: list[str], target: str, target_type: str) -> list[str]:
    if target_type == "email":
        return [email for email in candidate_emails if email == target]
    if target_type == "domain":
        domain = target.removeprefix("@")
        return [email for email in candidate_emails if email.endswith(f"@{domain}")]
    return [email for email in candidate_emails if target in email]


def _data_types(text: str) -> set[str]:
    found: set[str] = set()
    if CREDENTIAL_RE.search(text):
        found.add("password")
    if AWS_ACCESS_KEY_RE.search(text):
        found.add("aws_access_key")
    if JWT_RE.search(text):
        found.add("jwt")
    if PRIVATE_KEY_RE.search(text):
        found.add("private_key")
    if API_KEY_HINT_RE.search(text):
        found.add("secret_hint")
    return found


def _severity(data_types: set[str]) -> str:
    if data_types.intersection({"password", "aws_access_key", "jwt", "private_key"}):
        return "high"
    if "secret_hint" in data_types:
        return "medium"
    return "medium"


def _confidence(data_types: set[str], *, exact_email: bool) -> float:
    if data_types.intersection({"password", "aws_access_key", "jwt", "private_key"}):
        return 0.9 if exact_email else 0.82
    if exact_email:
        return 0.78
    return 0.68


def _snippet(text: str, needle: str, *, fallback: str, radius: int) -> str:
    lowered = text.lower()
    offset = lowered.find(needle.lower())
    if offset < 0:
        offset = lowered.find(fallback.lower())
    if offset < 0:
        return text[: radius * 2]
    start = max(offset - radius, 0)
    end = min(offset + len(needle) + radius, len(text))
    return text[start:end]