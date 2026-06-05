"""Safe v2 report renderers.

These renderers operate on already-collected investigation and finding data.
They do not enrich, scan, scrape, or contact targets.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def _read_value(item: Any, key: str, default: Any = "") -> Any:
    if isinstance(item, Mapping):
        return item.get(key, default)
    return getattr(item, key, default)


def _finding_title(finding: Any) -> str:
    data = _read_value(finding, "data", {}) or {}
    if isinstance(data, Mapping):
        return str(data.get("title") or data.get("summary") or _read_value(finding, "source", "Finding"))
    return str(_read_value(finding, "source", "Finding"))


def _finding_summary(finding: Any) -> str:
    data = _read_value(finding, "data", {}) or {}
    if isinstance(data, Mapping):
        return str(data.get("summary") or data.get("description") or "")
    return ""


def _escape_markdown(value: Any) -> str:
    return str(value or "").replace("```", "'''").strip()


def _finding_lines(findings: Sequence[Any]) -> str:
    if not findings:
        return "- No findings recorded."

    lines: list[str] = []
    for finding in findings:
        severity = _escape_markdown(_read_value(finding, "severity", "info")).upper()
        source = _escape_markdown(_read_value(finding, "source", "unknown"))
        confidence = _read_value(finding, "confidence", 0.0)
        title = _escape_markdown(_finding_title(finding))
        summary = _escape_markdown(_finding_summary(finding))
        lines.append(f"- [{severity}] {title} ({source}, confidence {confidence})")
        if summary:
            lines.append(f"  {summary}")
    return "\n".join(lines)


def _severity_counts(findings: Sequence[Any]) -> dict[str, int]:
    return {
        severity: sum(1 for finding in findings if str(_read_value(finding, "severity", "info")).lower() == severity)
        for severity in ["critical", "high", "medium", "low", "info"]
    }


def _finding_payload(finding: Any) -> dict[str, Any]:
    return {
        "source": _read_value(finding, "source", "unknown"),
        "severity": _read_value(finding, "severity", "info"),
        "confidence": _read_value(finding, "confidence", 0.0),
        "title": _finding_title(finding),
        "summary": _finding_summary(finding),
        "data": _read_value(finding, "data", {}) or {},
    }


def render_json_report(
    investigation: Any,
    findings: Sequence[Any],
    *,
    generated_at: datetime | None = None,
) -> str:
    """Render a structured JSON investigation report."""

    generated = generated_at or datetime.now(UTC)
    payload = {
        "meta": {
            "generated_at": generated.isoformat(),
            "tool": "aegis-v2",
            "format": "json",
        },
        "investigation": {
            "title": _read_value(investigation, "title", "Untitled investigation"),
            "status": _read_value(investigation, "status", "unknown"),
        },
        "severity_counts": _severity_counts(findings),
        "findings": [_finding_payload(finding) for finding in findings],
        "handling_notes": [
            "Generated from passive investigation records.",
            "Verify all findings against primary sources before action.",
            "Do not use this output for exploitation, credential replay, intrusive scanning, or unauthorized access.",
        ],
    }
    return json.dumps(payload, indent=2, default=str)


def render_markdown_report(
    investigation: Any,
    findings: Sequence[Any],
    *,
    generated_at: datetime | None = None,
) -> str:
    """Render a document-ready Markdown investigation report."""

    generated = generated_at or datetime.now(UTC)
    counts = _severity_counts(findings)
    title = _escape_markdown(_read_value(investigation, "title", "Untitled investigation"))
    status = _escape_markdown(_read_value(investigation, "status", "unknown"))

    return f"""# Aegis Investigation Report

Generated: {generated.isoformat()}
Investigation: {title}
Status: {status}

## Executive Summary

This report summarizes locally persisted passive OSINT findings for analyst review.

## Severity Overview

- Critical: {counts["critical"]}
- High: {counts["high"]}
- Medium: {counts["medium"]}
- Low: {counts["low"]}
- Info: {counts["info"]}

## Findings

{_finding_lines(findings)}

## Handling Notes

- This report is generated from passive investigation records.
- Verify all findings against primary sources before action.
- Do not use this output for exploitation, credential replay, intrusive scanning, or unauthorized access.
"""


def render_briefing_outline(
    investigation: Any,
    findings: Sequence[Any],
    *,
    generated_at: datetime | None = None,
) -> str:
    """Render a presentation-ready Markdown briefing outline."""

    generated = generated_at or datetime.now(UTC)
    title = _escape_markdown(_read_value(investigation, "title", "Untitled investigation"))
    sorted_findings = sorted(
        findings,
        key=lambda finding: SEVERITY_ORDER.get(str(_read_value(finding, "severity", "info")).lower(), 0),
        reverse=True,
    )

    return f"""# Aegis Investigation Briefing Outline

Generated: {generated.isoformat()}
Investigation: {title}

## Slide 1 - Investigation Context

Claim: {title} has a passive evidence set ready for analyst review.

Proof object: Investigation metadata and finding count.

## Slide 2 - Risk Posture

Claim: Current severity mix defines the review queue.

Proof object: Severity overview across {len(findings)} findings.

## Slide 3 - Highest-Priority Findings

Claim: The highest-severity findings should be verified first.

Proof object: Findings sorted by severity.

{_finding_lines(sorted_findings[:8])}

## Slide 4 - Source And Confidence Review

Claim: Sources and confidence values determine follow-up quality.

Proof object: Finding source labels, confidence scores, and analyst notes.

## Slide 5 - Passive Next Steps

Claim: Follow-up should remain passive, documented, and authorized.

Proof object: Source checks, evidence preservation, and collection gaps.
"""


def render_report(
    report_format: str,
    investigation: Any,
    findings: Sequence[Any],
    *,
    generated_at: datetime | None = None,
) -> str:
    """Render a report using the v2 in-memory renderer set."""

    normalized = report_format.lower()
    if normalized == "json":
        return render_json_report(investigation, findings, generated_at=generated_at)
    if normalized == "markdown":
        return render_markdown_report(investigation, findings, generated_at=generated_at)
    if normalized == "briefing":
        return render_briefing_outline(investigation, findings, generated_at=generated_at)
    raise ValueError(f"Unsupported v2 report renderer format: {report_format}")
