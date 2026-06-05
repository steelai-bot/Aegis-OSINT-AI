"""Safe v2 report renderers.

These renderers operate on already-collected investigation and finding data.
They do not enrich, scan, scrape, or contact targets.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from backend.reports.templates import ReportTemplate, get_report_template

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


def _handling_notes(template: ReportTemplate) -> list[str]:
    return list(template.handling_notes)


def _handling_note_lines(template: ReportTemplate) -> str:
    return "\n".join(f"- {note}" for note in template.handling_notes)


def render_json_report(
    investigation: Any,
    findings: Sequence[Any],
    *,
    generated_at: datetime | None = None,
    template_name: str = "investigation",
) -> str:
    """Render a structured JSON investigation report."""

    generated = generated_at or datetime.now(UTC)
    template = get_report_template(template_name)
    payload = {
        "meta": {
            "generated_at": generated.isoformat(),
            "tool": "aegis-v2",
            "format": "json",
            "template": template.name,
        },
        "investigation": {
            "title": _read_value(investigation, "title", "Untitled investigation"),
            "status": _read_value(investigation, "status", "unknown"),
        },
        "severity_counts": _severity_counts(findings),
        "findings": [_finding_payload(finding) for finding in findings],
        "handling_notes": _handling_notes(template),
    }
    return json.dumps(payload, indent=2, default=str)


def render_markdown_report(
    investigation: Any,
    findings: Sequence[Any],
    *,
    generated_at: datetime | None = None,
    template_name: str = "investigation",
) -> str:
    """Render a document-ready Markdown investigation report."""

    generated = generated_at or datetime.now(UTC)
    template = get_report_template(template_name)
    counts = _severity_counts(findings)
    title = _escape_markdown(_read_value(investigation, "title", "Untitled investigation"))
    status = _escape_markdown(_read_value(investigation, "status", "unknown"))

    return f"""# {template.title}

Generated: {generated.isoformat()}
Investigation: {title}
Status: {status}

## Executive Summary

{template.executive_summary}

## Severity Overview

- Critical: {counts["critical"]}
- High: {counts["high"]}
- Medium: {counts["medium"]}
- Low: {counts["low"]}
- Info: {counts["info"]}

## Findings

{_finding_lines(findings)}

## Handling Notes

{_handling_note_lines(template)}
"""


def render_briefing_outline(
    investigation: Any,
    findings: Sequence[Any],
    *,
    generated_at: datetime | None = None,
    template_name: str = "investigation",
) -> str:
    """Render a presentation-ready Markdown briefing outline."""

    generated = generated_at or datetime.now(UTC)
    template = get_report_template(template_name)
    title = _escape_markdown(_read_value(investigation, "title", "Untitled investigation"))
    sorted_findings = sorted(
        findings,
        key=lambda finding: SEVERITY_ORDER.get(str(_read_value(finding, "severity", "info")).lower(), 0),
        reverse=True,
    )
    slide_sections: list[str] = []
    for index, slide in enumerate(template.briefing_slides, start=1):
        claim = slide.claim.format(title=title, finding_count=len(findings))
        proof_object = slide.proof_object.format(title=title, finding_count=len(findings))
        section = f"""## Slide {index} - {slide.title}

Claim: {claim}

Proof object: {proof_object}
"""
        if slide.title == "Highest-Priority Findings":
            section = f"{section}\n{_finding_lines(sorted_findings[:8])}\n"
        slide_sections.append(section.rstrip())

    return f"""# {template.briefing_title}

Generated: {generated.isoformat()}
Investigation: {title}

{chr(10).join(slide_sections)}
"""


def render_report(
    report_format: str,
    investigation: Any,
    findings: Sequence[Any],
    *,
    generated_at: datetime | None = None,
    template_name: str = "investigation",
) -> str:
    """Render a report using the v2 in-memory renderer set."""

    normalized = report_format.lower()
    if normalized == "json":
        return render_json_report(investigation, findings, generated_at=generated_at, template_name=template_name)
    if normalized == "markdown":
        return render_markdown_report(investigation, findings, generated_at=generated_at, template_name=template_name)
    if normalized == "briefing":
        return render_briefing_outline(investigation, findings, generated_at=generated_at, template_name=template_name)
    raise ValueError(f"Unsupported v2 report renderer format: {report_format}")
