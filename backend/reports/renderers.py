"""Safe v2 report renderers.

These renderers operate on already-collected investigation and finding data.
They do not enrich, scan, scrape, or contact targets.
"""

from __future__ import annotations

import json
from html import escape
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


def _escape_html(value: Any) -> str:
    return escape(str(value or "").strip(), quote=True)


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


def _handling_note_items(template: ReportTemplate) -> str:
    return "\n".join(f"<li>{_escape_html(note)}</li>" for note in template.handling_notes)


def _finding_items(findings: Sequence[Any]) -> str:
    if not findings:
        return '<li class="finding finding-info">No findings recorded.</li>'

    items: list[str] = []
    for finding in findings:
        severity = _escape_html(_read_value(finding, "severity", "info")).lower()
        source = _escape_html(_read_value(finding, "source", "unknown"))
        confidence = _escape_html(_read_value(finding, "confidence", 0.0))
        title = _escape_html(_finding_title(finding))
        summary = _escape_html(_finding_summary(finding))
        summary_html = f"<p>{summary}</p>" if summary else ""
        items.append(
            f"""<li class="finding finding-{severity}">
  <div class="finding-header">
    <strong>{title}</strong>
    <span>{severity.upper()} · {source} · confidence {confidence}</span>
  </div>
  {summary_html}
</li>"""
        )
    return "\n".join(items)


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


def render_html_report(
    investigation: Any,
    findings: Sequence[Any],
    *,
    generated_at: datetime | None = None,
    template_name: str = "investigation",
) -> str:
    """Render a standalone HTML investigation report."""

    generated = generated_at or datetime.now(UTC)
    template = get_report_template(template_name)
    counts = _severity_counts(findings)
    title = _escape_html(_read_value(investigation, "title", "Untitled investigation"))
    status = _escape_html(_read_value(investigation, "status", "unknown"))

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_escape_html(template.title)} - {title}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f7f8fa;
      --text: #1f2937;
      --muted: #5b6472;
      --border: #d9dee7;
      --surface: #ffffff;
      --accent: #2563eb;
      --high: #b45309;
      --critical: #b91c1c;
      --medium: #1d4ed8;
      --low: #4b5563;
    }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: Arial, Helvetica, sans-serif;
      line-height: 1.5;
    }}
    main {{
      max-width: 980px;
      margin: 0 auto;
      padding: 32px 20px;
    }}
    header, section {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 16px;
    }}
    h1, h2 {{
      margin: 0 0 12px;
    }}
    .meta, .finding-header span {{
      color: var(--muted);
      font-size: 0.92rem;
    }}
    .severity-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
      gap: 10px;
      padding: 0;
      list-style: none;
    }}
    .severity-grid li {{
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 12px;
    }}
    .severity-grid strong {{
      display: block;
      font-size: 1.5rem;
    }}
    .findings {{
      list-style: none;
      padding: 0;
      margin: 0;
    }}
    .finding {{
      border-left: 4px solid var(--low);
      border-top: 1px solid var(--border);
      padding: 14px 0 14px 12px;
    }}
    .finding:first-child {{
      border-top: 0;
    }}
    .finding-critical {{ border-left-color: var(--critical); }}
    .finding-high {{ border-left-color: var(--high); }}
    .finding-medium {{ border-left-color: var(--medium); }}
    .finding-info, .finding-low {{ border-left-color: var(--low); }}
    .finding-header {{
      display: flex;
      justify-content: space-between;
      gap: 16px;
      flex-wrap: wrap;
    }}
    .notes {{
      margin-bottom: 0;
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1>{_escape_html(template.title)}</h1>
      <div class="meta">Generated: {_escape_html(generated.isoformat())}</div>
      <div class="meta">Investigation: {title}</div>
      <div class="meta">Status: {status}</div>
    </header>
    <section>
      <h2>Executive Summary</h2>
      <p>{_escape_html(template.executive_summary)}</p>
    </section>
    <section>
      <h2>Severity Overview</h2>
      <ul class="severity-grid">
        <li><strong>{counts["critical"]}</strong>Critical</li>
        <li><strong>{counts["high"]}</strong>High</li>
        <li><strong>{counts["medium"]}</strong>Medium</li>
        <li><strong>{counts["low"]}</strong>Low</li>
        <li><strong>{counts["info"]}</strong>Info</li>
      </ul>
    </section>
    <section>
      <h2>Findings</h2>
      <ul class="findings">
        {_finding_items(findings)}
      </ul>
    </section>
    <section>
      <h2>Handling Notes</h2>
      <ul class="notes">
        {_handling_note_items(template)}
      </ul>
    </section>
  </main>
</body>
</html>"""


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
    if normalized == "html":
        return render_html_report(investigation, findings, generated_at=generated_at, template_name=template_name)
    if normalized == "markdown":
        return render_markdown_report(investigation, findings, generated_at=generated_at, template_name=template_name)
    if normalized == "briefing":
        return render_briefing_outline(investigation, findings, generated_at=generated_at, template_name=template_name)
    raise ValueError(f"Unsupported v2 report renderer format: {report_format}")
