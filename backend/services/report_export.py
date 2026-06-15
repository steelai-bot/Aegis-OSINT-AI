"""Report export service — PDF and CSV generation for investigations."""

from __future__ import annotations

import csv
import io
from typing import Any

from jinja2 import Template


PDF_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Investigation Report</title>
<style>
  body { font-family: Arial, sans-serif; margin: 20px; color: #333; }
  h1 { color: #0d9488; border-bottom: 2px solid #0d9488; padding-bottom: 8px; }
  h2 { color: #115e59; margin-top: 24px; }
  table { border-collapse: collapse; width: 100%; margin: 12px 0; }
  th, td { border: 1px solid #ccc; padding: 6px 10px; text-align: left; font-size: 12px; }
  th { background: #f0fdfa; }
  .meta { color: #555; font-size: 13px; margin-bottom: 16px; }
  .footer { margin-top: 20px; font-size: 11px; color: #888; }
  .badge { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 11px; }
  .badge-high { background: #fee2e2; color: #991b1b; }
  .badge-medium { background: #fef3c7; color: #92400e; }
  .badge-low { background: #dbeafe; color: #1e40af; }
</style>
</head>
<body>
<h1>Investigation Report</h1>
<div class="meta">
  <strong>Investigation:</strong> {{ title }}<br>
  <strong>Generated:</strong> {{ generated_at }}<br>
  <strong>Type:</strong> {{ report_type }}
</div>
<h2>Targets ({{ targets|length }})</h2>
<table>
<th><th>Value</th><th>Type</th><th>Added</th></tr>
{% for t in targets %}
<tr>
  <td>{{ loop.index }}</td>
  <td>{{ t.value }}</td>
  <td>{{ t.type }}</td>
  <td>{{ t.created_at }}</td>
</tr>
{% endfor %}
</table>
<h2>Findings ({{ findings|length }})</h2>
<table>
<tr><th>#</th><th>Source</th><th>Severity</th><th>Category</th><th>Confidence</th><th>Indicator Type</th><th>Created</th></tr>
{% for f in findings %}
<tr>
  <td>{{ loop.index }}</td>
  <td>{{ f.source }}</td>
  <td><span class="badge badge-{{ f.severity }}">{{ f.severity }}</span></td>
  <td>{{ f.threat_category or '—' }}</td>
  <td>{{ f.confidence }}%</td>
  <td>{{ f.indicator_type or '—' }}</td>
  <td>{{ f.created_at }}</td>
</tr>
{% endfor %}
</table>
{% if summaries %}
<h2>Summary</h2>
<table>
<tr><th>Metric</th><th>Value</th></tr>
<tr><td>Total findings</td><td>{{ summaries.total_findings }}</td></tr>
<tr><td>High severity</td><td>{{ summaries.high_severity }}</td></tr>
<tr><td>Medium severity</td><td>{{ summaries.medium_severity }}</td></tr>
<tr><td>Low severity</td><td>{{ summaries.low_severity }}</td></tr>
<tr><td>Enriched findings</td><td>{{ summaries.enriched_count }}</td></tr>
</table>
{% endif %}
<p class="footer">Aegis OSINT Investigation Framework — generated {{ generated_at }}</p>
</body>
</html>"""


def generate_html_report(investigation: dict[str, Any], findings: list[dict], targets: list[dict]) -> str:
    """Return a full HTML document suitable for PDF rendering."""
    summary = _summarize_findings(findings)
    template = Template(PDF_TEMPLATE)
    return template.render(
        title=investigation.get("title", "Untitled Investigation"),
        generated_at=investigation.get("generated_at", ""),
        report_type="investigation",
        targets=targets,
        findings=findings,
        summaries=summary,
    )


def generate_csv_report(investigation: dict[str, Any], findings: list[dict], targets: list[dict]) -> str:
    """Return CSV text with a header row and one row per finding."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "investigation_id", "investigation_title",
        "finding_id", "source", "severity", "threat_category", "indicator_type",
        "confidence", "risk_score", "exploitability", "remediation_status",
        "created_at",
    ])
    for f in findings:
        writer.writerow([
            investigation.get("id", ""),
            investigation.get("title", ""),
            f.get("id", ""),
            f.get("source", ""),
            f.get("severity", ""),
            f.get("threat_category", ""),
            f.get("indicator_type", ""),
            f.get("confidence", 0),
            f.get("risk_score", 0),
            f.get("exploitability", ""),
            f.get("remediation_status", ""),
            f.get("created_at", ""),
        ])
    return buf.getvalue()


def _summarize_findings(findings: list[dict]) -> dict[str,Any]:
    counts = {"total_findings": len(findings), "high_severity": 0, "medium_severity": 0, "low_severity": 0, "enriched_count": 0}
    for f in findings:
        sev = (f.get("severity") or "").lower()
        if sev == "high":
            counts["high_severity"] += 1
        elif sev == "medium":
            counts["medium_severity"] += 1
        elif sev == "low":
            counts["low_severity"] += 1
        if f.get("enriched"):
            counts["enriched_count"] += 1
    return counts