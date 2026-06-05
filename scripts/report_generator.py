"""
report_generator.py — AU-OSINT-RECON
HTML/JSON/CSV/Markdown report generation with interactive dashboard and briefing outline output.
Risk scoring, timeline visualization, executive summary.
"""

import json
import csv
import os
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from collections import defaultdict


# ─────────────────────────────────────────────
#  Risk Scoring
# ─────────────────────────────────────────────

SEVERITY_WEIGHTS = {
    "critical": 10,
    "high":      7,
    "medium":    4,
    "low":       1,
    "info":      0,
}

CATEGORY_MULTIPLIERS = {
    "credential_breach":  1.5,
    "exploit_vuln":       1.8,
    "darkweb_listing":    2.0,
    "paste_exposure":     1.3,
    "telegram_leak":      1.6,
    "osint_exposure":     1.1,
    "financial_data":     2.2,
    "pii_exposure":       1.9,
}


def calculate_risk_score(findings: list[dict]) -> dict:
    """
    Aggregate risk score across all findings.
    Returns overall score (0-100), grade (A-F), and per-category breakdown.
    """
    if not findings:
        return {"score": 0, "grade": "A", "breakdown": {}}

    category_scores: dict[str, list[float]] = defaultdict(list)
    raw_total = 0.0

    for f in findings:
        severity  = f.get("severity", "info").lower()
        category  = f.get("category", "osint_exposure").lower()
        base      = SEVERITY_WEIGHTS.get(severity, 0)
        mult      = CATEGORY_MULTIPLIERS.get(category, 1.0)
        score     = base * mult
        raw_total += score
        category_scores[category].append(score)

    # Normalise to 0-100 (cap at 100)
    max_possible = len(findings) * SEVERITY_WEIGHTS["critical"] * max(CATEGORY_MULTIPLIERS.values())
    normalised   = min(100, round((raw_total / max_possible) * 100, 1)) if max_possible else 0

    breakdown = {
        cat: round(sum(scores), 2)
        for cat, scores in category_scores.items()
    }

    grade_map = [(90, "F"), (70, "D"), (50, "C"), (30, "B"), (0, "A")]
    grade = next(g for threshold, g in grade_map if normalised >= threshold)

    return {"score": normalised, "grade": grade, "breakdown": breakdown}


# ─────────────────────────────────────────────
#  Timeline Builder
# ─────────────────────────────────────────────

def build_timeline(findings: list[dict]) -> list[dict]:
    """
    Sort findings by date_found (ISO string) for timeline visualisation.
    Findings without dates are grouped at the end under 'unknown'.
    """
    dated   = [f for f in findings if f.get("date_found")]
    undated = [f for f in findings if not f.get("date_found")]

    dated.sort(key=lambda x: x["date_found"])

    timeline = []
    for f in dated:
        timeline.append({
            "date":     f["date_found"],
            "title":    f.get("title", "Finding"),
            "severity": f.get("severity", "info"),
            "category": f.get("category", ""),
            "summary":  f.get("summary", ""),
            "source":   f.get("source", ""),
        })

    for f in undated:
        timeline.append({
            "date":     "unknown",
            "title":    f.get("title", "Finding"),
            "severity": f.get("severity", "info"),
            "category": f.get("category", ""),
            "summary":  f.get("summary", ""),
            "source":   f.get("source", ""),
        })

    return timeline


# ─────────────────────────────────────────────
#  Executive Summary
# ─────────────────────────────────────────────

def generate_executive_summary(
    target: str,
    findings: list[dict],
    risk: dict,
    modules_run: list[str],
) -> str:
    """
    Plain-text executive summary suitable for embedding in HTML or PDF.
    """
    now         = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total       = len(findings)
    critical    = sum(1 for f in findings if f.get("severity") == "critical")
    high        = sum(1 for f in findings if f.get("severity") == "high")
    medium      = sum(1 for f in findings if f.get("severity") == "medium")
    low         = sum(1 for f in findings if f.get("severity") == "low")
    categories  = list({f.get("category", "unknown") for f in findings})

    lines = [
        f"AU-OSINT-RECON — Executive Summary",
        f"Generated : {now}",
        f"Target    : {target}",
        f"Modules   : {', '.join(modules_run) if modules_run else 'N/A'}",
        "",
        f"Risk Score : {risk['score']} / 100  (Grade: {risk['grade']})",
        "",
        f"Total Findings : {total}",
        f"  Critical : {critical}",
        f"  High     : {high}",
        f"  Medium   : {medium}",
        f"  Low      : {low}",
        "",
        f"Finding Categories : {', '.join(categories) if categories else 'none'}",
        "",
    ]

    if critical > 0:
        lines.append("⚠  CRITICAL findings require immediate remediation.")
    if high > 0:
        lines.append("⚠  HIGH severity findings should be addressed within 24-48 hours.")
    if risk["score"] >= 70:
        lines.append("🔴  Overall risk posture is SEVERE. Escalate to incident response.")
    elif risk["score"] >= 40:
        lines.append("🟠  Overall risk posture is ELEVATED. Schedule urgent review.")
    else:
        lines.append("🟢  Overall risk posture is MANAGEABLE. Continue monitoring.")

    return "\n".join(lines)


# ─────────────────────────────────────────────
#  JSON Export
# ─────────────────────────────────────────────

def export_json(
    target: str,
    findings: list[dict],
    risk: dict,
    timeline: list[dict],
    summary: str,
    modules_run: list[str],
    output_path: str,
) -> str:
    """
    Write full structured JSON report. Returns path written.
    """
    report = {
        "meta": {
            "target":       target,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tool":         "au-osint-recon",
            "modules_run":  modules_run,
            "finding_count": len(findings),
        },
        "risk":     risk,
        "summary":  summary,
        "timeline": timeline,
        "findings": findings,
    }

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)

    return output_path


# ─────────────────────────────────────────────
#  CSV Export
# ─────────────────────────────────────────────

CSV_FIELDS = [
    "title", "severity", "category", "source",
    "date_found", "summary", "target", "raw_data",
]


def export_csv(findings: list[dict], output_path: str) -> str:
    """
    Write flat CSV of all findings. Returns path written.
    """
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for f in findings:
            row = {field: f.get(field, "") for field in CSV_FIELDS}
            # Flatten raw_data if dict
            if isinstance(row.get("raw_data"), dict):
                row["raw_data"] = json.dumps(row["raw_data"])
            writer.writerow(row)

    return output_path


# ─────────────────────────────────────────────────────────────────────────────
#  Markdown / Briefing Outline Export
# ─────────────────────────────────────────────────────────────────────────────

def _md_escape(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("```", "'''").strip()


def _finding_bullets(findings: list[dict], limit: int | None = None) -> str:
    items = findings[:limit] if limit else findings
    if not items:
        return "- No findings recorded."
    lines = []
    for finding in items:
        title = _md_escape(finding.get("title", "Untitled finding"))
        severity = _md_escape(finding.get("severity", "info")).upper()
        source = _md_escape(finding.get("source", "unknown"))
        summary = _md_escape(finding.get("summary", ""))
        lines.append(f"- [{severity}] {title} ({source})")
        if summary:
            lines.append(f"  {summary}")
    return "\n".join(lines)


def export_markdown(
    target: str,
    findings: list[dict],
    risk: dict,
    timeline: list[dict],
    summary: str,
    modules_run: list[str],
    output_path: str,
) -> str:
    """Write a document-oriented Markdown report. Returns path written."""

    severity_counts = {
        severity: sum(1 for finding in findings if finding.get("severity", "info").lower() == severity)
        for severity in ["critical", "high", "medium", "low", "info"]
    }
    timeline_lines = [
        f"- {_md_escape(item.get('date', 'unknown'))}: {_md_escape(item.get('title', 'Finding'))} ({_md_escape(item.get('severity', 'info'))})"
        for item in timeline
    ] or ["- No timeline data."]

    content = f"""# Aegis OSINT Report

Generated: {datetime.now(timezone.utc).isoformat()}
Target: {_md_escape(target)}
Modules: {', '.join(modules_run) if modules_run else 'N/A'}

## Executive Summary

{_md_escape(summary)}

## Risk

- Score: {risk.get('score', 0)} / 100
- Grade: {risk.get('grade', 'A')}
- Critical: {severity_counts['critical']}
- High: {severity_counts['high']}
- Medium: {severity_counts['medium']}
- Low: {severity_counts['low']}
- Info: {severity_counts['info']}

## Findings

{_finding_bullets(findings)}

## Timeline

{chr(10).join(timeline_lines)}

## Handling Notes

- This report is for lawful, defensive, passive OSINT review.
- Verify findings against primary sources before action.
- Do not use this output for exploitation, credential replay, intrusive scanning, or unauthorized access.
"""

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(content)

    return output_path


def export_briefing_outline(
    target: str,
    findings: list[dict],
    risk: dict,
    timeline: list[dict],
    summary: str,
    modules_run: list[str],
    output_path: str,
) -> str:
    """Write a presentation-ready Markdown briefing outline. Returns path written."""

    top_findings = sorted(
        findings,
        key=lambda finding: SEVERITY_WEIGHTS.get(finding.get("severity", "info").lower(), 0),
        reverse=True,
    )[:8]
    timeline_focus = timeline[:8]
    timeline_lines = [
        f"- {_md_escape(item.get('date', 'unknown'))}: {_md_escape(item.get('title', 'Finding'))}"
        for item in timeline_focus
    ] or ["- No dated events available."]

    content = f"""# Aegis OSINT Briefing Deck Outline

Generated: {datetime.now(timezone.utc).isoformat()}
Target: {_md_escape(target)}
Modules: {', '.join(modules_run) if modules_run else 'N/A'}

## Slide 1 - Investigation Context

Claim: {_md_escape(target)} has a passive OSINT evidence set ready for analyst review.

Proof object: Scope, modules run, and finding count.

## Slide 2 - Risk Posture

Claim: Current risk is graded {risk.get('grade', 'A')} with a score of {risk.get('score', 0)} / 100.

Proof object: Severity counts and category breakdown.

## Slide 3 - Highest-Priority Findings

Claim: The most severe findings define the immediate review queue.

Proof object: Top findings by severity.

{_finding_bullets(top_findings)}

## Slide 4 - Timeline

Claim: Chronology shows how the evidence set developed.

Proof object: Earliest dated findings and source trail.

{chr(10).join(timeline_lines)}

## Slide 5 - Analyst Caveats

Claim: Findings require source verification before operational use.

Proof object: Executive summary and handling notes.

{_md_escape(summary)}

## Slide 6 - Passive Next Steps

Claim: Follow-up should remain passive, documented, and authorized.

Proof object: Source checks, evidence preservation, and documented collection gaps.
"""

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(content)

    return output_path


# ─────────────────────────────────────────────
#  HTML Dashboard Export
# ─────────────────────────────────────────────

def _severity_color(severity: str) -> str:
    return {
        "critical": "#ff2d55",
        "high":     "#ff6b35",
        "medium":   "#ffd60a",
        "low":      "#30d158",
        "info":     "#636366",
    }.get(severity.lower(), "#636366")


def _severity_badge(severity: str) -> str:
    color = _severity_color(severity)
    return (
        f'<span style="background:{color};color:#000;padding:2px 8px;'
        f'border-radius:4px;font-size:11px;font-weight:700;'
        f'text-transform:uppercase;">{severity}</span>'
    )


def _build_findings_rows(findings: list[dict]) -> str:
    if not findings:
        return '<tr><td colspan="6" style="text-align:center;color:#636366;padding:24px;">No findings recorded.</td></tr>'

    rows = []
    for i, f in enumerate(findings):
        sev     = f.get("severity", "info")
        cat     = f.get("category", "—")
        title   = f.get("title", "Untitled")
        source  = f.get("source", "—")
        date    = f.get("date_found", "—")
        summary = f.get("summary", "")
        raw     = json.dumps(f.get("raw_data", {}), indent=2) if f.get("raw_data") else ""

        detail_id = f"detail_{i}"
        toggle_js = f"toggleDetail('{detail_id}')"

        rows.append(f"""
        <tr class="finding-row" onclick="{toggle_js}" style="cursor:pointer;">
            <td>{_severity_badge(sev)}</td>
            <td style="font-weight:600;">{title}</td>
            <td><span class="cat-tag">{cat}</span></td>
            <td>{source}</td>
            <td>{date}</td>
            <td><button class="expand-btn" onclick="event.stopPropagation();{toggle_js}">▼</button></td>
        </tr>
        <tr id="{detail_id}" class="detail-row" style="display:none;">
            <td colspan="6">
                <div class="detail-box">
                    <p><strong>Summary:</strong> {summary}</p>
                    {"<pre class='raw-pre'>" + raw + "</pre>" if raw else ""}
                </div>
            </td>
        </tr>
        """)

    return "\n".join(rows)


def _build_timeline_items(timeline: list[dict]) -> str:
    if not timeline:
        return '<li style="color:#636366;">No timeline data.</li>'

    items = []
    for t in timeline:
        color = _severity_color(t.get("severity", "info"))
        items.append(f"""
        <li class="tl-item">
            <span class="tl-dot" style="background:{color};"></span>
            <div class="tl-content">
                <span class="tl-date">{t['date']}</span>
                <span class="tl-title">{t['title']}</span>
                <span class="tl-source">{t.get('source','')}</span>
            </div>
        </li>
        """)

    return "\n".join(items)


def _build_breakdown_bars(breakdown: dict) -> str:
    if not breakdown:
        return "<p style='color:#636366;'>No category data.</p>"

    max_val = max(breakdown.values()) if breakdown else 1
    bars    = []
    for cat, val in sorted(breakdown.items(), key=lambda x: -x[1]):
        pct = round((val / max_val) * 100)
        bars.append(f"""
        <div class="bar-row">
            <span class="bar-label">{cat}</span>
            <div class="bar-track">
                <div class="bar-fill" style="width:{pct}%;"></div>
            </div>
            <span class="bar-val">{val}</span>
        </div>
        """)

    return "\n".join(bars)


def export_html(
    target: str,
    findings: list[dict],
    risk: dict,
    timeline: list[dict],
    summary: str,
    modules_run: list[str],
    output_path: str,
    template_path: str | None = None,
) -> str:
    """
    Render interactive HTML dashboard. Uses external template if provided,
    otherwise falls back to inline template. Returns path written.
    """
    # Try loading external template
    template_html = None
    if template_path and Path(template_path).exists():
        with open(template_path, "r", encoding="utf-8") as fh:
            template_html = fh.read()

    now           = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total         = len(findings)
    critical_cnt  = sum(1 for f in findings if f.get("severity") == "critical")
    high_cnt      = sum(1 for f in findings if f.get("severity") == "high")
    medium_cnt    = sum(1 for f in findings if f.get("severity") == "medium")
    low_cnt       = sum(1 for f in findings if f.get("severity") == "low")
    score         = risk.get("score", 0)
    grade         = risk.get("grade", "A")
    breakdown     = risk.get("breakdown", {})

    score_color = (
        "#ff2d55" if score >= 70 else
        "#ff6b35" if score >= 40 else
        "#ffd60a" if score >= 20 else
        "#30d158"
    )

    findings_rows    = _build_findings_rows(findings)
    timeline_items   = _build_timeline_items(timeline)
    breakdown_bars   = _build_breakdown_bars(breakdown)
    modules_str      = ", ".join(modules_run) if modules_run else "N/A"
    summary_escaped  = summary.replace("\n", "<br>")

    # Inline fallback template
    if not template_html:
        template_html = _inline_template()

    html = (
        template_html
        .replace("{{TARGET}}", target)
        .replace("{{GENERATED_AT}}", now)
        .replace("{{MODULES}}", modules_str)
        .replace("{{TOTAL}}", str(total))
        .replace("{{CRITICAL}}", str(critical_cnt))
        .replace("{{HIGH}}", str(high_cnt))
        .replace("{{MEDIUM}}", str(medium_cnt))
        .replace("{{LOW}}", str(low_cnt))
        .replace("{{SCORE}}", str(score))
        .replace("{{GRADE}}", grade)
        .replace("{{SCORE_COLOR}}", score_color)
        .replace("{{SUMMARY}}", summary_escaped)
        .replace("{{FINDINGS_ROWS}}", findings_rows)
        .replace("{{TIMELINE_ITEMS}}", timeline_items)
        .replace("{{BREAKDOWN_BARS}}", breakdown_bars)
    )

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    return output_path


# ─────────────────────────────────────────────
#  Inline HTML Template (fallback)
# ─────────────────────────────────────────────

def _inline_template() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AU-OSINT-RECON — {{TARGET}}</title>
<style>
  :root {
    --bg:       #0a0a0f;
    --surface:  #111118;
    --border:   #1e1e2e;
    --text:     #e0e0e8;
    --muted:    #636366;
    --accent:   #ff2d55;
    --accent2:  #0a84ff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'SF Mono', 'Fira Code', monospace; font-size: 13px; line-height: 1.6; }
  header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 20px 32px; display: flex; align-items: center; gap: 16px; }
  header h1 { font-size: 18px; color: var(--accent); letter-spacing: 2px; }
  header .meta { color: var(--muted); font-size: 11px; margin-left: auto; text-align: right; }
  .container { max-width: 1400px; margin: 0 auto; padding: 24px 32px; }
  .grid-top { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 28px; }
  .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px 20px; }
  .stat-card .label { color: var(--muted); font-size: 10px; text-transform: uppercase; letter-spacing: 1px; }
  .stat-card .value { font-size: 28px; font-weight: 700; margin-top: 4px; }
  .risk-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 28px; display: flex; align-items: center; gap: 32px; }
  .risk-score { font-size: 64px; font-weight: 900; color: {{SCORE_COLOR}}; line-height: 1; }
  .risk-grade { font-size: 32px; font-weight: 700; color: {{SCORE_COLOR}}; }
  .risk-label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }
  .section { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 24px; overflow: hidden; }
  .section-header { padding: 14px 20px; border-bottom: 1px solid var(--border); font-size: 12px; text-transform: uppercase; letter-spacing: 1.5px; color: var(--muted); }
  .section-body { padding: 20px; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; color: var(--muted); font-size: 10px; text-transform: uppercase; letter-spacing: 1px; padding: 8px 12px; border-bottom: 1px solid var(--border); }
  td { padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: middle; }
  .finding-row:hover { background: rgba(255,255,255,0.03); }
  .detail-row td { background: #0d0d14; }
  .detail-box { padding: 12px; }
  .detail-box p { margin-bottom: 8px; }
  .raw-pre { background: #080810; border: 1px solid var(--border); border-radius: 4px; padding: 12px; overflow-x: auto; font-size: 11px; color: #8e8e93; max-height: 200px; }
  .cat-tag { background: #1c1c2e; border: 1px solid var(--border); border-radius: 4px; padding: 2px 8px; font-size: 11px; color: var(--muted); }
  .expand-btn { background: none; border: 1px solid var(--border); color: var(--muted); border-radius: 4px; padding: 2px 8px; cursor: pointer; font-size: 11px; }
  .expand-btn:hover { background: var(--border); }
  .tl-list { list-style: none; padding: 0; }
  .tl-item { display: flex; align-items: flex-start; gap: 12px; padding: 10px 0; border-bottom: 1px solid var(--border); }
  .tl-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; margin-top: 4px; }
  .tl-content { display: flex; flex-direction: column; gap: 2px; }
  .tl-date { color: var(--muted); font-size: 11px; }
  .tl-title { font-weight: 600; }
  .tl-source { color: var(--muted); font-size: 11px; }
  .bar-row { display: flex; align-items: center; gap: 12px; margin-bottom: 10px; }
  .bar-label { width: 180px; color: var(--muted); font-size: 11px; flex-shrink: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .bar-track { flex: 1; background: var(--border); border-radius: 4px; height: 8px; }
  .bar-fill { height: 100%; background: var(--accent2); border-radius: 4px; transition: width 0.4s; }
  .bar-val { width: 40px; text-align: right; color: var(--muted); font-size: 11px; }
  .summary-pre { white-space: pre-wrap; color: var(--text); font-family: inherit; font-size: 12px; line-height: 1.8; }
  .tabs { display: flex; gap: 0; border-bottom: 1px solid var(--border); }
  .tab { padding: 10px 20px; cursor: pointer; color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; border-bottom: 2px solid transparent; }
  .tab.active { color: var(--text); border-bottom-color: var(--accent); }
  .tab-content { display: none; padding: 20px; }
  .tab-content.active { display: block; }
  @media (max-width: 600px) { .container { padding: 12px 16px; } .grid-top { grid-template-columns: repeat(2, 1fr); } }
</style>
</head>
<body>
<header>
  <div>
    <h1>AU-OSINT-RECON</h1>
    <div style="color:var(--muted);font-size:11px;margin-top:2px;">Australian Breach Intelligence Platform</div>
  </div>
  <div class="meta">
    <div>Target: <strong style="color:var(--text);">{{TARGET}}</strong></div>
    <div>Generated: {{GENERATED_AT}}</div>
    <div>Modules: {{MODULES}}</div>
  </div>
</header>

<div class="container">

  <!-- Risk Score -->
  <div class="risk-card">
    <div>
      <div class="risk-label">Risk Score</div>
      <div class="risk-score">{{SCORE}}</div>
    </div>
    <div>
      <div class="risk-label">Grade</div>
      <div class="risk-grade">{{GRADE}}</div>
    </div>
    <div style="flex:1;">
      <div class="risk-label" style="margin-bottom:8px;">Category Breakdown</div>
      {{BREAKDOWN_BARS}}
    </div>
  </div>

  <!-- Stat Cards -->
  <div class="grid-top">
    <div class="stat-card">
      <div class="label">Total Findings</div>
      <div class="value" style="color:var(--accent2);">{{TOTAL}}</div>
    </div>
    <div class="stat-card">
      <div class="label">Critical</div>
      <div class="value" style="color:#ff2d55;">{{CRITICAL}}</div>
    </div>
    <div class="stat-card">
      <div class="label">High</div>
      <div class="value" style="color:#ff6b35;">{{HIGH}}</div>
    </div>
    <div class="stat-card">
      <div class="label">Medium</div>
      <div class="value" style="color:#ffd60a;">{{MEDIUM}}</div>
    </div>
    <div class="stat-card">
      <div class="label">Low</div>
      <div class="value" style="color:#30d158;">{{LOW}}</div>
    </div>
  </div>

  <!-- Findings Table -->
  <div class="section">
    <div class="section-header">Findings</div>
    <div class="tabs">
      <div class="tab active" onclick="switchTab('all')">All</div>
      <div class="tab" onclick="switchTab('critical')">Critical</div>
      <div class="tab" onclick="switchTab('high')">High</div>
      <div class="tab" onclick="switchTab('medium')">Medium</div>
    </div>
    <div style="overflow-x:auto;">
      <table id="findings-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Title</th>
            <th>Category</th>
            <th>Source</th>
            <th>Date</th>
            <th></th>
          </tr>
        </thead>
        <tbody id="findings-body">
          {{FINDINGS_ROWS}}
        </tbody>
      </table>
    </div>
  </div>

  <!-- Timeline + Summary side by side -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:24px;">
    <div class="section">
      <div class="section-header">Timeline</div>
      <div class="section-body" style="max-height:400px;overflow-y:auto;">
        <ul class="tl-list">
          {{TIMELINE_ITEMS}}
        </ul>
      </div>
    </div>
    <div class="section">
      <div class="section-header">Executive Summary</div>
      <div class="section-body">
        <pre class="summary-pre">{{SUMMARY}}</pre>
      </div>
    </div>
  </div>

</div>

<script>
function toggleDetail(id) {
  const row = document.getElementById(id);
  if (!row) return;
  row.style.display = row.style.display === 'none' ? 'table-row' : 'none';
}

function switchTab(filter) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  event.target.classList.add('active');
  const rows = document.querySelectorAll('#findings-body .finding-row');
  rows.forEach(row => {
    const sev = row.querySelector('span') ? row.querySelector('span').textContent.toLowerCase() : '';
    if (filter === 'all' || sev === filter) {
      row.style.display = '';
    } else {
      row.style.display = 'none';
    }
  });
}
</script>
</body>
</html>"""


# ─────────────────────────────────────────────
#  Master Report Runner
# ─────────────────────────────────────────────

class ReportGenerator:
    """
    Orchestrates all export formats from a single findings payload.

    Usage:
        rg = ReportGenerator(output_dir="./reports", target="example.com.au")
        rg.load_findings(findings_list)
        rg.run(modules_run=["breach", "osint", "exploit"])
    """

    def __init__(self, output_dir: str = "./reports", target: str = "unknown"):
        self.output_dir   = Path(output_dir)
        self.target       = target
        self.findings: list[dict] = []
        self.modules_run: list[str] = []

        # Resolve template path relative to this file
        skill_root     = Path(__file__).parent.parent
        self.template  = str(skill_root / "assets" / "dashboard_template.html")

    def load_findings(self, findings: list[dict]) -> None:
        self.findings = findings

    def add_finding(
        self,
        title: str,
        severity: str,
        category: str,
        source: str,
        summary: str = "",
        date_found: str = "",
        raw_data: Any = None,
        target: str = "",
    ) -> None:
        self.findings.append({
            "title":      title,
            "severity":   severity.lower(),
            "category":   category.lower(),
            "source":     source,
            "summary":    summary,
            "date_found": date_found or datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "raw_data":   raw_data or {},
            "target":     target or self.target,
        })

    def run(self, modules_run: list[str] | None = None) -> dict[str, str]:
        """
        Generate all report formats. Returns dict of output paths.
        """
        self.modules_run = modules_run or []
        self.output_dir.mkdir(parents=True, exist_ok=True)

        slug      = self.target.replace(".", "_").replace("/", "_")[:40]
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        base      = self.output_dir / f"{slug}_{timestamp}"

        risk     = calculate_risk_score(self.findings)
        timeline = build_timeline(self.findings)
        summary  = generate_executive_summary(
            self.target, self.findings, risk, self.modules_run
        )

        json_path = export_json(
            self.target, self.findings, risk, timeline, summary,
            self.modules_run, str(base) + ".json"
        )
        csv_path = export_csv(self.findings, str(base) + ".csv")
        html_path = export_html(
            self.target, self.findings, risk, timeline, summary,
            self.modules_run, str(base) + ".html",
            template_path=self.template,
        )
        markdown_path = export_markdown(
            self.target, self.findings, risk, timeline, summary,
            self.modules_run, str(base) + ".md",
        )
        briefing_path = export_briefing_outline(
            self.target, self.findings, risk, timeline, summary,
            self.modules_run, str(base) + "_briefing.md",
        )

        return {
            "json": json_path,
            "csv":  csv_path,
            "html": html_path,
            "markdown": markdown_path,
            "briefing": briefing_path,
        }


# ─────────────────────────────────────────────
#  CLI entry point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AU-OSINT-RECON Report Generator")
    parser.add_argument("--input",  required=True, help="Path to JSON findings file")
    parser.add_argument("--target", default="unknown", help="Target identifier")
    parser.add_argument("--output", default="./reports", help="Output directory")
    parser.add_argument("--modules", default="", help="Comma-separated modules run")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as fh:
        raw = json.load(fh)

    findings = raw if isinstance(raw, list) else raw.get("findings", [])
    modules  = [m.strip() for m in args.modules.split(",") if m.strip()]

    rg = ReportGenerator(output_dir=args.output, target=args.target)
    rg.load_findings(findings)
    paths = rg.run(modules_run=modules)

    print("Reports generated:")
    for fmt, path in paths.items():
        print(f"  {fmt.upper():5s} → {path}")
