"""
Report Generation Module
Handles HTML, JSON, CSV, and Markdown report generation.
"""

import os
import json
import csv
from datetime import datetime, timezone
from typing import Dict, List, Any
from pathlib import Path

class ReportGenerator:
    """Generate reports in various formats."""
    
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate(self, format: str, target: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
        """Generate report in specified format."""
        if format == "json":
            return self._generate_json(target, findings)
        elif format == "csv":
            return self._generate_csv(target, findings)
        elif format == "markdown" or format == "md":
            return self._generate_markdown(target, findings)
        elif format == "html":
            return self._generate_html(target, findings)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _calculate_risk_score(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate risk score from findings."""
        if not findings:
            return {"score": 0, "grade": "A", "breakdown": {}}
        
        SEVERITY_WEIGHTS = {
            "critical": 10,
            "high": 7,
            "medium": 4,
            "low": 1,
            "info": 0,
        }
        
        category_scores = {}
        raw_total = 0.0
        
        for finding in findings:
            severity = finding.get("severity", "info").lower()
            category = finding.get("category", "osint_exposure").lower()
            base = SEVERITY_WEIGHTS.get(severity, 0)
            score = base
            raw_total += score
            
            if category not in category_scores:
                category_scores[category] = 0
            category_scores[category] += score
        
        max_possible = len(findings) * SEVERITY_WEIGHTS["critical"] * 2.0
        normalised = min(100, round((raw_total / max_possible) * 100, 1)) if max_possible else 0
        
        grade_map = [(90, "F"), (70, "D"), (50, "C"), (30, "B"), (0, "A")]
        grade = next((g for threshold, g in grade_map if normalised >= threshold), "A")
        
        return {
            "score": normalised,
            "grade": grade,
            "breakdown": category_scores
        }
    
    def _build_timeline(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build timeline from findings."""
        dated = [f for f in findings if f.get("created_at")]
        undated = [f for f in findings if not f.get("created_at")]
        
        dated.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        
        timeline = []
        for f in dated:
            timeline.append({
                "date": f.get("created_at", "")[:10],
                "title": f"{f.get('source', 'Unknown')} - {f.get('category', 'unknown')}",
                "severity": f.get("severity", "info"),
                "category": f.get("category", ""),
                "source": f.get("source", ""),
            })
        
        for f in undated:
            timeline.append({
                "date": "unknown",
                "title": f"{f.get('source', 'Unknown')} - {f.get('category', 'unknown')}",
                "severity": f.get("severity", "info"),
                "category": f.get("category", ""),
                "source": f.get("source", ""),
            })
        
        return timeline[:50]
    
    def _generate_executive_summary(self, target: Dict[str, Any], findings: List[Dict[str, Any]], risk: Dict[str, Any], modules_run: List[str] = None) -> str:
        """Generate executive summary."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        total = len(findings)
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        medium = sum(1 for f in findings if f.get("severity") == "medium")
        low = sum(1 for f in findings if f.get("severity") == "low")
        
        lines = [
            f"Aegis OSINT AI — Executive Summary",
            f"Generated : {now}",
            f"Target    : {target.get('query', 'unknown')}",
            f"",
            f"Risk Score : {risk.get('score', 0)} / 100  (Grade: {risk.get('grade', 'A')})",
            f"",
            f"Total Findings : {total}",
            f"  Critical : {critical}",
            f"  High     : {high}",
            f"  Medium   : {medium}",
            f"  Low      : {low}",
            f"",
        ]
        
        if critical > 0:
            lines.append("⚠  CRITICAL findings require immediate attention.")
        if high > 0:
            lines.append("⚠  HIGH severity findings should be reviewed promptly.")
        if risk.get("score", 0) >= 70:
            lines.append("🔴  Overall risk posture is SEVERE.")
        elif risk.get("score", 0) >= 40:
            lines.append("🟠  Overall risk posture is ELEVATED.")
        else:
            lines.append("🟢  Overall risk posture is MANAGEABLE.")
        
        return "\n".join(lines)
    
    def _generate_json(self, target: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
        """Generate JSON report."""
        risk = self._calculate_risk_score(findings)
        timeline = self._build_timeline(findings)
        summary = self._generate_executive_summary(target, findings, risk, [])
        
        report = {
            "meta": {
                "target": target.get("query", "unknown"),
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "tool": "aegis-osint-ai",
                "finding_count": len(findings),
            },
            "risk": risk,
            "summary": summary,
            "timeline": timeline,
            "findings": findings,
        }
        
        return json.dumps(report, indent=2, default=str)
    
    def _generate_csv(self, target: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
        """Generate CSV report."""
        output = []
        writer = csv.writer(output)
        
        writer.writerow([
            "id", "target_id", "source", "category", "severity", 
            "confidence", "data", "created_at"
        ])
        
        for finding in findings:
            writer.writerow([
                finding.get("id", ""),
                finding.get("target_id", ""),
                finding.get("source", ""),
                finding.get("category", ""),
                finding.get("severity", ""),
                finding.get("confidence", ""),
                json.dumps(finding.get("data", {})),
                finding.get("created_at", "")
            ])
        
        return "\n".join(output)
    
    def _generate_markdown(self, target: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
        """Generate Markdown report."""
        risk = self._calculate_risk_score(findings)
        timeline = self._build_timeline(findings)
        summary = self._generate_executive_summary(target, findings, risk, [])
        
        lines = [
            f"# Aegis OSINT Report",
            f"",
            f"**Target:** {target.get('query', 'unknown')}",
            f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
            f"",
            f"## Executive Summary",
            f"",
            summary,
            f"",
            f"## Risk Assessment",
            f"",
            f"- **Score:** {risk.get('score', 0)} / 100",
            f"- **Grade:** {risk.get('grade', 'A')}",
            f"",
            f"## Findings ({len(findings)} total)",
            f"",
        ]
        
        if findings:
            for finding in findings:
                lines.extend([
                    f"### {finding.get('source', 'Unknown')} - {finding.get('severity', 'info').upper()}",
                    f"",
                    f"**Category:** {finding.get('category', 'unknown')}",
                    f"**Confidence:** {finding.get('confidence', 0):.0%}",
                    f"**Data:**",
                    f"```json",
                    f"{json.dumps(finding.get('data', {}), indent=2)}",
                    f"```",
                    f"",
                    f"---",
                    f""
                ])
        else:
            lines.append("*No findings recorded.*")
            lines.append("")
        
        lines.extend([
            f"## Timeline",
            f"",
        ])
        
        if timeline:
            for event in timeline:
                lines.append(f"- **{event.get('date', 'unknown')}**: {event.get('title', 'Event')} ({event.get('severity', 'info')})")
        else:
            lines.append("*No timeline data.*")
        
        return "\n".join(lines)
    
    def _generate_html(self, target: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
        """Generate HTML report."""
        risk = self._calculate_risk_score(findings)
        timeline = self._build_timeline(findings)
        summary = self._generate_executive_summary(target, findings, risk, [])
        
        severity_colors = {
            "critical": "#ff2d55",
            "high": "#ff6b35",
            "medium": "#ffd60a",
            "low": "#30d158",
            "info": "#636366"
        }
        
        score = risk.get('score', 0)
        score_color = "#ff2d55" if score >= 70 else "#ff6b35" if score >= 40 else "#ffd60a" if score >= 20 else "#30d158"
        
        findings_rows = ""
        if findings:
            for i, finding in enumerate(findings):
                severity = finding.get('severity', 'info')
                color = severity_colors.get(severity, '#636366')
                findings_rows += f"""
                <tr class="finding-row" onclick="toggleDetail('detail-{i}')" style="cursor:pointer;">
                    <td><span style="background:{color};color:#000;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;text-transform:uppercase;">{severity}</span></td>
                    <td style="font-weight:600;">{finding.get('source', 'Unknown')}</td>
                    <td><span style="background:#1c1c2e;border:1px solid #1e1e2e;border-radius:4px;padding:2px 8px;font-size:11px;color:#636366;">{finding.get('category', 'unknown')}</span></td>
                    <td>{finding.get('confidence', 0):.0%}</td>
                    <td>{finding.get('created_at', '')[:10]}</td>
                    <td><button onclick="event.stopPropagation();toggleDetail('detail-{i}')">▼</button></td>
                </tr>
                <tr id="detail-{i}" style="display:none;">
                    <td colspan="6"><pre style="background:#080810;padding:12px;border-radius:4px;">{json.dumps(finding.get('data', {}), indent=2)}</pre></td>
                </tr>
                """
        else:
            findings_rows = '<tr><td colspan="6" style="text-align:center;color:#636366;padding:24px;">No findings recorded.</td></tr>'
        
        timeline_items = ""
        if timeline:
            for t in timeline:
                severity = t.get('severity', 'info')
                color = severity_colors.get(severity, '#636366')
                timeline_items += f"""
                <li style="display:flex;align-items:flex-start;gap:12px;padding:10px 0;border-bottom:1px solid #1e1e2e;">
                    <span style="width:10px;height:10px;border-radius:50%;background:{color};flex-shrink:0;margin-top:4px;"></span>
                    <div>
                        <span style="color:#636366;font-size:11px;">{t.get('date', 'unknown')}</span>
                        <span style="font-weight:600;display:block;">{t.get('title', 'Event')}</span>
                    </div>
                </li>
                """
        else:
            timeline_items = '<li style="color:#636366;">No timeline data.</li>'
        
        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Aegis OSINT Report - {target.get('query', 'unknown')}</title>
    <style>
        :root {{ --bg: #0a0a0f; --surface: #111118; --border: #1e1e2e; --text: #e0e0e8; --muted: #636366; --accent: #ff2d55; }}
        body {{ background: var(--bg); color: var(--text); font-family: monospace; font-size: 13px; }}
        header {{ background: var(--surface); padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 24px; }}
        .risk-card {{ background: var(--surface); padding: 20px; margin-bottom: 20px; border-radius: 8px; display: flex; gap: 32px; }}
        .risk-score {{ font-size: 48px; font-weight: 900; color: {score_color}; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 10px; border-bottom: 1px solid var(--border); }}
    </style>
</head>
<body>
    <header>
        <h1 style="color:var(--accent);">Aegis OSINT AI</h1>
        <p>Target: {target.get('query', 'unknown')}</p>
    </header>
    <div class="container">
        <div class="risk-card">
            <div><div>Risk Score</div><div class="risk-score">{score}</div></div>
            <div><div>Grade</div><div style="font-size:24px;color:{score_color};">{risk.get('grade', 'A')}</div></div>
        </div>
        <h2>Findings ({len(findings)})</h2>
        <table>
            <thead><tr><th>Severity</th><th>Source</th><th>Category</th><th>Confidence</th><th>Date</th><th></th></tr></thead>
            <tbody>{findings_rows}</tbody>
        </table>
    </div>
    <script>function toggleDetail(id) {{ document.getElementById(id).style.display = document.getElementById(id).style.display === 'none' ? 'table-row' : 'none'; }}</script>
</body>
</html>"""