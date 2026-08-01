"""
Report Generation Module
Handles HTML, JSON, Markdown, CSV, and PDF report generation with a modular section-based architecture.
"""

import csv
import io
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class ReportGenerator:
    """
    Generate professional OSINT reports using modular section generators.
    """

    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Define the professional report structure
        self.sections = [
            ("summary", self._generate_section_summary),
            ("executive", self._generate_section_executive),
            ("target_info", self._generate_section_target_info),
            ("key_findings", self._generate_section_key_findings),
            ("evidence", self._generate_section_evidence),
            ("relationships", self._generate_section_relationships),
            ("timeline", self._generate_section_timeline),
            ("risk", self._generate_section_risk),
            ("recommendations", self._generate_section_recommendations),
            ("appendix", self._generate_section_appendix),
        ]

    def generate(
        self,
        format: str,
        target: dict[str, Any],
        findings: list[dict[str, Any]],
        entities: list[dict[str, Any]] | None = None,
        relationships: list[dict[str, Any]] | None = None,
        timeline: list[dict[str, Any]] | None = None,
    ) -> str | bytes:
        """
        Assemble the report by calling each section generator.
        """
        # Pre-calculate common data
        risk = self._calculate_risk_score(findings)

        # Collect section content
        report_data = {}
        for section_id, generator in self.sections:
            report_data[section_id] = generator(
                target, findings, risk, entities, relationships, timeline
            )

        if format == "json":
            return self._assemble_json(target, report_data, risk)
        elif format == "markdown" or format == "md":
            return self._assemble_markdown(target, report_data, risk)
        elif format == "html":
            return self._assemble_html(target, report_data, risk)
        elif format == "csv":
            return self._assemble_csv(target, findings, entities, timeline)
        elif format == "pdf":
            return self._assemble_pdf(target, report_data, risk, findings, entities, timeline)
        else:
            raise ValueError(f"Unsupported format: {format}")

    # --- Section Generators ---

    def _generate_section_summary(
        self, target, findings, risk, entities, relationships, timeline
    ) -> dict[str, Any]:
        return {
            "title": "Investigation Summary",
            "content": f"Investigation conducted on {target.get('query')} resulting in {len(findings)} findings.",
            "metrics": {
                "total_findings": len(findings),
                "entities_discovered": len(entities) if entities else 0,
                "relationships_mapped": len(relationships) if relationships else 0,
            },
        }

    def _generate_section_executive(
        self, target, findings, risk, entities, relationships, timeline
    ) -> dict[str, Any]:
        now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")

        status = "MANAGEABLE"
        if risk.get("score", 0) >= 70:
            status = "SEVERE"
        elif risk.get("score", 0) >= 40:
            status = "ELEVATED"

        return {
            "title": "Executive Summary",
            "generated_at": now,
            "risk_grade": risk.get("grade", "A"),
            "risk_score": risk.get("score", 0),
            "status": status,
            "critical_count": critical,
            "high_count": high,
            "summary_text": f"The overall risk posture for {target.get('query')} is {status}.",
        }

    def _generate_section_target_info(
        self, target, findings, risk, entities, relationships, timeline
    ) -> dict[str, Any]:
        return {"title": "Target Information", "target": target}

    def _generate_section_key_findings(
        self, target, findings, risk, entities, relationships, timeline
    ) -> list[dict[str, Any]]:
        # Return top 5 most severe findings
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings, key=lambda x: severity_order.get(x.get("severity", "info").lower(), 4)
        )
        return sorted_findings[:5]

    def _generate_section_evidence(
        self, target, findings: list[dict[str, Any]], risk, entities, relationships, timeline
    ) -> list[dict[str, Any]]:
        return findings

    def _generate_section_relationships(
        self, target, findings, risk, entities, relationships, timeline
    ) -> list[dict[str, Any]]:
        return relationships or []

    def _generate_section_timeline(
        self, target, findings, risk, entities, relationships, timeline
    ) -> list[dict[str, Any]]:
        return timeline or []

    def _generate_section_risk(
        self, target, findings, risk, entities, relationships, timeline
    ) -> dict[str, Any]:
        return {
            "title": "Risk Assessment",
            "score": risk.get("score", 0),
            "grade": risk.get("grade", "A"),
            "breakdown": risk.get("breakdown", {}),
        }

    def _generate_section_recommendations(
        self, target, findings, risk, entities, relationships, timeline
    ) -> list[str]:
        recs = ["Perform regular credential rotations."]
        if any(f.get("severity") == "critical" for f in findings):
            recs.append("Immediate remediation of critical exposures required.")
        if any("leak" in f.get("category", "").lower() for f in findings):
            recs.append("Initiate password reset for all exposed accounts.")
        return recs

    def _generate_section_appendix(
        self, target, findings, risk, entities, relationships, timeline
    ) -> dict[str, Any]:
        return {
            "title": "Appendix",
            "tool_version": "Aegis OSINT AI v1.0.0",
            "methodology": "Automated plugin-based discovery and entity relationship mapping.",
        }

    # --- Assemblers ---

    def _assemble_json(self, target, report_data, risk) -> str:
        return json.dumps(
            {
                "meta": {
                    "target": target.get("query"),
                    "generated_at": datetime.now(UTC).isoformat(),
                },
                "risk": risk,
                "sections": report_data,
            },
            indent=2,
            default=str,
        )

    def _assemble_markdown(self, target, report_data, risk) -> str:
        lines = [f"# Aegis OSINT Report: {target.get('query')}", ""]

        # Executive Summary
        exec_s = report_data["executive"]
        lines.extend(
            [
                "## Executive Summary",
                f"**Status:** {exec_s['status']}",
                f"**Risk Grade:** {exec_s['risk_grade']} ({exec_s['risk_score']}/100)",
                f"**Critical Findings:** {exec_s['critical_count']}",
                "",
                exec_s["summary_text"],
                "",
            ]
        )

        # Key Findings
        lines.append("## Key Findings")
        for f in report_data["key_findings"]:
            lines.append(f"- **{f.get('source')}**: {f.get('category')} ({f.get('severity')})")
        lines.append("")

        # Timeline
        lines.append("## Investigation Timeline")
        for t in report_data["timeline"]:
            lines.append(f"- {t.get('timestamp', 'N/A')}: {t.get('description')}")
        lines.append("")

        # Relationships
        lines.append("## Entity Relationships")
        for r in report_data["relationships"]:
            lines.append(
                f"- {r.get('source_entity_id')} -> {r.get('relationship_type')} -> {r.get('target_entity_id')}"
            )
        lines.append("")

        return "\n".join(lines)

    def _assemble_html(self, target, report_data, risk) -> str:
        html = [
            "<html>",
            "<head>",
            f"<title>Report for {target.get('query')}</title>",
            "<style>body{font-family:sans-serif; margin:20px; line-height:1.6;} h1,h2{color:#333;} .risk{font-weight:bold;}</style>",
            "</head>",
            "<body>",
            f"<h1>Report for {target.get('query')}</h1>",
            f"<p class='risk'>Risk Grade: {risk.get('grade')} | Score: {risk.get('score')}/100</p>",
        ]

        exec_s = report_data["executive"]
        html.append("<h2>Executive Summary</h2>")
        html.append(f"<p>{exec_s['summary_text']}</p>")

        html.append("<h2>Key Findings</h2><ul>")
        for f in report_data["key_findings"]:
            html.append(
                f"<li><b>{f.get('source')}</b>: {f.get('category')} ({f.get('severity')})</li>"
            )
        html.append("</ul>")

        html.append("<h2>Timeline</h2><ul>")
        for t in report_data["timeline"]:
            html.append(f"<li>{t.get('timestamp', 'N/A')}: {t.get('description')}</li>")
        html.append("</ul>")

        html.append("<h2>Entity Relationships</h2><ul>")
        for r in report_data["relationships"]:
            html.append(
                f"<li>Entity {r.get('source_entity_id')} -> {r.get('relationship_type')} -> Entity {r.get('target_entity_id')}</li>"
            )
        html.append("</ul>")

        html.append("</body></html>")
        return "\n".join(html)

    def _assemble_csv(
        self,
        target: dict[str, Any],
        findings: list[dict[str, Any]],
        entities: list[dict[str, Any]] | None = None,
        timeline: list[dict[str, Any]] | None = None,
    ) -> str:
        """Generate a CSV report with findings, entities, and timeline sections."""
        output = io.StringIO()
        writer = csv.writer(output)

        # --- Target info ---
        writer.writerow(["TARGET INFORMATION"])
        writer.writerow(["Query", target.get("query", "")])
        writer.writerow(["Type", target.get("target_type", "")])
        writer.writerow(["Status", target.get("status", "")])
        writer.writerow(["Created", target.get("created_at", "")])
        writer.writerow([])

        # --- Findings ---
        writer.writerow(["FINDINGS"])
        writer.writerow(["ID", "Source", "Category", "Severity", "Confidence", "Data", "Created"])
        for f in findings:
            data_str = json.dumps(f.get("data", {}), default=str) if f.get("data") else ""
            writer.writerow(
                [
                    f.get("id", ""),
                    f.get("source", ""),
                    f.get("category", ""),
                    f.get("severity", ""),
                    f.get("confidence", ""),
                    data_str,
                    f.get("created_at", ""),
                ]
            )
        writer.writerow([])

        # --- Entities ---
        if entities:
            writer.writerow(["ENTITIES"])
            writer.writerow(["ID", "Type", "Value", "Confidence", "First Seen"])
            for e in entities:
                writer.writerow(
                    [
                        e.get("id", ""),
                        e.get("type", e.get("entity_type", "")),
                        e.get("value", ""),
                        e.get("confidence", ""),
                        e.get("first_seen", ""),
                    ]
                )
            writer.writerow([])

        # --- Timeline ---
        if timeline:
            writer.writerow(["TIMELINE"])
            writer.writerow(["ID", "Type", "Plugin", "Severity", "Description", "Timestamp"])
            for t in timeline:
                writer.writerow(
                    [
                        t.get("id", ""),
                        t.get("event_type", t.get("type", "")),
                        t.get("plugin", ""),
                        t.get("severity", ""),
                        t.get("description", ""),
                        t.get("timestamp", ""),
                    ]
                )

        return output.getvalue()

    def _assemble_pdf(
        self,
        target: dict[str, Any],
        report_data: dict[str, Any],
        risk: dict[str, Any],
        findings: list[dict[str, Any]],
        entities: list[dict[str, Any]] | None = None,
        timeline: list[dict[str, Any]] | None = None,
    ) -> bytes:
        """Generate a professional PDF report using reportlab."""
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=A4,
            leftMargin=20 * mm,
            rightMargin=20 * mm,
            topMargin=20 * mm,
            bottomMargin=20 * mm,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "CustomTitle", parent=styles["Title"], fontSize=20, textColor=colors.HexColor("#0d1322")
        )
        heading_style = ParagraphStyle(
            "CustomHeading",
            parent=styles["Heading2"],
            fontSize=14,
            textColor=colors.HexColor("#06b6d4"),
        )
        body_style = ParagraphStyle("CustomBody", parent=styles["Normal"], fontSize=10, leading=14)
        small_style = ParagraphStyle(
            "Small", parent=styles["Normal"], fontSize=8, textColor=colors.grey
        )

        story: list = []

        # --- Title ---
        story.append(Paragraph("Aegis OSINT Report", title_style))
        story.append(Spacer(1, 6 * mm))
        story.append(Paragraph(f"Target: {target.get('query', 'N/A')}", body_style))
        story.append(Paragraph(f"Type: {target.get('target_type', 'N/A')}", body_style))
        story.append(Paragraph(f"Status: {target.get('status', 'N/A')}", body_style))
        story.append(
            Paragraph(f"Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}", small_style)
        )
        story.append(Spacer(1, 8 * mm))

        # --- Executive Summary ---
        exec_s = report_data["executive"]
        story.append(Paragraph("Executive Summary", heading_style))
        story.append(Spacer(1, 3 * mm))
        story.append(Paragraph(f"<b>Status:</b> {exec_s['status']}", body_style))
        story.append(
            Paragraph(
                f"<b>Risk Grade:</b> {exec_s['risk_grade']} ({exec_s['risk_score']}/100)",
                body_style,
            )
        )
        story.append(Paragraph(f"<b>Critical Findings:</b> {exec_s['critical_count']}", body_style))
        story.append(Paragraph(exec_s["summary_text"], body_style))
        story.append(Spacer(1, 8 * mm))

        # --- Key Findings Table ---
        story.append(Paragraph("Key Findings", heading_style))
        story.append(Spacer(1, 3 * mm))

        finding_rows = [["Source", "Category", "Severity", "Confidence"]]
        for f in report_data["key_findings"]:
            conf = f.get("confidence", 0)
            conf_str = f"{conf:.0%}" if isinstance(conf, (int, float)) else str(conf)
            finding_rows.append(
                [
                    str(f.get("source", ""))[:40],
                    str(f.get("category", ""))[:30],
                    str(f.get("severity", "")),
                    conf_str,
                ]
            )

        findings_table = Table(finding_rows, colWidths=[50 * mm, 45 * mm, 30 * mm, 30 * mm])
        findings_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d1322")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#1f293d")),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#f8fafc")],
                    ),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(findings_table)
        story.append(Spacer(1, 8 * mm))

        # --- Entities Table ---
        if entities:
            story.append(Paragraph("Discovered Entities", heading_style))
            story.append(Spacer(1, 3 * mm))
            entity_rows = [["Type", "Value", "Confidence"]]
            for e in entities[:20]:
                conf = e.get("confidence", 0)
                conf_str = f"{conf:.0%}" if isinstance(conf, (int, float)) else str(conf)
                entity_rows.append(
                    [
                        str(e.get("type", e.get("entity_type", "")))[:20],
                        str(e.get("value", ""))[:50],
                        conf_str,
                    ]
                )
            entities_table = Table(entity_rows, colWidths=[35 * mm, 80 * mm, 30 * mm])
            entities_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d1322")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#1f293d")),
                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [colors.white, colors.HexColor("#f8fafc")],
                        ),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            story.append(entities_table)
            story.append(Spacer(1, 8 * mm))

        # --- Timeline ---
        if timeline:
            story.append(Paragraph("Investigation Timeline", heading_style))
            story.append(Spacer(1, 3 * mm))
            tl_rows = [["Timestamp", "Plugin", "Description"]]
            for t in timeline[:30]:
                tl_rows.append(
                    [
                        str(t.get("timestamp", ""))[:20],
                        str(t.get("plugin", ""))[:20],
                        str(t.get("description", ""))[:60],
                    ]
                )
            tl_table = Table(tl_rows, colWidths=[35 * mm, 35 * mm, 80 * mm])
            tl_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d1322")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#1f293d")),
                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [colors.white, colors.HexColor("#f8fafc")],
                        ),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            story.append(tl_table)
            story.append(Spacer(1, 8 * mm))

        # --- Recommendations ---
        story.append(Paragraph("Recommendations", heading_style))
        story.append(Spacer(1, 3 * mm))
        for rec in report_data["recommendations"]:
            story.append(Paragraph(f"&bull; {rec}", body_style))
        story.append(Spacer(1, 8 * mm))

        # --- Footer ---
        story.append(
            Paragraph("Aegis OSINT AI v1.0.0 | Automated plugin-based OSINT framework", small_style)
        )

        doc.build(story)
        pdf_bytes = buf.getvalue()
        buf.close()
        return pdf_bytes

    # --- Helpers ---

    def _calculate_risk_score(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        if not findings:
            return {"score": 0, "grade": "A", "breakdown": {}}

        SEVERITY_WEIGHTS = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
        category_scores: dict[str, float] = {}

        raw_total = 0.0

        for finding in findings:
            severity = finding.get("severity", "info").lower()
            category = finding.get("category", "osint_exposure").lower()
            score = SEVERITY_WEIGHTS.get(severity, 0)
            raw_total += score
            category_scores[category] = category_scores.get(category, 0) + score

        max_possible = len(findings) * 10 * 2.0
        normalised = min(100, round((raw_total / max_possible) * 100, 1)) if max_possible else 0
        grade_map = [(90, "F"), (70, "D"), (50, "C"), (30, "B"), (0, "A")]
        grade = next((g for threshold, g in grade_map if normalised >= threshold), "A")

        return {"score": normalised, "grade": grade, "breakdown": category_scores}
