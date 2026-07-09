"""
Report Generation Module
Handles HTML, JSON, and Markdown report generation with a modular section-based architecture.
"""

import json
from datetime import datetime, timezone
from typing import Dict, List, Any, Callable
from pathlib import Path

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

    def generate(self, format: str, target: Dict[str, Any], findings: List[Dict[str, Any]], 
                 entities: List[Dict[str, Any]] = None, relationships: List[Dict[str, Any]] = None, 
                 timeline: List[Dict[str, Any]] = None) -> str:
        """
        Assemble the report by calling each section generator.
        """
        # Pre-calculate common data
        risk = self._calculate_risk_score(findings)
        
        # Collect section content
        report_data = {}
        for section_id, generator in self.sections:
            report_data[section_id] = generator(target, findings, risk, entities, relationships, timeline)

        if format == "json":
            return self._assemble_json(target, report_data, risk)
        elif format == "markdown" or format == "md":
            return self._assemble_markdown(target, report_data, risk)
        elif format == "html":
            return self._assemble_html(target, report_data, risk)
        else:
            raise ValueError(f"Unsupported format: {format}")

    # --- Section Generators ---

    def _generate_section_summary(self, target, findings, risk, entities, relationships, timeline) -> Dict[str, Any]:
        return {
            "title": "Investigation Summary",
            "content": f"Investigation conducted on {target.get('query')} resulting in {len(findings)} findings.",
            "metrics": {
                "total_findings": len(findings),
                "entities_discovered": len(entities) if entities else 0,
                "relationships_mapped": len(relationships) if relationships else 0
            }
        }

    def _generate_section_executive(self, target, findings, risk, entities, relationships, timeline) -> Dict[str, Any]:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        
        status = "MANAGEABLE"
        if risk.get("score", 0) >= 70: status = "SEVERE"
        elif risk.get("score", 0) >= 40: status = "ELEVATED"

        return {
            "title": "Executive Summary",
            "generated_at": now,
            "risk_grade": risk.get("grade", "A"),
            "risk_score": risk.get("score", 0),
            "status": status,
            "critical_count": critical,
            "high_count": high,
            "summary_text": f"The overall risk posture for {target.get('query')} is {status}."
        }

    def _generate_section_target_info(self, target, findings, risk, entities, relationships, timeline) -> Dict[str, Any]:
        return {
            "title": "Target Information",
            "target": target
        }

    def _generate_section_key_findings(self, target, findings, risk, entities, relationships, timeline) -> List[Dict[str, Any]]:
        # Return top 5 most severe findings
        sorted_findings = sorted(findings, key=lambda x: x.get("severity", "info") == "critical", reverse=True)
        return sorted_findings[:5]

    def _generate_section_evidence(self, target, findings, risk, entities, relationships, timeline) -> List[Dict[str, Any]]:
        return findings

    def _generate_section_relationships(self, target, findings, risk, entities, relationships, timeline) -> List[Dict[str, Any]]:
        return relationships or []

    def _generate_section_timeline(self, target, findings, risk, entities, relationships, timeline) -> List[Dict[str, Any]]:
        return timeline or []

    def _generate_section_risk(self, target, findings, risk, entities, relationships, timeline) -> Dict[str, Any]:
        return {
            "title": "Risk Assessment",
            "score": risk.get("score", 0),
            "grade": risk.get("grade", "A"),
            "breakdown": risk.get("breakdown", {})
        }

    def _generate_section_recommendations(self, target, findings, risk, entities, relationships, timeline) -> List[str]:
        recs = ["Perform regular credential rotations."]
        if any(f.get("severity") == "critical" for f in findings):
            recs.append("Immediate remediation of critical exposures required.")
        if any("leak" in f.get("category", "").lower() for f in findings):
            recs.append("Initiate password reset for all exposed accounts.")
        return recs

    def _generate_section_appendix(self, target, findings, risk, entities, relationships, timeline) -> Dict[str, Any]:
        return {
            "title": "Appendix",
            "tool_version": "Aegis OSINT AI v1.0.0",
            "methodology": "Automated plugin-based discovery and entity relationship mapping."
        }

    # --- Assemblers ---

    def _assemble_json(self, target, report_data, risk) -> str:
        return json.dumps({
            "meta": {"target": target.get("query"), "generated_at": datetime.now(timezone.utc).isoformat()},
            "risk": risk,
            "sections": report_data
        }, indent=2, default=str)

    def _assemble_markdown(self, target, report_data, risk) -> str:
        lines = [f"# Aegis OSINT Report: {target.get('query')}", ""]
        
        # Executive Summary
        exec_s = report_data["executive"]
        lines.extend([
            "## Executive Summary",
            f"**Status:** {exec_s['status']}",
            f"**Risk Grade:** {exec_s['risk_grade']} ({exec_s['risk_score']}/100)",
            f"**Critical Findings:** {exec_s['critical_count']}",
            f"",
            exec_s['summary_text'],
            ""
        ])

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
            lines.append(f"- {r.get('source_entity_id')} -> {r.get('relationship_type')} -> {r.get('target_entity_id')}")
        lines.append("")

        return "\n".join(lines)

    def _assemble_html(self, target, report_data, risk) -> str:
        # Simplified HTML assembly for MVP
        return f"<html><body><h1>Report for {target.get('query')}</h1><p>Risk Score: {risk.get('score')}</p></body></html>"

    # --- Helpers ---

    def _calculate_risk_score(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not findings:
            return {"score": 0, "grade": "A", "breakdown": {}}
        
        SEVERITY_WEIGHTS = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
        category_scores = {}
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