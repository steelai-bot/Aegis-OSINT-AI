"""Reusable report templates for safe v2 renderers."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class BriefingSlideTemplate:
    title: str
    claim: str
    proof_object: str


@dataclass(frozen=True, slots=True)
class ReportTemplate:
    name: str
    title: str
    executive_summary: str
    handling_notes: tuple[str, ...]
    briefing_title: str
    briefing_slides: tuple[BriefingSlideTemplate, ...]


DEFAULT_HANDLING_NOTES = (
    "This report is generated from passive investigation records.",
    "Verify all findings against primary sources before action.",
    "Do not use this output for exploitation, credential replay, intrusive scanning, or unauthorized access.",
)


INVESTIGATION_REPORT_TEMPLATE = ReportTemplate(
    name="investigation",
    title="Aegis Investigation Report",
    executive_summary="This report summarizes locally persisted passive OSINT findings for analyst review.",
    handling_notes=DEFAULT_HANDLING_NOTES,
    briefing_title="Aegis Investigation Briefing Outline",
    briefing_slides=(
        BriefingSlideTemplate(
            title="Investigation Context",
            claim="{title} has a passive evidence set ready for analyst review.",
            proof_object="Investigation metadata and finding count.",
        ),
        BriefingSlideTemplate(
            title="Risk Posture",
            claim="Current severity mix defines the review queue.",
            proof_object="Severity overview across {finding_count} findings.",
        ),
        BriefingSlideTemplate(
            title="Highest-Priority Findings",
            claim="The highest-severity findings should be verified first.",
            proof_object="Findings sorted by severity.",
        ),
        BriefingSlideTemplate(
            title="Source And Confidence Review",
            claim="Sources and confidence values determine follow-up quality.",
            proof_object="Finding source labels, confidence scores, and analyst notes.",
        ),
        BriefingSlideTemplate(
            title="Passive Next Steps",
            claim="Follow-up should remain passive, documented, and authorized.",
            proof_object="Source checks, evidence preservation, and collection gaps.",
        ),
    ),
)

REPORT_TEMPLATES = {
    INVESTIGATION_REPORT_TEMPLATE.name: INVESTIGATION_REPORT_TEMPLATE,
}


def get_report_template(name: str = "investigation") -> ReportTemplate:
    """Return a named report template."""

    try:
        return REPORT_TEMPLATES[name]
    except KeyError as exc:
        raise ValueError(f"Unknown report template: {name}") from exc
