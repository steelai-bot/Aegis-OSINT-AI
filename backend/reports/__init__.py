"""Report generation package."""

from backend.reports.correlation import build_finding_correlation_graph
from backend.reports.renderers import (
    render_briefing_outline,
    render_html_report,
    render_json_report,
    render_markdown_report,
    render_pdf_report,
    render_report,
)
from backend.reports.templates import BriefingSlideTemplate, ReportTemplate, get_report_template

__all__ = [
    "BriefingSlideTemplate",
    "ReportTemplate",
    "build_finding_correlation_graph",
    "get_report_template",
    "render_briefing_outline",
    "render_html_report",
    "render_json_report",
    "render_markdown_report",
    "render_pdf_report",
    "render_report",
]
