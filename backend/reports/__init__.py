"""Report generation package."""

from backend.reports.renderers import render_briefing_outline, render_json_report, render_markdown_report, render_report
from backend.reports.templates import BriefingSlideTemplate, ReportTemplate, get_report_template

__all__ = [
    "BriefingSlideTemplate",
    "ReportTemplate",
    "get_report_template",
    "render_briefing_outline",
    "render_json_report",
    "render_markdown_report",
    "render_report",
]
