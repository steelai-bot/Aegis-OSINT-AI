"""Report template contract tests."""

import base64
import json
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from backend.reports import (
    get_report_template,
    render_briefing_outline,
    render_html_report,
    render_json_report,
    render_markdown_report,
    render_pdf_report,
)


def test_default_report_template_defines_handling_notes_and_briefing_slides() -> None:
    template = get_report_template()

    assert template.name == "investigation"
    assert template.title == "Aegis Investigation Report"
    assert len(template.handling_notes) == 3
    assert "credential replay" in template.handling_notes[-1]
    assert [slide.title for slide in template.briefing_slides] == [
        "Investigation Context",
        "Risk Posture",
        "Highest-Priority Findings",
        "Source And Confidence Review",
        "Passive Next Steps",
    ]


def test_json_renderer_includes_template_metadata_and_notes() -> None:
    generated_at = datetime(2026, 6, 5, tzinfo=UTC)
    investigation = SimpleNamespace(title="Template investigation", status="pending")

    payload = json.loads(render_json_report(investigation, [], generated_at=generated_at))

    assert payload["meta"]["template"] == "investigation"
    assert payload["correlation_graph"]["summary"] == {"node_count": 0, "edge_count": 0, "finding_count": 0}
    assert payload["handling_notes"] == list(get_report_template().handling_notes)


def test_markdown_and_briefing_renderers_use_template_content() -> None:
    generated_at = datetime(2026, 6, 5, tzinfo=UTC)
    investigation = SimpleNamespace(title="Template investigation", status="pending")
    findings = [
        {
            "source": "unit-test",
            "severity": "high",
            "confidence": 0.9,
            "data": {"title": "Passive signal", "summary": "A safe template finding."},
        }
    ]

    markdown = render_markdown_report(investigation, findings, generated_at=generated_at)
    briefing = render_briefing_outline(investigation, findings, generated_at=generated_at)

    assert "# Aegis Investigation Report" in markdown
    assert get_report_template().executive_summary in markdown
    assert "Do not use this output for exploitation" in markdown
    assert "## Correlation Graph" in markdown
    assert "- Findings: 1" in markdown
    assert "# Aegis Investigation Briefing Outline" in briefing
    assert "Slide 3 - Highest-Priority Findings" in briefing
    assert "Passive signal" in briefing


def test_html_renderer_escapes_persisted_finding_content() -> None:
    generated_at = datetime(2026, 6, 5, tzinfo=UTC)
    investigation = SimpleNamespace(title="<Unsafe investigation>", status="pending")
    findings = [
        {
            "source": "unit-test",
            "severity": "high",
            "confidence": 0.9,
            "data": {"title": "<script>alert(1)</script>", "summary": "Use <b>escaped</b> content."},
        }
    ]

    html = render_html_report(investigation, findings, generated_at=generated_at)

    assert "<!doctype html>" in html
    assert "&lt;Unsafe investigation&gt;" in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "Use &lt;b&gt;escaped&lt;/b&gt; content." in html
    assert "Correlation Graph" in html
    assert "<script>alert(1)</script>" not in html


def test_pdf_renderer_returns_base64_encoded_pdf_bytes() -> None:
    generated_at = datetime(2026, 6, 5, tzinfo=UTC)
    investigation = SimpleNamespace(title="PDF investigation", status="pending")
    findings = [
        {
            "source": "unit-test",
            "severity": "medium",
            "confidence": 0.7,
            "data": {"title": "PDF passive signal", "summary": "A safe PDF finding."},
        }
    ]

    encoded_pdf = render_pdf_report(investigation, findings, generated_at=generated_at)
    pdf_bytes = base64.b64decode(encoded_pdf)

    assert pdf_bytes.startswith(b"%PDF-1.4")
    assert b"PDF investigation" in pdf_bytes
    assert b"PDF passive signal" in pdf_bytes
    assert b"Correlation Graph" in pdf_bytes
    assert b"Do not use this output for exploitation" in pdf_bytes


def test_unknown_report_template_raises_clear_error() -> None:
    with pytest.raises(ValueError, match="Unknown report template"):
        get_report_template("missing")
