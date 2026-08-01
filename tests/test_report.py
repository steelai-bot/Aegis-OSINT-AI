from backend.report import ReportGenerator


def test_report_generation():
    rg = ReportGenerator("data/reports")
    target = {"query": "example.com", "target_type": "domain"}
    findings = [{"severity": "high", "category": "exposure", "source": "test"}]

    html = rg.generate("html", target, findings)
    assert "example.com" in html
    assert "Report for" in html
    assert "Executive Summary" in html
    assert "Risk Grade" in html

    json_report = rg.generate("json", target, findings)
    assert "example.com" in json_report


def test_csv_generation():
    """CSV export contains target info, a findings section, and entities/timeline sections."""
    rg = ReportGenerator("data/reports")
    target = {"query": "example.com", "target_type": "domain", "status": "completed"}
    findings = [
        {
            "id": 1,
            "source": "breach_check",
            "category": "breach",
            "severity": "high",
            "confidence": 0.9,
            "data": {"breach": "TestBreach", "email": "user@example.com"},
            "created_at": "2026-01-01 00:00:00",
        }
    ]
    entities = [{"id": 1, "type": "email", "value": "user@example.com", "confidence": 0.9}]
    timeline = [
        {
            "id": 1,
            "event_type": "info",
            "plugin": "breach_check",
            "severity": "info",
            "description": "Scanned breach",
            "timestamp": "2026-01-01 00:00:00",
        }
    ]

    csv = rg.generate("csv", target, findings, entities, timeline=timeline)
    assert "TARGET INFORMATION" in csv
    assert "FINDINGS" in csv
    assert "ENTITIES" in csv
    assert "TIMELINE" in csv
    assert "breach_check" in csv
    assert "TestBreach" in csv
    assert "user@example.com" in csv


def test_csv_empty_findings():
    """CSV export works with no findings (no crash, no sections for entities/timeline)."""
    rg = ReportGenerator("data/reports")
    target = {"query": "example.com", "target_type": "domain"}
    csv = rg.generate("csv", target, [])
    assert "TARGET INFORMATION" in csv
    assert "example.com" in csv
    assert "FINDINGS" in csv


def test_pdf_generation():
    """PDF export produces a valid PDF byte stream (starts with %PDF-)."""
    rg = ReportGenerator("data/reports")
    target = {"query": "example.com", "target_type": "domain", "status": "completed"}
    findings = [
        {
            "source": "breach_check",
            "category": "breach",
            "severity": "critical",
            "confidence": 0.9,
            "data": {"breach": "TestBreach"},
        }
    ]
    entities = [{"id": 1, "type": "email", "value": "user@example.com", "confidence": 0.9}]
    timeline = [
        {
            "id": 1,
            "event_type": "info",
            "plugin": "breach_check",
            "severity": "info",
            "description": "Scanned breach",
            "timestamp": "2026-01-01 00:00:00",
        }
    ]

    pdf = rg.generate("pdf", target, findings, entities, timeline=timeline)
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 1000


def test_pdf_empty_findings():
    """PDF export works even with no findings."""
    rg = ReportGenerator("data/reports")
    target = {"query": "example.com", "target_type": "domain"}
    pdf = rg.generate("pdf", target, [])
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF-")
