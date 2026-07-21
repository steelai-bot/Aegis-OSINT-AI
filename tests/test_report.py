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
