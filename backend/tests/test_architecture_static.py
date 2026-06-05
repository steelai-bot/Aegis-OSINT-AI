"""Static architectural contract tests for the migration foundation."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text()


def test_required_planning_documents_exist() -> None:
    for path in ["ARCHITECTURE.md", "MIGRATION_PLAN.md", "TODO.md"]:
        assert (ROOT / path).is_file(), f"{path} must exist before migration work"


def test_agent_contract_documents_no_direct_agent_calls() -> None:
    text = read("ARCHITECTURE.md")
    assert "Agents must never call other agents directly" in text
    assert "investigation context" in text
    assert "event bus" in text


def test_backend_foundation_files_exist() -> None:
    expected = [
        "backend/api/app.py",
        "backend/api/routes/health.py",
        "backend/core/config.py",
        "backend/core/events.py",
        "backend/core/http.py",
        "backend/agents/base.py",
        "backend/plugins/base.py",
        "backend/providers/base.py",
        "backend/storage/database.py",
        "alembic/versions/0001_initial_schema.py",
    ]
    missing = [path for path in expected if not (ROOT / path).is_file()]
    assert not missing


def test_v2_http_client_keeps_tls_verification_enabled() -> None:
    text = read("backend/core/http.py")
    assert "verify=True" in text
    assert "verify=False" not in text


def test_required_agent_classes_exist() -> None:
    files = {
        "backend/agents/recon.py": "class ReconAgent",
        "backend/agents/domain.py": "class DomainAgent",
        "backend/agents/email.py": "class EmailAgent",
        "backend/agents/social.py": "class SocialAgent",
        "backend/agents/breach.py": "class BreachAgent",
        "backend/agents/threat_intel.py": "class ThreatIntelAgent",
        "backend/agents/report.py": "class ReportAgent",
    }
    for path, marker in files.items():
        assert marker in read(path)


def test_provider_specific_logic_stays_in_provider_package() -> None:
    allowed = {"backend/providers/factory.py", "backend/core/config.py"}
    vendor_terms = ["OpenAI", "Anthropic", "Gemini", "Ollama"]
    violations: list[str] = []
    for path in (ROOT / "backend").rglob("*.py"):
        rel = path.relative_to(ROOT).as_posix()
        if rel.startswith("backend/providers/") or rel.startswith("backend/tests/") or rel in allowed:
            continue
        text = path.read_text()
        if any(term in text for term in vendor_terms):
            violations.append(rel)
    assert not violations


def test_phase_two_api_routes_exist() -> None:
    app_text = read("backend/api/app.py")
    for module_name in ["investigations", "targets", "findings", "reports", "agents"]:
        assert module_name in app_text

    route_markers = {
        "backend/api/routes/investigations.py": ["/investigations", "InvestigationService"],
        "backend/api/routes/targets.py": ["/targets", "TargetService"],
        "backend/api/routes/findings.py": ["/findings", "FindingService"],
        "backend/api/routes/reports.py": ["/reports", "ReportService"],
        "backend/api/routes/agents.py": ["/agents/run", "InvestigationEngine"],
    }
    for path, markers in route_markers.items():
        content = read(path)
        for marker in markers:
            assert marker in content


def test_initial_plugin_modules_exist() -> None:
    plugin_files = {
        "backend/plugins/whois.py": "class WhoisPlugin",
        "backend/plugins/dns.py": "class DnsPlugin",
        "backend/plugins/crtsh.py": "class CrtShPlugin",
        "backend/plugins/shodan.py": "class ShodanPlugin",
        "backend/plugins/virustotal.py": "class VirusTotalPlugin",
        "backend/plugins/securitytrails.py": "class SecurityTrailsPlugin",
        "backend/plugins/hibp.py": "class HaveIBeenPwnedPlugin",
    }
    for path, marker in plugin_files.items():
        assert marker in read(path)
