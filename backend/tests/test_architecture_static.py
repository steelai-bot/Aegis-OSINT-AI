"""Static architectural contract tests for the migration foundation."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_required_planning_documents_exist() -> None:
    for path in ["ARCHITECTURE.md", "MIGRATION_PLAN.md", "TODO.md"]:
        assert (ROOT / path).is_file(), f"{path} must exist before migration work"


def test_phase_zero_guardrails_isolate_prohibited_legacy_runtime() -> None:
    prohibited_scripts = [
        "advanced_exploits.py",
        "credential_parser.py",
        "darkweb_crawler.py",
        "eni_signature.py",
        "exploit_scanner.py",
        "infostealer_parser.py",
        "leaked_db_hunter.py",
        "orchestrator.py",
        "pivot_chain.py",
        "pre_exploit.py",
        "session_hijacker.py",
        "sneaky_recon.py",
        "telegram_monitor.py",
        "tui.py",
    ]

    for filename in prohibited_scripts:
        assert not (ROOT / "scripts" / filename).exists()
        assert (ROOT / "legacy" / "quarantine" / filename).is_file()

    assert not (ROOT / "references" / "exploit_payloads.md").exists()
    assert (ROOT / "legacy" / "quarantine" / "references" / "exploit_payloads.md").is_file()

    readme_text = read("README.md").lower()
    skill_text = read("SKILL.md").lower()
    setup_text = read("setup_wizard.py").lower()
    for text in [readme_text, skill_text, setup_text]:
        assert "scripts/orchestrator.py" not in text
        assert "--modules exploit" not in text
        assert "red team operations" not in text
        assert "credential replay" in text or "quarantine" in text


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
    vendor_terms = ["OpenAI", "Anthropic", "Gemini", "HuggingFace", "Hugging Face", "Ollama"]
    violations: list[str] = []
    for path in (ROOT / "backend").rglob("*.py"):
        rel = path.relative_to(ROOT).as_posix()
        if rel.startswith("backend/providers/") or rel.startswith("backend/tests/") or rel in allowed:
            continue
        text = path.read_text(encoding="utf-8")
        if any(term in text for term in vendor_terms):
            violations.append(rel)
    assert not violations


def test_huggingface_provider_is_registered() -> None:
    config_text = read("backend/core/config.py")
    factory_text = read("backend/providers/factory.py")
    provider_text = read("backend/providers/huggingface.py")

    assert '"huggingface"' in config_text
    assert "huggingface_api_key" in config_text
    assert 'settings.llm_provider == "huggingface"' in factory_text
    assert "class HuggingFaceProvider" in provider_text
    assert "https://router.huggingface.co/v1/chat/completions" in provider_text


def test_llm_provider_factory_routes_all_configured_providers() -> None:
    config_text = read("backend/core/config.py")
    factory_text = read("backend/providers/factory.py")
    providers = {
        "openai": ("backend/providers/openai.py", "class OpenAIProvider"),
        "anthropic": ("backend/providers/anthropic.py", "class AnthropicProvider"),
        "gemini": ("backend/providers/gemini.py", "class GeminiProvider"),
        "huggingface": ("backend/providers/huggingface.py", "class HuggingFaceProvider"),
        "ollama": ("backend/providers/ollama.py", "class OllamaProvider"),
    }

    for provider, (path, class_marker) in providers.items():
        assert f'"{provider}"' in config_text
        assert f'settings.llm_provider == "{provider}"' in factory_text
        assert class_marker in read(path)


def test_report_generator_outputs_document_and_briefing_formats() -> None:
    text = read("scripts/report_generator.py")
    assert "def export_markdown" in text
    assert "def export_briefing_outline" in text
    assert '"markdown": markdown_path' in text
    assert '"briefing": briefing_path' in text
    assert "_briefing.md" in text


def test_v2_markdown_report_renderer_exists() -> None:
    schema_text = read("backend/api/schemas/reports.py")
    route_text = read("backend/api/routes/reports.py")
    package_text = read("backend/reports/__init__.py")
    renderer_text = read("backend/reports/renderers.py")

    assert "ReportFormat" in schema_text
    assert "RenderableReportFormat" in schema_text
    assert "ReportRenderRequest" in schema_text
    assert "ReportRenderResponse" in schema_text
    for report_format in ['"html"', '"json"', '"csv"', '"markdown"', '"briefing"', '"pdf"']:
        assert report_format in schema_text
    assert '"/investigations/{investigation_id}/reports/render"' in route_text
    assert "render_report(payload.format, investigation, findings)" in route_text
    assert "render_markdown_report" in package_text
    assert "render_json_report" in package_text
    assert "render_briefing_outline" in package_text
    assert "render_report" in package_text
    assert "def render_markdown_report" in renderer_text
    assert "def render_json_report" in renderer_text
    assert "def render_briefing_outline" in renderer_text
    assert "def render_report" in renderer_text
    assert "Unsupported v2 report renderer format" in renderer_text
    assert "Do not use this output for exploitation" in renderer_text


def test_readme_documents_v2_render_api_contract() -> None:
    text = read("README.md")

    assert "### v2 Render API" in text
    assert "POST /investigations/{investigation_id}/reports/render" in text
    assert '{ "format": "markdown" }' in text
    assert "Supported render formats are `json`, `markdown`, and `briefing`." in text
    assert "`html`, `csv`, and `pdf` remain report record formats" in text


def test_kali_compatibility_registry_exists() -> None:
    registry_text = read("backend/core/kali_tools.py")
    cli_text = read("scripts/kali_compatibility.py")
    docs_text = read("docs/kali_compatibility.md")
    readme_text = read("README.md")
    architecture_text = read("ARCHITECTURE.md")

    assert 'KALI_MIN_VERSION = "2026.1"' in registry_text
    assert "KALI_RECENT_TOOLS" in registry_text
    assert "detect_kali" in registry_text
    assert "inspect_recent_kali_tools" in registry_text
    assert "apt_install_command" in registry_text
    assert "https://www.kali.org/blog/kali-linux-2026-1-release/" in registry_text
    assert "https://www.kali.org/blog/kali-linux-2025-4-release/" in registry_text
    for package in [
        "adaptixc2",
        "atomic-operator",
        "fluxion",
        "gef",
        "metasploit-mcp",
        "sstimap",
        "wpprobe",
        "xsstrike",
        "bpf-linker",
        "evil-winrm-py",
        "hexstrike-ai",
    ]:
        assert package in registry_text
        assert package in docs_text

    assert "build_report" in cli_text
    assert "python3 scripts/kali_compatibility.py --json" in docs_text
    assert "Kali Linux 2026.1+" in readme_text
    assert "Kali Tool Compatibility" in architecture_text


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
