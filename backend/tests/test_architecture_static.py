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
    template_text = read("backend/reports/templates.py")
    correlation_text = read("backend/reports/correlation.py")

    assert "ReportFormat" in schema_text
    assert "RenderableReportFormat" in schema_text
    assert "ReportRenderRequest" in schema_text
    assert "ReportRenderResponse" in schema_text
    for report_format in ['"html"', '"json"', '"csv"', '"markdown"', '"briefing"', '"pdf"']:
        assert report_format in schema_text
    assert '"/investigations/{investigation_id}/reports/render"' in route_text
    assert "render_report(payload.format, investigation, findings)" in route_text
    assert "render_html_report" in package_text
    assert "render_markdown_report" in package_text
    assert "render_pdf_report" in package_text
    assert "render_json_report" in package_text
    assert "render_briefing_outline" in package_text
    assert "build_finding_correlation_graph" in package_text
    assert "get_report_template" in package_text
    assert "render_report" in package_text
    assert "class ReportTemplate" in template_text
    assert "INVESTIGATION_REPORT_TEMPLATE" in template_text
    assert "DEFAULT_HANDLING_NOTES" in template_text
    assert "def build_finding_correlation_graph" in correlation_text
    assert "ENTITY_KEYS" in correlation_text
    assert "def render_markdown_report" in renderer_text
    assert "def render_html_report" in renderer_text
    assert "def render_json_report" in renderer_text
    assert "def render_briefing_outline" in renderer_text
    assert "def render_pdf_report" in renderer_text
    assert "base64.b64encode" in renderer_text
    assert "def render_report" in renderer_text
    assert "get_report_template(template_name)" in renderer_text
    assert "correlation_graph" in renderer_text
    assert "Unsupported v2 report renderer format" in renderer_text
    assert "Do not use this output for exploitation" in template_text


def test_finding_correlation_graph_tests_exist() -> None:
    test_text = read("backend/tests/test_correlation_graph.py")

    assert "test_finding_correlation_graph_links_findings_sources_severity_types_and_entities" in test_text
    assert "test_empty_finding_correlation_graph_is_stable" in test_text


def test_readme_documents_v2_render_api_contract() -> None:
    text = read("README.md")

    assert "### v2 Render API" in text
    assert "POST /investigations/{investigation_id}/reports/render" in text
    assert '{ "format": "markdown" }' in text
    assert "Supported render formats are `html`, `json`, `markdown`, `briefing`, and `pdf`." in text
    assert "PDF render responses return base64-encoded PDF bytes" in text
    assert "`csv` remains a report record format" in text


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


def test_phase_two_api_integration_tests_exist() -> None:
    test_text = read("backend/tests/test_api_integration.py")
    requirements_text = read("requirements.txt")

    assert "ASGITransport" in test_text
    assert "sqlite+aiosqlite://" in test_text
    assert "app.dependency_overrides[get_db_session]" in test_text
    assert "test_investigation_target_finding_and_report_flow" in test_text
    assert "aiosqlite>=0.20.0" in requirements_text


def test_agent_persistence_models_and_workflow_exist() -> None:
    models_text = read("backend/models/__init__.py")
    context_model_text = read("backend/models/agent_context.py")
    task_model_text = read("backend/models/agent_task_result.py")
    service_text = read("backend/services/agent_persistence.py")
    engine_text = read("backend/services/investigation_engine.py")
    route_text = read("backend/api/routes/agents.py")
    migration_text = read("alembic/versions/0002_agent_persistence.py")
    integration_test_text = read("backend/tests/test_api_integration.py")

    assert "AgentContextSnapshot" in models_text
    assert "AgentTaskResult" in models_text
    assert "class AgentContextSnapshot" in context_model_text
    assert "class AgentTaskResult" in task_model_text
    assert "class AgentPersistenceService" in service_text
    assert "create_context_snapshot" in service_text
    assert "create_task_result" in service_text
    assert "AgentPersistenceService(session)" in engine_text
    assert "task_result_id" in engine_text
    assert "InvestigationEngine(session=session)" in route_text
    assert "agent_context_snapshots" in migration_text
    assert "agent_task_results" in migration_text
    assert "test_agent_run_persists_task_result_metadata" in integration_test_text


def test_event_driven_agent_workflow_and_unit_tests_exist() -> None:
    engine_text = read("backend/services/investigation_engine.py")
    architecture_text = read("ARCHITECTURE.md")
    unit_test_text = read("backend/tests/test_agents_unit.py")

    assert "class WorkflowStep" in engine_text
    assert "workflow.started" in engine_text
    assert "workflow.step.ready" in engine_text
    assert "workflow.step.completed" in engine_text
    assert "workflow.completed" in engine_text
    assert "missing_dependencies" in engine_text
    assert "workflow.step.ready" in architecture_text
    assert "test_base_agent_publishes_lifecycle_events" in unit_test_text
    assert "test_investigation_engine_emits_workflow_events_in_agent_order" in unit_test_text


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


def test_plugin_configuration_tests_exist() -> None:
    registry_text = read("backend/plugins/registry.py")
    test_text = read("backend/tests/test_plugins_configuration.py")

    assert "enabled_plugin_names" in registry_text
    assert "disabled_plugin_names" in registry_text
    assert "plugin_configs" in registry_text
    assert "def is_enabled" in registry_text
    assert "test_plugin_registry_filters_and_injects_plugin_config" in test_text
    assert "test_api_backed_plugins_skip_without_required_api_keys" in test_text


def test_tool_execution_layer_contract_exists() -> None:
    base_text = read("backend/plugins/base.py")
    app_text = read("backend/api/app.py")
    service_text = read("backend/services/tool_execution.py")
    audit_service_text = read("backend/services/audit.py")
    audit_route_text = read("backend/api/routes/audit.py")
    audit_schema_text = read("backend/api/schemas/audit.py")
    approval_service_text = read("backend/services/tool_execution_approvals.py")
    approval_route_text = read("backend/api/routes/tool_execution_approvals.py")
    approval_schema_text = read("backend/api/schemas/tool_execution_approvals.py")
    approval_model_text = read("backend/models/tool_execution_approval.py")
    approval_migration_text = read("alembic/versions/0006_tool_execution_approvals.py")
    orchestrator_text = read("backend/services/collection_orchestrator.py")
    schema_text = read("backend/api/schemas/collections.py")
    docs_text = read("docs/tool_execution_layer.md")

    assert "execution_mode" in base_text
    assert "requires_approval" in base_text
    assert "class ToolExecutionController" in service_text
    assert "class InMemoryRateLimiter" in service_text
    assert "ToolExecutionApprovalService" in service_text
    assert "audit.router" in app_text
    assert "list_events" in audit_service_text
    assert '"/audit/events"' in audit_route_text
    assert "event_type_prefix" in audit_route_text
    assert "AuditEventRead" in audit_schema_text
    assert "class ToolExecutionApproval" in approval_model_text
    assert "tool_execution_approvals" in approval_migration_text
    assert "class ToolExecutionApprovalService" in approval_service_text
    assert "consume_approval" in approval_service_text
    assert '"/tool-execution/approvals"' in approval_route_text
    assert "ToolExecutionApprovalCreate" in approval_schema_text
    assert "tool.execution.decision" in service_text
    assert "ToolExecutionController" in orchestrator_text
    assert "tool.execution.completed" in orchestrator_text
    assert "tool.execution.failed" in orchestrator_text
    assert "approval_token" in schema_text
    assert "AEGIS_TOOL_EXECUTION_MODE" in docs_text
