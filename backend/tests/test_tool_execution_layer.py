"""Tool execution policy, approval, rate-limit, and orchestration tests."""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

import backend.api.routes._audit as route_audit
from backend.api.app import create_app
from backend.core.config import Settings
from backend.core.events import EventBus, event_bus
from backend.models import AuditEvent, ToolExecutionApproval, ToolExecutionRateLimitBucket
from backend.models.base import Base
from backend.plugins.base import BasePlugin, PluginResult
from backend.plugins.registry import PluginRegistry
from backend.services.collection_orchestrator import CollectionJob, CollectionOrchestrator
from backend.services.audit import AuditEventService
from backend.services.egress_audit import EgressAuditSubscriber
from backend.services.tool_execution import InMemoryRateLimiter, ToolExecutionController
from backend.services.tool_execution_approvals import ToolExecutionApprovalService
from backend.storage.database import get_db_session


class PassiveToolPlugin(BasePlugin):
    name = "passive_tool"
    indicator_types = ("domain",)

    async def execute(self, target: str, context: dict | None = None) -> PluginResult:
        return PluginResult(plugin_name=self.name, status="completed", findings=[])


class OperatorToolPlugin(BasePlugin):
    name = "operator_tool"
    indicator_types = ("domain",)
    execution_mode = "operator_assisted"

    async def execute(self, target: str, context: dict | None = None) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            status="completed",
            findings=[{"source": self.name, "type": "tool.test", "value": target, "confidence": 0.9}],
        )


class MustNotRunOperatorToolPlugin(OperatorToolPlugin):
    name = "blocked_operator_tool"

    async def execute(self, target: str, context: dict | None = None) -> PluginResult:
        raise AssertionError("blocked tools must not execute")


class EgressPublishingPlugin(BasePlugin):
    name = "egress_plugin"
    indicator_types = ("domain",)

    async def execute(self, target: str, context: dict | None = None) -> PluginResult:
        assert self.event_bus is not None
        await self.event_bus.publish(
            "tool.execution.egress",
            {
                "egress_policy_status": "allowed",
                "egress_policy_reason": "egress_policy_allowed",
                "egress_plugin_name": self.name,
                "egress_scheme": "https",
                "egress_host": "api.example.test",
                "egress_matched_rule": "api.example.test",
                "raw_url": f"https://api.example.test/search?q={target}",
                "authorization_header": "Bearer secret-token",
            },
        )
        return PluginResult(plugin_name=self.name, status="completed", findings=[])


@pytest_asyncio.fixture
async def approval_session() -> AsyncSession:
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async with engine.begin() as connection:
        await connection.run_sync(
            Base.metadata.create_all,
            tables=[ToolExecutionApproval.__table__, AuditEvent.__table__, ToolExecutionRateLimitBucket.__table__],
        )

    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest_asyncio.fixture
async def approval_client() -> AsyncClient:
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async with engine.begin() as connection:
        await connection.run_sync(
            Base.metadata.create_all,
            tables=[ToolExecutionApproval.__table__, AuditEvent.__table__, ToolExecutionRateLimitBucket.__table__],
        )

    async def override_db_session():
        async with session_factory() as session:
            yield session

    original_audit_session_local = route_audit.AsyncSessionLocal
    route_audit.AsyncSessionLocal = session_factory
    app = create_app()
    app.dependency_overrides[get_db_session] = override_db_session
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as test_client:
            yield test_client
    finally:
        route_audit.AsyncSessionLocal = original_audit_session_local
        app.dependency_overrides.clear()
        await engine.dispose()


@pytest.mark.asyncio
async def test_passive_tool_is_allowed_by_default_policy() -> None:
    controller = ToolExecutionController(settings=Settings(), rate_limiter=InMemoryRateLimiter())

    decision = await controller.authorize(plugin=PassiveToolPlugin(), target="example.com", target_type="domain")

    assert decision.allowed
    assert decision.status == "allowed"
    assert decision.requested_mode == "passive"
    assert decision.plugin_mode == "passive"


@pytest.mark.asyncio
async def test_operator_tool_requires_runtime_mode_and_approval_token() -> None:
    controller = ToolExecutionController(
        settings=Settings(tool_execution_mode="operator_assisted", tool_execution_approval_token="approve"),
        rate_limiter=InMemoryRateLimiter(),
    )

    missing_approval = await controller.authorize(
        plugin=OperatorToolPlugin(), target="example.com", target_type="domain"
    )
    approved = await controller.authorize(
        plugin=OperatorToolPlugin(), target="example.com", target_type="domain", approval_token="approve"
    )

    assert missing_approval.status == "approval_required"
    assert approved.allowed
    assert approved.requires_approval


@pytest.mark.asyncio
async def test_request_mode_cannot_escalate_above_configured_runtime_mode() -> None:
    controller = ToolExecutionController(
        settings=Settings(tool_execution_mode="passive", tool_execution_approval_token="approve"),
        rate_limiter=InMemoryRateLimiter(),
    )

    decision = await controller.authorize(
        plugin=OperatorToolPlugin(),
        target="example.com",
        target_type="domain",
        requested_mode="operator_assisted",
        approval_token="approve",
    )

    assert decision.status == "blocked"
    assert decision.reason == "runtime_mode_too_restrictive"
    assert decision.requested_mode == "passive"


@pytest.mark.asyncio
async def test_tool_execution_rate_limit_blocks_repeated_attempts() -> None:
    controller = ToolExecutionController(
        settings=Settings(tool_execution_rate_limit_per_minute=1),
        rate_limiter=InMemoryRateLimiter(),
    )

    first = await controller.authorize(plugin=PassiveToolPlugin(), target="example.com", target_type="domain")
    second = await controller.authorize(plugin=PassiveToolPlugin(), target="example.com", target_type="domain")

    assert first.allowed
    assert second.status == "rate_limited"
    assert second.reason == "rate_limit_exceeded"
    assert second.metadata["rate_limit_backend"] == "memory"


@pytest.mark.asyncio
async def test_database_rate_limiter_blocks_across_controller_instances(approval_session: AsyncSession) -> None:
    settings = Settings(tool_execution_rate_limit_per_minute=1, tool_execution_rate_limit_backend="database")
    first_controller = ToolExecutionController(settings=settings, audit_session=approval_session)
    second_controller = ToolExecutionController(settings=settings, audit_session=approval_session)

    first = await first_controller.authorize(plugin=PassiveToolPlugin(), target="example.com", target_type="domain")
    second = await second_controller.authorize(plugin=PassiveToolPlugin(), target="example.com", target_type="domain")

    assert first.allowed
    assert first.metadata["rate_limit_backend"] == "database"
    assert second.status == "rate_limited"
    assert second.metadata["rate_limit_backend"] == "database"


@pytest.mark.asyncio
async def test_database_rate_limiter_falls_back_to_memory_on_failure(approval_session: AsyncSession) -> None:
    class BrokenDatabaseRateLimiter:
        async def allow(self, key: str, *, limit: int, window_seconds: int = 60) -> bool:
            raise RuntimeError("simulated database limiter outage")

    controller = ToolExecutionController(
        settings=Settings(tool_execution_rate_limit_per_minute=1, tool_execution_rate_limit_backend="database"),
        rate_limiter=InMemoryRateLimiter(),
        database_rate_limiter=BrokenDatabaseRateLimiter(),  # type: ignore[arg-type]
        audit_session=approval_session,
    )

    first = await controller.authorize(plugin=PassiveToolPlugin(), target="example.com", target_type="domain")
    second = await controller.authorize(plugin=PassiveToolPlugin(), target="example.com", target_type="domain")

    assert first.allowed
    assert first.metadata["rate_limit_backend"] == "memory_fallback"
    assert second.status == "rate_limited"
    assert second.metadata["rate_limit_backend"] == "memory_fallback"


@pytest.mark.asyncio
async def test_database_rate_limiter_without_session_uses_memory_fallback() -> None:
    controller = ToolExecutionController(
        settings=Settings(tool_execution_rate_limit_per_minute=1, tool_execution_rate_limit_backend="database"),
        rate_limiter=InMemoryRateLimiter(),
    )

    first = await controller.authorize(plugin=PassiveToolPlugin(), target="example.com", target_type="domain")
    second = await controller.authorize(plugin=PassiveToolPlugin(), target="example.com", target_type="domain")

    assert first.allowed
    assert first.metadata["rate_limit_backend"] == "memory_fallback"
    assert second.status == "rate_limited"
    assert second.metadata["rate_limit_backend"] == "memory_fallback"


@pytest.mark.asyncio
async def test_orchestrator_blocks_operator_tool_before_plugin_execute() -> None:
    orchestrator = CollectionOrchestrator(
        registry=PluginRegistry([MustNotRunOperatorToolPlugin]),
        tool_execution=ToolExecutionController(settings=Settings(), rate_limiter=InMemoryRateLimiter()),
    )

    result = await orchestrator.run_job(CollectionJob(target="example.com", target_type="domain"))

    assert result.plugin_results[0].plugin_name == "blocked_operator_tool"
    assert result.plugin_results[0].status == "blocked"
    assert result.plugin_results[0].metadata["policy_reason"] == "runtime_mode_too_restrictive"
    assert result.findings == []


@pytest.mark.asyncio
async def test_orchestrator_runs_operator_tool_with_mode_and_approval() -> None:
    orchestrator = CollectionOrchestrator(
        registry=PluginRegistry([OperatorToolPlugin]),
        tool_execution=ToolExecutionController(
            settings=Settings(tool_execution_mode="operator_assisted", tool_execution_approval_token="approve"),
            rate_limiter=InMemoryRateLimiter(),
        ),
    )

    result = await orchestrator.run_job(
        CollectionJob(
            target="example.com",
            target_type="domain",
            execution_mode="operator_assisted",
            approval_token="approve",
            authorized_scope="unit-test",
        )
    )

    assert result.plugin_results[0].status == "completed"
    assert len(result.findings) == 1
    assert result.findings[0]["collector_plugin"] == "operator_tool"


@pytest.mark.asyncio
async def test_egress_audit_subscriber_persists_sanitized_events(approval_session: AsyncSession) -> None:
    bus = EventBus()
    subscriber = EgressAuditSubscriber(approval_session)
    subscriber.subscribe(bus)

    await bus.publish(
        "tool.execution.egress",
        {
            "egress_policy_status": "blocked",
            "egress_policy_reason": "host_not_in_plugin_allowlist",
            "egress_plugin_name": "unit_plugin",
            "egress_scheme": "https",
            "egress_host": "blocked.example",
            "egress_matched_rule": None,
            "raw_url": "https://blocked.example/path?token=secret",
            "token": "secret",
            "headers": {"Authorization": "Bearer secret"},
        },
    )
    subscriber.unsubscribe(bus)

    events = await AuditEventService(approval_session).list_events(event_type="tool.execution.egress")

    assert len(events) == 1
    assert events[0].status == "blocked"
    assert events[0].resource_type == "tool_egress"
    assert events[0].resource_id == "unit_plugin"
    assert events[0].metadata_json["egress_host"] == "blocked.example"
    assert "raw_url" not in events[0].metadata_json
    assert "token" not in str(events[0].metadata_json).lower()
    assert "/path" not in str(events[0].metadata_json)


@pytest.mark.asyncio
async def test_orchestrator_persists_plugin_egress_audit_events(approval_session: AsyncSession) -> None:
    bus = EventBus()
    orchestrator = CollectionOrchestrator(
        registry=PluginRegistry([EgressPublishingPlugin], bus=bus),
        session=approval_session,
        bus=bus,
        tool_execution=ToolExecutionController(
            settings=Settings(tool_execution_rate_limit_per_minute=0),
            rate_limiter=InMemoryRateLimiter(),
            audit_session=approval_session,
        ),
    )

    result = await orchestrator.run_job(CollectionJob(target="example.com", target_type="domain"))
    events = await AuditEventService(approval_session).list_events(event_type_prefix="tool.execution.")

    assert result.plugin_results[0].status == "completed"
    egress_events = [event for event in events if event.event_type == "tool.execution.egress"]
    assert len(egress_events) == 1
    assert egress_events[0].status == "allowed"
    assert egress_events[0].resource_type == "tool_egress"
    assert egress_events[0].resource_id == "egress_plugin"
    assert egress_events[0].metadata_json["egress_host"] == "api.example.test"
    assert "example.com" not in str(egress_events[0].metadata_json)
    assert "secret-token" not in str(egress_events[0].metadata_json)


@pytest.mark.asyncio
async def test_orchestrator_uses_scoped_bus_for_persistent_egress_audit(approval_session: AsyncSession) -> None:
    orchestrator = CollectionOrchestrator(
        registry=PluginRegistry([EgressPublishingPlugin]),
        session=approval_session,
        tool_execution=ToolExecutionController(
            settings=Settings(tool_execution_rate_limit_per_minute=0),
            rate_limiter=InMemoryRateLimiter(),
            audit_session=approval_session,
        ),
    )

    assert orchestrator.event_bus is not event_bus
    await orchestrator.run_job(CollectionJob(target="example.com", target_type="domain"))
    events = await AuditEventService(approval_session).list_events(event_type="tool.execution.egress")

    assert len(events) == 1
    assert events[0].resource_id == "egress_plugin"


@pytest.mark.asyncio
async def test_persistent_approval_allows_once_and_is_consumed(approval_session: AsyncSession) -> None:
    created = await ToolExecutionApprovalService(approval_session).create_approval(
        plugin_name="operator_tool",
        target_type="domain",
        target="example.com",
        execution_mode="operator_assisted",
        authorized_scope="unit-test",
        max_uses=1,
    )
    controller = ToolExecutionController(
        settings=Settings(tool_execution_mode="operator_assisted"),
        rate_limiter=InMemoryRateLimiter(),
        approval_session=approval_session,
    )

    allowed = await controller.authorize(
        plugin=OperatorToolPlugin(),
        target="example.com",
        target_type="domain",
        requested_mode="operator_assisted",
        approval_token=created.token,
    )
    reused = await controller.authorize(
        plugin=OperatorToolPlugin(),
        target="example.com",
        target_type="domain",
        requested_mode="operator_assisted",
        approval_token=created.token,
    )

    assert allowed.allowed
    assert allowed.metadata["approval_source"] == "persistent"
    assert allowed.metadata["approval_id"] == str(created.approval.id)
    assert reused.status == "approval_required"
    assert reused.reason == "approval_used"


@pytest.mark.asyncio
async def test_persistent_approval_scope_mismatch_blocks(approval_session: AsyncSession) -> None:
    created = await ToolExecutionApprovalService(approval_session).create_approval(
        plugin_name="operator_tool",
        target_type="domain",
        target="example.com",
        execution_mode="operator_assisted",
    )
    controller = ToolExecutionController(
        settings=Settings(tool_execution_mode="operator_assisted"),
        rate_limiter=InMemoryRateLimiter(),
        approval_session=approval_session,
    )

    decision = await controller.authorize(
        plugin=OperatorToolPlugin(),
        target="other.example",
        target_type="domain",
        requested_mode="operator_assisted",
        approval_token=created.token,
    )

    assert decision.status == "approval_required"
    assert decision.reason == "approval_target_mismatch"


@pytest.mark.asyncio
async def test_approval_api_create_list_get_and_revoke(approval_client: AsyncClient) -> None:
    create_response = await approval_client.post(
        "/tool-execution/approvals",
        json={
            "plugin_name": "operator_tool",
            "target_type": "domain",
            "target": "example.com",
            "execution_mode": "operator_assisted",
            "authorized_scope": "unit-test",
            "reason": "integration coverage",
            "expires_in_minutes": 15,
            "max_uses": 1,
        },
    )

    assert create_response.status_code == 201
    created = create_response.json()
    assert created["approval_token"]
    assert created["target_hash"]
    assert "example.com" not in create_response.text

    list_response = await approval_client.get("/tool-execution/approvals")
    assert list_response.status_code == 200
    assert list_response.json()["approvals"][0]["id"] == created["id"]
    assert "approval_token" not in list_response.text

    get_response = await approval_client.get(f"/tool-execution/approvals/{created['id']}")
    assert get_response.status_code == 200
    assert get_response.json()["id"] == created["id"]
    assert "approval_token" not in get_response.text

    revoke_response = await approval_client.delete(f"/tool-execution/approvals/{created['id']}")
    assert revoke_response.status_code == 200
    assert revoke_response.json()["status"] == "revoked"


@pytest.mark.asyncio
async def test_audit_api_lists_tool_execution_events_by_default(approval_client: AsyncClient) -> None:
    create_response = await approval_client.post(
        "/tool-execution/approvals",
        json={
            "plugin_name": "operator_tool",
            "target_type": "domain",
            "target": "example.com",
            "execution_mode": "operator_assisted",
        },
    )

    assert create_response.status_code == 201

    list_response = await approval_client.get("/audit/events")
    assert list_response.status_code == 200
    events = list_response.json()["events"]
    assert events[0]["event_type"] == "tool.execution.approval.created"
    assert events[0]["resource_type"] == "tool_execution_approval"
    assert "approval_token" not in list_response.text
    assert "example.com" not in list_response.text

    get_response = await approval_client.get(f"/audit/events/{events[0]['id']}")
    assert get_response.status_code == 200
    assert get_response.json()["id"] == events[0]["id"]


@pytest.mark.asyncio
async def test_audit_service_filters_event_type_prefix(approval_session: AsyncSession) -> None:
    service = AuditEventService(approval_session)
    await service.create_event(event_type="tool.execution.decision", status="approval_required", resource_id="operator_tool")
    await service.create_event(event_type="finding.created", status="success", resource_id="finding-1")

    events = await service.list_events(event_type_prefix="tool.execution.")

    assert [event.event_type for event in events] == ["tool.execution.decision"]
