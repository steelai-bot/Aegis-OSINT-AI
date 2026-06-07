"""Tool execution policy, approval, rate-limit, and orchestration tests."""

from __future__ import annotations

import pytest

from backend.core.config import Settings
from backend.plugins.base import BasePlugin, PluginResult
from backend.plugins.registry import PluginRegistry
from backend.services.collection_orchestrator import CollectionJob, CollectionOrchestrator
from backend.services.tool_execution import InMemoryRateLimiter, ToolExecutionController


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
