"""Policy-gated tool execution controls for plugin workflows.

The layer gives collection orchestration a single decision point for execution
mode checks, operator approval requirements, rate limits, and audit-event
emission. Local deployments can use a process-local limiter while distributed
API/worker deployments can opt into a database-backed fixed-window limiter.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.config import Settings, get_settings
from backend.models.tool_execution_rate_limit import ToolExecutionRateLimitBucket
from backend.plugins.base import BasePlugin
from backend.services.audit import AuditEventService
from backend.services.tool_execution_approvals import ToolExecutionApprovalService, hash_tool_target


logger = logging.getLogger(__name__)

ExecutionMode = Literal["passive", "operator_assisted", "manual_review_only", "disabled"]
DecisionStatus = Literal["allowed", "blocked", "approval_required", "rate_limited"]

MODE_ORDER: dict[ExecutionMode, int] = {
    "passive": 0,
    "operator_assisted": 1,
    "manual_review_only": 2,
    "disabled": -1,
}
VALID_EXECUTION_MODES = frozenset(MODE_ORDER)


@dataclass(frozen=True, slots=True)
class ToolExecutionDecision:
    """Outcome of a policy decision before a plugin/tool is invoked."""

    plugin_name: str
    status: DecisionStatus
    reason: str
    requested_mode: ExecutionMode
    plugin_mode: ExecutionMode
    target_type: str
    requires_approval: bool = False
    rate_limit_key: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.status == "allowed"

    def plugin_result_metadata(self) -> dict[str, Any]:
        """Return API-safe policy metadata for blocked plugin summaries."""

        return {
            "policy_status": self.status,
            "policy_reason": self.reason,
            "requested_mode": self.requested_mode,
            "plugin_mode": self.plugin_mode,
            "requires_approval": self.requires_approval,
            **self.metadata,
        }


class InMemoryRateLimiter:
    """Simple fixed-window process-local rate limiter for MVP execution gating."""

    def __init__(self) -> None:
        self._windows: dict[str, list[datetime]] = {}

    async def allow(self, key: str, *, limit: int, window_seconds: int = 60) -> bool:
        if limit <= 0:
            return True

        now = datetime.now(UTC)
        cutoff = now - timedelta(seconds=window_seconds)
        timestamps = [timestamp for timestamp in self._windows.get(key, []) if timestamp > cutoff]
        if len(timestamps) >= limit:
            self._windows[key] = timestamps
            return False

        timestamps.append(now)
        self._windows[key] = timestamps
        return True

    def clear(self) -> None:
        self._windows.clear()


class DatabaseRateLimiter:
    """Database-backed fixed-window limiter shared across processes.

    Each policy key has one durable bucket. The row is locked during updates on
    databases that support `SELECT ... FOR UPDATE` (PostgreSQL in production),
    preventing multiple API/worker processes from independently exceeding the
    same per-minute allowance. If the database write path fails, callers should
    fall back to the local limiter rather than bypass rate limiting entirely.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def allow(self, key: str, *, limit: int, window_seconds: int = 60, _retried_insert: bool = False) -> bool:
        if limit <= 0:
            return True

        now = datetime.now(UTC)
        cutoff = now - timedelta(seconds=window_seconds)
        storage_key = _rate_limit_storage_key(key)

        result = await self.session.execute(
            select(ToolExecutionRateLimitBucket)
            .where(ToolExecutionRateLimitBucket.key == storage_key)
            .with_for_update()
        )
        bucket = result.scalar_one_or_none()
        if bucket is None:
            self.session.add(ToolExecutionRateLimitBucket(key=storage_key, window_start=now, count=1))
            try:
                await self.session.commit()
            except IntegrityError:
                await self.session.rollback()
                if _retried_insert:
                    raise
                return await self.allow(
                    key,
                    limit=limit,
                    window_seconds=window_seconds,
                    _retried_insert=True,
                )
            return True

        if _ensure_aware_utc(bucket.window_start) <= cutoff:
            bucket.window_start = now
            bucket.count = 1
            await self.session.commit()
            return True

        if bucket.count >= limit:
            await self.session.commit()
            return False

        bucket.count += 1
        await self.session.commit()
        return True


class ToolExecutionController:
    """Authorize and audit tool/plugin execution attempts."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        rate_limiter: InMemoryRateLimiter | None = None,
        database_rate_limiter: DatabaseRateLimiter | None = None,
        audit_session: AsyncSession | None = None,
        approval_session: AsyncSession | None = None,
        approval_service: ToolExecutionApprovalService | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.rate_limiter = rate_limiter or default_rate_limiter
        self.database_rate_limiter = database_rate_limiter or (
            DatabaseRateLimiter(audit_session)
            if audit_session is not None and self.settings.tool_execution_rate_limit_backend == "database"
            else None
        )
        self.audit_session = audit_session
        self.approval_session = approval_session or audit_session
        self.approval_service = approval_service or (
            ToolExecutionApprovalService(self.approval_session) if self.approval_session is not None else None
        )

    async def authorize(
        self,
        *,
        plugin: BasePlugin,
        target: str,
        target_type: str,
        requested_mode: str | None = None,
        approval_token: str | None = None,
        authorized_scope: str | None = None,
    ) -> ToolExecutionDecision:
        """Return the execution decision for a plugin invocation."""

        configured_mode = normalize_execution_mode(self.settings.tool_execution_mode)
        runtime_mode = self._effective_runtime_mode(configured_mode, requested_mode)
        plugin_mode = normalize_execution_mode(getattr(plugin, "execution_mode", "passive"))
        target_hash = hash_tool_target(target)
        base_metadata = {
            "target_hash": target_hash,
            "authorized_scope": authorized_scope,
        }

        if runtime_mode == "disabled":
            return self._decision(plugin, "blocked", "tool_execution_disabled", runtime_mode, plugin_mode, target_type, base_metadata)

        if plugin_mode == "disabled":
            return self._decision(plugin, "blocked", "plugin_execution_disabled", runtime_mode, plugin_mode, target_type, base_metadata)

        if MODE_ORDER[plugin_mode] > MODE_ORDER[runtime_mode]:
            return self._decision(plugin, "blocked", "runtime_mode_too_restrictive", runtime_mode, plugin_mode, target_type, base_metadata)

        requires_approval = bool(getattr(plugin, "requires_approval", False)) or plugin_mode != "passive"
        if requires_approval:
            approval_metadata: dict[str, Any] = {}
            persistent_result = await self._persistent_approval_matches(
                approval_token=approval_token,
                plugin=plugin,
                target_type=target_type,
                target_hash=target_hash,
                plugin_mode=plugin_mode,
                requested_mode=runtime_mode,
            )
            if persistent_result is not None:
                persistent_allowed, persistent_reason, approval_metadata = persistent_result
                if not persistent_allowed and not self._approval_matches(approval_token):
                    return self._decision(
                        plugin,
                        "approval_required",
                        persistent_reason,
                        runtime_mode,
                        plugin_mode,
                        target_type,
                        {**base_metadata, **approval_metadata},
                        requires_approval=True,
                    )
                if persistent_allowed:
                    base_metadata = {**base_metadata, **approval_metadata}
            elif not self._approval_matches(approval_token):
                reason = "approval_token_not_configured" if not self.settings.tool_execution_approval_token else "approval_required"
                return self._decision(
                    plugin,
                    "approval_required",
                    reason,
                    runtime_mode,
                    plugin_mode,
                    target_type,
                    base_metadata,
                    requires_approval=True,
                )

        limit = self.settings.tool_execution_rate_limit_per_minute
        rate_limit_key = self._rate_limit_key(plugin=plugin, target_hash=target_hash, target_type=target_type)
        rate_limit_allowed, rate_limit_backend = await self._rate_limit_allowed(rate_limit_key, limit=limit)
        if limit > 0 and not rate_limit_allowed:
            return self._decision(
                plugin,
                "rate_limited",
                "rate_limit_exceeded",
                runtime_mode,
                plugin_mode,
                target_type,
                {**base_metadata, "rate_limit_per_minute": limit, "rate_limit_backend": rate_limit_backend},
                requires_approval=requires_approval,
                rate_limit_key=rate_limit_key,
            )

        return self._decision(
            plugin,
            "allowed",
            "policy_allowed",
            runtime_mode,
            plugin_mode,
            target_type,
            {**base_metadata, "rate_limit_per_minute": limit, "rate_limit_backend": rate_limit_backend},
            requires_approval=requires_approval,
            rate_limit_key=rate_limit_key,
        )

    async def record_decision(self, decision: ToolExecutionDecision) -> None:
        """Persist a sanitized audit event for a policy decision when possible."""

        await self._record_audit_event(
            event_type="tool.execution.decision",
            status=decision.status,
            resource_id=decision.plugin_name,
            metadata=decision.plugin_result_metadata(),
        )

    async def record_outcome(
        self,
        *,
        decision: ToolExecutionDecision,
        status: str,
        finding_count: int = 0,
        error: str | None = None,
    ) -> None:
        """Persist a sanitized audit event after an allowed plugin attempt."""

        metadata = {
            **decision.plugin_result_metadata(),
            "plugin_status": status,
            "finding_count": finding_count,
            "error": error,
        }
        await self._record_audit_event(
            event_type="tool.execution.completed" if error is None else "tool.execution.failed",
            status=status,
            resource_id=decision.plugin_name,
            metadata=metadata,
        )

    def _decision(
        self,
        plugin: BasePlugin,
        status: DecisionStatus,
        reason: str,
        requested_mode: ExecutionMode,
        plugin_mode: ExecutionMode,
        target_type: str,
        metadata: dict[str, Any],
        *,
        requires_approval: bool = False,
        rate_limit_key: str | None = None,
    ) -> ToolExecutionDecision:
        return ToolExecutionDecision(
            plugin_name=plugin.name,
            status=status,
            reason=reason,
            requested_mode=requested_mode,
            plugin_mode=plugin_mode,
            target_type=target_type,
            requires_approval=requires_approval,
            rate_limit_key=rate_limit_key,
            metadata={key: value for key, value in metadata.items() if value is not None},
        )

    def _approval_matches(self, approval_token: str | None) -> bool:
        configured = self.settings.tool_execution_approval_token
        return bool(configured and approval_token and configured == approval_token)

    async def _persistent_approval_matches(
        self,
        *,
        approval_token: str | None,
        plugin: BasePlugin,
        target_type: str,
        target_hash: str,
        plugin_mode: ExecutionMode,
        requested_mode: ExecutionMode,
    ) -> tuple[bool, str, dict[str, Any]] | None:
        if self.approval_service is None or not approval_token:
            return None
        try:
            result = await self.approval_service.consume_approval(
                token=approval_token,
                plugin_name=plugin.name,
                target_type=target_type,
                target_hash=target_hash,
                plugin_mode=plugin_mode,
                requested_mode=requested_mode,
            )
        except Exception as exc:
            if self.approval_session is not None:
                await self.approval_session.rollback()
            logger.warning("Failed to validate persistent tool approval (%s)", type(exc).__name__)
            return False, "approval_lookup_failed", {"approval_source": "persistent"}

        metadata: dict[str, Any] = {"approval_source": "persistent"}
        if result.approval is not None:
            metadata.update(
                {
                    "approval_id": str(result.approval.id),
                    "approval_status": result.approval.status,
                    "approval_use_count": result.approval.use_count,
                    "approval_max_uses": result.approval.max_uses,
                }
            )
        return result.allowed, result.reason, metadata

    def _effective_runtime_mode(self, configured_mode: ExecutionMode, requested_mode: str | None) -> ExecutionMode:
        requested = normalize_execution_mode(requested_mode) if requested_mode else configured_mode
        if configured_mode == "disabled":
            return "disabled"
        if requested == "disabled":
            return "disabled"
        if MODE_ORDER[requested] > MODE_ORDER[configured_mode]:
            return configured_mode
        return requested

    def _rate_limit_key(self, *, plugin: BasePlugin, target_hash: str, target_type: str) -> str:
        configured_key = getattr(plugin, "rate_limit_key", None)
        if configured_key:
            return str(configured_key)
        return f"{plugin.name}:{target_type}:{target_hash}"

    async def _rate_limit_allowed(self, key: str, *, limit: int) -> tuple[bool, str]:
        if limit <= 0:
            return True, "disabled"

        if self.settings.tool_execution_rate_limit_backend == "database":
            if self.database_rate_limiter is None:
                return await self.rate_limiter.allow(key, limit=limit), "memory_fallback"
            try:
                return await self.database_rate_limiter.allow(key, limit=limit), "database"
            except Exception as exc:
                if self.audit_session is not None:
                    await self.audit_session.rollback()
                logger.warning("Database tool execution rate limiter failed (%s); using memory fallback", type(exc).__name__)
                return await self.rate_limiter.allow(key, limit=limit), "memory_fallback"

        return await self.rate_limiter.allow(key, limit=limit), "memory"

    async def _record_audit_event(
        self,
        *,
        event_type: str,
        status: str,
        resource_id: str,
        metadata: dict[str, Any],
    ) -> None:
        if self.audit_session is None:
            return
        try:
            await AuditEventService(self.audit_session).create_event(
                event_type=event_type,
                status=status,
                resource_type="tool",
                resource_id=resource_id,
                metadata=metadata,
            )
        except Exception as exc:  # Audit logging must not hide successful execution.
            await self.audit_session.rollback()
            logger.warning("Failed to persist tool execution audit event '%s' (%s)", event_type, type(exc).__name__)


def normalize_execution_mode(value: str | None) -> ExecutionMode:
    normalized = (value or "passive").strip().lower().replace("-", "_")
    if normalized not in VALID_EXECUTION_MODES:
        return "passive"
    return normalized  # type: ignore[return-value]


def _hash_target(target: str) -> str:
    return hash_tool_target(target)


def _rate_limit_storage_key(key: str) -> str:
    """Return a DB-safe bucket key while preserving readable short keys."""

    normalized = key[:255]
    if len(key) <= 255:
        return normalized
    digest = sha256(key.encode("utf-8", errors="ignore")).hexdigest()
    return f"{key[:190]}:{digest}"


def _ensure_aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


default_rate_limiter = InMemoryRateLimiter()
