"""Service layer for persistent tool execution approval grants."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from secrets import compare_digest, token_urlsafe
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.tool_execution_approval import ToolExecutionApproval
from backend.services.audit import sanitize_audit_metadata


@dataclass(frozen=True, slots=True)
class CreatedToolExecutionApproval:
    """Created approval record with its one-time plaintext token."""

    approval: ToolExecutionApproval
    token: str


@dataclass(frozen=True, slots=True)
class ApprovalValidationResult:
    """Result of validating and optionally consuming a persistent approval token."""

    allowed: bool
    reason: str
    approval: ToolExecutionApproval | None = None


class ToolExecutionApprovalService:
    """CRUD and token validation for persistent approval records."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create_approval(
        self,
        *,
        plugin_name: str | None = None,
        target_type: str | None = None,
        target: str | None = None,
        target_hash: str | None = None,
        execution_mode: str = "operator_assisted",
        authorized_scope: str | None = None,
        reason: str | None = None,
        requested_by: str | None = None,
        approved_by: str | None = None,
        expires_in_minutes: int = 30,
        max_uses: int = 1,
        metadata: dict[str, Any] | None = None,
    ) -> CreatedToolExecutionApproval:
        """Create an active approval and return its plaintext token once."""

        token = token_urlsafe(32)
        approval = ToolExecutionApproval(
            token_hash=hash_approval_token(token),
            status="active",
            plugin_name=_optional_truncated(plugin_name, 100),
            target_type=_optional_truncated(target_type, 50),
            target_hash=target_hash or (hash_tool_target(target) if target else None),
            execution_mode=_optional_truncated(execution_mode, 50) or "operator_assisted",
            authorized_scope=_optional_truncated(authorized_scope, 2048),
            reason=_optional_truncated(reason, 2048),
            requested_by=_optional_truncated(requested_by, 255),
            approved_by=_optional_truncated(approved_by, 255),
            expires_at=datetime.now(UTC) + timedelta(minutes=max(1, expires_in_minutes)),
            max_uses=max(1, max_uses),
            use_count=0,
            metadata_json=sanitize_audit_metadata(metadata),
        )
        self.session.add(approval)
        await self.session.commit()
        await self.session.refresh(approval)
        return CreatedToolExecutionApproval(approval=approval, token=token)

    async def list_approvals(self, *, status: str | None = None, limit: int = 100) -> list[ToolExecutionApproval]:
        """Return recent approval records without exposing token material."""

        stmt = select(ToolExecutionApproval).order_by(ToolExecutionApproval.created_at.desc()).limit(max(1, min(limit, 500)))
        if status:
            stmt = stmt.where(ToolExecutionApproval.status == status)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_approval(self, approval_id: UUID) -> ToolExecutionApproval | None:
        """Return one approval record by ID."""

        return await self.session.get(ToolExecutionApproval, approval_id)

    async def revoke_approval(self, approval_id: UUID) -> ToolExecutionApproval | None:
        """Revoke an approval if it exists."""

        approval = await self.get_approval(approval_id)
        if approval is None:
            return None
        approval.status = "revoked"
        approval.revoked_at = datetime.now(UTC)
        await self.session.commit()
        await self.session.refresh(approval)
        return approval

    async def consume_approval(
        self,
        *,
        token: str | None,
        plugin_name: str,
        target_type: str,
        target_hash: str,
        plugin_mode: str,
        requested_mode: str,
    ) -> ApprovalValidationResult:
        """Validate a token against scope constraints and consume one use."""

        if not token:
            return ApprovalValidationResult(False, "approval_required")

        approval = await self._get_by_token(token)
        if approval is None:
            return ApprovalValidationResult(False, "approval_token_invalid")

        now = datetime.now(UTC)
        if approval.status != "active":
            return ApprovalValidationResult(False, f"approval_{approval.status}", approval)
        expires_at = _ensure_aware_utc(approval.expires_at)
        if expires_at <= now:
            approval.status = "expired"
            await self.session.commit()
            return ApprovalValidationResult(False, "approval_expired", approval)
        if approval.use_count >= approval.max_uses:
            approval.status = "used"
            await self.session.commit()
            return ApprovalValidationResult(False, "approval_already_used", approval)
        if approval.plugin_name and approval.plugin_name != plugin_name:
            return ApprovalValidationResult(False, "approval_plugin_mismatch", approval)
        if approval.target_type and approval.target_type != target_type:
            return ApprovalValidationResult(False, "approval_target_type_mismatch", approval)
        if approval.target_hash and approval.target_hash != target_hash:
            return ApprovalValidationResult(False, "approval_target_mismatch", approval)
        if not approval_mode_allows(approval.execution_mode, plugin_mode):
            return ApprovalValidationResult(False, "approval_mode_too_restrictive", approval)
        if not approval_mode_allows(approval.execution_mode, requested_mode):
            return ApprovalValidationResult(False, "approval_requested_mode_mismatch", approval)

        approval.use_count += 1
        approval.used_at = now
        if approval.use_count >= approval.max_uses:
            approval.status = "used"
        await self.session.commit()
        await self.session.refresh(approval)
        return ApprovalValidationResult(True, "persistent_approval_allowed", approval)

    async def _get_by_token(self, token: str) -> ToolExecutionApproval | None:
        token_hash = hash_approval_token(token)
        stmt = select(ToolExecutionApproval).where(ToolExecutionApproval.token_hash == token_hash)
        result = await self.session.execute(stmt)
        approval = result.scalar_one_or_none()
        if approval is None:
            return None
        if not compare_digest(approval.token_hash, token_hash):
            return None
        return approval


def hash_approval_token(token: str) -> str:
    """Return the storage hash for an approval token."""

    return sha256(token.encode("utf-8", errors="ignore")).hexdigest()


def hash_tool_target(target: str) -> str:
    """Return the API-safe target hash used by approval and execution policy."""

    return sha256(target.strip().lower().encode("utf-8", errors="ignore")).hexdigest()


def approval_mode_allows(approval_mode: str, requested_mode: str) -> bool:
    """Return whether an approval mode is broad enough for a requested/plugin mode."""

    order = {"passive": 0, "operator_assisted": 1, "manual_review_only": 2, "disabled": -1}
    approval_value = order.get(approval_mode, 0)
    requested_value = order.get(requested_mode, 0)
    return approval_mode != "disabled" and approval_value >= requested_value


def _optional_truncated(value: str | None, max_length: int) -> str | None:
    if value is None:
        return None
    return value[:max_length]


def _ensure_aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)