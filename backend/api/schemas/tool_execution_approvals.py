"""API schemas for persistent tool execution approvals."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


ExecutionApprovalMode = Literal["operator_assisted", "manual_review_only"]


class ToolExecutionApprovalCreate(BaseModel):
    """Request to create a scoped approval token for non-passive tool execution."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "plugin_name": "operator_tool",
                    "target_type": "domain",
                    "target": "example.com",
                    "execution_mode": "operator_assisted",
                    "authorized_scope": "Customer-approved assessment scope #A-123",
                    "reason": "Run operator-assisted verification for approved domain.",
                    "expires_in_minutes": 30,
                    "max_uses": 1,
                }
            ]
        }
    )

    plugin_name: str | None = Field(default=None, max_length=100)
    target_type: str | None = Field(default=None, max_length=50)
    target: str | None = Field(default=None, min_length=1, max_length=2048, exclude=True)
    target_hash: str | None = Field(default=None, min_length=64, max_length=64)
    execution_mode: ExecutionApprovalMode = "operator_assisted"
    authorized_scope: str | None = Field(default=None, max_length=2048)
    reason: str | None = Field(default=None, max_length=2048)
    requested_by: str | None = Field(default=None, max_length=255)
    expires_in_minutes: int = Field(default=30, ge=1, le=24 * 60)
    max_uses: int = Field(default=1, ge=1, le=100)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def require_target_or_hash(self) -> "ToolExecutionApprovalCreate":
        if not self.target and not self.target_hash:
            raise ValueError("Either target or target_hash is required for a scoped approval.")
        return self


class ToolExecutionApprovalRead(BaseModel):
    """API-safe approval record without token material."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    status: str
    plugin_name: str | None = None
    target_type: str | None = None
    target_hash: str | None = None
    execution_mode: str
    authorized_scope: str | None = None
    reason: str | None = None
    requested_by: str | None = None
    approved_by: str | None = None
    expires_at: datetime
    used_at: datetime | None = None
    revoked_at: datetime | None = None
    max_uses: int
    use_count: int
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class ToolExecutionApprovalCreated(ToolExecutionApprovalRead):
    """Create response that returns the plaintext token exactly once."""

    approval_token: str = Field(min_length=1)


class ToolExecutionApprovalListResponse(BaseModel):
    """List response wrapper for persistent approvals."""

    approvals: list[ToolExecutionApprovalRead] = Field(default_factory=list)