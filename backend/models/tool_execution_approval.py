"""Persistent approval records for gated tool execution."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import JSON, DateTime, Index, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.models.base import Base, TimestampMixin


class ToolExecutionApproval(TimestampMixin, Base):
    """Durable, token-hashed approval grant for non-passive tool execution."""

    __tablename__ = "tool_execution_approvals"
    __table_args__ = (
        Index("ix_tool_execution_approvals_created_at", "created_at"),
        Index("ix_tool_execution_approvals_lookup", "status", "plugin_name", "target_type"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    status: Mapped[str] = mapped_column(String(30), default="active", nullable=False, index=True)
    plugin_name: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    target_type: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    target_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    execution_mode: Mapped[str] = mapped_column(String(50), default="operator_assisted", nullable=False, index=True)
    authorized_scope: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    reason: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    requested_by: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    max_uses: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    use_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), default=dict, nullable=False
    )