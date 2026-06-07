"""Durable rate-limit buckets for distributed tool execution controls."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.models.base import Base, TimestampMixin


class ToolExecutionRateLimitBucket(TimestampMixin, Base):
    """Fixed-window counter shared by API/worker processes for one policy key."""

    __tablename__ = "tool_execution_rate_limit_buckets"
    __table_args__ = (
        Index("ix_tool_execution_rate_limit_buckets_window_start", "window_start"),
        Index("ix_tool_execution_rate_limit_buckets_updated_at", "updated_at"),
    )

    key: Mapped[str] = mapped_column(String(255), primary_key=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
