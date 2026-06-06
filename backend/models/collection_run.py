"""Persisted passive collection run status."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.models.base import Base, TimestampMixin


class CollectionRun(TimestampMixin, Base):
    """Process-local background collection run tracking record."""

    __tablename__ = "collection_runs"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    run_scope: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    investigation_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), nullable=True, index=True
    )
    target_id: Mapped[UUID | None] = mapped_column(ForeignKey("targets.id", ondelete="SET NULL"), nullable=True, index=True)
    target: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    target_type: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    plugin_name: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(50), default="queued", nullable=False, index=True)
    priority: Mapped[int] = mapped_column(default=100, nullable=False)
    enrich: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    config_json: Mapped[dict[str, Any]] = mapped_column(JSON().with_variant(JSONB(), "postgresql"), default=dict, nullable=False)
    result_json: Mapped[dict[str, Any]] = mapped_column(JSON().with_variant(JSONB(), "postgresql"), default=dict, nullable=False)
    error_json: Mapped[dict[str, Any]] = mapped_column(JSON().with_variant(JSONB(), "postgresql"), default=dict, nullable=False)
    persisted_count: Mapped[int] = mapped_column(default=0, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
