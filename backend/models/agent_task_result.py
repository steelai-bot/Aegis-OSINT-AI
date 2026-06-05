"""Persisted task results returned by investigation agents."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import JSON, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.models.base import Base, TimestampMixin


class AgentTaskResult(TimestampMixin, Base):
    __tablename__ = "agent_task_results"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    investigation_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    context_snapshot_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("agent_context_snapshots.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    agent_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    findings_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"),
        default=list,
        nullable=False,
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"),
        default=dict,
        nullable=False,
    )

    context_snapshot = relationship("AgentContextSnapshot", back_populates="task_results")
