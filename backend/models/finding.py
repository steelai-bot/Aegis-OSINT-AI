"""Finding persistence model."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.models.base import Base, TimestampMixin


class Finding(TimestampMixin, Base):
    __tablename__ = "findings"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    investigation_id: Mapped[UUID] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    target_id: Mapped[UUID | None] = mapped_column(ForeignKey("targets.id", ondelete="SET NULL"), nullable=True, index=True)
    source: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    severity: Mapped[str] = mapped_column(String(50), default="info", nullable=False, index=True)
    data: Mapped[dict] = mapped_column(JSON().with_variant(JSONB(), "postgresql"), default=dict, nullable=False)
    threat_category: Mapped[str] = mapped_column(String(50), default="unknown", nullable=False, index=True)
    indicator_type: Mapped[str] = mapped_column(String(50), default="unknown", nullable=False, index=True)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False, index=True
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False, index=True
    )
    breach_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    threat_actor: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    campaign_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    source_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    collector_plugin: Mapped[str] = mapped_column(String(100), default="", nullable=False, index=True)
    raw_evidence: Mapped[dict] = mapped_column(JSON().with_variant(JSONB(), "postgresql"), default=dict, nullable=False)
    enriched: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    enrichment_data: Mapped[dict] = mapped_column(JSON().with_variant(JSONB(), "postgresql"), default=dict, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False, index=True)
    exploitability: Mapped[str] = mapped_column(String(20), default="unknown", nullable=False)
    remediation_status: Mapped[str] = mapped_column(String(30), default="open", nullable=False, index=True)
    remediation_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    investigation = relationship("Investigation", back_populates="findings")
    target = relationship("Target", back_populates="findings")
    embedding = relationship("Embedding", back_populates="finding", uselist=False, cascade="all, delete-orphan")
