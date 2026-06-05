"""Finding persistence model."""

from __future__ import annotations

from uuid import UUID, uuid4

from sqlalchemy import JSON, Float, ForeignKey, String
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

    investigation = relationship("Investigation", back_populates="findings")
    target = relationship("Target", back_populates="findings")
    embedding = relationship("Embedding", back_populates="finding", uselist=False, cascade="all, delete-orphan")
