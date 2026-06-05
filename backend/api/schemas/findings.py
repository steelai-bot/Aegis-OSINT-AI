"""Finding API schemas."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class FindingCreate(BaseModel):
    investigation_id: UUID
    target_id: UUID | None = None
    source: str = Field(min_length=1, max_length=255)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    severity: str = Field(default="info", max_length=50)
    data: dict[str, Any] = Field(default_factory=dict)


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    investigation_id: UUID
    target_id: UUID | None
    source: str
    confidence: float
    severity: str
    data: dict[str, Any]
    created_at: datetime
    updated_at: datetime
