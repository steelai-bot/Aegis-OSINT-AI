"""Target API schemas."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class TargetCreate(BaseModel):
    investigation_id: UUID
    type: str = Field(min_length=1, max_length=50)
    value: str = Field(min_length=1, max_length=2048)


class TargetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    investigation_id: UUID
    type: str
    value: str
    created_at: datetime
    updated_at: datetime
