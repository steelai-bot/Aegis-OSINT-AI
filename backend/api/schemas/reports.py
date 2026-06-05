"""Report API schemas."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ReportCreate(BaseModel):
    investigation_id: UUID
    path: str = Field(min_length=1, max_length=2048)
    format: str = Field(min_length=1, max_length=20)


class ReportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    investigation_id: UUID
    path: str
    format: str
    created_at: datetime
    updated_at: datetime
