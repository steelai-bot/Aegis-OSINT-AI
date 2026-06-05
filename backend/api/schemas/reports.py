"""Report API schemas."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

ReportFormat = Literal["html", "json", "csv", "markdown", "briefing", "pdf"]
RenderableReportFormat = Literal["json", "markdown", "briefing"]


class ReportCreate(BaseModel):
    investigation_id: UUID
    path: str = Field(min_length=1, max_length=2048)
    format: ReportFormat


class ReportRenderRequest(BaseModel):
    format: RenderableReportFormat


class ReportRenderResponse(BaseModel):
    investigation_id: UUID
    format: RenderableReportFormat
    content: str


class ReportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    investigation_id: UUID
    path: str
    format: str
    created_at: datetime
    updated_at: datetime
