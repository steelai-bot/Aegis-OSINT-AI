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
    threat_category: str = Field(default="unknown", max_length=50)
    indicator_type: str = Field(default="unknown", max_length=50)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    breach_date: datetime | None = None
    threat_actor: str | None = Field(default=None, max_length=255)
    campaign_id: str | None = Field(default=None, max_length=255)
    source_url: str | None = None
    collector_plugin: str = Field(default="", max_length=100)
    raw_evidence: dict[str, Any] = Field(default_factory=dict)
    enriched: bool = False
    enrichment_data: dict[str, Any] = Field(default_factory=dict)
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    exploitability: str = Field(default="unknown", max_length=20)
    remediation_status: str = Field(default="open", max_length=30)
    remediation_notes: str | None = None


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    investigation_id: UUID
    target_id: UUID | None
    source: str
    confidence: float
    severity: str
    data: dict[str, Any]
    threat_category: str
    indicator_type: str
    first_seen: datetime
    last_seen: datetime
    breach_date: datetime | None
    threat_actor: str | None
    campaign_id: str | None
    source_url: str | None
    collector_plugin: str
    raw_evidence: dict[str, Any]
    enriched: bool
    enrichment_data: dict[str, Any]
    risk_score: float
    exploitability: str
    remediation_status: str
    remediation_notes: str | None
    created_at: datetime
    updated_at: datetime
