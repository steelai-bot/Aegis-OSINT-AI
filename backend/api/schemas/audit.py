"""API schemas for audit event readback."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class AuditEventRead(BaseModel):
    """API-safe structured audit event."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    event_type: str
    actor_id: str | None = None
    actor_role: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    status: str
    request_id: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class AuditEventListResponse(BaseModel):
    """List response wrapper for audit events."""

    events: list[AuditEventRead] = Field(default_factory=list)
