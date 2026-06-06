"""Collection orchestration API schemas."""

from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class CollectionRunRequest(BaseModel):
    """Request to run approved passive collection plugins for a target."""

    target: str = Field(min_length=1, max_length=2048)
    target_type: str = Field(min_length=1, max_length=50)
    plugin_name: str | None = Field(default=None, max_length=100)
    investigation_id: UUID | None = None
    target_id: UUID | None = None
    priority: int = Field(default=100, ge=0, le=1000)
    config: dict[str, Any] = Field(default_factory=dict)
    enrich: bool = False


class CollectionPluginResultRead(BaseModel):
    """API-safe plugin execution summary."""

    plugin_name: str
    status: str
    findings: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CollectionRunResponse(BaseModel):
    """Normalized collection run response."""

    target: str
    plugin_results: list[CollectionPluginResultRead] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    persisted_count: int = 0
    errors: dict[str, str] = Field(default_factory=dict)