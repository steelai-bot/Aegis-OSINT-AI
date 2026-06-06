"""Collection orchestration API schemas."""

from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class CollectionRunRequest(BaseModel):
    """Request to run approved passive collection plugins for a target."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {"target": "example.com", "target_type": "domain", "plugin_name": "crtsh"},
                {
                    "target": "example.com",
                    "target_type": "domain",
                    "plugin_name": "s3_scanner",
                    "config": {"bucket_names": ["example-assets", "example-logs"]},
                },
                {
                    "target": "Example Brand",
                    "target_type": "keyword",
                    "plugin_name": "ransomware_blog_scraper",
                    "config": {"sources": ["https://authorized-public-source.example/leaks"]},
                },
            ]
        }
    )

    target: str = Field(min_length=1, max_length=2048)
    target_type: str = Field(min_length=1, max_length=50)
    plugin_name: str | None = Field(default=None, max_length=100)
    investigation_id: UUID | None = None
    target_id: UUID | None = None
    priority: int = Field(default=100, ge=0, le=1000)
    config: dict[str, Any] = Field(default_factory=dict)
    enrich: bool = False


class CollectionWorkflowRunRequest(BaseModel):
    """Request to run approved passive collection for existing workflow targets."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {"plugin_name": "crtsh", "enrich": False},
                {
                    "plugin_name": "telegram_channel_monitor",
                    "config": {"channels": ["@authorized_public_channel"]},
                    "enrich": False,
                },
            ]
        }
    )

    plugin_name: str | None = Field(default=None, max_length=100)
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
    target_type: str | None = None
    target_id: UUID | None = None
    plugin_results: list[CollectionPluginResultRead] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    persisted_count: int = 0
    errors: dict[str, str] = Field(default_factory=dict)


class CollectionInvestigationRunResponse(BaseModel):
    """Collection run response for all targets in an investigation."""

    investigation_id: UUID
    target_results: list[CollectionRunResponse] = Field(default_factory=list)
    persisted_count: int = 0
    errors: dict[str, str] = Field(default_factory=dict)