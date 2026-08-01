from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


def _utcnow():
    """Timezone-aware UTC now for Pydantic default_factory."""
    return datetime.now(UTC)


class TargetType(StrEnum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    EMAIL = "email"
    GITHUB = "github"
    PHONE = "phone"
    LEAK = "leak"
    COMPANY = "company"
    IP = "ip"
    PERSON = "person"
    UNKNOWN = "unknown"
    USERNAME = "username"
    ADDRESS = "address"
    ABN = "abn"
    NZ_DOMAIN = "nz_domain"
    NZ_COMPANY = "nz_company"
    AUTO = "auto"


class InvestigationStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class PluginMetadata(BaseModel):
    name: str = Field(..., description="Unique identifier for the plugin")
    description: str = Field(..., description="Brief description of what the plugin does")
    version: str = Field(default="1.0.0", description="Plugin version (semver)")
    supported_entity_types: list[TargetType] = Field(
        ..., description="Types of targets this plugin can process"
    )
    required_api_keys: list[str] = Field(
        default_factory=list, description="List of environment variable names for required API keys"
    )
    supported_authentication: list[str] = Field(
        default_factory=lambda: ["none"],
        description="Supported auth methods (e.g., api_key, oauth, username_password, session_cookie, none)",
    )
    tags: list[str] = Field(
        default_factory=list, description="Tags for categorization (e.g., 'dns', 'passive')"
    )
    execution_cost: float = Field(default=1.0, description="Relative weight/cost of execution")
    estimated_time: int = Field(default=5, description="Estimated execution time in seconds")
    dependencies: list[str] = Field(
        default_factory=list, description="List of other plugin names this plugin depends on"
    )
    min_app_version: str = Field(default="1.0.0", description="Minimum Aegis version required")


class PluginResponse(BaseModel):
    provider: str = Field(..., description="Name of the plugin that provided the result")
    entity_type: TargetType
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score from 0.0 to 1.0")
    evidence: list[dict[str, Any]] = Field(
        default_factory=list, description="Structured evidence found"
    )
    raw: dict[str, Any] = Field(
        default_factory=dict, description="Original raw output from the provider"
    )


class InvestigationWorkflow(BaseModel):
    target_id: int
    target_type: TargetType
    steps: list[str] = Field(..., description="Ordered list of plugin names to execute")
    status: InvestigationStatus = InvestigationStatus.PENDING
    results: list[PluginResponse] = Field(default_factory=list)


class InvestigationTemplate(BaseModel):
    target_type: TargetType
    steps: list[str] = Field(..., description="Standard sequence of plugins for this target type")


class EntityType(StrEnum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    EMAIL = "email"
    GITHUB = "github"
    PHONE = "phone"
    LEAK = "leak"
    COMPANY = "company"
    IP = "ip"
    PERSON = "person"
    USERNAME = "username"
    URL = "url"
    ADDRESS = "address"
    UNKNOWN = "unknown"


class Entity(BaseModel):
    id: int | None = None
    type: EntityType
    value: str
    display_name: str | None = None
    first_seen: datetime = Field(default_factory=_utcnow)
    last_seen: datetime = Field(default_factory=_utcnow)
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    metadata_json: dict[str, Any] = Field(default_factory=dict)


class RelationshipType(StrEnum):
    RESOLVES_TO = "resolves_to"
    BELONGS_TO = "belongs_to"
    REGISTERED_TO = "registered_to"
    FOUND_IN = "found_in"
    LINKED_TO = "linked_to"
    EXPOSED_IN = "exposed_in"
    UNKNOWN = "unknown"


class Relationship(BaseModel):
    id: int | None = None
    source_entity_id: int
    target_entity_id: int
    relationship_type: RelationshipType
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    source_plugin: str
    created_at: datetime = Field(default_factory=_utcnow)


class TimelineEventType(StrEnum):
    INVESTIGATION_CREATED = "investigation_created"
    PLANNING_COMPLETED = "planning_completed"
    PLUGIN_STARTED = "plugin_started"
    PLUGIN_COMPLETED = "plugin_completed"
    ENTITY_DISCOVERED = "entity_discovered"
    RELATIONSHIP_DISCOVERED = "relationship_discovered"
    REPORT_GENERATED = "report_generated"
    ERROR = "error"


class TimelineEvent(BaseModel):
    id: int | None = None
    target_id: int
    timestamp: datetime = Field(default_factory=_utcnow)
    event_type: TimelineEventType
    plugin: str | None = None
    severity: str = "info"  # info, warning, critical
    description: str
    entity_id: int | None = None


class DarkWebHit(BaseModel):
    """Normalized single dark-web/breach result for the Dark Web UI page.

    Transport/UI-only model - not persisted directly; plugin findings carry the
    same fields inside their evidence dicts.
    """

    source: str = Field(
        ..., description="Plugin/source name, e.g. 'ahmia', 'psbdmp', 'hibp_pastes', 'telegram'"
    )
    category: str = Field(
        ..., description="stealer_log | breach | forum_mention | database_dump | telegram | paste"
    )
    title: str
    snippet: str = ""
    url: str | None = None
    download_url: str | None = None
    date: str | None = None
    severity: str = "info"  # info | warning | critical
    confidence: float = Field(0.7, ge=0.0, le=1.0)
    tor: bool = Field(False, description="True when the hit was fetched via the Tor proxy")
    extra: dict[str, Any] = Field(default_factory=dict)
