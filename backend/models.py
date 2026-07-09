from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from enum import Enum
from datetime import datetime

class TargetType(str, Enum):
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
    ABN = "abn"
    NZ_DOMAIN = "nz_domain"
    NZ_COMPANY = "nz_company"
    AUTO = "auto"

class InvestigationStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class PluginMetadata(BaseModel):
    name: str = Field(..., description="Unique identifier for the plugin")
    description: str = Field(..., description="Brief description of what the plugin does")
    supported_entity_types: List[TargetType] = Field(..., description="Types of targets this plugin can process")
    required_api_keys: List[str] = Field(default_factory=list, description="List of environment variable names for required API keys")
    tags: List[str] = Field(default_factory=list, description="Tags for categorization (e.g., 'dns', 'passive')")
    execution_cost: float = Field(default=1.0, description="Relative weight/cost of execution")
    estimated_time: int = Field(default=5, description="Estimated execution time in seconds")

class PluginResponse(BaseModel):
    provider: str = Field(..., description="Name of the plugin that provided the result")
    entity_type: TargetType
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score from 0.0 to 1.0")
    evidence: List[Dict[str, Any]] = Field(default_factory=list, description="Structured evidence found")
    raw: Dict[str, Any] = Field(default_factory=dict, description="Original raw output from the provider")

class InvestigationWorkflow(BaseModel):
    target_id: int
    target_type: TargetType
    steps: List[str] = Field(..., description="Ordered list of plugin names to execute")
    status: InvestigationStatus = InvestigationStatus.PENDING
    results: List[PluginResponse] = Field(default_factory=list)

class InvestigationTemplate(BaseModel):
    target_type: TargetType
    steps: List[str] = Field(..., description="Standard sequence of plugins for this target type")

class EntityType(str, Enum):
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

class Entity(BaseModel):
    id: Optional[int] = None
    type: EntityType
    value: str
    display_name: Optional[str] = None
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    metadata_json: Dict[str, Any] = Field(default_factory=dict)

class RelationshipType(str, Enum):
    RESOLVES_TO = "resolves_to"
    BELONGS_TO = "belongs_to"
    REGISTERED_TO = "registered_to"
    FOUND_IN = "found_in"
    LINKED_TO = "linked_to"
    EXPOSED_IN = "exposed_in"
    UNKNOWN = "unknown"

class Relationship(BaseModel):
    id: Optional[int] = None
    source_entity_id: int
    target_entity_id: int
    relationship_type: RelationshipType
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    source_plugin: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

class TimelineEventType(str, Enum):
    INVESTIGATION_CREATED = "investigation_created"
    PLANNING_COMPLETED = "planning_completed"
    PLUGIN_STARTED = "plugin_started"
    PLUGIN_COMPLETED = "plugin_completed"
    ENTITY_DISCOVERED = "entity_discovered"
    RELATIONSHIP_DISCOVERED = "relationship_discovered"
    REPORT_GENERATED = "report_generated"
    ERROR = "error"

class TimelineEvent(BaseModel):
    id: Optional[int] = None
    target_id: int
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: TimelineEventType
    plugin: Optional[str] = None
    severity: str = "info"  # info, warning, critical
    description: str
    entity_id: Optional[int] = None
