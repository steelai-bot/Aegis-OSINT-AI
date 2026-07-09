# Implementation Plan

[Overview]
Extend the Aegis OSINT AI backend to support a maintainable, extensible intelligence platform by introducing an Entity Graph, automatic Investigation Timeline, and a modular Report Generation architecture. This phase focuses on standardizing plugin outputs, centralizing API key management, and preparing the backend for future graph visualization and professional reporting without introducing new database technologies (SQLite only).

The current architecture uses a `PluginManager` to discover and run `BasePlugin` instances, with an `InvestigationEngine` orchestrating the workflow and a `ReportGenerator` producing basic outputs. This plan builds on that foundation by adding relational tables for entities and relationships, a timeline event log, and a refactored reporting module that supports Markdown, JSON, and HTML with a professional structure. The UI will be incrementally improved to include Dashboard, Investigations, Results, Reports, Settings, and Plugins pages, keeping the design minimal but better organized.

[Types]
Single sentence describing the type system changes.

New Pydantic models will be added to `backend/models.py` to represent entities, relationships, and timeline events, ensuring type-safe data flow between plugins, the engine, and the storage layer.

```python
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
```

[Files]
Single sentence describing file modifications.

New files will be created for storage abstraction and entity extraction; existing files (`models.py`, `engine.py`, `report.py`, `main.py`, `frontend/*`) will be modified to integrate the new features.

- New files:
  - `backend/storage.py`: Database-agnostic storage interface and SQLite implementation for targets, findings, entities, relationships, and timeline events.
  - `backend/plugins/email_plugin.py`: MVP plugin for email search (Hunter.io if key present, else pattern extraction).
  - `backend/plugins/github_plugin.py`: MVP plugin for GitHub user/repo search.
  - `backend/plugins/username_plugin.py`: MVP plugin for username search across platforms.
  - `backend/plugins/google_plugin.py`: MVP plugin for Google dorking/search.
  - `backend/plugins/metadata_plugin.py`: MVP plugin for metadata extraction from files/URLs.
- Existing files to modify:
  - `backend/models.py`: Add `Entity`, `Relationship`, `TimelineEvent`, `EntityType`, `RelationshipType`, `TimelineEventType` models.
  - `backend/engine.py`: Integrate storage layer, emit timeline events, extract entities from plugin responses, and build relationships.
  - `backend/report.py`: Refactor to modular section-based generation (Summary, Executive, Target Info, Key Findings, Evidence, Relationships, Timeline, Risk, Recommendations, Appendix).
  - `backend/main.py`: Add endpoints for entities, relationships, timeline, and plugin listing; centralize settings for new API keys (VirusTotal, Shodan, Hunter, IntelX, Censys, AbuseIPDB, URLScan).
  - `frontend/index.html`: Add Dashboard, Investigations, Results, Plugins pages; restructure navigation.
  - `frontend/app.js`: Implement UI logic for new pages and API consumption.
  - `frontend/style.css`: Update styles for new layout.
  - `README.md`: Document new architecture, database schema, and plugin development guide.
- Configuration:
  - `config/.env.example`: Add new API key placeholders.

[Functions]
Single sentence describing function modifications.

New functions will handle entity extraction and timeline logging; existing functions in the engine and report generator will be updated to use the storage layer and new models.

- New functions:
  - `backend/storage.py` -> `StorageInterface` (abstract) and `SQLiteStorage` (concrete) with methods: `save_entity`, `get_entity`, `save_relationship`, `log_timeline_event`, `get_timeline`, `get_entities_for_target`, `get_relationships_for_target`.
  - `backend/engine.py` -> `extract_entities(response: PluginResponse) -> List[Entity]`: Parse plugin evidence to identify entities (domain, email, github, etc.).
  - `backend/engine.py` -> `build_relationships(entities: List[Entity], plugin_name: str) -> List[Relationship]`: Infer relationships between discovered entities.
  - `backend/report.py` -> `generate_section_*`: Modular functions for each report section.
- Modified functions:
  - `backend/engine.py` -> `run_investigation`: Add timeline events at start, planning, each plugin start/complete, and report generation. Replace direct sqlite calls with storage layer.
  - `backend/main.py` -> `get_settings` / `save_settings`: Extend to support new provider keys.
  - `backend/main.py` -> `create_report`: Use new report generator structure.

[Classes]
Single sentence describing class modifications.

New storage and plugin classes will be introduced; the `InvestigationEngine` and `ReportGenerator` will be extended with entity and timeline capabilities.

- New classes:
  - `backend/storage.py` -> `StorageInterface` (ABC): Defines the database-agnostic contract.
  - `backend/storage.py` -> `SQLiteStorage(StorageInterface)`: Implements the contract using SQLite, matching the schema in the user's feedback.
  - `backend/plugins/email_plugin.py` -> `EmailPlugin(BasePlugin)`: Implements email discovery.
  - `backend/plugins/github_plugin.py` -> `GithubPlugin(BasePlugin)`: Implements GitHub search.
  - `backend/plugins/username_plugin.py` -> `UsernamePlugin(BasePlugin)`: Implements username enumeration.
  - `backend/plugins/google_plugin.py` -> `GooglePlugin(BasePlugin)`: Implements search-based discovery.
  - `backend/plugins/metadata_plugin.py` -> `MetadataPlugin(BasePlugin)`: Implements metadata extraction.
- Modified classes:
  - `backend/engine.py` -> `InvestigationEngine`: Add `storage: StorageInterface` attribute; update `run_investigation` to log timeline and persist entities/relationships.
  - `backend/report.py` -> `ReportGenerator`: Refactor to use a list of section generators; add `generate_markdown_v2`, `generate_html_v2`, `generate_json_v2` methods that assemble sections.

[Dependencies]
Single sentence describing dependency modifications.

No new external dependencies are required; the project will continue using `fastapi`, `httpx`, `pydantic`, and `python-dotenv`. The `whois` system tool remains a dependency for the WHOIS plugin.

[Testing]
Single sentence describing testing approach.

Manual API testing via `curl` or the frontend, plus a Python script to verify database schema creation and entity extraction logic. Ensure the project builds and runs after each feature addition.

[Implementation Order]
Single sentence describing the implementation sequence.

Numbered steps showing the logical order of changes to minimize conflicts and ensure successful integration.

1. Update `backend/models.py` with Entity, Relationship, and TimelineEvent models.
2. Create `backend/storage.py` with SQLiteStorage implementing the new schema (entities, relationships, timeline tables).
3. Refactor `backend/engine.py` to use StorageInterface, emit timeline events, and extract entities/relationships from plugin responses.
4. Create MVP plugins: email, github, username, google, metadata (following the BasePlugin pattern).
5. Update `backend/planner.py` templates to include new plugins for relevant target types.
6. Refactor `backend/report.py` into modular section-based generators (Markdown, JSON, HTML).
7. Extend `backend/main.py` with endpoints for entities, relationships, timeline, and centralized settings for new API keys.
8. Update `frontend/index.html`, `app.js`, and `style.css` to add Dashboard, Investigations, Results, Plugins pages and improve organization.
9. Update `config/.env.example` and `README.md` with new architecture and setup instructions.
10. Verify the application builds and runs; test a full investigation cycle via the UI or API.