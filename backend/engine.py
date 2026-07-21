import asyncio
import logging
from typing import Any

from backend.models import (
    Entity,
    EntityType,
    InvestigationStatus,
    PluginResponse,
    Relationship,
    RelationshipType,
    TargetType,
    TimelineEvent,
    TimelineEventType,
)
from backend.planner import AIPlanner
from backend.plugin_manager import PluginManager
from backend.storage import SQLiteStorage

logger = logging.getLogger(__name__)

class InvestigationEngine:
    """
    The Investigation Engine orchestrates the entire OSINT workflow.
    It uses the AIPlanner to determine the steps and the PluginManager to execute them.
    Now with parallel plugin execution and batched database writes.
    Singleton to avoid redundant plugin discovery on every request.
    """
    _instance = None

    @classmethod
    def get_instance(cls, db_path: str):
        if cls._instance is None:
            cls._instance = cls(db_path)
        return cls._instance

    def __init__(self, db_path: str):
        if self.__class__._instance is not None:
            raise RuntimeError("Use InvestigationEngine.get_instance() instead of direct instantiation")
        self.db_path = db_path
        self.storage = SQLiteStorage(db_path)
        self.plugin_manager = PluginManager()
        self.planner = AIPlanner()
        self._initialized = False

    async def initialize(self):
        self.plugin_manager.discover_plugins()
        self._initialized = True

    async def run_investigation(self, target_id: int, target_type: TargetType, query: str, use_dynamic: bool = False) -> dict[str, Any]:
        """
        The main entry point for running an investigation.
        Executes plugins in parallel, then persists all results in a single DB transaction.
        """
        logger.info(f"Starting investigation for target {target_id} ({target_type}): {query}")

        try:
            async with self.storage.transaction():
                await self.storage.log_timeline_event(TimelineEvent(
                    target_id=target_id,
                    event_type=TimelineEventType.INVESTIGATION_CREATED,
                    description=f"Investigation started for {query} ({target_type.value})"
                ))

                await self.storage.update_target_status(target_id, InvestigationStatus.RUNNING.value)

                steps = await self.planner.plan_investigation(target_type, query, use_dynamic)
                logger.info(f"Plan generated: {steps}")

                await self.storage.log_timeline_event(TimelineEvent(
                    target_id=target_id,
                    event_type=TimelineEventType.PLANNING_COMPLETED,
                    description=f"Planning completed. Steps: {', '.join(steps)}"
                ))

                all_results: list[PluginResponse] = []
                failed_count = 0
                timeline_buffer: list[TimelineEvent] = []

                if steps:
                    logger.info(f"Executing {len(steps)} plugins in parallel...")
                    plugin_tasks = [
                        self._execute_plugin(plugin_name, query, target_type, target_id, timeline_buffer)
                        for plugin_name in steps
                    ]
                    plugin_results = await asyncio.gather(*plugin_tasks, return_exceptions=True)

                    for result in plugin_results:
                        if isinstance(result, Exception):
                            logger.error(f"Plugin execution failed: {result}")
                            failed_count += 1
                        elif isinstance(result, list):
                            all_results.extend(result)

                for res in all_results:
                    await self.storage.save_finding(target_id, res.provider, res.confidence, res.evidence)
                    entities = self.extract_entities(res, target_id)
                    saved_entities: list[Entity] = []
                    for entity in entities:
                        entity_id = await self.storage.save_entity(entity)
                        entity.id = entity_id
                        saved_entities.append(entity)
                        timeline_buffer.append(TimelineEvent(
                            target_id=target_id,
                            event_type=TimelineEventType.ENTITY_DISCOVERED,
                            plugin=res.provider,
                            entity_id=entity_id,
                            description=f"Entity discovered: {entity.type.value} = {entity.value}"
                        ))

                    relationships = self.build_relationships(saved_entities, res.provider)
                    for rel in relationships:
                        await self.storage.save_relationship(rel)
                        timeline_buffer.append(TimelineEvent(
                            target_id=target_id,
                            event_type=TimelineEventType.RELATIONSHIP_DISCOVERED,
                            plugin=res.provider,
                            description=f"Relationship: {rel.relationship_type.value}"
                        ))

                if failed_count > 0:
                    timeline_buffer.append(TimelineEvent(
                        target_id=target_id,
                        event_type=TimelineEventType.ERROR,
                        severity="warning",
                        description=f"{failed_count} plugin(s) failed during investigation"
                    ))

                status = InvestigationStatus.FAILED.value if len(steps) > 0 and failed_count == len(steps) else InvestigationStatus.COMPLETED.value
                description = f"Investigation completed with {len(all_results)} findings" if status == InvestigationStatus.COMPLETED.value else f"Investigation failed: all {len(steps)} plugins failed"

                await self.storage.update_target_status(target_id, status)
                timeline_buffer.append(TimelineEvent(
                    target_id=target_id,
                    event_type=TimelineEventType.REPORT_GENERATED,
                    description=description
                ))

                if timeline_buffer:
                    await self.storage.log_timeline_events_batch(timeline_buffer)

                return {
                    "target_id": target_id,
                    "status": status,
                    "steps_executed": steps,
                    "findings_count": len(all_results),
                    "results": [res.model_dump() for res in all_results]
                }

        except Exception as e:
            logger.exception(f"Investigation failed for target {target_id}: {e}")
            try:
                async with self.storage.transaction():
                    await self.storage.update_target_status(target_id, InvestigationStatus.FAILED.value)
                    await self.storage.log_timeline_event(TimelineEvent(
                        target_id=target_id,
                        event_type=TimelineEventType.ERROR,
                        severity="critical",
                        description=f"Investigation failed: {str(e)}"
                    ))
            except Exception as tx_err:
                logger.error(f"Failed to log error to timeline: {tx_err}")
            return {
                "target_id": target_id,
                "status": InvestigationStatus.FAILED.value,
                "error": str(e)
            }

    async def _execute_plugin(self, plugin_name: str, query: str, target_type: TargetType, target_id: int, timeline_buffer: list[TimelineEvent]) -> list[PluginResponse]:
        """Execute single plugin and buffer timeline events."""
        timeline_buffer.append(TimelineEvent(
            target_id=target_id,
            event_type=TimelineEventType.PLUGIN_STARTED,
            plugin=plugin_name,
            description=f"Plugin {plugin_name} started"
        ))

        try:
            results = await self.plugin_manager.execute_plugin(plugin_name, query, target_type)
            timeline_buffer.append(TimelineEvent(
                target_id=target_id,
                event_type=TimelineEventType.PLUGIN_COMPLETED,
                plugin=plugin_name,
                description=f"Plugin {plugin_name} completed with {len(results)} findings"
            ))
            return results
        except Exception as plugin_exc:
            logger.error(f"Plugin {plugin_name} failed: {plugin_exc}")
            timeline_buffer.append(TimelineEvent(
                target_id=target_id,
                event_type=TimelineEventType.ERROR,
                plugin=plugin_name,
                severity="error",
                description=f"Plugin {plugin_name} failed: {str(plugin_exc)}"
            ))
            return []

    def extract_entities(self, response: PluginResponse, target_id: int) -> list[Entity]:
        """Parse plugin evidence to identify entities (domain, email, github, etc.)."""
        entities: list[Entity] = []

        # Helper to add entity if not duplicate
        def add_entity(etype: EntityType, value: str, confidence: float = 0.8, display: str | None = None):
            if value and value.strip():
                entities.append(Entity(
                    type=etype,
                    value=value.strip(),
                    display_name=display,
                    confidence=confidence,
                    metadata_json={"source": response.provider}
                ))

        # Extract from evidence
        for ev in response.evidence:
            if not isinstance(ev, dict):
                continue

            # Common patterns
            for _key, val in ev.items():
                if isinstance(val, str):
                    # Email
                    if '@' in val and '.' in val.split('@')[-1]:
                        add_entity(EntityType.EMAIL, val, response.confidence)
                    # Domain
                    elif '.' in val and ' ' not in val and not val.startswith('http'):
                        if any(tld in val.lower() for tld in ['.com', '.net', '.org', '.io', '.co', '.dev']):
                            add_entity(EntityType.DOMAIN, val, response.confidence)
                    # GitHub
                    elif 'github.com/' in val:
                        add_entity(EntityType.GITHUB, val, response.confidence)
                    # IP
                    elif val.replace('.', '').isdigit() and val.count('.') == 3:
                        add_entity(EntityType.IP, val, response.confidence)

                # Handle lists of values
                if isinstance(val, list):
                    for item in val:
                        if isinstance(item, str) and '@' in item:
                            add_entity(EntityType.EMAIL, item, response.confidence)

        # Extract from raw data
        raw = response.raw
        if isinstance(raw, dict):
            # Check for common keys
            if 'emails' in raw:
                for email in raw['emails']:
                    if isinstance(email, str):
                        add_entity(EntityType.EMAIL, email, response.confidence)
            if 'domains' in raw:
                for domain in raw['domains']:
                    if isinstance(domain, str):
                        add_entity(EntityType.DOMAIN, domain, response.confidence)

        return entities

    def build_relationships(self, entities: list[Entity], plugin_name: str) -> list[Relationship]:
        """Infer relationships between discovered entities."""
        relationships: list[Relationship] = []

        # Simple heuristic: if we have a domain and emails, link them
        domains = [e for e in entities if e.type == EntityType.DOMAIN and e.id is not None]
        emails = [e for e in entities if e.type == EntityType.EMAIL and e.id is not None]

        for domain in domains:
            for email in emails:
                if email.value.lower().endswith(domain.value.lower()):
                    relationships.append(Relationship(
                        source_entity_id=domain.id,
                        target_entity_id=email.id,
                        relationship_type=RelationshipType.REGISTERED_TO,
                        confidence=0.7,
                        source_plugin=plugin_name
                    ))

        return relationships
