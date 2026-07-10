import logging
import re
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
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.storage = SQLiteStorage(db_path)
        self.plugin_manager = PluginManager()
        self.planner = AIPlanner()

        # Ensure plugins are discovered on startup
        self.plugin_manager.discover_plugins()

    async def run_investigation(self, target_id: int, target_type: TargetType, query: str, use_dynamic: bool = False) -> dict[str, Any]:
        """
        The main entry point for running an investigation.
        """
        logger.info(f"Starting investigation for target {target_id} ({target_type}): {query}")

        # Log investigation created
        self.storage.log_timeline_event(TimelineEvent(
            target_id=target_id,
            event_type=TimelineEventType.INVESTIGATION_CREATED,
            description=f"Investigation started for {query} ({target_type.value})"
        ))

        self.storage.update_target_status(target_id, InvestigationStatus.RUNNING.value)

        try:
            # 1. Plan the investigation
            steps = await self.planner.plan_investigation(target_type, query, use_dynamic)
            logger.info(f"Plan generated: {steps}")

            self.storage.log_timeline_event(TimelineEvent(
                target_id=target_id,
                event_type=TimelineEventType.PLANNING_COMPLETED,
                description=f"Planning completed. Steps: {', '.join(steps)}"
            ))

            all_results: list[PluginResponse] = []

            # 2. Execute each step
            for plugin_name in steps:
                logger.info(f"Executing step: {plugin_name}")

                self.storage.log_timeline_event(TimelineEvent(
                    target_id=target_id,
                    event_type=TimelineEventType.PLUGIN_STARTED,
                    plugin=plugin_name,
                    description=f"Plugin {plugin_name} started"
                ))

                try:
                    results = await self.plugin_manager.execute_plugin(plugin_name, query, target_type)

                    for res in results:
                        all_results.append(res)
                        self.storage.save_finding(target_id, res.provider, res.confidence, res.evidence)

                        # Extract entities and relationships
                        entities = self.extract_entities(res, target_id)
                        saved_entities = []
                        for entity in entities:
                            entity_id = self.storage.save_entity(entity)
                            entity.id = entity_id
                            saved_entities.append(entity)
                            self.storage.log_timeline_event(TimelineEvent(
                                target_id=target_id,
                                event_type=TimelineEventType.ENTITY_DISCOVERED,
                                plugin=res.provider,
                                entity_id=entity_id,
                                description=f"Entity discovered: {entity.type.value} = {entity.value}"
                            ))

                        relationships = self.build_relationships(saved_entities, res.provider)
                        for rel in relationships:
                            self.storage.save_relationship(rel)
                            self.storage.log_timeline_event(TimelineEvent(
                                target_id=target_id,
                                event_type=TimelineEventType.RELATIONSHIP_DISCOVERED,
                                plugin=res.provider,
                                description=f"Relationship: {rel.relationship_type.value}"
                            ))

                    self.storage.log_timeline_event(TimelineEvent(
                        target_id=target_id,
                        event_type=TimelineEventType.PLUGIN_COMPLETED,
                        plugin=plugin_name,
                        description=f"Plugin {plugin_name} completed"
                    ))
                except Exception as plugin_exc:
                    logger.error(f"Plugin {plugin_name} failed: {plugin_exc}")
                    self.storage.log_timeline_event(TimelineEvent(
                        target_id=target_id,
                        event_type=TimelineEventType.ERROR,
                        plugin=plugin_name,
                        severity="error",
                        description=f"Plugin {plugin_name} failed: {str(plugin_exc)}"
                    ))

            # 3. Mark as completed
            self.storage.update_target_status(target_id, InvestigationStatus.COMPLETED.value)

            self.storage.log_timeline_event(TimelineEvent(
                target_id=target_id,
                event_type=TimelineEventType.REPORT_GENERATED,
                description="Investigation completed"
            ))

            return {
                "target_id": target_id,
                "status": InvestigationStatus.COMPLETED.value,
                "steps_executed": steps,
                "findings_count": len(all_results),
                "results": [res.dict() for res in all_results]
            }

        except Exception as e:
            logger.exception(f"Investigation failed for target {target_id}: {e}")
            self.storage.update_target_status(target_id, InvestigationStatus.FAILED.value)
            self.storage.log_timeline_event(TimelineEvent(
                target_id=target_id,
                event_type=TimelineEventType.ERROR,
                severity="critical",
                description=f"Investigation failed: {str(e)}"
            ))
            return {
                "target_id": target_id,
                "status": InvestigationStatus.FAILED.value,
                "error": str(e)
            }

    def extract_entities(self, response: PluginResponse, target_id: int) -> list[Entity]:
        """Parse plugin evidence/raw output and identify useful entities."""
        entities: list[Entity] = []
        seen: set[tuple[EntityType, str]] = set()

        def add_entity(
            etype: EntityType,
            value: str,
            confidence: float = 0.8,
            display: str | None = None,
        ) -> None:
            normalized = value.strip() if isinstance(value, str) else ""
            if not normalized:
                return

            dedupe_key = (etype, normalized.lower())
            if dedupe_key in seen:
                return
            seen.add(dedupe_key)

            entities.append(
                Entity(
                    type=etype,
                    value=normalized,
                    display_name=display,
                    confidence=confidence,
                    metadata_json={"source": response.provider, "target_id": target_id},
                )
            )

        def inspect_value(value: Any) -> None:
            if isinstance(value, list):
                for item in value:
                    inspect_value(item)
                return
            if isinstance(value, dict):
                for item in value.values():
                    inspect_value(item)
                return
            if not isinstance(value, str):
                return

            val = value.strip()
            low = val.lower()

            if "github.com/" in low:
                add_entity(EntityType.GITHUB, val, response.confidence)
            elif "@" in val and "." in val.split("@")[-1]:
                add_entity(EntityType.EMAIL, val, response.confidence)
            elif re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", val):
                add_entity(EntityType.IP, val, response.confidence)
            elif re.match(r"^\d{11}$", val) and hasattr(EntityType, "ABN"):
                add_entity(EntityType.ABN, val, response.confidence)
            elif re.match(r"^\+?[\d\s-]{8,15}$", val):
                add_entity(EntityType.PHONE, val, response.confidence)
            elif "." in val and " " not in val and not low.startswith(("http://", "https://")):
                common_tlds = [".com", ".net", ".org", ".io", ".co", ".dev", ".ai", ".bg"]
                if any(tld in low for tld in common_tlds):
                    add_entity(EntityType.DOMAIN, val, response.confidence)

        for evidence_item in response.evidence:
            inspect_value(evidence_item)

        inspect_value(response.raw)
        return entities

    def build_relationships(self, entities: list[Entity], plugin_name: str) -> list[Relationship]:
        """Infer relationships between discovered entities."""
        relationships: list[Relationship] = []

        # Domain ↔ Email
        domains = [e for e in entities if e.type == EntityType.DOMAIN and e.id is not None]
        emails = [e for e in entities if e.type == EntityType.EMAIL and e.id is not None]

        for domain in domains:
            for email in emails:
                if email.value.lower().endswith(domain.value.lower()):
                    assert domain.id is not None
                    assert email.id is not None
                    relationships.append(Relationship(
                        source_entity_id=domain.id,
                        target_entity_id=email.id,
                        relationship_type=RelationshipType.REGISTERED_TO,
                        confidence=0.75,
                        source_plugin=plugin_name
                    ))

        # Domain ↔ IP (from Shodan/VirusTotal)
        ips = [e for e in entities if e.type == EntityType.IP and e.id is not None]
        for domain in domains:
            for ip in ips:
                assert domain.id is not None
                assert ip.id is not None
                relationships.append(Relationship(
                    source_entity_id=domain.id,
                    target_entity_id=ip.id,
                    relationship_type=RelationshipType.RESOLVES_TO,
                    confidence=0.65,
                    source_plugin=plugin_name
                ))

        # Email ↔ Phone (if both present in same evidence)
        phones = [e for e in entities if e.type == EntityType.PHONE and e.id is not None]
        for email in emails:
            for phone in phones:
                assert email.id is not None
                assert phone.id is not None
                relationships.append(Relationship(
                    source_entity_id=email.id,
                    target_entity_id=phone.id,
                    relationship_type=RelationshipType.LINKED_TO,
                    confidence=0.6,
                    source_plugin=plugin_name
                ))

        return relationships
