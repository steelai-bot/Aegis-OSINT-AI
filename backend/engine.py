import logging
import re
from typing import List, Dict, Any, Optional
from datetime import datetime

from backend.models import (
    TargetType, InvestigationStatus, PluginResponse, 
    Entity, EntityType, Relationship, RelationshipType, 
    TimelineEvent, TimelineEventType
)
from backend.plugin_manager import PluginManager
from backend.planner import AIPlanner
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

    async def run_investigation(self, target_id: int, target_type: TargetType, query: str, use_dynamic: bool = False) -> Dict[str, Any]:
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
            
            all_results: List[PluginResponse] = []
            
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

    def extract_entities(self, response: PluginResponse, target_id: int) -> List[Entity]:
        """Parse plugin evidence to identify entities (domain, email, github, etc.)."""
        entities: List[Entity] = []
        
        # Helper to add entity if not duplicate
        def add_entity(etype: EntityType, value: str, confidence: float = 0.8, display: Optional[str] = None):
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
                    for key, val in ev.items():
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
                            # Phone numbers (basic)
                            elif re.match(r'^\+?[\d\s-]{8,15}$', val):
                                add_entity(EntityType.PHONE, val, response.confidence)
                            # ABN (Australian Business Number)
                            elif re.match(r'^\d{11}$', val):
                                add_entity(EntityType.ABN, val, response.confidence)
                
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

    def build_relationships(self, entities: List[Entity], plugin_name: str) -> List[Relationship]:
        """Infer relationships between discovered entities."""
        relationships: List[Relationship] = []
        
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