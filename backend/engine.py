import asyncio
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

# --- Pivot configuration (person-centric investigations) ---
MAX_PIVOT_DEPTH = 2
MAX_PIVOT_QUERIES_PER_ROUND = 8
PIVOT_CONFIDENCE_DECAY = 0.8
MIN_PIVOT_CONFIDENCE = 0.4

# Entity types worth re-investigating and the target type they map to
PIVOT_ENTITY_TO_TARGET: dict[EntityType, TargetType] = {
    EntityType.EMAIL: TargetType.EMAIL,
    EntityType.USERNAME: TargetType.USERNAME,
    EntityType.PHONE: TargetType.PHONE,
    EntityType.DOMAIN: TargetType.DOMAIN,
}

# Person-search seed fields and how each one is investigated
SEED_FIELD_TO_TARGET: dict[str, TargetType] = {
    "full_name": TargetType.PERSON,
    "email": TargetType.EMAIL,
    "phone": TargetType.PHONE,
    "username": TargetType.USERNAME,
}
# Free-text address seeds have no dedicated plugins - search-oriented steps only
ADDRESS_SEED_STEPS = ["google_dorking", "darkweb_monitor", "stealer_logs"]


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
            raise RuntimeError(
                "Use InvestigationEngine.get_instance() instead of direct instantiation"
            )
        self.db_path = db_path
        self.storage = SQLiteStorage(db_path)
        self.plugin_manager = PluginManager()
        self.planner = AIPlanner()
        self._initialized = False

    async def initialize(self):
        self.plugin_manager.discover_plugins()
        self._initialized = True

    async def run_investigation(
        self, target_id: int, target_type: TargetType, query: str, use_dynamic: bool = False
    ) -> dict[str, Any]:
        """
        The main entry point for running an investigation.
        Executes plugins in parallel WITHOUT holding a DB transaction (plugin
        network calls can take 30s+ and must never hold the SQLite write lock,
        otherwise concurrent requests fail with 'database is locked'), then
        persists all results in a short transaction.
        """
        logger.info(f"Starting investigation for target {target_id} ({target_type}): {query}")

        try:
            # Short transaction: record investigation start (fast, local writes only)
            async with self.storage.transaction():
                await self.storage.log_timeline_event(
                    TimelineEvent(
                        target_id=target_id,
                        event_type=TimelineEventType.INVESTIGATION_CREATED,
                        description=f"Investigation started for {query} ({target_type.value})",
                    )
                )
                await self.storage.update_target_status(
                    target_id, InvestigationStatus.RUNNING.value
                )

            # Planning can involve LLM calls - runs outside any DB transaction
            steps = await self.planner.plan_investigation(target_type, query, use_dynamic)
            logger.info(f"Plan generated: {steps}")

            if not self.plugin_manager._plugins:
                self.plugin_manager.discover_plugins()

            valid_steps = []
            for s in steps:
                if s in self.plugin_manager.get_all_plugin_names():
                    status = self.plugin_manager._plugin_statuses.get(s, "enabled")
                    if status == "enabled":
                        valid_steps.append(s)
                    else:
                        logger.warning(
                            f"Plugin '{s}' is disabled due to missing credentials or dependencies. Skipping."
                        )
                else:
                    logger.warning(f"Plugin '{s}' not found in registry. Skipping.")
            steps = valid_steps

            async with self.storage.transaction():
                await self.storage.log_timeline_event(
                    TimelineEvent(
                        target_id=target_id,
                        event_type=TimelineEventType.PLANNING_COMPLETED,
                        description=f"Planning completed. Steps: {', '.join(steps)}",
                    )
                )

            all_results: list[PluginResponse] = []
            failed_count = 0
            timeline_buffer: list[TimelineEvent] = []

            # Plugin execution is network-bound - must NOT hold the DB write lock
            if steps:
                logger.info(f"Executing {len(steps)} plugins in parallel...")
                plugin_tasks = [
                    self._execute_plugin(
                        plugin_name, query, target_type, target_id, timeline_buffer
                    )
                    for plugin_name in steps
                ]
                plugin_results = await asyncio.gather(*plugin_tasks, return_exceptions=True)

                for result in plugin_results:
                    if isinstance(result, Exception):
                        logger.error(f"Plugin execution failed: {result}")
                        failed_count += 1
                    elif isinstance(result, list):
                        all_results.extend(result)

            # Short transaction: persist all results (fast, local writes only)
            async with self.storage.transaction():
                for res in all_results:
                    await self.storage.save_finding(
                        target_id, res.provider, res.confidence, res.evidence
                    )
                    entities = self.extract_entities(res, target_id)
                    saved_entities: list[Entity] = []
                    for entity in entities:
                        entity_id = await self.storage.save_entity(entity)
                        entity.id = entity_id
                        saved_entities.append(entity)
                        timeline_buffer.append(
                            TimelineEvent(
                                target_id=target_id,
                                event_type=TimelineEventType.ENTITY_DISCOVERED,
                                plugin=res.provider,
                                entity_id=entity_id,
                                description=f"Entity discovered: {entity.type.value} = {entity.value}",
                            )
                        )

                    relationships = self.build_relationships(saved_entities, res.provider)
                    for rel in relationships:
                        await self.storage.save_relationship(rel)
                        timeline_buffer.append(
                            TimelineEvent(
                                target_id=target_id,
                                event_type=TimelineEventType.RELATIONSHIP_DISCOVERED,
                                plugin=res.provider,
                                description=f"Relationship: {rel.relationship_type.value}",
                            )
                        )

                if failed_count > 0:
                    timeline_buffer.append(
                        TimelineEvent(
                            target_id=target_id,
                            event_type=TimelineEventType.ERROR,
                            severity="warning",
                            description=f"{failed_count} plugin(s) failed during investigation",
                        )
                    )

                status = (
                    InvestigationStatus.FAILED.value
                    if len(steps) > 0 and failed_count == len(steps)
                    else InvestigationStatus.COMPLETED.value
                )
                description = (
                    f"Investigation completed with {len(all_results)} findings"
                    if status == InvestigationStatus.COMPLETED.value
                    else f"Investigation failed: all {len(steps)} plugins failed"
                )

                await self.storage.update_target_status(target_id, status)
                timeline_buffer.append(
                    TimelineEvent(
                        target_id=target_id,
                        event_type=TimelineEventType.REPORT_GENERATED,
                        description=description,
                    )
                )

                if timeline_buffer:
                    await self.storage.log_timeline_events_batch(timeline_buffer)

                return {
                    "target_id": target_id,
                    "status": status,
                    "steps_executed": steps,
                    "findings_count": len(all_results),
                    "results": [res.model_dump() for res in all_results],
                }

        except Exception as e:
            logger.exception(f"Investigation failed for target {target_id}: {e}")
            try:
                async with self.storage.transaction():
                    await self.storage.update_target_status(
                        target_id, InvestigationStatus.FAILED.value
                    )
                    await self.storage.log_timeline_event(
                        TimelineEvent(
                            target_id=target_id,
                            event_type=TimelineEventType.ERROR,
                            severity="critical",
                            description=f"Investigation failed: {str(e)}",
                        )
                    )
            except Exception as tx_err:
                logger.error(f"Failed to log error to timeline: {tx_err}")
            return {
                "target_id": target_id,
                "status": InvestigationStatus.FAILED.value,
                "error": str(e),
            }

    async def _persist_results(
        self,
        target_id: int,
        results: list[PluginResponse],
        timeline_buffer: list[TimelineEvent],
        confidence_factor: float = 1.0,
    ) -> list[Entity]:
        """Persist findings/entities/relationships for a batch of plugin results.

        Returns all saved entities (with ids assigned) so callers can pivot on them.
        """
        saved: list[Entity] = []
        async with self.storage.transaction():
            for res in results:
                if confidence_factor != 1.0:
                    res = res.model_copy(
                        update={"confidence": round(res.confidence * confidence_factor, 4)}
                    )
                await self.storage.save_finding(
                    target_id, res.provider, res.confidence, res.evidence
                )
                entities = self.extract_entities(res, target_id)
                saved_entities: list[Entity] = []
                for entity in entities:
                    entity_id = await self.storage.save_entity(entity)
                    entity.id = entity_id
                    saved_entities.append(entity)
                    timeline_buffer.append(
                        TimelineEvent(
                            target_id=target_id,
                            event_type=TimelineEventType.ENTITY_DISCOVERED,
                            plugin=res.provider,
                            entity_id=entity_id,
                            description=f"Entity discovered: {entity.type.value} = {entity.value}",
                        )
                    )

                relationships = self.build_relationships(saved_entities, res.provider)
                for rel in relationships:
                    await self.storage.save_relationship(rel)
                    timeline_buffer.append(
                        TimelineEvent(
                            target_id=target_id,
                            event_type=TimelineEventType.RELATIONSHIP_DISCOVERED,
                            plugin=res.provider,
                            description=f"Relationship: {rel.relationship_type.value}",
                        )
                    )
                saved.extend(saved_entities)
        return saved

    def _enabled_steps(self, steps: list[str]) -> list[str]:
        """Filter planned steps to discovered + enabled plugins."""
        return [
            s
            for s in steps
            if s in self.plugin_manager.get_all_plugin_names()
            and self.plugin_manager._plugin_statuses.get(s, "enabled") == "enabled"
        ]

    async def run_person_investigation(
        self, target_id: int, seeds: dict[str, str], pivot_depth: int = 1
    ) -> dict[str, Any]:
        """Multi-seed person investigation with iterative entity pivoting.

        Round 0 investigates every provided seed (name, email, phone, address,
        username) with its type-appropriate plugin template. Each subsequent
        pivot round feeds newly discovered pivotable entities (emails, usernames,
        phones, domains) back through their own templates with confidence decay,
        deduplication and hard limits to prevent query explosion.
        """
        seeds = {k: (v or "").strip() for k, v in seeds.items() if (v or "").strip()}
        logger.info(f"Starting person investigation for target {target_id}: {list(seeds)}")
        pivot_depth = max(0, min(pivot_depth, MAX_PIVOT_DEPTH))

        timeline_buffer: list[TimelineEvent] = []
        all_results: list[PluginResponse] = []
        failed_count = 0
        executed: set[tuple[str, str]] = set()  # (plugin, normalized query) dedup
        queried_values: set[str] = set()

        try:
            async with self.storage.transaction():
                await self.storage.log_timeline_event(
                    TimelineEvent(
                        target_id=target_id,
                        event_type=TimelineEventType.INVESTIGATION_CREATED,
                        description=f"Person investigation started ({', '.join(seeds)})",
                    )
                )
                await self.storage.update_target_status(
                    target_id, InvestigationStatus.RUNNING.value
                )

            if not self.plugin_manager._plugins:
                self.plugin_manager.discover_plugins()

            # --- Round 0: investigate each seed with its own template ---
            round_tasks = []
            for field, value in seeds.items():
                queried_values.add(value.lower())
                if field == "address":
                    ttype = TargetType.PERSON
                    steps = self._enabled_steps(ADDRESS_SEED_STEPS)
                else:
                    ttype = SEED_FIELD_TO_TARGET.get(field, TargetType.PERSON)
                    steps = self._enabled_steps(await self.planner.plan_investigation(ttype, value))
                for plugin_name in steps:
                    key = (plugin_name, value.lower())
                    if key in executed:
                        continue
                    executed.add(key)
                    round_tasks.append(
                        self._execute_plugin(plugin_name, value, ttype, target_id, timeline_buffer)
                    )

            timeline_buffer.append(
                TimelineEvent(
                    target_id=target_id,
                    event_type=TimelineEventType.PLANNING_COMPLETED,
                    description=(
                        f"Person investigation planned: {len(round_tasks)} plugin "
                        f"executions across {len(seeds)} seed(s)"
                    ),
                )
            )

            gathered = await asyncio.gather(*round_tasks, return_exceptions=True)
            round_results: list[PluginResponse] = []
            for r in gathered:
                if isinstance(r, Exception):
                    logger.error(f"Seed plugin execution failed: {r}")
                    failed_count += 1
                elif isinstance(r, list):
                    round_results.extend(r)
            all_results.extend(round_results)
            discovered = await self._persist_results(target_id, round_results, timeline_buffer)

            # --- Pivot rounds: feed newly discovered identifiers back in ---
            for depth in range(1, pivot_depth + 1):
                candidates: list[Entity] = []
                seen: set[str] = set()
                for e in discovered:
                    if e.type not in PIVOT_ENTITY_TO_TARGET:
                        continue
                    norm = e.value.strip().lower()
                    if norm in queried_values or norm in seen:
                        continue
                    if e.confidence < MIN_PIVOT_CONFIDENCE:
                        continue
                    seen.add(norm)
                    candidates.append(e)
                    if len(candidates) >= MAX_PIVOT_QUERIES_PER_ROUND:
                        break
                if not candidates:
                    break

                timeline_buffer.append(
                    TimelineEvent(
                        target_id=target_id,
                        event_type=TimelineEventType.PLANNING_COMPLETED,
                        description=(
                            f"Pivot round {depth}: re-investigating "
                            f"{len(candidates)} discovered identifier(s)"
                        ),
                    )
                )

                pivot_tasks = []
                for e in candidates:
                    ttype = PIVOT_ENTITY_TO_TARGET[e.type]
                    norm = e.value.strip().lower()
                    queried_values.add(norm)
                    steps = self._enabled_steps(
                        await self.planner.plan_investigation(ttype, e.value)
                    )
                    for plugin_name in steps:
                        key = (plugin_name, norm)
                        if key in executed:
                            continue
                        executed.add(key)
                        pivot_tasks.append(
                            self._execute_plugin(
                                plugin_name, e.value, ttype, target_id, timeline_buffer
                            )
                        )

                gathered = await asyncio.gather(*pivot_tasks, return_exceptions=True)
                round_results = []
                for r in gathered:
                    if isinstance(r, Exception):
                        logger.error(f"Pivot plugin execution failed: {r}")
                        failed_count += 1
                    elif isinstance(r, list):
                        round_results.extend(r)
                all_results.extend(round_results)
                decay = PIVOT_CONFIDENCE_DECAY**depth
                discovered = await self._persist_results(
                    target_id, round_results, timeline_buffer, confidence_factor=decay
                )

            # --- Finalize ---
            async with self.storage.transaction():
                if failed_count > 0:
                    timeline_buffer.append(
                        TimelineEvent(
                            target_id=target_id,
                            event_type=TimelineEventType.ERROR,
                            severity="warning",
                            description=f"{failed_count} plugin(s) failed during investigation",
                        )
                    )
                status = (
                    InvestigationStatus.FAILED.value
                    if len(executed) > 0 and failed_count == len(executed)
                    else InvestigationStatus.COMPLETED.value
                )
                description = (
                    f"Person investigation completed with {len(all_results)} findings "
                    f"({len(queried_values)} identifiers investigated)"
                    if status == InvestigationStatus.COMPLETED.value
                    else "Person investigation failed: all plugin executions failed"
                )
                await self.storage.update_target_status(target_id, status)
                timeline_buffer.append(
                    TimelineEvent(
                        target_id=target_id,
                        event_type=TimelineEventType.REPORT_GENERATED,
                        description=description,
                    )
                )
                if timeline_buffer:
                    await self.storage.log_timeline_events_batch(timeline_buffer)

            return {
                "target_id": target_id,
                "status": status,
                "seeds": seeds,
                "identifiers_investigated": len(queried_values),
                "findings_count": len(all_results),
                "results": [res.model_dump() for res in all_results],
            }

        except Exception as e:
            logger.exception(f"Person investigation failed for target {target_id}: {e}")
            try:
                async with self.storage.transaction():
                    await self.storage.update_target_status(
                        target_id, InvestigationStatus.FAILED.value
                    )
                    await self.storage.log_timeline_event(
                        TimelineEvent(
                            target_id=target_id,
                            event_type=TimelineEventType.ERROR,
                            severity="critical",
                            description=f"Person investigation failed: {str(e)}",
                        )
                    )
            except Exception as tx_err:
                logger.error(f"Failed to log error to timeline: {tx_err}")
            return {
                "target_id": target_id,
                "status": InvestigationStatus.FAILED.value,
                "error": str(e),
            }

    async def _execute_plugin(
        self,
        plugin_name: str,
        query: str,
        target_type: TargetType,
        target_id: int,
        timeline_buffer: list[TimelineEvent],
    ) -> list[PluginResponse]:
        """Execute single plugin and buffer timeline events."""
        timeline_buffer.append(
            TimelineEvent(
                target_id=target_id,
                event_type=TimelineEventType.PLUGIN_STARTED,
                plugin=plugin_name,
                description=f"Plugin {plugin_name} started",
            )
        )

        try:
            results = await self.plugin_manager.execute_plugin(plugin_name, query, target_type)
            timeline_buffer.append(
                TimelineEvent(
                    target_id=target_id,
                    event_type=TimelineEventType.PLUGIN_COMPLETED,
                    plugin=plugin_name,
                    description=f"Plugin {plugin_name} completed with {len(results)} findings",
                )
            )
            return results
        except Exception as plugin_exc:
            logger.error(f"Plugin {plugin_name} failed: {plugin_exc}")
            timeline_buffer.append(
                TimelineEvent(
                    target_id=target_id,
                    event_type=TimelineEventType.ERROR,
                    plugin=plugin_name,
                    severity="error",
                    description=f"Plugin {plugin_name} failed: {str(plugin_exc)}",
                )
            )
            # Re-raise so asyncio.gather counts this as a failure and the
            # investigation status correctly reflects plugin failures.
            raise

    def extract_entities(self, response: PluginResponse, target_id: int) -> list[Entity]:
        """Parse plugin evidence to identify entities (domain, email, github, etc.)."""
        entities: list[Entity] = []
        seen_values: set[str] = set()

        # Helper to add entity if not duplicate
        def add_entity(
            etype: EntityType, value: str, confidence: float = 0.8, display: str | None = None
        ):
            if value and value.strip():
                normalized = value.strip().lower()
                if normalized not in seen_values:
                    seen_values.add(normalized)
                    entities.append(
                        Entity(
                            type=etype,
                            value=value.strip(),
                            display_name=display,
                            confidence=confidence,
                            metadata_json={"source": response.provider},
                        )
                    )

        # Pre-compiled patterns (imported from storage module)
        from backend.storage import DOMAIN_PATTERN, EMAIL_PATTERN, GITHUB_PATTERN, IPV4_PATTERN

        # Extract from evidence
        for ev in response.evidence:
            if not isinstance(ev, dict):
                continue

            for _key, val in ev.items():
                if isinstance(val, str):
                    # Email - use regex for accuracy
                    if EMAIL_PATTERN.match(val):
                        add_entity(EntityType.EMAIL, val, response.confidence)
                    # Domain - use regex
                    elif DOMAIN_PATTERN.match(val):
                        add_entity(EntityType.DOMAIN, val, response.confidence)
                    # GitHub URL
                    elif GITHUB_PATTERN.search(val):
                        add_entity(EntityType.GITHUB, val, response.confidence)
                    # IPv4 address
                    elif IPV4_PATTERN.match(val):
                        add_entity(EntityType.IP, val, response.confidence)

                # Handle lists of values
                elif isinstance(val, list):
                    for item in val:
                        if isinstance(item, str) and EMAIL_PATTERN.match(item):
                            add_entity(EntityType.EMAIL, item, response.confidence)

        # Extract from raw data
        raw = response.raw
        if isinstance(raw, dict):
            if "emails" in raw:
                for email in raw["emails"]:
                    if isinstance(email, str) and EMAIL_PATTERN.match(email):
                        add_entity(EntityType.EMAIL, email, response.confidence)
            if "domains" in raw:
                for domain in raw["domains"]:
                    if isinstance(domain, str) and DOMAIN_PATTERN.match(domain):
                        add_entity(EntityType.DOMAIN, domain, response.confidence)

        # Person-centric extraction: usernames, URLs, phones from evidence
        url_pattern = re.compile(r"^https?://[^\s<>\"']+$", re.IGNORECASE)
        phone_pattern = re.compile(r"^\+?[0-9][0-9\s\-()]{6,14}$")
        username_pattern = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{2,29}$")

        for ev in response.evidence:
            if not isinstance(ev, dict):
                continue
            for key, val in ev.items():
                key_l = str(key).lower()
                if key_l in ("usernames", "username_candidates") and isinstance(val, list):
                    for item in val:
                        if isinstance(item, str) and username_pattern.match(item):
                            add_entity(EntityType.USERNAME, item, response.confidence * 0.8)
                elif key_l in ("urls", "profiles") and isinstance(val, list):
                    for item in val:
                        if isinstance(item, str) and url_pattern.match(item):
                            add_entity(EntityType.URL, item, response.confidence * 0.8)
                        elif isinstance(item, dict):
                            u = item.get("url")
                            if isinstance(u, str) and url_pattern.match(u):
                                add_entity(EntityType.URL, u, response.confidence * 0.8)
                            uname = item.get("username")
                            if isinstance(uname, str) and username_pattern.match(uname):
                                add_entity(EntityType.USERNAME, uname, response.confidence * 0.8)
                elif key_l in ("url", "profile_url", "download_url"):
                    if isinstance(val, str) and url_pattern.match(val):
                        add_entity(EntityType.URL, val, response.confidence * 0.8)
                elif key_l in ("phone", "phones", "e164"):
                    values = val if isinstance(val, list) else [val]
                    for item in values:
                        if isinstance(item, str) and phone_pattern.match(item.strip()):
                            add_entity(EntityType.PHONE, item.strip(), response.confidence * 0.8)
                elif key_l in ("location", "address"):
                    if isinstance(val, str) and 3 <= len(val.strip()) <= 200:
                        add_entity(EntityType.ADDRESS, val.strip(), response.confidence * 0.7)

        return entities

    def build_relationships(self, entities: list[Entity], plugin_name: str) -> list[Relationship]:
        """Infer relationships between discovered entities."""
        relationships: list[Relationship] = []

        # Simple heuristic: if we have a domain and emails, link them
        domains = [e for e in entities if e.type == EntityType.DOMAIN and e.id is not None]
        emails = [e for e in entities if e.type == EntityType.EMAIL and e.id is not None]

        for domain in domains:
            for email in emails:
                if domain.id is None or email.id is None:
                    continue
                if email.value.lower().endswith(domain.value.lower()):
                    relationships.append(
                        Relationship(
                            source_entity_id=domain.id,
                            target_entity_id=email.id,
                            relationship_type=RelationshipType.REGISTERED_TO,
                            confidence=0.7,
                            source_plugin=plugin_name,
                        )
                    )

        return relationships
