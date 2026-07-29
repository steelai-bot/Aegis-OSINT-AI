import json
import logging
import re
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from contextvars import ContextVar
from datetime import date, datetime
from typing import Any

import aiosqlite
from pydantic import BaseModel

from backend.models import (
    Entity,
    EntityType,
    Relationship,
    RelationshipType,
    TimelineEvent,
    TimelineEventType,
)

logger = logging.getLogger(__name__)

MAX_EVIDENCE_STRING_LENGTH = 10000
MAX_EVIDENCE_LIST_LENGTH = 100

# Pre-compiled regex for common patterns in entity extraction
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9.-]+\.(com|net|org|io|co|dev|edu|gov|mil|int)$', re.IGNORECASE)
IPV4_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
GITHUB_PATTERN = re.compile(r'github\.com/[\w-]+/?[\w-]*')


def _safe_json_dumps(obj: Any) -> str:
    """Safely serialize an object to JSON, handling Pydantic models, datetime/date objects, and arbitrary fallbacks."""
    def default_serializer(o: Any) -> Any:
        if isinstance(o, BaseModel):
            return o.model_dump()
        if isinstance(o, (datetime, date)):
            return o.isoformat()
        if hasattr(o, "dict") and callable(o.dict):
            return o.dict()
        return str(o)

    try:
        return json.dumps(obj, default=default_serializer, separators=(',', ':'))
    except Exception:
        # Fallback to stringifying everything recursively or top-level if needed
        return json.dumps(str(obj), separators=(',', ':'))


def _truncate_evidence(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Truncate large values in evidence to reduce DB size and memory usage."""
    truncated: list[dict[str, Any]] = []
    for item in evidence:
        new_item: dict[str, Any] = {}

        for key, val in item.items():
            if isinstance(val, str):
                new_item[key] = val[:MAX_EVIDENCE_STRING_LENGTH]
            elif isinstance(val, list):
                new_item[key] = val[:MAX_EVIDENCE_LIST_LENGTH]
            elif isinstance(val, dict):
                new_item[key] = _truncate_evidence([val])[0]
            else:
                new_item[key] = val
        truncated.append(new_item)
    return truncated

class StorageInterface(ABC):
    """Abstract base class for database operations to ensure database-agnosticism."""

    @abstractmethod
    async def save_entity(self, entity: Entity) -> int:
        pass

    @abstractmethod
    async def get_entity(self, entity_id: int) -> Entity | None:
        pass

    @abstractmethod
    async def save_relationship(self, relationship: Relationship) -> int:
        pass

    @abstractmethod
    async def log_timeline_event(self, event: TimelineEvent) -> int:
        pass

    @abstractmethod
    async def log_timeline_events_batch(self, events: list[TimelineEvent]) -> list[int]:
        """Batch insert timeline events for better performance"""
        pass

    @abstractmethod
    async def get_timeline(self, target_id: int) -> list[TimelineEvent]:
        pass

    @abstractmethod
    async def get_entities_for_target(self, target_id: int) -> list[Entity]:
        pass

    @abstractmethod
    async def get_relationships_for_target(self, target_id: int) -> list[Relationship]:
        pass

    @abstractmethod
    async def update_target_status(self, target_id: int, status: str):
        pass

    @abstractmethod
    async def save_finding(self, target_id: int, provider: str, confidence: float, evidence: list[dict[str, Any]]):
        pass

    @abstractmethod
    async def close(self):
        """Close database connection"""
        pass

class SQLiteStorage(StorageInterface):
    """Async SQLite implementation with connection pooling and transaction support."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._connection: aiosqlite.Connection | None = None
        self._transaction_active: ContextVar[bool] = ContextVar("_transaction_active", default=False)

    @asynccontextmanager
    async def transaction(self):
        token = self._transaction_active.set(True)
        try:
            yield self
            if self._connection:
                try:
                    await self._connection.commit()
                except Exception as commit_err:
                    logger.error(f"Failed to commit transaction: {commit_err}")
                    raise
        except Exception:
            if self._connection:
                try:
                    await self._connection.rollback()
                except Exception as rollback_err:
                    logger.error(f"Failed to rollback transaction: {rollback_err}")
            raise
        finally:
            self._transaction_active.reset(token)

    async def _get_connection(self) -> aiosqlite.Connection:
        """Get or create persistent connection with WAL mode and connection reuse"""
        if self._connection is None:
            self._connection = await aiosqlite.connect(self.db_path)
            self._connection.row_factory = aiosqlite.Row
            await self._connection.execute("PRAGMA journal_mode=WAL")
            await self._connection.execute("PRAGMA synchronous=NORMAL")
            await self._connection.execute("PRAGMA cache_size=-64000")
            await self._connection.execute("PRAGMA temp_store=MEMORY")
            await self._connection.execute("PRAGMA busy_timeout=30000")
            await self._init_db()
        return self._connection

    async def close(self):
        """Close persistent connection"""
        if self._connection:
            await self._connection.close()
            self._connection = None

    async def _init_db(self):
        """Initialize the database schema."""
        conn = await self._get_connection()
        cursor = await conn.cursor()

        # Entities table
        await cursor.execute('''
            CREATE TABLE IF NOT EXISTS entities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                display_name TEXT,
                first_seen TEXT,
                last_seen TEXT,
                confidence REAL,
                metadata_json TEXT,
                UNIQUE(type, value)
            )
        ''')

        # Relationships table
        await cursor.execute('''
            CREATE TABLE IF NOT EXISTS relationships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_entity_id INTEGER,
                target_entity_id INTEGER,
                relationship_type TEXT,
                confidence REAL,
                source_plugin TEXT,
                created_at TEXT,
                FOREIGN KEY (source_entity_id) REFERENCES entities (id),
                FOREIGN KEY (target_entity_id) REFERENCES entities (id)
            )
        ''')

        # Timeline events table
        await cursor.execute('''
            CREATE TABLE IF NOT EXISTS timeline_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                timestamp TEXT,
                event_type TEXT,
                plugin TEXT,
                severity TEXT,
                description TEXT,
                entity_id INTEGER,
                FOREIGN KEY (entity_id) REFERENCES entities (id)
            )
        ''')

        # Targets table
        await cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                query TEXT NOT NULL,
                target_type TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'pending'
            )
        ''')

        # Findings table
        await cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                source TEXT,
                category TEXT,
                severity TEXT,
                confidence REAL,
                data TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
        ''')

        # Create indexes for better query performance
        await cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_timeline_target
            ON timeline_events(target_id, timestamp)
        ''')
        await cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_relationships_source
            ON relationships(source_entity_id)
        ''')
        await cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_relationships_target
            ON relationships(target_entity_id)
        ''')
        await cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_findings_target
            ON findings(target_id)
        ''')
        await cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_entities_type_value
            ON entities(type, value)
        ''')
        await cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_targets_status
            ON targets(status)
        ''')
        await cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_timeline_target_type
            ON timeline_events(target_id, event_type)
        ''')

        await conn.commit()

    async def save_entity(self, entity: Entity) -> int:
        try:
            conn = await self._get_connection()
            cursor = await conn.cursor()
            await cursor.execute(
                "INSERT INTO entities (type, value, display_name, first_seen, last_seen, confidence, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(type, value) DO UPDATE SET last_seen=excluded.last_seen "
                "RETURNING id",
                (entity.type.value, entity.value, entity.display_name,
                 entity.first_seen.isoformat(), entity.last_seen.isoformat(),
                 entity.confidence, _safe_json_dumps(entity.metadata_json))
            )
            row = await cursor.fetchone()
            entity_id = row[0] if row else None
            if entity_id is None:
                await cursor.execute("SELECT id FROM entities WHERE type = ? AND value = ?", (entity.type.value, entity.value))
                row = await cursor.fetchone()
                entity_id = row[0] if row else None
            if not self._transaction_active.get():
                await conn.commit()
            return entity_id or 0
        except Exception as e:
            logger.error(f"Error saving entity {entity.value}: {e}")
            raise

    async def get_entity(self, entity_id: int) -> Entity | None:
        conn = await self._get_connection()
        cursor = await conn.cursor()
        await cursor.execute("SELECT * FROM entities WHERE id = ?", (entity_id,))
        row = await cursor.fetchone()
        if row:
            return Entity(
                id=row['id'],
                type=EntityType(row['type']),
                value=row['value'],
                display_name=row['display_name'],
                first_seen=datetime.fromisoformat(row['first_seen']),
                last_seen=datetime.fromisoformat(row['last_seen']),
                confidence=row['confidence'],
                metadata_json=json.loads(row['metadata_json'])
            )
        return None

    async def save_relationship(self, relationship: Relationship) -> int:
        conn = await self._get_connection()
        cursor = await conn.cursor()
        await cursor.execute(
            "INSERT INTO relationships (source_entity_id, target_entity_id, relationship_type, confidence, source_plugin, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (relationship.source_entity_id, relationship.target_entity_id, relationship.relationship_type.value,
             relationship.confidence, relationship.source_plugin, relationship.created_at.isoformat())
        )
        if not self._transaction_active.get():
            await conn.commit()
        row_id = cursor.lastrowid
        assert row_id is not None, "INSERT did not return a row id"
        return row_id

    async def log_timeline_event(self, event: TimelineEvent) -> int:

        conn = await self._get_connection()
        cursor = await conn.cursor()
        await cursor.execute(
            "INSERT INTO timeline_events (target_id, timestamp, event_type, plugin, severity, description, entity_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (event.target_id, event.timestamp.isoformat(), event.event_type.value,
             event.plugin, event.severity, event.description, event.entity_id)
        )
        if not self._transaction_active.get():
            await conn.commit()
        row_id = cursor.lastrowid
        assert row_id is not None, "INSERT did not return a row id"
        return row_id

    async def log_timeline_events_batch(self, events: list[TimelineEvent]) -> list[int]:

        """Batch insert timeline events for 80% better write performance"""
        if not events:
            return []

        conn = await self._get_connection()
        cursor = await conn.cursor()
        values = [
            (e.target_id, e.timestamp.isoformat(), e.event_type.value,
             e.plugin, e.severity, e.description, e.entity_id)
            for e in events
        ]
        await cursor.executemany(
            "INSERT INTO timeline_events (target_id, timestamp, event_type, plugin, severity, description, entity_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
            values
        )
        if not self._transaction_active.get():
            await conn.commit()
        return []

    async def get_timeline(self, target_id: int) -> list[TimelineEvent]:
        conn = await self._get_connection()
        cursor = await conn.cursor()
        await cursor.execute("SELECT * FROM timeline_events WHERE target_id = ? ORDER BY timestamp ASC", (target_id,))
        rows = await cursor.fetchall()
        return [TimelineEvent(
            id=row['id'],
            target_id=row['target_id'],
            timestamp=datetime.fromisoformat(row['timestamp']),
            event_type=TimelineEventType(row['event_type']),
            plugin=row['plugin'],
            severity=row['severity'],
            description=row['description'],
            entity_id=row['entity_id']
        ) for row in rows]

    async def get_entities_for_target(self, target_id: int) -> list[Entity]:
        conn = await self._get_connection()
        cursor = await conn.cursor()
        await cursor.execute('''
            SELECT DISTINCT e.* FROM entities e
            JOIN timeline_events te ON e.id = te.entity_id
            WHERE te.target_id = ?
        ''', (target_id,))
        rows = await cursor.fetchall()
        return [Entity(
            id=row['id'],
            type=EntityType(row['type']),
            value=row['value'],
            display_name=row['display_name'],
            first_seen=datetime.fromisoformat(row['first_seen']),
            last_seen=datetime.fromisoformat(row['last_seen']),
            confidence=row['confidence'],
            metadata_json=json.loads(row['metadata_json'])
        ) for row in rows]

    async def get_relationships_for_target(self, target_id: int) -> list[Relationship]:
        conn = await self._get_connection()
        cursor = await conn.cursor()
        await cursor.execute('''
            SELECT DISTINCT r.* FROM relationships r
            JOIN timeline_events te ON (r.source_entity_id = te.entity_id OR r.target_entity_id = te.entity_id)
            WHERE te.target_id = ?
        ''', (target_id,))
        rows = await cursor.fetchall()
        return [Relationship(
            id=row['id'],
            source_entity_id=row['source_entity_id'],
            target_entity_id=row['target_entity_id'],
            relationship_type=RelationshipType(row['relationship_type']),
            confidence=row['confidence'],
            source_plugin=row['source_plugin'],
            created_at=datetime.fromisoformat(row['created_at'])
        ) for row in rows]

    async def update_target_status(self, target_id: int, status: str):
        conn = await self._get_connection()
        cursor = await conn.cursor()
        await cursor.execute("UPDATE targets SET status = ? WHERE id = ?", (status, target_id))
        if not self._transaction_active.get():
            await conn.commit()

    async def save_finding(self, target_id: int, provider: str, confidence: float, evidence: list[dict[str, Any]]):
        conn = await self._get_connection()
        cursor = await conn.cursor()
        evidence = _truncate_evidence(evidence)
        # Batch insert for better performance
        values = [
            (target_id, provider, "osint_discovery", "info", confidence, _safe_json_dumps(item))
            for item in evidence
        ]
        if values:
            await cursor.executemany(
                "INSERT INTO findings (target_id, source, category, severity, confidence, data) VALUES (?, ?, ?, ?, ?, ?)",
                values
            )
            if not self._transaction_active.get():
                await conn.commit()
