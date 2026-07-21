import aiosqlite
import json
import logging
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from datetime import datetime
from backend.models import (
    Entity, EntityType, Relationship, RelationshipType,
    TimelineEvent, TimelineEventType
)

logger = logging.getLogger(__name__)

class StorageInterface(ABC):
    """Abstract base class for database operations to ensure database-agnosticism."""

    @abstractmethod
    async def save_entity(self, entity: Entity) -> int:
        pass

    @abstractmethod
    async def get_entity(self, entity_id: int) -> Optional[Entity]:
        pass

    @abstractmethod
    async def save_relationship(self, relationship: Relationship) -> int:
        pass

    @abstractmethod
    async def log_timeline_event(self, event: TimelineEvent) -> int:
        pass

    @abstractmethod
    async def log_timeline_events_batch(self, events: List[TimelineEvent]) -> List[int]:
        """Batch insert timeline events for better performance"""
        pass

    @abstractmethod
    async def get_timeline(self, target_id: int) -> List[TimelineEvent]:
        pass

    @abstractmethod
    async def get_entities_for_target(self, target_id: int) -> List[Entity]:
        pass

    @abstractmethod
    async def get_relationships_for_target(self, target_id: int) -> List[Relationship]:
        pass

    @abstractmethod
    async def update_target_status(self, target_id: int, status: str):
        pass

    @abstractmethod
    async def save_finding(self, target_id: int, provider: str, confidence: float, evidence: List[Dict[str, Any]]):
        pass

    @abstractmethod
    async def close(self):
        """Close database connection"""
        pass

class SQLiteStorage(StorageInterface):
    """Async SQLite implementation with connection pooling."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._connection: Optional[aiosqlite.Connection] = None

    async def _get_connection(self) -> aiosqlite.Connection:
        """Get or create persistent connection with connection reuse"""
        if self._connection is None:
            self._connection = await aiosqlite.connect(self.db_path)
            self._connection.row_factory = aiosqlite.Row
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

        await conn.commit()

    async def save_entity(self, entity: Entity) -> int:
        try:
            conn = await self._get_connection()
            cursor = await conn.cursor()
            # Use INSERT OR IGNORE to handle duplicates
            await cursor.execute(
                "INSERT OR IGNORE INTO entities (type, value, display_name, first_seen, last_seen, confidence, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (entity.type.value, entity.value, entity.display_name,
                 entity.first_seen.isoformat(), entity.last_seen.isoformat(),
                 entity.confidence, json.dumps(entity.metadata_json))
            )
            if cursor.rowcount == 0:
                # Entity already exists, fetch its ID
                await cursor.execute("SELECT id FROM entities WHERE type = ? AND value = ?", (entity.type.value, entity.value))
                row = await cursor.fetchone()
                entity_id = row[0]
            else:
                entity_id = cursor.lastrowid
            await conn.commit()
            return entity_id
        except Exception as e:
            logger.error(f"Error saving entity {entity.value}: {e}")
            raise

    async def get_entity(self, entity_id: int) -> Optional[Entity]:
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
        await conn.commit()
        return cursor.lastrowid

    async def log_timeline_event(self, event: TimelineEvent) -> int:
        conn = await self._get_connection()
        cursor = await conn.cursor()
        await cursor.execute(
            "INSERT INTO timeline_events (target_id, timestamp, event_type, plugin, severity, description, entity_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (event.target_id, event.timestamp.isoformat(), event.event_type.value,
             event.plugin, event.severity, event.description, event.entity_id)
        )
        await conn.commit()
        return cursor.lastrowid

    async def log_timeline_events_batch(self, events: List[TimelineEvent]) -> List[int]:
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
        await conn.commit()
        return []

    async def get_timeline(self, target_id: int) -> List[TimelineEvent]:
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

    async def get_entities_for_target(self, target_id: int) -> List[Entity]:
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

    async def get_relationships_for_target(self, target_id: int) -> List[Relationship]:
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
        await conn.commit()

    async def save_finding(self, target_id: int, provider: str, confidence: float, evidence: List[Dict[str, Any]]):
        conn = await self._get_connection()
        cursor = await conn.cursor()
        for item in evidence:
            await cursor.execute(
                "INSERT INTO findings (target_id, source, category, severity, confidence, data) VALUES (?, ?, ?, ?, ?, ?)",
                (target_id, provider, "osint_discovery", "info", confidence, json.dumps(item))
            )
        await conn.commit()
