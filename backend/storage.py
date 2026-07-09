import sqlite3
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
    def save_entity(self, entity: Entity) -> int:
        pass

    @abstractmethod
    def get_entity(self, entity_id: int) -> Optional[Entity]:
        pass

    @abstractmethod
    def save_relationship(self, relationship: Relationship) -> int:
        pass

    @abstractmethod
    def log_timeline_event(self, event: TimelineEvent) -> int:
        pass

    @abstractmethod
    def get_timeline(self, target_id: int) -> List[TimelineEvent]:
        pass

    @abstractmethod
    def get_entities_for_target(self, target_id: int) -> List[Entity]:
        pass

    @abstractmethod
    def get_relationships_for_target(self, target_id: int) -> List[Relationship]:
        pass

    @abstractmethod
    def update_target_status(self, target_id: int, status: str):
        pass

    @abstractmethod
    def save_finding(self, target_id: int, provider: str, confidence: float, evidence: List[Dict[str, Any]]):
        pass

class SQLiteStorage(StorageInterface):
    """SQLite implementation of the StorageInterface."""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initialize the database schema."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Entities table
            cursor.execute('''
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
            cursor.execute('''
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
            cursor.execute('''
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
            
            conn.commit()

    def save_entity(self, entity: Entity) -> int:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                # Use INSERT OR IGNORE or handle conflict to get existing ID
                cursor.execute(
                    "INSERT OR IGNORE INTO entities (type, value, display_name, first_seen, last_seen, confidence, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (entity.type.value, entity.value, entity.display_name, 
                     entity.first_seen.isoformat(), entity.last_seen.isoformat(), 
                     entity.confidence, json.dumps(entity.metadata_json))
                )
                if cursor.rowcount == 0:
                    cursor.execute("SELECT id FROM entities WHERE type = ? AND value = ?", (entity.type.value, entity.value))
                    entity_id = cursor.fetchone()[0]
                else:
                    entity_id = cursor.lastrowid
                conn.commit()
                return entity_id
        except Exception as e:
            logger.error(f"Error saving entity {entity.value}: {e}")
            raise

    def get_entity(self, entity_id: int) -> Optional[Entity]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM entities WHERE id = ?", (entity_id,))
            row = cursor.fetchone()
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

    def save_relationship(self, relationship: Relationship) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO relationships (source_entity_id, target_entity_id, relationship_type, confidence, source_plugin, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (relationship.source_entity_id, relationship.target_entity_id, relationship.relationship_type.value, 
                 relationship.confidence, relationship.source_plugin, relationship.created_at.isoformat())
            )
            conn.commit()
            return cursor.lastrowid

    def log_timeline_event(self, event: TimelineEvent) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO timeline_events (target_id, timestamp, event_type, plugin, severity, description, entity_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (event.target_id, event.timestamp.isoformat(), event.event_type.value, 
                 event.plugin, event.severity, event.description, event.entity_id)
            )
            conn.commit()
            return cursor.lastrowid

    def get_timeline(self, target_id: int) -> List[TimelineEvent]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM timeline_events WHERE target_id = ? ORDER BY timestamp ASC", (target_id,))
            rows = cursor.fetchall()
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

    def get_entities_for_target(self, target_id: int) -> List[Entity]:
        # This requires a way to link entities to targets. 
        # In this schema, we can find entities via relationships or timeline events.
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT DISTINCT e.* FROM entities e 
                JOIN timeline_events te ON e.id = te.entity_id 
                WHERE te.target_id = ?
            ''', (target_id,))
            rows = cursor.fetchall()
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

    def get_relationships_for_target(self, target_id: int) -> List[Relationship]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT DISTINCT r.* FROM relationships r
                JOIN timeline_events te ON (r.source_entity_id = te.entity_id OR r.target_entity_id = te.entity_id)
                WHERE te.target_id = ?
            ''', (target_id,))
            rows = cursor.fetchall()
            return [Relationship(
                id=row['id'],
                source_entity_id=row['source_entity_id'],
                target_entity_id=row['target_entity_id'],
                relationship_type=RelationshipType(row['relationship_type']),
                confidence=row['confidence'],
                source_plugin=row['source_plugin'],
                created_at=datetime.fromisoformat(row['created_at'])
            ) for row in rows]

    def update_target_status(self, target_id: int, status: str):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE targets SET status = ? WHERE id = ?", (status, target_id))
            conn.commit()

    def save_finding(self, target_id: int, provider: str, confidence: float, evidence: List[Dict[str, Any]]):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            for item in evidence:
                cursor.execute(
                    "INSERT INTO findings (target_id, source, category, severity, confidence, data) VALUES (?, ?, ?, ?, ?, ?)",
                    (target_id, provider, "osint_discovery", "info", confidence, json.dumps(item))
                )
            conn.commit()