import os
import pytest
from backend.storage import SQLiteStorage
from backend.models import Entity, EntityType

import tempfile

@pytest.fixture
def storage():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    s = SQLiteStorage(path)
    yield s
    if os.path.exists(path):
        try:
            os.remove(path)
        except Exception:
            pass

def test_save_and_get_entity(storage):
    e = Entity(type=EntityType.EMAIL, value="test@example.com", confidence=0.9)
    eid = storage.save_entity(e)
    assert eid is not None
    assert eid > 0

def test_timeline_logging(storage):
    from backend.models import TimelineEvent, TimelineEventType
    t = TimelineEvent(target_id=1, event_type=TimelineEventType.INVESTIGATION_CREATED, description="Started")
    storage.log_timeline_event(t)
    events = storage.get_timeline(1)
    assert len(events) == 1
    assert events[0].description == "Started"
