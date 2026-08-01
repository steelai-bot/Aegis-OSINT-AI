import os
import tempfile
from datetime import datetime

import pytest

from backend.models import Entity, EntityType
from backend.storage import SQLiteStorage


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


@pytest.mark.asyncio
async def test_save_and_get_entity(storage):
    e = Entity(
        type=EntityType.EMAIL,
        value="test@example.com",
        confidence=0.9,
        metadata_json={"custom": datetime.now()},
    )
    eid = await storage.save_entity(e)
    assert eid is not None
    assert eid > 0


@pytest.mark.asyncio
async def test_safe_json_dumps_and_transactions(storage):
    # Test safe serialization with complex objects, pydantic models, datetimes
    await storage._get_connection()
    async with storage.transaction():
        await storage.save_finding(
            target_id=1,
            provider="test_provider",
            confidence=0.95,
            evidence=[
                {"model": Entity(type=EntityType.IP, value="127.0.0.1"), "time": datetime.now()}
            ],
        )


@pytest.mark.asyncio
async def test_transaction_error_logging(storage):
    await storage._get_connection()
    with pytest.raises(ValueError):
        async with storage.transaction():
            raise ValueError("Intentional error")


@pytest.mark.asyncio
async def test_timeline_logging(storage):
    from backend.models import TimelineEvent, TimelineEventType

    t = TimelineEvent(
        target_id=1, event_type=TimelineEventType.INVESTIGATION_CREATED, description="Started"
    )
    await storage.log_timeline_event(t)
    events = await storage.get_timeline(1)
    assert len(events) == 1
    assert events[0].description == "Started"
