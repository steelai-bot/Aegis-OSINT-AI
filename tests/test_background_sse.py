"""Tests for background investigation mode + SSE progress streaming."""

import pytest
import pytest_asyncio

import backend.main as main_module
from backend.main import app, init_db
from backend.storage import SQLiteStorage


@pytest_asyncio.fixture
async def storage():
    """Real SQLiteStorage on the isolated test DB (creates timeline tables)."""
    init_db()
    s = SQLiteStorage(main_module.DATABASE_PATH)
    await s._get_connection()
    yield s
    await s.close()


@pytest.mark.asyncio
async def test_search_background_returns_immediately(monkeypatch):
    from httpx import ASGITransport, AsyncClient

    init_db()
    called: dict = {}

    async def fake_bg(target_id, target_type_obj, query):
        called["target_id"] = target_id
        called["query"] = query

    monkeypatch.setattr(main_module, "_run_investigation_background", fake_bg)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post(
            "/api/search",
            data={"query": "example.com", "target_type": "domain", "background": "true"},
        )

    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["status"] == "running"
    assert data["target_id"] > 0
    # Background task was dispatched (asyncio.create_task runs it on the loop)
    await main_module.asyncio.sleep(0)
    assert called.get("query") == "example.com"


@pytest.mark.asyncio
async def test_person_search_background_returns_immediately(monkeypatch):
    from httpx import ASGITransport, AsyncClient

    init_db()
    called: dict = {}

    async def fake_bg(target_id, seeds, pivot_depth):
        called["target_id"] = target_id
        called["seeds"] = seeds

    monkeypatch.setattr(main_module, "_run_person_investigation_background", fake_bg)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post(
            "/api/search/person",
            data={"full_name": "Ivan Petrov", "background": "true"},
        )

    assert resp.status_code == 200
    assert resp.json()["data"]["status"] == "running"
    await main_module.asyncio.sleep(0)
    assert called.get("seeds") == {"full_name": "Ivan Petrov"}


@pytest.mark.asyncio
async def test_sse_streams_events_and_done(storage):
    from httpx import ASGITransport, AsyncClient

    from backend.models import TimelineEvent, TimelineEventType

    # Completed target with two timeline events
    with main_module.get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO targets (query, target_type, status) VALUES (?, ?, ?)",
            ("example.com", "domain", "completed"),
        )
        target_id = cursor.lastrowid
        conn.commit()

    await storage.log_timeline_event(
        TimelineEvent(
            target_id=target_id,
            event_type=TimelineEventType.INVESTIGATION_CREATED,
            description="started",
        )
    )
    await storage.log_timeline_event(
        TimelineEvent(
            target_id=target_id,
            event_type=TimelineEventType.REPORT_GENERATED,
            description="done",
        )
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        async with ac.stream("GET", f"/api/targets/{target_id}/events") as resp:
            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith("text/event-stream")
            body = await resp.aread()

    text = body.decode()
    assert "started" in text
    assert "done" in text
    assert "event: done" in text
    assert '"status": "completed"' in text


@pytest.mark.asyncio
async def test_result_card_renders_status(storage):
    from httpx import ASGITransport, AsyncClient

    with main_module.get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO targets (query, target_type, status) VALUES (?, ?, ?)",
            ("example.com", "domain", "completed"),
        )
        target_id = cursor.lastrowid
        conn.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get(f"/api/targets/{target_id}/result-card")
        assert resp.status_code == 200
        assert "completed" in resp.text

        missing = await ac.get("/api/targets/999999/result-card")
        assert missing.status_code == 404
