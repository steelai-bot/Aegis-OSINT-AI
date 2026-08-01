"""Tests for AI executive summaries (C2)."""

import pytest

import backend.main as main_module
from backend.main import app, init_db
from backend.providers import AIProviderFactory
from backend.summarizer import SummaryError, build_summary_prompt, generate_summary


class _FakeResponse:
    def __init__(self, content):
        self.content = content


class _FakeProvider:
    def __init__(self, content="## Overview\nAll good.", default_model=None):
        self._content = content
        self._default_model = default_model
        self.calls: list[tuple[str, str]] = []

    async def chat(self, prompt, model):
        self.calls.append((prompt, model))
        return _FakeResponse(self._content)


TARGET = {"id": 1, "query": "example.com", "target_type": "domain", "status": "completed"}
FINDINGS = [
    {
        "source": "breach_check",
        "severity": "critical",
        "confidence": 0.9,
        "data": {"breach": "Collection1"},
    }
]
ENTITIES = [{"type": "email", "value": "admin@example.com", "confidence": 0.9}]
TIMELINE: list = []


def test_build_prompt_contains_sections_and_data():
    prompt = build_summary_prompt(TARGET, FINDINGS, ENTITIES, TIMELINE)
    assert "example.com" in prompt
    assert "breach_check" in prompt
    assert "admin@example.com" in prompt
    for section in ("Overview", "Key Findings", "Exposure & Leaks", "Risk Assessment"):
        assert section in prompt


def test_build_prompt_truncates_huge_context():
    huge = [{"source": "x", "severity": "info", "confidence": 0.1, "data": {"blob": "A" * 50000}}]
    prompt = build_summary_prompt(TARGET, huge, ENTITIES, TIMELINE)
    assert len(prompt) < 50000


@pytest.mark.asyncio
async def test_generate_summary_uses_first_configured_provider(monkeypatch):
    fake = _FakeProvider(default_model="test-model")
    monkeypatch.setattr(
        AIProviderFactory, "get_provider", lambda name: fake if name == "openrouter" else None
    )

    result = await generate_summary(TARGET, FINDINGS, ENTITIES, TIMELINE)
    assert result["provider"] == "openrouter"
    assert result["model"] == "test-model"
    assert "Overview" in result["summary"]
    assert len(fake.calls) == 1


@pytest.mark.asyncio
async def test_generate_summary_falls_back_to_next_provider(monkeypatch):
    fake = _FakeProvider()
    monkeypatch.setattr(
        AIProviderFactory, "get_provider", lambda name: fake if name == "gemini" else None
    )
    result = await generate_summary(TARGET, FINDINGS, ENTITIES, TIMELINE)
    assert result["provider"] == "gemini"


@pytest.mark.asyncio
async def test_generate_summary_no_provider_raises(monkeypatch):
    monkeypatch.setattr(AIProviderFactory, "get_provider", lambda name: None)
    with pytest.raises(SummaryError):
        await generate_summary(TARGET, FINDINGS, ENTITIES, TIMELINE)


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


class _FakeStorage:
    async def get_entities_for_target(self, target_id):
        return []

    async def get_timeline(self, target_id):
        return []


def _seed_target_with_finding() -> int:
    init_db()
    with main_module.get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO targets (query, target_type, status) VALUES (?, ?, ?)",
            ("example.com", "domain", "completed"),
        )
        target_id = cursor.lastrowid
        cursor.execute(
            "INSERT INTO findings (target_id, source, category, severity, confidence, data) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (target_id, "breach_check", "breach", "critical", 0.9, '{"breach": "Collection1"}'),
        )
        conn.commit()
    return target_id


@pytest.mark.asyncio
async def test_summary_endpoint_success_and_persists_report(monkeypatch):
    from httpx import ASGITransport, AsyncClient

    target_id = _seed_target_with_finding()
    fake = _FakeProvider(default_model="test-model")
    monkeypatch.setattr(
        AIProviderFactory, "get_provider", lambda name: fake if name == "openrouter" else None
    )
    monkeypatch.setattr(app.state, "storage", _FakeStorage(), raising=False)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post(f"/api/targets/{target_id}/summary")

    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["provider"] == "openrouter"
    assert data["report_id"] > 0

    # Persisted as an ai_summary report
    with main_module.get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT format, content FROM reports WHERE id = ?", (data["report_id"],))
        row = cursor.fetchone()
    assert row[0] == "ai_summary"
    assert "Overview" in row[1]


@pytest.mark.asyncio
async def test_summary_endpoint_404_and_422(monkeypatch):
    from httpx import ASGITransport, AsyncClient

    init_db()
    monkeypatch.setattr(app.state, "storage", _FakeStorage(), raising=False)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        missing = await ac.post("/api/targets/999999/summary")
        assert missing.status_code == 404

        # Target without findings -> 422
        with main_module.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO targets (query, target_type, status) VALUES (?, ?, ?)",
                ("empty.com", "domain", "pending"),
            )
            empty_id = cursor.lastrowid
            conn.commit()
        no_findings = await ac.post(f"/api/targets/{empty_id}/summary")
        assert no_findings.status_code == 422
