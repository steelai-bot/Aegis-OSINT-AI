"""Tests for person-centric search: new plugins, detection, pivot engine, endpoint."""

import httpx
import pytest
import respx

from backend.engine import InvestigationEngine
from backend.http_client import EnhancedHTTPClient
from backend.main import _detect_target_type, app
from backend.models import EntityType, PluginResponse, TargetType
from backend.plugins.emailrep_plugin import EmailRepPlugin
from backend.plugins.gravatar_plugin import GravatarPlugin
from backend.plugins.name_permutator_plugin import NamePermutatorPlugin
from backend.plugins.phone_lookup_plugin import PhoneLookupPlugin


@pytest.fixture(autouse=True)
def reset_http_client():
    EnhancedHTTPClient._instance = None
    EnhancedHTTPClient._client = None
    yield
    EnhancedHTTPClient._instance = None
    EnhancedHTTPClient._client = None


@pytest.fixture
def engine(tmp_path, monkeypatch):
    """Isolated engine instance with a temp DB (bypasses the singleton)."""
    monkeypatch.setattr(InvestigationEngine, "_instance", None)
    return InvestigationEngine(str(tmp_path / "person_test.db"))


# ---------------------------------------------------------------------------
# Target-type detection
# ---------------------------------------------------------------------------


def test_detect_person_name_latin():
    assert _detect_target_type("Ivan Petrov") == TargetType.PERSON


def test_detect_person_name_cyrillic():
    assert _detect_target_type("Иван Петров") == TargetType.PERSON


def test_detect_partial_phone():
    assert _detect_target_type("0888123") == TargetType.PHONE
    assert _detect_target_type("+359 888 12") == TargetType.PHONE


def test_detect_existing_types_unchanged():
    assert _detect_target_type("user@example.com") == TargetType.EMAIL
    assert _detect_target_type("example.com") == TargetType.DOMAIN
    assert _detect_target_type("1.2.3.4") == TargetType.IP
    assert _detect_target_type("somehandle") == TargetType.USERNAME


# ---------------------------------------------------------------------------
# NamePermutatorPlugin
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_name_permutator_latin():
    plugin = NamePermutatorPlugin()
    results = await plugin.execute("Ivan Petrov", TargetType.PERSON)
    assert len(results) == 1
    usernames = results[0].evidence[0]["usernames"]
    assert "ivanpetrov" in usernames
    assert "ivan.petrov" in usernames
    assert "i.petrov" in usernames
    assert "petrov.ivan" in usernames


@pytest.mark.asyncio
async def test_name_permutator_cyrillic_transliteration():
    plugin = NamePermutatorPlugin()
    results = await plugin.execute("Иван Петров", TargetType.PERSON)
    usernames = results[0].evidence[0]["usernames"]
    assert "ivanpetrov" in usernames


@pytest.mark.asyncio
async def test_name_permutator_single_name():
    plugin = NamePermutatorPlugin()
    results = await plugin.execute("madonna", TargetType.PERSON)
    assert results[0].evidence[0]["usernames"] == ["madonna"]


# ---------------------------------------------------------------------------
# PhoneLookupPlugin (offline)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_phone_lookup_valid_bg_number():
    plugin = PhoneLookupPlugin()
    results = await plugin.execute("+359888123456", TargetType.PHONE)
    assert len(results) == 1
    ev = results[0].evidence[0]
    assert ev["type"] == "phone_info"
    assert ev["e164"] == "+359888123456"
    assert ev["region"] == "BG"
    assert ev["valid"] is True
    assert ev["line_type"] == "mobile"


@pytest.mark.asyncio
async def test_phone_lookup_partial_number():
    plugin = PhoneLookupPlugin()
    results = await plugin.execute("888123", TargetType.PHONE)
    assert len(results) == 1
    ev = results[0].evidence[0]
    assert ev["type"] == "phone_partial"
    assert ev["fragment"] == "888123"
    assert ev["digit_count"] == 6


@pytest.mark.asyncio
async def test_phone_lookup_too_short():
    plugin = PhoneLookupPlugin()
    assert await plugin.execute("123", TargetType.PHONE) == []


# ---------------------------------------------------------------------------
# GravatarPlugin (mocked HTTP)
# ---------------------------------------------------------------------------

GRAVATAR_PROFILE = {
    "entry": [
        {
            "displayName": "Ivan Petrov",
            "preferredUsername": "ivanpetrov",
            "currentLocation": "Sofia, Bulgaria",
            "aboutMe": "OSINT researcher",
            "profileUrl": "https://gravatar.com/ivanpetrov",
            "thumbnailUrl": "https://0.gravatar.com/avatar/abc",
            "accounts": [
                {"name": "GitHub", "username": "ivanpetrov", "url": "https://github.com/ivanpetrov"}
            ],
            "urls": [{"value": "https://ivanpetrov.example.com"}],
        }
    ]
}


@pytest.mark.asyncio
@respx.mock
async def test_gravatar_profile_found():
    respx.get(url__regex=r"https://www\.gravatar\.com/[a-f0-9]+\.json").mock(
        return_value=httpx.Response(200, json=GRAVATAR_PROFILE)
    )
    plugin = GravatarPlugin()
    results = await plugin.execute("ivan@example.com", TargetType.EMAIL)
    assert len(results) == 1
    ev = results[0].evidence[0]
    assert ev["display_name"] == "Ivan Petrov"
    assert ev["location"] == "Sofia, Bulgaria"
    assert ev["accounts"][0]["username"] == "ivanpetrov"


@pytest.mark.asyncio
@respx.mock
async def test_gravatar_no_profile():
    respx.get(url__regex=r"https://www\.gravatar\.com/[a-f0-9]+\.json").mock(
        return_value=httpx.Response(404)
    )
    plugin = GravatarPlugin()
    assert await plugin.execute("nobody@example.com", TargetType.EMAIL) == []


# ---------------------------------------------------------------------------
# EmailRepPlugin (mocked HTTP)
# ---------------------------------------------------------------------------

EMAILREP_RESPONSE = {
    "email": "ivan@example.com",
    "reputation": "high",
    "suspicious": False,
    "references": 4,
    "first_seen": "2020-01-01",
    "last_seen": "2026-01-01",
    "details": {
        "domain_reputation": "high",
        "domain_exists": True,
        "disposable": False,
        "free_provider": True,
        "deliverable": True,
        "data_breach": True,
        "credentials_leaked": True,
        "credentials_leaked_recent": False,
        "malicious_activity": False,
    },
    "profiles": ["github", "gravatar"],
}


@pytest.mark.asyncio
@respx.mock
async def test_emailrep_leak_attribution():
    respx.get("https://emailrep.io/ivan@example.com").mock(
        return_value=httpx.Response(200, json=EMAILREP_RESPONSE)
    )
    plugin = EmailRepPlugin()
    results = await plugin.execute("ivan@example.com", TargetType.EMAIL)
    assert len(results) == 1
    ev = results[0].evidence[0]
    assert ev["reputation"] == "high"
    assert "data_breach" in ev["leaked_in"]
    assert "credentials_leaked" in ev["leaked_in"]
    assert ev["profiles"] == ["github", "gravatar"]


@pytest.mark.asyncio
@respx.mock
async def test_emailrep_rate_limited():
    respx.get("https://emailrep.io/ivan@example.com").mock(return_value=httpx.Response(429))
    plugin = EmailRepPlugin()
    assert await plugin.execute("ivan@example.com", TargetType.EMAIL) == []


# ---------------------------------------------------------------------------
# Entity extraction (new types)
# ---------------------------------------------------------------------------


def test_extract_entities_usernames_urls_phones(engine):
    resp = PluginResponse(
        provider="test",
        entity_type=TargetType.PERSON,
        confidence=0.9,
        evidence=[
            {
                "usernames": ["ivanpetrov", "i.petrov"],
                "profile_url": "https://gravatar.com/ivanpetrov",
                "e164": "+359888123456",
                "location": "Sofia, Bulgaria",
            }
        ],
    )
    entities = engine.extract_entities(resp, target_id=1)
    by_type: dict[str, list[str]] = {}
    for e in entities:
        by_type.setdefault(e.type.value, []).append(e.value)

    assert set(by_type[EntityType.USERNAME.value]) == {"ivanpetrov", "i.petrov"}
    assert "https://gravatar.com/ivanpetrov" in by_type[EntityType.URL.value]
    assert "+359888123456" in by_type[EntityType.PHONE.value]
    assert "Sofia, Bulgaria" in by_type[EntityType.ADDRESS.value]


# ---------------------------------------------------------------------------
# Pivot engine
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_person_investigation_pivots_on_discovered_entities(engine, monkeypatch):
    """Round 0 discovers an email; round 1 must re-investigate that email."""
    executed: list[tuple[str, str, str]] = []

    async def fake_execute(plugin_name, query, target_type):
        executed.append((plugin_name, query, target_type.value))
        if plugin_name == "name_permutator":
            return [
                PluginResponse(
                    provider="name_permutator",
                    entity_type=TargetType.PERSON,
                    confidence=0.9,
                    evidence=[{"usernames": ["ivanpetrov"], "email": "ivan@example.com"}],
                )
            ]
        return []

    async def fake_plan(target_type, query, use_dynamic=False):
        return {
            TargetType.PERSON: ["name_permutator"],
            TargetType.EMAIL: ["emailrep_lookup"],
            TargetType.USERNAME: ["username_enumeration"],
        }.get(target_type, [])

    monkeypatch.setattr(engine.plugin_manager, "execute_plugin", fake_execute)
    monkeypatch.setattr(engine.plugin_manager, "_plugin_statuses", {})
    monkeypatch.setattr(engine.planner, "plan_investigation", fake_plan)

    result = await engine.run_person_investigation(
        target_id=1, seeds={"full_name": "Ivan Petrov"}, pivot_depth=1
    )

    assert result["status"] == "completed"
    # Round 0: name_permutator on the name
    assert ("name_permutator", "Ivan Petrov", "person") in executed
    # Pivot round: discovered email re-investigated, discovered username too
    assert ("emailrep_lookup", "ivan@example.com", "email") in executed
    assert ("username_enumeration", "ivanpetrov", "username") in executed
    # No duplicate executions of the same (plugin, query) pair
    assert len(executed) == len(set(executed))


@pytest.mark.asyncio
async def test_person_investigation_depth_zero_skips_pivot(engine, monkeypatch):
    executed: list[str] = []

    async def fake_execute(plugin_name, query, target_type):
        executed.append(plugin_name)
        return [
            PluginResponse(
                provider=plugin_name,
                entity_type=TargetType.PERSON,
                confidence=0.9,
                evidence=[{"usernames": ["ivanpetrov"]}],
            )
        ]

    async def fake_plan(target_type, query, use_dynamic=False):
        return ["name_permutator"] if target_type == TargetType.PERSON else ["other_plugin"]

    monkeypatch.setattr(engine.plugin_manager, "execute_plugin", fake_execute)
    monkeypatch.setattr(engine.plugin_manager, "_plugin_statuses", {})
    monkeypatch.setattr(engine.planner, "plan_investigation", fake_plan)

    result = await engine.run_person_investigation(
        target_id=1, seeds={"full_name": "Ivan Petrov"}, pivot_depth=0
    )

    assert result["status"] == "completed"
    assert executed == ["name_permutator"]  # no pivot round executed


# ---------------------------------------------------------------------------
# /api/search/person endpoint
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_person_endpoint_requires_a_field():
    from httpx import ASGITransport, AsyncClient

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post("/api/search/person", data={})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_person_endpoint_runs_engine(tmp_path, monkeypatch):
    from httpx import ASGITransport, AsyncClient

    from backend.main import init_db

    class _FakeStorage:
        async def get_entities_for_target(self, target_id):
            return []

        async def get_relationships_for_target(self, target_id):
            return []

        async def get_timeline(self, target_id):
            return []

    called: dict = {}

    async def fake_run(self, target_id, seeds, pivot_depth=1):
        called["target_id"] = target_id
        called["seeds"] = seeds
        called["pivot_depth"] = pivot_depth
        return {
            "target_id": target_id,
            "status": "completed",
            "seeds": seeds,
            "identifiers_investigated": 1,
            "findings_count": 0,
            "results": [],
        }

    # ASGITransport does not run the lifespan - create schema + storage manually.
    # The endpoint creates a fresh engine (singleton reset) and calls initialize()
    # itself, which runs real plugin discovery - harmless and fast.
    init_db()
    monkeypatch.setattr(app.state, "storage", _FakeStorage(), raising=False)
    monkeypatch.setattr(InvestigationEngine, "_instance", None)
    monkeypatch.setattr(InvestigationEngine, "run_person_investigation", fake_run)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post(
            "/api/search/person",
            data={"full_name": "Ivan Petrov", "email": "ivan@example.com", "pivot_depth": "1"},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert called["seeds"] == {"full_name": "Ivan Petrov", "email": "ivan@example.com"}
    assert body["data"]["target_id"] == called["target_id"]
