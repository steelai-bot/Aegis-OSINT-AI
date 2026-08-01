"""Tests for global (non-BG) support: masked phones, addresses, unidecode, findings UI."""

import json

import pytest
from fastapi.testclient import TestClient

from backend.main import _classify_finding, _detect_target_type, app, get_db
from backend.models import TargetType
from backend.plugins.name_permutator_plugin import NamePermutatorPlugin
from backend.plugins.phone_lookup_plugin import PhoneLookupPlugin


@pytest.fixture(scope="module")
def client():
    """Lifespan-managed TestClient (runs init_db against the isolated test DB)."""
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# Target-type detection - global inputs
# ---------------------------------------------------------------------------


def test_detect_masked_phone_x():
    assert _detect_target_type("XXXX XXX 019") == TargetType.PHONE


def test_detect_masked_phone_stars_with_cc():
    assert _detect_target_type("+61 *** *** 019") == TargetType.PHONE


def test_detect_au_address():
    assert _detect_target_type("69 Goodwood ST HENDRA, QLD, 4011, AU") == TargetType.ADDRESS


def test_detect_us_address():
    assert _detect_target_type("1600 Pennsylvania Avenue NW, Washington, DC 20500") == (
        TargetType.ADDRESS
    )


def test_detect_global_person_names():
    assert _detect_target_type("CAMERON DAVID EDWARDS") == TargetType.PERSON
    assert _detect_target_type("Иван Петров") == TargetType.PERSON
    assert _detect_target_type("José García") == TargetType.PERSON


def test_detect_existing_types_still_unchanged():
    assert _detect_target_type("user@example.com") == TargetType.EMAIL
    assert _detect_target_type("example.com") == TargetType.DOMAIN
    assert _detect_target_type("+61 400 123 456") == TargetType.PHONE
    assert _detect_target_type("somehandle") == TargetType.USERNAME


# ---------------------------------------------------------------------------
# PhoneLookupPlugin - masked + international numbers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_phone_lookup_masked_fragment():
    plugin = PhoneLookupPlugin()
    results = await plugin.execute("XXXX XXX 019", TargetType.PHONE)
    assert len(results) == 1
    ev = results[0].evidence[0]
    assert ev["type"] == "phone_partial"
    assert ev["masked"] is True
    assert ev["visible_digits"] == 3
    assert ev["fragment"] == "019"


@pytest.mark.asyncio
async def test_phone_lookup_masked_with_country_code():
    plugin = PhoneLookupPlugin()
    results = await plugin.execute("+61 *** *** 019", TargetType.PHONE)
    ev = results[0].evidence[0]
    assert ev["type"] == "phone_partial"
    assert ev["masked"] is True
    assert ev.get("possible_country_code") == 61
    assert "AU" in ev.get("possible_regions", [])


@pytest.mark.asyncio
async def test_phone_lookup_full_au_number():
    plugin = PhoneLookupPlugin()
    results = await plugin.execute("+61 400 123 456", TargetType.PHONE)
    ev = results[0].evidence[0]
    assert ev["type"] == "phone_info"
    assert ev["region"] == "AU"
    assert ev["e164"].startswith("+61")


# ---------------------------------------------------------------------------
# NamePermutatorPlugin - unidecode global transliteration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_permutator_english_three_part_name():
    plugin = NamePermutatorPlugin()
    results = await plugin.execute("Cameron David Edwards", TargetType.PERSON)
    usernames = results[0].evidence[0]["usernames"]
    assert "cameronedwards" in usernames
    assert "cameron.edwards" in usernames
    assert "c.edwards" in usernames


@pytest.mark.asyncio
async def test_permutator_russian_cyrillic():
    plugin = NamePermutatorPlugin()
    results = await plugin.execute("Дмитрий Медведев", TargetType.PERSON)
    usernames = results[0].evidence[0]["usernames"]
    assert "dmitriimedvedev" in usernames


@pytest.mark.asyncio
async def test_permutator_greek():
    plugin = NamePermutatorPlugin()
    results = await plugin.execute("Νίκος Παπαδόπουλος", TargetType.PERSON)
    usernames = results[0].evidence[0]["usernames"]
    assert "nikospapadopoulos" in usernames


@pytest.mark.asyncio
async def test_permutator_diacritics():
    plugin = NamePermutatorPlugin()
    results = await plugin.execute("José García", TargetType.PERSON)
    usernames = results[0].evidence[0]["usernames"]
    assert "josegarcia" in usernames


# ---------------------------------------------------------------------------
# Findings classification + HTML endpoint
# ---------------------------------------------------------------------------


def test_classify_finding_groups():
    assert _classify_finding("stealer_logs", {"type": "credential"}) == "exposure"
    assert _classify_finding("breach_check", {"type": "breach"}) == "exposure"
    assert _classify_finding("gravatar_lookup", {"type": "profile"}) == "contact"
    assert _classify_finding("username_enumeration", {"type": "profile"}) == "identity"
    assert _classify_finding("crt_sh", {"type": "certificate"}) == "infrastructure"
    assert _classify_finding("misc_plugin", {"type": "note"}) == "other"


def test_findings_html_partial(client):
    # Seed a target + findings directly
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO targets (query, target_type, status) VALUES (?, ?, ?)",
            ("globaltest@example.com", "email", "completed"),
        )
        target_id = cursor.lastrowid
        cursor.execute(
            "INSERT INTO findings (target_id, source, category, severity, confidence, data) VALUES (?, ?, ?, ?, ?, ?)",
            (
                target_id,
                "breach_check",
                "osint_discovery",
                "info",
                0.9,
                json.dumps(
                    {"type": "breach", "title": "TestBreach", "description": "Found in test breach"}
                ),
            ),
        )
        cursor.execute(
            "INSERT INTO findings (target_id, source, category, severity, confidence, data) VALUES (?, ?, ?, ?, ?, ?)",
            (
                target_id,
                "gravatar_lookup",
                "osint_discovery",
                "info",
                0.8,
                json.dumps({"type": "profile", "url": "https://gravatar.com/test"}),
            ),
        )
        conn.commit()

    resp = client.get(f"/api/findings?target_id={target_id}&format=html")
    assert resp.status_code == 200
    html = resp.text
    assert "Exposure" in html  # group label (HTML-escaped form of "Exposure & Leaks")
    assert "TestBreach" in html
    assert "breach_check" in html
    assert "gravatar_lookup" in html

    # JSON format still works and includes enrichment fields
    resp_json = client.get(f"/api/findings?target_id={target_id}")
    assert resp_json.status_code == 200
    data = resp_json.json()["data"]
    assert len(data) == 2
    assert all("group" in f and "title" in f for f in data)
