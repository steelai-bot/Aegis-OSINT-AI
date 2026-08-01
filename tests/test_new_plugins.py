import httpx
import pytest
import respx

from backend.engine import InvestigationEngine
from backend.http_client import EnhancedHTTPClient
from backend.models import TargetType
from backend.plugins.base import PluginExecutionError
from backend.plugins.wayback_plugin import WaybackPlugin
from backend.plugins.web_recon_plugin import WebReconPlugin


@pytest.fixture(autouse=True)
def reset_http_singleton():
    """Reset the shared HTTP client singleton so each test gets a fresh client
    bound to its own event loop (pytest-asyncio creates a loop per test)."""
    EnhancedHTTPClient._instance = None
    EnhancedHTTPClient._client = None
    yield
    EnhancedHTTPClient._instance = None
    EnhancedHTTPClient._client = None


# ---------------------------------------------------------------------------
# Wayback Machine plugin
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_wayback_returns_snapshot_and_captures():
    respx.get(url__startswith="https://archive.org/wayback/available").mock(
        return_value=httpx.Response(
            200,
            json={
                "archived_snapshots": {
                    "closest": {
                        "available": True,
                        "url": "http://web.archive.org/web/20240101/https://example.com",
                        "timestamp": "20240101120000",
                        "status": "200",
                    }
                }
            },
        )
    )
    respx.get(url__startswith="https://web.archive.org/cdx/search/cdx").mock(
        return_value=httpx.Response(
            200,
            json=[
                ["timestamp", "original", "statuscode", "mimetype"],
                ["20240101120000", "https://example.com/", "200", "text/html"],
                ["20240201120000", "https://example.com/about", "200", "text/html"],
            ],
        )
    )

    plugin = WaybackPlugin()
    results = await plugin.execute("example.com", TargetType.DOMAIN)

    assert len(results) == 1
    resp = results[0]
    assert resp.provider == "wayback_machine"
    types = {e["type"] for e in resp.evidence}
    assert types == {"latest_snapshot", "recent_captures"}
    captures = next(e for e in resp.evidence if e["type"] == "recent_captures")
    assert captures["capture_count"] == 2


@pytest.mark.asyncio
@respx.mock
async def test_wayback_no_data_returns_empty():
    respx.get(url__startswith="https://archive.org/wayback/available").mock(
        return_value=httpx.Response(200, json={"archived_snapshots": {}})
    )
    respx.get(url__startswith="https://web.archive.org/cdx/search/cdx").mock(
        return_value=httpx.Response(200, json=[])
    )

    plugin = WaybackPlugin()
    results = await plugin.execute("nothing.invalid", TargetType.DOMAIN)
    assert results == []


# ---------------------------------------------------------------------------
# Web recon plugin
# ---------------------------------------------------------------------------

ROBOTS_TXT = """User-agent: *
Disallow: /admin
Disallow: /backup
Sitemap: https://example.com/sitemap.xml
"""

SECURITY_TXT = """Contact: mailto:security@example.com
Contact: mailto:abuse@example.com
Expires: 2027-01-01T00:00:00.000Z
"""

SITEMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<urlset><url><loc>https://example.com/</loc></url><url><loc>https://example.com/about</loc></url></urlset>
"""


@pytest.mark.asyncio
@respx.mock
async def test_web_recon_parses_files():
    respx.get("https://example.com/robots.txt").mock(
        return_value=httpx.Response(200, text=ROBOTS_TXT)
    )
    respx.get("https://example.com/.well-known/security.txt").mock(
        return_value=httpx.Response(200, text=SECURITY_TXT)
    )
    respx.get("https://example.com/security.txt").mock(return_value=httpx.Response(404))
    respx.get("https://example.com/sitemap.xml").mock(
        return_value=httpx.Response(200, text=SITEMAP_XML)
    )

    plugin = WebReconPlugin()
    results = await plugin.execute("example.com", TargetType.DOMAIN)

    assert len(results) == 1
    resp = results[0]
    assert resp.provider == "web_recon"
    types = {e["type"] for e in resp.evidence}
    assert types == {"robots_txt", "security_txt", "sitemap_xml"}

    robots = next(e for e in resp.evidence if e["type"] == "robots_txt")
    assert "/admin" in robots["disallowed_paths"]
    assert "https://example.com/sitemap.xml" in robots["sitemaps"]

    security = next(e for e in resp.evidence if e["type"] == "security_txt")
    assert "security@example.com" in security["contacts"]
    assert "security@example.com" in resp.raw["emails"]

    sitemap = next(e for e in resp.evidence if e["type"] == "sitemap_xml")
    assert sitemap["url_count"] == 2


@pytest.mark.asyncio
@respx.mock
async def test_web_recon_all_missing_returns_empty():
    for path in ("/robots.txt", "/.well-known/security.txt", "/security.txt", "/sitemap.xml"):
        respx.get(f"https://empty.example{path}").mock(return_value=httpx.Response(404))

    plugin = WebReconPlugin()
    results = await plugin.execute("empty.example", TargetType.DOMAIN)
    assert results == []


# ---------------------------------------------------------------------------
# Engine failure propagation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_engine_execute_plugin_reraises(monkeypatch):
    """_execute_plugin must log an ERROR timeline event AND re-raise so the
    investigation failure counter stays accurate."""
    engine = InvestigationEngine("data/test_engine.db")

    async def fake_execute_plugin(plugin_name, query, target_type):
        raise PluginExecutionError(plugin_name, "boom")

    monkeypatch.setattr(engine.plugin_manager, "execute_plugin", fake_execute_plugin)

    timeline_buffer = []
    with pytest.raises(PluginExecutionError):
        await engine._execute_plugin("fake", "example.com", TargetType.DOMAIN, 1, timeline_buffer)

    error_events = [e for e in timeline_buffer if e.event_type.value == "error"]
    assert len(error_events) == 1
    assert "boom" in error_events[0].description
