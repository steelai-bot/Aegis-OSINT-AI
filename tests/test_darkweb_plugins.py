import hashlib

import httpx
import pytest
import respx

from backend.http_client import EnhancedHTTPClient
from backend.models import TargetType
from backend.plugins.breach_check_plugin import BreachCheckPlugin
from backend.plugins.darkweb_monitor_plugin import DarkWebMonitorPlugin
from backend.plugins.exposed_credentials_plugin import ExposedCredentialsPlugin
from backend.plugins.leaked_db_plugin import LeakedDBPlugin
from backend.plugins.stealer_logs_plugin import StealerLogsPlugin
from backend.plugins.telegram_osint_plugin import TelegramOSINTPlugin
from backend.tor_client import TorClient, TorUnavailableError


@pytest.fixture(autouse=True)
def reset_singletons(monkeypatch):
    """Fresh HTTP client + Tor cache per test; Tor always unavailable by default."""
    EnhancedHTTPClient._instance = None
    EnhancedHTTPClient._client = None
    TorClient._instance = None
    # Strip paid API keys so tests are deterministic
    for key in ("HIBP_API_KEY", "DEHASHED_API_KEY", "LEAKCHECK_API_KEY", "SNUSBASE_API_KEY"):
        monkeypatch.delenv(key, raising=False)

    async def _no_tor(self, force: bool = False) -> bool:
        return False

    monkeypatch.setattr(TorClient, "is_available", _no_tor)
    yield
    EnhancedHTTPClient._instance = None
    EnhancedHTTPClient._client = None
    TorClient._instance = None


# ---------------------------------------------------------------------------
# TorClient
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tor_client_get_client_raises_when_unavailable():
    tor = TorClient.get_instance()
    with pytest.raises(TorUnavailableError):
        await tor.get_client()


@pytest.mark.asyncio
async def test_tor_client_status_reports_unavailable():
    tor = TorClient.get_instance()
    status = await tor.status()
    assert status["available"] is False
    assert "address" in status


# ---------------------------------------------------------------------------
# StealerLogsPlugin
# ---------------------------------------------------------------------------

PSBDMP_RESPONSE = {
    "data": [
        {"id": "abc123", "title": "stealer log dump 2026", "text": "user@example.com:password123", "time": "2026-01-15"},
    ]
}

TG_HTML = """
<html><body>
<div class="tgme_widget_message" data-post="redlogslounge/123">
  <div class="tgme_widget_message_text">Fresh logs: user@example.com leaked</div>
  <a class="tgme_widget_message_date" href="https://t.me/redlogslounge/123"><time datetime="2026-01-15T10:00:00+00:00"></time></a>
</div>
</body></html>
"""

AHMIA_HTML = """
<html><body><ol>
<li class="result"><a href="http://exampleonion.onion/logs">Stealer logs marketplace</a><p>Fresh stealer logs daily</p></li>
</ol></body></html>
"""


@pytest.mark.asyncio
@respx.mock
async def test_stealer_logs_psbdmp_hit():
    respx.get(url__startswith="https://psbdmp.ws/api/search/").mock(
        return_value=httpx.Response(200, json=PSBDMP_RESPONSE)
    )
    respx.get(url__startswith="https://t.me/s/").mock(return_value=httpx.Response(404))
    respx.get(url__startswith="https://ahmia.fi/search").mock(return_value=httpx.Response(200, text="<html></html>"))

    plugin = StealerLogsPlugin()
    results = await plugin.execute("user@example.com", TargetType.EMAIL)

    assert len(results) == 1
    resp = results[0]
    assert resp.provider == "stealer_logs"
    assert resp.evidence[0]["type"] == "stealer_log"
    assert resp.evidence[0]["download_url"] == "https://psbdmp.ws/api/dump/get/abc123"


@pytest.mark.asyncio
@respx.mock
async def test_stealer_logs_telegram_channel_hit():
    respx.get(url__startswith="https://psbdmp.ws/api/search/").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    respx.get(url__startswith="https://t.me/s/").mock(return_value=httpx.Response(200, text=TG_HTML))
    respx.get(url__startswith="https://ahmia.fi/search").mock(return_value=httpx.Response(200, text="<html></html>"))

    plugin = StealerLogsPlugin()
    results = await plugin.execute("user@example.com", TargetType.EMAIL)

    assert len(results) == 1
    ev = results[0].evidence[0]
    assert ev["type"] == "stealer_log"
    assert ev["severity"] == "critical"
    assert ev["url"] == "https://t.me/redlogslounge/123"


@pytest.mark.asyncio
@respx.mock
async def test_stealer_logs_no_hits_returns_empty():
    respx.get(url__startswith="https://psbdmp.ws/api/search/").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    respx.get(url__startswith="https://t.me/s/").mock(return_value=httpx.Response(404))
    respx.get(url__startswith="https://ahmia.fi/search").mock(return_value=httpx.Response(200, text="<html></html>"))

    plugin = StealerLogsPlugin()
    results = await plugin.execute("nobody@nowhere.invalid", TargetType.EMAIL)
    assert results == []


# ---------------------------------------------------------------------------
# BreachCheckPlugin
# ---------------------------------------------------------------------------

HIBP_BREACHES = [
    {
        "Name": "Canva",
        "Title": "Canva",
        "BreachDate": "2019-05-24",
        "PwnCount": 137272116,
        "DataClasses": ["Email addresses", "Names", "Passwords"],
        "Domain": "canva.com",
        "IsVerified": True,
    },
    {
        "Name": "LinkedIn",
        "Title": "LinkedIn",
        "BreachDate": "2012-05-05",
        "PwnCount": 164611595,
        "DataClasses": ["Email addresses", "Passwords"],
        "Domain": "linkedin.com",
        "IsVerified": True,
    },
]

HIBP_PASTES = [
    {
        "Source": "Pastebin",
        "Id": "xYz123Ab",
        "Title": "combo list",
        "Date": "2025-12-01T00:00:00Z",
        "EmailCount": 1500,
    }
]


@pytest.mark.asyncio
@respx.mock
async def test_breach_check_hibp_full(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "test-key")
    respx.get(url__startswith="https://haveibeenpwned.com/api/v3/breachedaccount/").mock(
        return_value=httpx.Response(200, json=HIBP_BREACHES)
    )
    respx.get(url__startswith="https://haveibeenpwned.com/api/v3/pasteaccount/").mock(
        return_value=httpx.Response(200, json=HIBP_PASTES)
    )

    plugin = BreachCheckPlugin()
    results = await plugin.execute("user@example.com", TargetType.EMAIL)

    assert len(results) == 2
    breach_resp = next(r for r in results if r.raw.get("source") == "hibp_breachedaccount")
    assert len(breach_resp.evidence) == 2
    assert breach_resp.evidence[0]["severity"] == "critical"
    assert "canva" in breach_resp.evidence[0]["url"].lower() or "PwnedWebsites" in breach_resp.evidence[0]["url"]

    paste_resp = next(r for r in results if r.raw.get("source") == "hibp_pasteaccount")
    assert paste_resp.evidence[0]["download_url"] == "https://pastebin.com/raw/xYz123Ab"


@pytest.mark.asyncio
@respx.mock
async def test_breach_check_hibp_401_graceful(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "bad-key")
    respx.get(url__startswith="https://haveibeenpwned.com/api/v3/breachedaccount/").mock(
        return_value=httpx.Response(401)
    )
    respx.get(url__startswith="https://haveibeenpwned.com/api/v3/pasteaccount/").mock(
        return_value=httpx.Response(401)
    )

    plugin = BreachCheckPlugin()
    results = await plugin.execute("user@example.com", TargetType.EMAIL)
    assert len(results) == 1
    assert results[0].evidence[0]["severity"] == "warning"
    assert "401" in results[0].evidence[0]["title"]


@pytest.mark.asyncio
@respx.mock
async def test_breach_check_kanonymity_fallback():
    email = "user@example.com"
    digest = hashlib.sha1(email.encode()).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    respx.get(f"https://api.pwnedpasswords.com/range/{prefix}").mock(
        return_value=httpx.Response(200, text=f"AAAAA:10\n{suffix}:523\nBBBBB:3")
    )

    plugin = BreachCheckPlugin()
    results = await plugin.execute(email, TargetType.EMAIL)

    assert len(results) == 1
    assert results[0].raw["source"] == "pwnedpasswords_range"
    assert results[0].raw["count"] == 523
    assert results[0].evidence[0]["severity"] == "critical"


@pytest.mark.asyncio
@respx.mock
async def test_breach_check_phone_info_hit():
    plugin = BreachCheckPlugin()
    results = await plugin.execute("+359888123456", TargetType.PHONE)
    assert len(results) == 1
    assert results[0].evidence[0]["severity"] == "info"


# ---------------------------------------------------------------------------
# LeakedDBPlugin
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_leaked_db_psbdmp_dump_with_download():
    respx.get(url__startswith="https://psbdmp.ws/api/search/").mock(
        return_value=httpx.Response(200, json={
            "data": [{"id": "dump42", "title": "example.com full database dump", "text": "...", "time": "2026-02-01"}]
        })
    )
    respx.get(url__startswith="https://onion.live/").mock(return_value=httpx.Response(200, text="<html></html>"))

    plugin = LeakedDBPlugin()
    results = await plugin.execute("example.com", TargetType.DOMAIN)

    assert len(results) == 1
    ev = results[0].evidence[0]
    assert ev["type"] == "database_dump"
    assert ev["severity"] == "critical"  # query appears in title
    assert ev["download_url"] == "https://psbdmp.ws/api/dump/get/dump42"


@pytest.mark.asyncio
@respx.mock
async def test_leaked_db_no_hits():
    respx.get(url__startswith="https://psbdmp.ws/api/search/").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    respx.get(url__startswith="https://onion.live/").mock(return_value=httpx.Response(404))

    plugin = LeakedDBPlugin()
    results = await plugin.execute("nothing.invalid", TargetType.DOMAIN)
    assert results == []


# ---------------------------------------------------------------------------
# DarkWebMonitorPlugin
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_darkweb_monitor_ahmia_clearnet():
    respx.get(url__startswith="https://ahmia.fi/search").mock(
        return_value=httpx.Response(200, text=AHMIA_HTML)
    )
    respx.get(url__startswith="https://onion.live/").mock(return_value=httpx.Response(200, text="<html></html>"))

    plugin = DarkWebMonitorPlugin()
    results = await plugin.execute("example.com", TargetType.DOMAIN)

    assert len(results) == 1
    ev = results[0].evidence[0]
    assert ev["type"] == "forum_mention"
    assert ev["url"] == "http://exampleonion.onion/logs"
    assert ev["tor"] is False


@pytest.mark.asyncio
@respx.mock
async def test_darkweb_monitor_all_sources_fail_returns_empty():
    respx.get(url__startswith="https://ahmia.fi/search").mock(side_effect=httpx.ConnectError("boom"))
    respx.get(url__startswith="https://onion.live/").mock(side_effect=httpx.ConnectError("boom"))

    plugin = DarkWebMonitorPlugin()
    results = await plugin.execute("example.com", TargetType.DOMAIN)
    assert results == []


# ---------------------------------------------------------------------------
# TelegramOSINTPlugin
# ---------------------------------------------------------------------------

DDG_HTML = """
<html><body>
<div class="result">
  <a class="result__a" href="https://t.me/somechannel/42">Mention of targetuser in channel</a>
  <a class="result__snippet">targetuser was mentioned here</a>
</div>
<div class="result">
  <a class="result__a" href="https://example.com/unrelated">Unrelated</a>
</div>
</body></html>
"""


@pytest.mark.asyncio
@respx.mock
async def test_telegram_osint_channel_and_ddg_hits():
    respx.get(url__startswith="https://t.me/s/").mock(return_value=httpx.Response(200, text=TG_HTML))
    respx.get(url__startswith="https://html.duckduckgo.com/html/").mock(
        return_value=httpx.Response(200, text=DDG_HTML)
    )

    plugin = TelegramOSINTPlugin()
    results = await plugin.execute("user@example.com", TargetType.EMAIL)

    # channel previews hit + ddg hit
    assert len(results) == 2
    channel_resp = next(r for r in results if r.raw["source"] == "telegram_channel_previews")
    assert channel_resp.evidence[0]["type"] == "telegram"
    assert channel_resp.evidence[0]["url"] == "https://t.me/redlogslounge/123"

    ddg_resp = next(r for r in results if r.raw["source"] == "duckduckgo_site_tme")
    assert len(ddg_resp.evidence) == 1  # unrelated non-t.me result filtered out
    assert "t.me" in ddg_resp.evidence[0]["url"]


@pytest.mark.asyncio
@respx.mock
async def test_telegram_osint_no_mentions():
    respx.get(url__startswith="https://t.me/s/").mock(return_value=httpx.Response(200, text="<html><body></body></html>"))
    respx.get(url__startswith="https://html.duckduckgo.com/html/").mock(
        return_value=httpx.Response(200, text="<html><body></body></html>")
    )

    plugin = TelegramOSINTPlugin()
    results = await plugin.execute("ghostuser", TargetType.USERNAME)
    assert results == []


# ---------------------------------------------------------------------------
# ExposedCredentialsPlugin (rewritten)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_exposed_credentials_email_psbdmp_hit():
    respx.get(url__startswith="https://psbdmp.ws/api/search/").mock(
        return_value=httpx.Response(200, json=PSBDMP_RESPONSE)
    )
    respx.get(url__startswith="https://t.me/s/").mock(return_value=httpx.Response(404))
    respx.get(url__startswith="https://api.pwnedpasswords.com/range/").mock(
        return_value=httpx.Response(200, text="AAAAA:10\nBBBBB:3")
    )

    plugin = ExposedCredentialsPlugin()
    results = await plugin.execute("user@example.com", TargetType.EMAIL)

    assert len(results) == 1
    assert results[0].provider == "exposed_credentials"
    ev = results[0].evidence[0]
    assert "url" in ev and "download_url" in ev
    assert ev["type"] == "paste"


@pytest.mark.asyncio
@respx.mock
async def test_exposed_credentials_phone_info_only():
    respx.get(url__startswith="https://psbdmp.ws/api/search/").mock(
        return_value=httpx.Response(200, json={"data": []})
    )

    plugin = ExposedCredentialsPlugin()
    results = await plugin.execute("+359 888 123 456", TargetType.PHONE)

    assert len(results) == 1
    assert results[0].evidence[0]["severity"] == "info"
    assert results[0].raw["phone"] == "359888123456"


# ---------------------------------------------------------------------------
# Planner templates
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_planner_email_template_includes_darkweb_plugins():
    from backend.planner import AIPlanner

    planner = AIPlanner()
    steps = await planner.plan_investigation(TargetType.EMAIL, "user@example.com")
    assert "breach_check" in steps
    assert "stealer_logs" in steps
    assert "darkweb_monitor" in steps


@pytest.mark.asyncio
async def test_planner_domain_template_includes_leaked_db():
    from backend.planner import AIPlanner

    planner = AIPlanner()
    steps = await planner.plan_investigation(TargetType.DOMAIN, "example.com")
    assert "leaked_db" in steps
    assert "darkweb_monitor" in steps


# ---------------------------------------------------------------------------
# Plugin discovery: all new plugins enabled without keys
# ---------------------------------------------------------------------------

def test_new_plugins_discovered_and_enabled():
    from backend.plugin_manager import PluginManager

    PluginManager._instance = None
    pm = PluginManager()
    pm.discover_plugins()
    try:
        for name in ("stealer_logs", "darkweb_monitor", "breach_check", "leaked_db", "telegram_osint", "exposed_credentials"):
            assert name in pm.get_all_plugin_names(), f"{name} not discovered"
            assert pm._plugin_statuses.get(name) == "enabled", f"{name} not enabled: {pm.get_plugin_error(name)}"
    finally:
        PluginManager._instance = None
