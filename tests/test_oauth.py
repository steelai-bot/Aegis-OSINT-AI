"""Tests for OAuth device flow (GitHub, RFC 8628) and its endpoints."""

import httpx
import pytest
import respx

from backend.config.settings import settings
from backend.http_client import EnhancedHTTPClient
from backend.main import app
from backend.oauth_manager import (
    GITHUB_ACCESS_TOKEN_URL,
    GITHUB_DEVICE_CODE_URL,
    OAuthError,
    OAuthManager,
)

CLIENT_ID = "test-oauth-client-id"

DEVICE_CODE_RESPONSE = {
    "device_code": "dc123",
    "user_code": "ABCD-1234",
    "verification_uri": "https://github.com/login/device",
    "expires_in": 900,
    "interval": 5,
}


@pytest.fixture(autouse=True)
def reset_http_client():
    EnhancedHTTPClient._instance = None
    EnhancedHTTPClient._client = None
    yield
    EnhancedHTTPClient._instance = None
    EnhancedHTTPClient._client = None


@pytest.fixture
def manager(tmp_path):
    return OAuthManager(tokens_path=str(tmp_path / "oauth_tokens.json"))


# ---------------------------------------------------------------------------
# OAuthManager - device flow
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_github_start_returns_user_code(manager):
    respx.post(GITHUB_DEVICE_CODE_URL).mock(
        return_value=httpx.Response(200, json=DEVICE_CODE_RESPONSE)
    )
    session = await manager.github_start(CLIENT_ID)
    assert session["user_code"] == "ABCD-1234"
    assert session["verification_uri"] == "https://github.com/login/device"
    assert session["interval"] == 5


@pytest.mark.asyncio
@respx.mock
async def test_github_start_rejected_raises(manager):
    respx.post(GITHUB_DEVICE_CODE_URL).mock(
        return_value=httpx.Response(
            200, json={"error": "unauthorized", "error_description": "bad client"}
        )
    )
    with pytest.raises(OAuthError):
        await manager.github_start(CLIENT_ID)


@pytest.mark.asyncio
@respx.mock
async def test_github_poll_pending(manager):
    respx.post(GITHUB_DEVICE_CODE_URL).mock(
        return_value=httpx.Response(200, json=DEVICE_CODE_RESPONSE)
    )
    respx.post(GITHUB_ACCESS_TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"error": "authorization_pending"})
    )
    await manager.github_start(CLIENT_ID)
    result = await manager.github_poll(CLIENT_ID)
    assert result["status"] == "pending"


@pytest.mark.asyncio
@respx.mock
async def test_github_poll_complete_persists_token(manager):
    respx.post(GITHUB_DEVICE_CODE_URL).mock(
        return_value=httpx.Response(200, json=DEVICE_CODE_RESPONSE)
    )
    respx.post(GITHUB_ACCESS_TOKEN_URL).mock(
        return_value=httpx.Response(
            200, json={"access_token": "gho_secret", "token_type": "bearer", "scope": "read:user"}
        )
    )
    await manager.github_start(CLIENT_ID)
    result = await manager.github_poll(CLIENT_ID)
    assert result["status"] == "complete"
    assert result["access_token"] == "gho_secret"

    stored = manager.get_token("github")
    assert stored is not None
    assert stored["access_token"] == "gho_secret"
    # Session is consumed after completion
    assert (await manager.github_poll(CLIENT_ID))["status"] == "error"


@pytest.mark.asyncio
async def test_github_poll_without_session(manager):
    result = await manager.github_poll(CLIENT_ID)
    assert result["status"] == "error"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_oauth_start_requires_client_id(monkeypatch):
    from httpx import ASGITransport, AsyncClient

    monkeypatch.delenv("GITHUB_OAUTH_CLIENT_ID", raising=False)
    monkeypatch.setattr(settings, "github_oauth_client_id", None)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post("/api/oauth/github/start")
    assert resp.status_code == 400
    assert "GITHUB_OAUTH_CLIENT_ID" in resp.json()["errors"][0]


@pytest.mark.asyncio
@respx.mock
async def test_oauth_full_flow_saves_token_without_leaking_it(tmp_path, monkeypatch):
    from httpx import ASGITransport, AsyncClient

    import backend.main as main_module

    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", CLIENT_ID)
    monkeypatch.setattr(
        main_module, "oauth_manager", OAuthManager(tokens_path=str(tmp_path / "tokens.json"))
    )

    configured: dict = {}

    def fake_configure(provider_id, auth_data):
        configured[provider_id] = auth_data

    monkeypatch.setattr(main_module.provider_manager, "configure_provider", fake_configure)

    respx.post(GITHUB_DEVICE_CODE_URL).mock(
        return_value=httpx.Response(200, json=DEVICE_CODE_RESPONSE)
    )
    respx.post(GITHUB_ACCESS_TOKEN_URL).mock(
        return_value=httpx.Response(
            200, json={"access_token": "gho_secret", "token_type": "bearer"}
        )
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        start = await ac.post("/api/oauth/github/start")
        assert start.status_code == 200
        assert start.json()["data"]["user_code"] == "ABCD-1234"

        poll = await ac.post("/api/oauth/github/poll")
        assert poll.status_code == 200
        data = poll.json()["data"]
        assert data["status"] == "complete"
        # The raw token must never be returned to the HTTP client
        assert "access_token" not in data
        assert "gho_secret" not in poll.text

    # Token was mirrored into the provider configuration as GITHUB_TOKEN
    assert configured["github"]["api_key"] == "gho_secret"


@pytest.mark.asyncio
async def test_oauth_status_endpoint(monkeypatch):
    from httpx import ASGITransport, AsyncClient

    monkeypatch.delenv("GITHUB_OAUTH_CLIENT_ID", raising=False)
    monkeypatch.setattr(settings, "github_oauth_client_id", None)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get("/api/oauth/status")
    assert resp.status_code == 200
    github = resp.json()["data"]["github"]
    assert github["oauth_configured"] is False
    assert github["flow"] == "device"
