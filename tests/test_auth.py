"""Tests for single-user application authentication (C5)."""

import pytest

from backend.auth import hash_password, verify_password
from backend.config.settings import settings
from backend.main import app

PASSWORD = "s3cret-pass"


@pytest.fixture
def auth_enabled(monkeypatch):
    """Turn auth on with known credentials for the duration of a test."""
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "auth_username", "admin")
    monkeypatch.setattr(settings, "auth_password_hash", hash_password(PASSWORD))
    return settings


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------


def test_hash_and_verify_roundtrip():
    stored = hash_password(PASSWORD)
    assert "$" in stored
    assert verify_password(PASSWORD, stored) is True


def test_verify_wrong_password():
    stored = hash_password(PASSWORD)
    assert verify_password("wrong", stored) is False


def test_verify_malformed_hash():
    assert verify_password(PASSWORD, "not-a-hash") is False
    assert verify_password(PASSWORD, "") is False


def test_hash_uses_random_salt():
    assert hash_password(PASSWORD) != hash_password(PASSWORD)


# ---------------------------------------------------------------------------
# Middleware gating
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_auth_disabled_allows_everything(monkeypatch):
    from httpx import ASGITransport, AsyncClient

    monkeypatch.setattr(settings, "auth_enabled", False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get("/")
        assert resp.status_code == 200


@pytest.mark.asyncio
async def test_pages_redirect_to_login_when_unauthenticated(auth_enabled):
    from httpx import ASGITransport, AsyncClient

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False
    ) as ac:
        resp = await ac.get("/")
        assert resp.status_code == 303
        assert resp.headers["location"] == "/login"


@pytest.mark.asyncio
async def test_api_returns_401_when_unauthenticated(auth_enabled):
    from httpx import ASGITransport, AsyncClient

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get("/api/targets")
        assert resp.status_code == 401
        assert resp.json()["errors"] == ["authentication_required"]


@pytest.mark.asyncio
async def test_public_paths_stay_open(auth_enabled):
    from httpx import ASGITransport, AsyncClient

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        health = await ac.get("/health")
        assert health.status_code == 200
        login = await ac.get("/login")
        assert login.status_code == 200
        assert "Sign In" in login.text


# ---------------------------------------------------------------------------
# Login / logout flow
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_wrong_credentials(auth_enabled):
    from httpx import ASGITransport, AsyncClient

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post("/api/login", data={"username": "admin", "password": "wrong"})
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_full_login_logout_flow(auth_enabled):
    from httpx import ASGITransport, AsyncClient

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False
    ) as ac:
        # Login with correct credentials
        resp = await ac.post("/api/login", data={"username": "admin", "password": PASSWORD})
        assert resp.status_code == 303
        assert resp.headers["location"] == "/"
        assert "session" in resp.headers.get("set-cookie", "")

        # Authenticated page access works with the session cookie
        page = await ac.get("/")
        assert page.status_code == 200

        # Logout clears the session
        await ac.get("/logout")
        gated = await ac.get("/")
        assert gated.status_code == 303
        assert gated.headers["location"] == "/login"
