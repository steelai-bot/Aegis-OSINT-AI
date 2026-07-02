"""OAuth authentication routes — external provider sign-in redirects."""

from __future__ import annotations

import os
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

router = APIRouter(prefix="/auth/oauth", tags=["auth"])

# ── Provider config ──────────────────────────────────────────────────────────

PROVIDERS: dict[str, dict[str, str]] = {
    "google": {
        "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "client_id_var": "GOOGLE_CLIENT_ID",
        "client_secret_var": "GOOGLE_CLIENT_SECRET",
        "scope": "openid email profile",
    },
    "github": {
        "authorize_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "client_id_var": "GITHUB_CLIENT_ID",
        "client_secret_var": "GITHUB_CLIENT_SECRET",
        "scope": "read:user user:email",
    },
    "huggingface": {
        "authorize_url": "https://huggingface.co/oauth/authorize",
        "token_url": "https://huggingface.co/oauth/token",
        "client_id_var": "HF_CLIENT_ID",
        "client_secret_var": "HF_CLIENT_SECRET",
        "scope": "openid profile",
    },
    "microsoft": {
        "authorize_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "client_id_var": "MICROSOFT_CLIENT_ID",
        "client_secret_var": "MICROSOFT_CLIENT_SECRET",
        "scope": "openid email profile User.Read",
    },
}

FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:3000")


def _get_callback_url(request: Request, provider: str) -> str:
    """Build the callback URL that the provider will redirect to."""
    base = str(request.base_url).rstrip("/")
    return f"{base}/api/v1/auth/oauth/{provider}/callback"


async def _exchange_code_for_token(
    provider: str, code: str, redirect_uri: str
) -> dict[str, Any]:
    """Exchange authorization code for access token from provider."""
    cfg = PROVIDERS.get(provider.lower())
    if not cfg:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")

    client_id = os.environ.get(cfg["client_id_var"])
    client_secret = os.environ.get(cfg["client_secret_var"])

    if not client_id or not client_secret:
        raise HTTPException(
            status_code=501,
            detail=(
                f"Provider '{provider}' is not configured. "
                f"Set {cfg['client_id_var']} and {cfg['client_secret_var']} in .env"
            ),
        )

    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            cfg["token_url"],
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri,
            },
            headers={"Accept": "application/json"},
        )
        if token_response.status_code != 200:
            raise HTTPException(
                status_code=502,
                detail=f"Token exchange failed: {token_response.text}",
            )
        return token_response.json()


@router.get("/{provider}")
async def oauth_login(provider: str, request: Request):
    """Redirect the user to the OAuth provider's authorization page."""
    cfg = PROVIDERS.get(provider.lower())
    if cfg is None:
        raise HTTPException(status_code=404, detail=f"Unknown OAuth provider: {provider}")

    client_id = os.environ.get(cfg["client_id_var"])
    if not client_id:
        raise HTTPException(
            status_code=501,
            detail=f"OAuth provider '{provider}' is not configured. Set {cfg['client_id_var']} in .env",
        )

    redirect_uri = _get_callback_url(request, provider)
    scope_encoded = cfg["scope"].replace(" ", "%20")
    url = (
        f"{cfg['authorize_url']}"
        f"?client_id={client_id}"
        f"&redirect_uri={redirect_uri}"
        f"&scope={scope_encoded}"
        f"&response_type=code"
        f"&state=aegis_oauth_{provider}"
    )
    return RedirectResponse(url=url)


@router.get("/{provider}/callback")
async def oauth_callback(
    provider: str,
    request: Request,
    code: str | None = None,
    state: str | None = None,
):
    """Handle OAuth callback with real token exchange."""
    cfg = PROVIDERS.get(provider.lower())
    if cfg is None:
        raise HTTPException(status_code=404, detail=f"Unknown OAuth provider: {provider}")

    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")

    # Build redirect_uri using the real incoming request, not a dummy Request object
    redirect_uri = _get_callback_url(request, provider)
    token_data = await _exchange_code_for_token(provider, code, redirect_uri)

    # TODO: Create or update user record with provider identity
    access_token = token_data.get("access_token", "")
    return RedirectResponse(
        url=f"{FRONTEND_URL}/login?oauth=success&provider={provider}&token={access_token}"
    )