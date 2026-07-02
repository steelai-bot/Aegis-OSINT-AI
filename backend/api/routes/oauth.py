"""OAuth authentication routes — external provider sign-in redirects."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

router = APIRouter(prefix="/auth/oauth", tags=["auth"])

# ── Provider config ──────────────────────────────────────────────────────────
# These read from .env and return the OAuth authorize URL for each provider.

PROVIDERS: dict[str, dict[str, str]] = {
    "google": {
        "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "client_id_var": "GOOGLE_CLIENT_ID",
        "scope": "openid email profile",
    },
    "github": {
        "authorize_url": "https://github.com/login/oauth/authorize",
        "client_id_var": "GITHUB_CLIENT_ID",
        "scope": "read:user user:email",
    },
    "huggingface": {
        "authorize_url": "https://huggingface.co/oauth/authorize",
        "client_id_var": "HF_CLIENT_ID",
        "scope": "openid profile",
    },
    "microsoft": {
        "authorize_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "client_id_var": "MICROSOFT_CLIENT_ID",
        "scope": "openid email profile User.Read",
    },
}


def _get_callback_url(request: Request, provider: str) -> str:
    """Build the callback URL that the provider will redirect to."""
    base = str(request.base_url).rstrip("/")
    return f"{base}/api/v1/auth/oauth/{provider}/callback"


@router.get("/{provider}")
async def oauth_login(provider: str, request: Request):
    """Redirect the user to the OAuth provider's authorization page."""
    cfg = PROVIDERS.get(provider.lower())
    if cfg is None:
        raise HTTPException(status_code=404, detail=f"Unknown OAuth provider: {provider}")

    client_id = __import__("os").environ.get(cfg["client_id_var"])
    if not client_id:
        raise HTTPException(
            status_code=501,
            detail=f"OAuth provider '{provider}' is not configured. Set {cfg['client_id_var']} in .env",
        )

    redirect_uri = _get_callback_url(request, provider)
    params = (
        f"client_id={client_id}"
        f"&redirect_uri={redirect_uri}"
        f"&scope={cfg['scope'].replace(' ', '%20')}"
        f"&response_type=code"
        f"&state=aegis_oauth_{provider}"
    )
    url = f"{cfg['authorize_url']}?{params}"
    return RedirectResponse(url=url)


@router.get("/{provider}/callback")
async def oauth_callback(provider: str, code: str | None = None, state: str | None = None):
    """Placeholder callback — receives the auth code from the provider."""
    cfg = PROVIDERS.get(provider.lower())
    if cfg is None:
        raise HTTPException(status_code=404, detail=f"Unknown OAuth provider: {provider}")

    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")

    # TODO: Exchange code for access token with the provider, then create/login user.
    # For now, redirect to frontend with a placeholder token.
    frontend_url = "http://localhost:3000"
    return RedirectResponse(
        url=f"{frontend_url}/login?oauth=success&provider={provider}&code={code[:20]}..."
    )