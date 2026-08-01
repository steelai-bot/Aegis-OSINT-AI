"""OAuth 2.0 Device Authorization Grant (RFC 8628) support.

Currently implements the GitHub device flow - the only mainstream provider
relevant to Aegis that supports OAuth without a client secret, which makes it
safe for a self-hosted desktop-style app. Tokens are persisted to
data/oauth_tokens.json (gitignored) and mirrored into .env via ProviderManager
so existing plugins keep reading GITHUB_TOKEN the way they always have.
"""

import json
import logging
import time
from pathlib import Path
from typing import Any

from backend.http_client import SharedHTTPClient

logger = logging.getLogger(__name__)

GITHUB_DEVICE_CODE_URL = "https://github.com/login/device/code"
GITHUB_ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token"
# Minimal privilege: identify the user; public OSINT data needs no extra scopes
GITHUB_SCOPE = "read:user user:email"


class OAuthError(Exception):
    """Raised when an OAuth provider rejects or fails a flow step."""


class OAuthManager:
    """Manages OAuth device-flow sessions and token persistence."""

    def __init__(self, tokens_path: str = "data/oauth_tokens.json"):
        self.tokens_path = Path(tokens_path)
        # Active device-flow sessions keyed by provider name
        self._sessions: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Token persistence
    # ------------------------------------------------------------------

    def _load_tokens(self) -> dict[str, Any]:
        if not self.tokens_path.exists():
            return {}
        try:
            data = json.loads(self.tokens_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception as e:
            logger.warning(f"Failed to read OAuth token store: {e}")
            return {}

    def save_token(self, provider: str, token_data: dict[str, Any]) -> None:
        tokens = self._load_tokens()
        tokens[provider] = {**token_data, "saved_at": time.time()}
        self.tokens_path.parent.mkdir(parents=True, exist_ok=True)
        self.tokens_path.write_text(json.dumps(tokens, indent=2), encoding="utf-8")

    def get_token(self, provider: str) -> dict[str, Any] | None:
        return self._load_tokens().get(provider)

    def delete_token(self, provider: str) -> bool:
        tokens = self._load_tokens()
        if provider not in tokens:
            return False
        del tokens[provider]
        self.tokens_path.parent.mkdir(parents=True, exist_ok=True)
        self.tokens_path.write_text(json.dumps(tokens, indent=2), encoding="utf-8")
        return True

    # ------------------------------------------------------------------
    # GitHub Device Flow (RFC 8628)
    # ------------------------------------------------------------------

    async def github_start(self, client_id: str) -> dict[str, Any]:
        """Begin a device flow: returns user_code + verification_uri for the UI."""
        client = await SharedHTTPClient().get_client()
        try:
            resp = await client.post(
                GITHUB_DEVICE_CODE_URL,
                data={"client_id": client_id, "scope": GITHUB_SCOPE},
                headers={"Accept": "application/json"},
            )
        except Exception as e:
            raise OAuthError(f"Failed to contact GitHub: {e}") from e

        if resp.status_code != 200:
            raise OAuthError(f"GitHub device code request failed (HTTP {resp.status_code})")

        data = resp.json()
        if "device_code" not in data:
            raise OAuthError(
                data.get("error_description")
                or "GitHub did not return a device code (is Device Flow enabled for this OAuth App?)"
            )

        session = {
            "device_code": data["device_code"],
            "interval": int(data.get("interval", 5)),
            "expires_at": time.time() + int(data.get("expires_in", 900)),
        }
        self._sessions["github"] = session

        return {
            "user_code": data.get("user_code"),
            "verification_uri": data.get("verification_uri"),
            "expires_in": int(data.get("expires_in", 900)),
            "interval": session["interval"],
        }

    async def github_poll(self, client_id: str) -> dict[str, Any]:
        """Single poll of the access-token endpoint.

        Returns a status dict: pending | slow_down | complete | expired | error.
        On 'complete' the access token is included for the caller to persist.
        """
        session = self._sessions.get("github")
        if not session:
            return {"status": "error", "error": "No active GitHub device flow - start first."}
        if time.time() > session["expires_at"]:
            self._sessions.pop("github", None)
            return {"status": "expired", "error": "Device code expired - start a new flow."}

        client = await SharedHTTPClient().get_client()
        try:
            resp = await client.post(
                GITHUB_ACCESS_TOKEN_URL,
                data={
                    "client_id": client_id,
                    "device_code": session["device_code"],
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                },
                headers={"Accept": "application/json"},
            )
        except Exception as e:
            return {"status": "error", "error": f"Failed to contact GitHub: {e}"}

        data = resp.json()

        if "access_token" in data:
            self._sessions.pop("github", None)
            token_data = {
                "access_token": data["access_token"],
                "token_type": data.get("token_type", "bearer"),
                "scope": data.get("scope", ""),
            }
            self.save_token("github", token_data)
            return {"status": "complete", **token_data}

        error = data.get("error")
        if error == "authorization_pending":
            return {"status": "pending"}
        if error == "slow_down":
            session["interval"] += 5
            return {"status": "slow_down", "interval": session["interval"]}
        if error in ("expired_token", "access_denied"):
            self._sessions.pop("github", None)
            return {
                "status": "expired" if error == "expired_token" else "error",
                "error": data.get("error_description", error),
            }
        return {"status": "error", "error": data.get("error_description", "Unknown OAuth error")}
