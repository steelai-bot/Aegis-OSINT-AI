"""
oauth_manager.py — Aegis-OSINT-AI
OAuth / OAuth2 authentication manager for supported providers.
Handles authorization flows, token storage, refresh, and revocation.
Supports: Google, Microsoft 365, GitHub, LinkedIn, Facebook,
          HuggingFace, Slack, Xero, MYOB, Atlassian, Dropbox, Reddit.
"""

import os
import re
import json
import time
import base64
import hashlib
import secrets
import webbrowser
import urllib.parse
from pathlib import Path
from datetime import datetime, timezone, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from typing import Any

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    from cryptography.fernet import Fernet
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False


# ─────────────────────────────────────────────
#  Provider Registry
# ─────────────────────────────────────────────

PROVIDERS = {
    # ── Google ──────────────────────────────────────────────
    "google": {
        "name":           "Google / Google Workspace",
        "auth_url":       "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url":      "https://oauth2.googleapis.com/token",
        "revoke_url":     "https://oauth2.googleapis.com/revoke",
        "userinfo_url":   "https://www.googleapis.com/oauth2/v3/userinfo",
        "scopes":         [
            "openid", "email", "profile",
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/drive.readonly",
        ],
        "flow":           "authorization_code",
        "pkce":           True,
        "env_client_id":  "GOOGLE_CLIENT_ID",
        "env_client_secret": "GOOGLE_CLIENT_SECRET",
        "redirect_port":  8080,
        "osint_value":    "critical",
        "notes":          "Access Gmail, Drive, Calendar. Requires Google Cloud Console app.",
    },

    # ── Microsoft 365 ────────────────────────────────────────
    "microsoft": {
        "name":           "Microsoft 365 / Azure AD",
        "auth_url":       "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "token_url":      "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "revoke_url":     None,
        "userinfo_url":   "https://graph.microsoft.com/v1.0/me",
        "scopes":         [
            "openid", "email", "profile", "offline_access",
            "https://graph.microsoft.com/Mail.Read",
            "https://graph.microsoft.com/Files.Read.All",
            "https://graph.microsoft.com/User.Read",
            "https://graph.microsoft.com/Calendars.Read",
        ],
        "flow":           "authorization_code",
        "pkce":           True,
        "env_client_id":  "MICROSOFT_CLIENT_ID",
        "env_client_secret": "MICROSOFT_CLIENT_SECRET",
        "redirect_port":  8080,
        "osint_value":    "critical",
        "notes":          "Access Outlook, OneDrive, Teams. Register app in Azure Portal.",
    },

    # ── GitHub ───────────────────────────────────────────────
    "github": {
        "name":           "GitHub",
        "auth_url":       "https://github.com/login/oauth/authorize",
        "token_url":      "https://github.com/login/oauth/access_token",
        "revoke_url":     "https://api.github.com/applications/{client_id}/token",
        "userinfo_url":   "https://api.github.com/user",
        "scopes":         ["repo", "read:user", "user:email", "read:org", "gist"],
        "flow":           "authorization_code",
        "pkce":           False,
        "env_client_id":  "GITHUB_CLIENT_ID",
        "env_client_secret": "GITHUB_CLIENT_SECRET",
        "redirect_port":  8080,
        "osint_value":    "high",
        "notes":          "Access repos, gists, org membership. Register at github.com/settings/apps.",
    },

    # ── LinkedIn ─────────────────────────────────────────────
    "linkedin": {
        "name":           "LinkedIn",
        "auth_url":       "https://www.linkedin.com/oauth/v2/authorization",
        "token_url":      "https://www.linkedin.com/oauth/v2/accessToken",
        "revoke_url":     None,
        "userinfo_url":   "https://api.linkedin.com/v2/me",
        "scopes":         ["r_liteprofile", "r_emailaddress", "r_organization_social"],
        "flow":           "authorization_code",
        "pkce":           False,
        "env_client_id":  "LINKEDIN_CLIENT_ID",
        "env_client_secret": "LINKEDIN_CLIENT_SECRET",
        "redirect_port":  8080,
        "osint_value":    "high",
        "notes":          "Employee enumeration, company intel. Register at linkedin.com/developers.",
    },

    # ── HuggingFace ──────────────────────────────────────────
    "huggingface": {
        "name":           "HuggingFace",
        "auth_url":       "https://huggingface.co/oauth/authorize",
        "token_url":      "https://huggingface.co/oauth/token",
        "revoke_url":     None,
        "userinfo_url":   "https://huggingface.co/api/whoami-v2",
        "scopes":         ["openid", "profile", "email", "read-repos", "write-repos", "manage-repos", "inference-api"],
        "flow":           "authorization_code",
        "pkce":           True,
        "env_client_id":  "HF_CLIENT_ID",
        "env_client_secret": "HF_CLIENT_SECRET",
        "redirect_port":  8080,
        "osint_value":    "medium",
        "notes":          "Model downloads, inference API. Register at huggingface.co/settings/applications.",
    },

    # ── Slack ────────────────────────────────────────────────
    "slack": {
        "name":           "Slack",
        "auth_url":       "https://slack.com/oauth/v2/authorize",
        "token_url":      "https://slack.com/api/oauth.v2.access",
        "revoke_url":     "https://slack.com/api/auth.revoke",
        "userinfo_url":   "https://slack.com/api/auth.test",
        "scopes":         ["channels:read", "channels:history", "users:read", "files:read", "search:read"],
        "flow":           "authorization_code",
        "pkce":           False,
        "env_client_id":  "SLACK_CLIENT_ID",
        "env_client_secret": "SLACK_CLIENT_SECRET",
        "redirect_port":  8080,
        "osint_value":    "high",
        "notes":          "Read channels, messages, files. Register at api.slack.com/apps.",
    },

    # ── Xero ─────────────────────────────────────────────────
    "xero": {
        "name":           "Xero Accounting",
        "auth_url":       "https://login.xero.com/identity/connect/authorize",
        "token_url":      "https://identity.xero.com/connect/token",
        "revoke_url":     "https://identity.xero.com/connect/revocation",
        "userinfo_url":   "https://api.xero.com/connections",
        "scopes":         ["openid", "profile", "email", "offline_access",
                           "accounting.transactions.read", "accounting.contacts.read",
                           "accounting.reports.read", "payroll.employees.read"],
        "flow":           "authorization_code",
        "pkce":           True,
        "env_client_id":  "XERO_CLIENT_ID",
        "env_client_secret": "XERO_CLIENT_SECRET",
        "redirect_port":  8080,
        "osint_value":    "critical",
        "notes":          "AU accounting data, payroll, contacts. Register at developer.xero.com.",
    },

    # ── Atlassian (Jira/Confluence) ──────────────────────────
    "atlassian": {
        "name":           "Atlassian (Jira / Confluence)",
        "auth_url":       "https://auth.atlassian.com/authorize",
        "token_url":      "https://auth.atlassian.com/oauth/token",
        "revoke_url":     None,
        "userinfo_url":   "https://api.atlassian.com/me",
        "scopes":         [
            "read:jira-work", "read:jira-user",
            "read:confluence-content.all", "read:confluence-user",
            "offline_access",
        ],
        "flow":           "authorization_code",
        "pkce":           True,
        "env_client_id":  "ATLASSIAN_CLIENT_ID",
        "env_client_secret": "ATLASSIAN_CLIENT_SECRET",
        "redirect_port":  8080,
        "osint_value":    "high",
        "notes":          "Jira tickets, Confluence pages. Register at developer.atlassian.com.",
    },

    # ── Dropbox ──────────────────────────────────────────────
    "dropbox": {
        "name":           "Dropbox",
        "auth_url":       "https://www.dropbox.com/oauth2/authorize",
        "token_url":      "https://api.dropboxapi.com/oauth2/token",
        "revoke_url":     "https://api.dropboxapi.com/2/auth/token/revoke",
        "userinfo_url":   "https://api.dropboxapi.com/2/users/get_current_account",
        "scopes":         ["files.metadata.read", "files.content.read", "sharing.read", "account_info.read"],
        "flow":           "authorization_code",
        "pkce":           True,
        "env_client_id":  "DROPBOX_CLIENT_ID",
        "env_client_secret": "DROPBOX_CLIENT_SECRET",
        "redirect_port":  8080,
        "osint_value":    "high",
        "notes":          "File access, shared links. Register at dropbox.com/developers.",
    },

    # ── Reddit ───────────────────────────────────────────────
    "reddit": {
        "name":           "Reddit",
        "auth_url":       "https://www.reddit.com/api/v1/authorize",
        "token_url":      "https://www.reddit.com/api/v1/access_token",
        "revoke_url":     "https://www.reddit.com/api/v1/revoke_token",
        "userinfo_url":   "https://oauth.reddit.com/api/v1/me",
        "scopes":         ["identity", "read", "history", "mysubreddits", "privatemessages"],
        "flow":           "authorization_code",
        "pkce":           False,
        "env_client_id":  "REDDIT_CLIENT_ID",
        "env_client_secret": "REDDIT_CLIENT_SECRET",
        "redirect_port":  8080,
        "osint_value":    "medium",
        "notes":          "User history, private messages. Register at reddit.com/prefs/apps.",
    },
}

# Providers that support ROPC (no browser needed — direct credential flow)
ROPC_PROVIDERS = {
    "microsoft_ropc": {
        "name":       "Microsoft 365 (ROPC — no browser)",
        "token_url":  "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "client_id":  "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Well-known public client
        "scope":      "https://graph.microsoft.com/.default offline_access",
        "flow":       "ropc",
        "osint_value": "critical",
    },
}


# ─────────────────────────────────────────────
#  PKCE Helpers
# ─────────────────────────────────────────────

def _pkce_pair() -> tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge (S256)."""
    verifier  = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


# ─────────────────────────────────────────────
#  Token Storage
# ─────────────────────────────────────────────

class TokenStore:
    """
    Encrypted local token storage.
    Tokens saved to .tokens/ directory, encrypted with Fernet if available.
    """

    def __init__(self, store_dir: str = ".tokens"):
        self.store_dir = Path(store_dir)
        self.store_dir.mkdir(mode=0o700, exist_ok=True)
        self._key = self._load_or_create_key()

    def _load_or_create_key(self) -> bytes | None:
        if not CRYPTO_OK:
            return None
        key_path = self.store_dir / ".key"
        if key_path.exists():
            return key_path.read_bytes()
        key = Fernet.generate_key()
        key_path.write_bytes(key)
        key_path.chmod(0o600)
        return key

    def save(self, provider: str, token_data: dict) -> None:
        token_data["saved_at"] = datetime.now(timezone.utc).isoformat()
        raw = json.dumps(token_data).encode()
        if CRYPTO_OK and self._key:
            raw = Fernet(self._key).encrypt(raw)
        path = self.store_dir / f"{provider}.token"
        path.write_bytes(raw)
        path.chmod(0o600)

    def load(self, provider: str) -> dict | None:
        path = self.store_dir / f"{provider}.token"
        if not path.exists():
            return None
        raw = path.read_bytes()
        if CRYPTO_OK and self._key:
            try:
                raw = Fernet(self._key).decrypt(raw)
            except Exception:
                return None
        try:
            return json.loads(raw)
        except Exception:
            return None

    def delete(self, provider: str) -> None:
        path = self.store_dir / f"{provider}.token"
        if path.exists():
            path.unlink()

    def list_saved(self) -> list[str]:
        return [p.stem for p in self.store_dir.glob("*.token")]

    def is_expired(self, token_data: dict, buffer_secs: int = 300) -> bool:
        expires_at = token_data.get("expires_at")
        if not expires_at:
            return False
        return time.time() >= (expires_at - buffer_secs)


# ─────────────────────────────────────────────
#  Local Redirect Server (for auth code flow)
# ─────────────────────────────────────────────

class _CallbackHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler to catch OAuth redirect."""
    code  = None
    state = None
    error = None

    def do_GET(self):
        params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        _CallbackHandler.code  = params.get("code",  [None])[0]
        _CallbackHandler.state = params.get("state", [None])[0]
        _CallbackHandler.error = params.get("error", [None])[0]
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        msg = "Authorization complete — you can close this tab." if _CallbackHandler.code else f"Error: {_CallbackHandler.error}"
        self.wfile.write(f"<html><body><h2>Aegis-OSINT-AI</h2><p>{msg}</p></body></html>".encode())

    def log_message(self, *args): pass  # Silence access log


def _wait_for_callback(port: int, timeout: int = 120) -> tuple[str | None, str | None]:
    """Start local HTTP server and wait for OAuth callback."""
    _CallbackHandler.code  = None
    _CallbackHandler.state = None
    _CallbackHandler.error = None

    server = HTTPServer(("127.0.0.1", port), _CallbackHandler)
    server.timeout = timeout

    def _serve():
        server.handle_request()

    t = Thread(target=_serve, daemon=True)
    t.start()
    t.join(timeout=timeout + 2)
    server.server_close()
    return _CallbackHandler.code, _CallbackHandler.state


# ─────────────────────────────────────────────
#  OAuth Manager
# ─────────────────────────────────────────────

class OAuthManager:
    """
    Handles OAuth / OAuth2 flows for all supported providers.
    Stores tokens encrypted locally, auto-refreshes on expiry.

    Usage:
        mgr = OAuthManager()
        token = mgr.login("google")
        token = mgr.login("microsoft")
        token = mgr.login_ropc("microsoft_ropc", email, password)
        info  = mgr.get_userinfo("google")
        mgr.revoke("google")
    """

    def __init__(self, store_dir: str = ".tokens"):
        self.store   = TokenStore(store_dir)
        self.session = requests.Session() if REQUESTS_OK else None

    # ── Authorization Code Flow ──────────────────────────────

    def login(self, provider_key: str, open_browser: bool = True) -> dict | None:
        """
        Run OAuth2 Authorization Code flow for a provider.
        Opens browser, waits for redirect, exchanges code for token.
        Returns token dict or None on failure.
        """
        cfg = PROVIDERS.get(provider_key)
        if not cfg:
            print(f"Unknown provider: {provider_key}")
            return None

        client_id     = os.getenv(cfg["env_client_id"], "")
        client_secret = os.getenv(cfg["env_client_secret"], "")

        if not client_id:
            print(f"  Missing {cfg['env_client_id']} in environment")
            print(f"  Register app: see notes → {cfg['notes']}")
            return None

        port         = cfg.get("redirect_port", 8080)
        redirect_uri = f"http://127.0.0.1:{port}/callback"
        state        = secrets.token_urlsafe(16)

        params = {
            "client_id":     client_id,
            "response_type": "code",
            "redirect_uri":  redirect_uri,
            "scope":         " ".join(cfg["scopes"]),
            "state":         state,
            "access_type":   "offline",
            "prompt":        "consent",
        }

        verifier = None
        if cfg.get("pkce"):
            verifier, challenge = _pkce_pair()
            params["code_challenge"]        = challenge
            params["code_challenge_method"] = "S256"

        auth_url = cfg["auth_url"] + "?" + urllib.parse.urlencode(params)

        print(f"\n  Opening browser for {cfg['name']} login...")
        print(f"  URL: {auth_url[:80]}...")

        if open_browser:
            webbrowser.open(auth_url)
        else:
            print(f"\n  Open this URL manually:\n  {auth_url}\n")

        print(f"  Waiting for callback on port {port}...")
        code, returned_state = _wait_for_callback(port)

        if not code:
            print(f"  No authorization code received")
            return None

        if returned_state != state:
            print(f"  State mismatch — possible CSRF")
            return None

        # Exchange code for token
        token_data = self._exchange_code(
            cfg, code, redirect_uri, client_id, client_secret, verifier
        )

        if token_data and "access_token" in token_data:
            token_data["provider"]    = provider_key
            token_data["expires_at"]  = time.time() + token_data.get("expires_in", 3600)
            self.store.save(provider_key, token_data)
            print(f"  ✓ Token saved for {cfg['name']}")
            return token_data

        print(f"  Token exchange failed: {token_data}")
        return None

    def _exchange_code(self, cfg, code, redirect_uri, client_id, client_secret, verifier=None) -> dict:
        payload = {
            "grant_type":   "authorization_code",
            "code":         code,
            "redirect_uri": redirect_uri,
            "client_id":    client_id,
        }
        if client_secret:
            payload["client_secret"] = client_secret
        if verifier:
            payload["code_verifier"] = verifier

        headers = {"Accept": "application/json"}
        r = self.session.post(cfg["token_url"], data=payload, headers=headers, timeout=15)
        try:
            return r.json()
        except Exception:
            return {"error": r.text[:200]}

    # ── ROPC Flow (no browser) ───────────────────────────────

    def login_ropc(self, provider_key: str, email: str, password: str) -> dict | None:
        """
        Resource Owner Password Credentials flow.
        No browser required — direct credential exchange.
        Only supported by Microsoft (and some enterprise IdPs).
        """
        cfg = ROPC_PROVIDERS.get(provider_key)
        if not cfg:
            print(f"ROPC not supported for: {provider_key}")
            return None

        payload = {
            "grant_type": "password",
            "client_id":  cfg["client_id"],
            "username":   email,
            "password":   password,
            "scope":      cfg["scope"],
        }

        r = self.session.post(cfg["token_url"], data=payload, timeout=12)
        data = r.json()

        if "access_token" in data:
            data["provider"]   = provider_key
            data["email"]      = email
            data["expires_at"] = time.time() + data.get("expires_in", 3600)
            self.store.save(provider_key, data)
            print(f"  ✓ ROPC token obtained for {email}")
            return data

        error = data.get("error_description", data.get("error", "unknown"))
        if "AADSTS50076" in error or "MFA" in error.upper():
            print(f"  ⚠ MFA required for {email}")
            return {"status": "mfa_required", "email": email}
        if "AADSTS50053" in error:
            print(f"  ✗ Account locked: {email}")
            return {"status": "locked", "email": email}

        print(f"  ✗ ROPC failed: {error[:100]}")
        return None

    # ── Token Refresh ────────────────────────────────────────

    def refresh(self, provider_key: str) -> dict | None:
        """Refresh an expired access token using the refresh_token."""
        token_data = self.store.load(provider_key)
        if not token_data:
            print(f"  No saved token for {provider_key}")
            return None

        refresh_token = token_data.get("refresh_token")
        if not refresh_token:
            print(f"  No refresh_token available — re-login required")
            return None

        cfg = PROVIDERS.get(provider_key) or ROPC_PROVIDERS.get(provider_key)
        if not cfg:
            return None

        client_id     = os.getenv(cfg.get("env_client_id", ""), "")
        client_secret = os.getenv(cfg.get("env_client_secret", ""), "")

        payload = {
            "grant_type":    "refresh_token",
            "refresh_token": refresh_token,
            "client_id":     client_id,
        }
        if client_secret:
            payload["client_secret"] = client_secret

        r = self.session.post(cfg["token_url"], data=payload, timeout=12)
        data = r.json()

        if "access_token" in data:
            data["provider"]   = provider_key
            data["expires_at"] = time.time() + data.get("expires_in", 3600)
            if not data.get("refresh_token"):
                data["refresh_token"] = refresh_token  # Keep old refresh token
            self.store.save(provider_key, data)
            print(f"  ✓ Token refreshed for {provider_key}")
            return data

        print(f"  ✗ Refresh failed: {data}")
        return None

    # ── Auto-refresh helper ──────────────────────────────────

    def get_token(self, provider_key: str) -> dict | None:
        """
        Get valid token for provider, auto-refreshing if expired.
        """
        token_data = self.store.load(provider_key)
        if not token_data:
            return None
        if self.store.is_expired(token_data):
            token_data = self.refresh(provider_key)
        return token_data

    def get_access_token(self, provider_key: str) -> str | None:
        """Return just the access_token string."""
        td = self.get_token(provider_key)
        return td.get("access_token") if td else None

    # ── User Info ────────────────────────────────────────────

    def get_userinfo(self, provider_key: str) -> dict | None:
        """Fetch user profile from provider API."""
        cfg = PROVIDERS.get(provider_key)
        if not cfg or not cfg.get("userinfo_url"):
            return None

        token = self.get_access_token(provider_key)
        if not token:
            print(f"  No token for {provider_key} — run login() first")
            return None

        headers = {"Authorization": f"Bearer {token}"}
        # Dropbox uses POST for userinfo
        if provider_key == "dropbox":
            r = self.session.post(cfg["userinfo_url"], headers=headers, timeout=10)
        else:
            r = self.session.get(cfg["userinfo_url"], headers=headers, timeout=10)

        if r.status_code == 200:
            return r.json()
        return {"error": r.status_code, "body": r.text[:200]}

    # ── Revoke ───────────────────────────────────────────────

    def revoke(self, provider_key: str) -> bool:
        """Revoke token and delete from local store."""
        cfg = PROVIDERS.get(provider_key)
        token_data = self.store.load(provider_key)

        if cfg and cfg.get("revoke_url") and token_data:
            token = token_data.get("access_token", "")
            try:
                self.session.post(
                    cfg["revoke_url"].replace("{client_id}", os.getenv(cfg.get("env_client_id",""), "")),
                    data={"token": token}, timeout=10
                )
            except Exception:
                pass

        self.store.delete(provider_key)
        print(f"  ✓ Token revoked and deleted for {provider_key}")
        return True

    # ── Status ───────────────────────────────────────────────

    def status(self) -> dict:
        """Show status of all saved tokens."""
        result = {}
        for provider_key in self.store.list_saved():
            td = self.store.load(provider_key)
            if not td:
                continue
            expired = self.store.is_expired(td)
            exp_ts  = td.get("expires_at", 0)
            exp_str = datetime.fromtimestamp(exp_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if exp_ts else "unknown"
            result[provider_key] = {
                "saved_at":    td.get("saved_at", ""),
                "expires_at":  exp_str,
                "expired":     expired,
                "has_refresh": bool(td.get("refresh_token")),
                "email":       td.get("email", ""),
            }
        return result

    def print_status(self) -> None:
        from rich.table import Table
        from rich.console import Console
        from rich import box
        console = Console()
        table = Table(title="OAuth Token Status", box=box.ROUNDED, border_style="dim cyan")
        table.add_column("Provider",    style="bold white", width=20)
        table.add_column("Expires",     style="dim",        width=22)
        table.add_column("Status",      style="bold",       width=12)
        table.add_column("Refresh",     style="dim",        width=8)
        table.add_column("Email",       style="dim",        width=30)

        for provider_key, info in self.status().items():
            status_str = "[red]EXPIRED[/red]" if info["expired"] else "[green]VALID[/green]"
            table.add_row(
                provider_key,
                info["expires_at"],
                status_str,
                "yes" if info["has_refresh"] else "no",
                info.get("email", ""),
            )

        if not self.status():
            console.print("[dim]No saved tokens.[/dim]")
        else:
            console.print(table)

    # ── List Providers ───────────────────────────────────────

    @staticmethod
    def list_providers() -> None:
        print(f"\n  {'Key':<20} {'Name':<35} {'Flow':<10} {'OSINT Value'}")
        print(f"  {'─'*20} {'─'*35} {'─'*10} {'─'*12}")
        for key, cfg in PROVIDERS.items():
            print(f"  {key:<20} {cfg['name']:<35} {cfg['flow']:<10} {cfg['osint_value']}")
        print()
        for key, cfg in ROPC_PROVIDERS.items():
            print(f"  {key:<20} {cfg['name']:<35} {'ropc':<10} {cfg['osint_value']}")
        print()


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Aegis-OSINT-AI OAuth Manager")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("list",    help="List available providers")
    sub.add_parser("status",  help="Show saved token status")

    login_p = sub.add_parser("login", help="Login to a provider")
    login_p.add_argument("provider", help="Provider key (e.g. google, microsoft)")
    login_p.add_argument("--no-browser", action="store_true")

    ropc_p = sub.add_parser("ropc", help="ROPC login (Microsoft, no browser)")
    ropc_p.add_argument("email")
    ropc_p.add_argument("password")

    info_p = sub.add_parser("userinfo", help="Fetch user info from provider")
    info_p.add_argument("provider")

    rev_p = sub.add_parser("revoke", help="Revoke and delete token")
    rev_p.add_argument("provider")

    ref_p = sub.add_parser("refresh", help="Refresh expired token")
    ref_p.add_argument("provider")

    args = parser.parse_args()
    mgr  = OAuthManager()

    if args.cmd == "list":
        OAuthManager.list_providers()
    elif args.cmd == "status":
        mgr.print_status()
    elif args.cmd == "login":
        mgr.login(args.provider, open_browser=not args.no_browser)
    elif args.cmd == "ropc":
        mgr.login_ropc("microsoft_ropc", args.email, args.password)
    elif args.cmd == "userinfo":
        info = mgr.get_userinfo(args.provider)
        print(json.dumps(info, indent=2, default=str))
    elif args.cmd == "revoke":
        mgr.revoke(args.provider)
    elif args.cmd == "refresh":
        mgr.refresh(args.provider)
    else:
        parser.print_help()
