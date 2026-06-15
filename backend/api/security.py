"""API authentication dependencies with JWT support.

Authentication is opt-in (``AEGIS_AUTH_ENABLED=true``). When disabled, the
dependencies return ``None`` so existing development flows keep working.

When enabled, callers must present a valid JWT access token issued by the
``/api/v1/auth/login`` endpoint.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

import jwt as pyjwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.core.config import Settings, get_settings

bearer_scheme = HTTPBearer(auto_error=False)

# ── Permission types ───────────────────────────────────────────────────────

Permission = Literal[
    "investigation:read",
    "investigation:create",
    "target:read",
    "target:create",
    "finding:read",
    "finding:create",
    "collection:run",
    "collection:status",
    "tool_execution:approve",
    "agent:run",
    "report:read",
    "report:create",
    "report:render",
    "audit:read",
    "auth:manage",
]

ADMIN_PERMISSIONS: set[Permission] = {
    "investigation:read",
    "investigation:create",
    "target:read",
    "target:create",
    "finding:read",
    "finding:create",
    "collection:run",
    "collection:status",
    "tool_execution:approve",
    "agent:run",
    "report:read",
    "report:create",
    "report:render",
    "audit:read",
    "auth:manage",
}

ROLE_PERMISSIONS: dict[str, set[Permission]] = {
    "admin": ADMIN_PERMISSIONS,
    "analyst": {
        "investigation:read",
        "investigation:create",
        "target:read",
        "target:create",
        "finding:read",
        "finding:create",
        "collection:run",
        "collection:status",
        "agent:run",
        "report:read",
        "report:create",
        "report:render",
    },
    "viewer": {
        "investigation:read",
        "target:read",
        "finding:read",
        "collection:status",
        "report:read",
    },
    "service": set(),
}


@dataclass(frozen=True)
class Principal:
    """Authenticated operator or service identity resolved for a request."""

    id: str
    role: str
    email: str | None = None
    display_name: str | None = None

    def has_permission(self, permission: Permission) -> bool:
        """Return whether the principal's role grants a permission."""
        return permission in ROLE_PERMISSIONS.get(self.role, set())


# ── Dependencies ───────────────────────────────────────────────────────────


async def _resolve_principal(
    credentials: HTTPAuthorizationCredentials | None,
    settings: Settings,
) -> Principal | None:
    """Decode a JWT access token and return a Principal, or ``None`` when auth is disabled."""
    if not settings.auth_enabled:
        return None

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _unauthorized()

    try:
        decoded = pyjwt.decode(
            credentials.credentials,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["sub", "type"]},
        )
    except pyjwt.ExpiredSignatureError:
        raise _unauthorized("Token has expired.")
    except pyjwt.PyJWTError:
        raise _unauthorized("Invalid token.")

    if decoded.get("type") != "access":
        raise _unauthorized("Token is not an access token.")

    return Principal(
        id=decoded["sub"],
        role=decoded.get("role", "viewer"),
        email=decoded.get("email"),
        display_name=decoded.get("display_name"),
    )


async def require_api_auth(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    settings: Settings = Depends(get_settings),
) -> Principal | None:
    """Require an authenticated principal when API auth is enabled."""
    return await _resolve_principal(credentials, settings)


async def require_health_auth(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    settings: Settings = Depends(get_settings),
) -> Principal | None:
    """Require health authentication only when operators opt out of public health checks."""
    if settings.auth_allow_unauthenticated_health:
        return None
    return await require_api_auth(credentials=credentials, settings=settings)


def require_permission(permission: Permission):
    """Require a role permission when API auth is enabled."""

    async def permission_dependency(
        principal: Principal | None = Depends(require_api_auth),
    ) -> Principal | None:
        if principal is None:
            return None
        if not principal.has_permission(permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' is required.",
            )
        return principal

    return permission_dependency


# ── Helpers ────────────────────────────────────────────────────────────────


def _unauthorized(detail: str | None = None) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail or "Valid bearer authentication is required.",
        headers={"WWW-Authenticate": "Bearer"},
    )