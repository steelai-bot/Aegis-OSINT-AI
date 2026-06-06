"""API authentication dependencies.

Authentication is opt-in for the MVP so local development and existing demos keep
their current behavior unless operators explicitly enable it through environment
configuration.
"""

from dataclasses import dataclass
from secrets import compare_digest
from typing import Literal

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.core.config import Settings, get_settings


bearer_scheme = HTTPBearer(auto_error=False)

Permission = Literal[
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

    def has_permission(self, permission: Permission) -> bool:
        """Return whether the principal's role grants a permission."""

        return permission in ROLE_PERMISSIONS.get(self.role, set())


async def require_api_auth(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    settings: Settings = Depends(get_settings),
) -> Principal | None:
    """Require the configured bearer token when API auth is enabled."""

    if not settings.auth_enabled:
        return None

    if not settings.api_auth_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API authentication is enabled but AEGIS_API_AUTH_TOKEN is not configured.",
        )

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _unauthorized()

    if not compare_digest(credentials.credentials, settings.api_auth_token):
        raise _unauthorized()

    return Principal(id="local-api-token", role="admin")


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


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Valid bearer authentication is required.",
        headers={"WWW-Authenticate": "Bearer"},
    )