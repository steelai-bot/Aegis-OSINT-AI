"""API authentication dependencies.

Authentication is opt-in for the MVP so local development and existing demos keep
their current behavior unless operators explicitly enable it through environment
configuration.
"""

from dataclasses import dataclass
from secrets import compare_digest

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.core.config import Settings, get_settings


bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class Principal:
    """Authenticated operator or service identity resolved for a request."""

    id: str
    role: str


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


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Valid bearer authentication is required.",
        headers={"WWW-Authenticate": "Bearer"},
    )