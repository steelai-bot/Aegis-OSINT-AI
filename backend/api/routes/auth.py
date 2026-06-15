"""Authentication API routes — login, register, token refresh, whoami."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.routes._audit import record_route_audit_event
from backend.api.security import Principal, require_api_auth
from backend.services.auth import AuthService
from backend.storage.database import get_db_session

router = APIRouter(prefix="/auth", tags=["auth"])


# ── Request / response schemas ─────────────────────────────────────────────


class RegisterRequest(BaseModel):
    email: str
    password: str
    display_name: str
    role: str = "analyst"


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class UserResponse(BaseModel):
    id: UUID
    email: str
    display_name: str
    role: str
    is_active: bool


# ── Routes ────────────────────────────────────────────────────────────────


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    payload: RegisterRequest,
    request: Request,
    session: AsyncSession = Depends(get_db_session),
):
    """Register a new operator account."""
    svc = AuthService(session)
    existing = await svc.get_user_by_email(payload.email)
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered.")
    user = await svc.create_user(
        email=payload.email,
        password=payload.password,
        display_name=payload.display_name,
        role=payload.role,
    )
    await record_route_audit_event(
        request=request,
        principal=None,
        event_type="auth.user.registered",
        status="success",
        resource_type="user",
        resource_id=str(user.id),
        metadata={"email": payload.email, "role": payload.role},
    )
    return UserResponse(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        role=user.role,
        is_active=user.is_active,
    )


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    session: AsyncSession = Depends(get_db_session),
):
    """Authenticate with email + password and receive JWT tokens."""
    svc = AuthService(session)
    user = await svc.authenticate(payload.email, payload.password)
    if user is None:
        await record_route_audit_event(
            request=request,
            principal=None,
            event_type="auth.login.failed",
            status="failure",
            resource_type="user",
            metadata={"email": payload.email},
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")
    await record_route_audit_event(
        request=request,
        principal=None,
        event_type="auth.login.succeeded",
        status="success",
        resource_type="user",
        resource_id=str(user.id),
        metadata={"email": payload.email, "role": user.role},
    )
    return TokenResponse(
        access_token=svc.create_access_token(user),
        refresh_token=svc.create_refresh_token(user),
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    payload: RefreshRequest,
    request: Request,
    session: AsyncSession = Depends(get_db_session),
):
    """Exchange a valid refresh token for a new access + refresh token pair."""
    svc = AuthService(session)
    try:
        decoded = svc.decode_token(payload.refresh_token)
    except Exception:
        await record_route_audit_event(
            request=request,
            principal=None,
            event_type="auth.token.refresh.failed",
            status="failure",
            metadata={"reason": "invalid_or_expired"},
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token.")

    if decoded.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is not a refresh token.")

    user = await svc.get_user_by_id(UUID(decoded["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive.")

    await record_route_audit_event(
        request=request,
        principal=None,
        event_type="auth.token.refreshed",
        status="success",
        resource_type="user",
        resource_id=str(user.id),
    )
    return TokenResponse(
        access_token=svc.create_access_token(user),
        refresh_token=svc.create_refresh_token(user),
    )


@router.get("/me", response_model=UserResponse)
async def whoami(
    principal: Principal | None = Depends(require_api_auth),
    session: AsyncSession = Depends(get_db_session),
):
    """Return the currently authenticated user's profile."""
    if principal is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication is disabled.")
    svc = AuthService(session)
    user = await svc.get_user_by_id(UUID(principal.id))
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return UserResponse(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        role=user.role,
        is_active=user.is_active,
    )