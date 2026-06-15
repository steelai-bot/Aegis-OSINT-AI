"""Authentication service — JWT tokens, password hashing, user CRUD."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

import bcrypt
import jwt as pyjwt

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.config import get_settings
from backend.models.user import User


class AuthService:
    """High-level authentication operations backed by the database."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self._settings = get_settings()

    # ── password helpers ──────────────────────────────────────────────

    @staticmethod
    def hash_password(plain: str) -> str:
        return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()

    @staticmethod
    def verify_password(plain: str, hashed: str) -> bool:
        return bcrypt.checkpw(plain.encode(), hashed.encode())

    # ── user persistence ──────────────────────────────────────────────

    async def create_user(
        self,
        email: str,
        password: str,
        display_name: str,
        role: str = "analyst",
    ) -> User:
        """Register a new operator account."""
        user = User(
            email=email,
            password_hash=self.hash_password(password),
            display_name=display_name,
            role=role,
        )
        self.session.add(user)
        await self.session.commit()
        await self.session.refresh(user)
        return user

    async def get_user_by_email(self, email: str) -> User | None:
        result = await self.session.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()

    async def get_user_by_id(self, user_id: UUID) -> User | None:
        return await self.session.get(User, user_id)

    # ── JWT token helpers ─────────────────────────────────────────────

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _secret(self) -> str:
        return self._settings.jwt_secret

    def _algo(self) -> str:
        return self._settings.jwt_algorithm

    def create_access_token(self, user: User) -> str:
        ttl = self._settings.jwt_access_token_ttl_minutes
        payload = {
            "sub": str(user.id),
            "email": user.email,
            "role": user.role,
            "display_name": user.display_name,
            "type": "access",
            "iat": self._now(),
            "exp": self._now() + timedelta(minutes=ttl),
        }
        return pyjwt.encode(payload, self._secret(), algorithm=self._algo())

    def create_refresh_token(self, user: User) -> str:
        ttl = self._settings.jwt_refresh_token_ttl_minutes
        payload = {
            "sub": str(user.id),
            "type": "refresh",
            "iat": self._now(),
            "exp": self._now() + timedelta(minutes=ttl),
        }
        return pyjwt.encode(payload, self._secret(), algorithm=self._algo())

    def decode_token(self, token: str) -> dict:
        """Decode and validate a JWT.

        Raises ``jwt.PyJWTError`` on expiry or invalid signature.
        """
        return pyjwt.decode(token, self._secret(), algorithms=[self._algo()])

    async def authenticate(self, email: str, password: str) -> User | None:
        """Return the user if credentials are valid, else ``None``."""
        user = await self.get_user_by_email(email)
        if user is None or not user.is_active:
            return None
        if not self.verify_password(password, user.password_hash):
            return None
        return user