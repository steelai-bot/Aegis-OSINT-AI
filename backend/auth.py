"""Single-user application authentication helpers.

Password hashing uses PBKDF2-HMAC-SHA256 from the standard library (no extra
dependency). The password hash is stored in .env as AUTH_PASSWORD_HASH in the
format `salt_hex$hash_hex`. Sessions are handled by Starlette's
SessionMiddleware (signed cookie via itsdangerous).
"""

import hashlib
import hmac
import secrets

PBKDF2_ITERATIONS = 120_000
SALT_BYTES = 16


def hash_password(password: str, salt: bytes | None = None) -> str:
    """Hash a password as `salt_hex$hash_hex` for storage in AUTH_PASSWORD_HASH."""
    if salt is None:
        salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verification of a password against a stored `salt$hash`."""
    try:
        salt_hex, hash_hex = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, TypeError):
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return hmac.compare_digest(digest, expected)


def generate_secret_key() -> str:
    """Random signing key for SessionMiddleware (persisted to .env on first run)."""
    return secrets.token_hex(32)
