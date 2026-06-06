"""Write-only audit event persistence service."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.audit_event import AuditEvent


SENSITIVE_METADATA_KEY_PARTS = frozenset(
    {
        "api_key",
        "authorization",
        "bearer",
        "credential",
        "header",
        "password",
        "secret",
        "token",
    }
)
MAX_METADATA_DEPTH = 4
MAX_METADATA_ITEMS = 50
MAX_METADATA_KEY_LENGTH = 100
MAX_METADATA_STRING_LENGTH = 2048
MAX_EVENT_TYPE_LENGTH = 100
MAX_ACTOR_ID_LENGTH = 255
MAX_ACTOR_ROLE_LENGTH = 50
MAX_RESOURCE_TYPE_LENGTH = 100
MAX_RESOURCE_ID_LENGTH = 100
MAX_STATUS_LENGTH = 30
MAX_REQUEST_ID_LENGTH = 100
MAX_IP_ADDRESS_LENGTH = 45
MAX_USER_AGENT_LENGTH = 512


class AuditEventService:
    """Persistence operations for structured audit events."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create_event(
        self,
        *,
        event_type: str,
        status: str,
        actor_id: str | None = None,
        actor_role: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        request_id: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> AuditEvent:
        """Persist a sanitized audit event."""

        event = AuditEvent(
            event_type=_truncate(event_type, MAX_EVENT_TYPE_LENGTH),
            actor_id=_optional_truncated(actor_id, MAX_ACTOR_ID_LENGTH),
            actor_role=_optional_truncated(actor_role, MAX_ACTOR_ROLE_LENGTH),
            resource_type=_optional_truncated(resource_type, MAX_RESOURCE_TYPE_LENGTH),
            resource_id=_optional_truncated(resource_id, MAX_RESOURCE_ID_LENGTH),
            status=_truncate(status, MAX_STATUS_LENGTH),
            request_id=_optional_truncated(request_id, MAX_REQUEST_ID_LENGTH),
            ip_address=_optional_truncated(ip_address, MAX_IP_ADDRESS_LENGTH),
            user_agent=_optional_truncated(user_agent, MAX_USER_AGENT_LENGTH),
            metadata_json=sanitize_audit_metadata(metadata),
        )
        self.session.add(event)
        await self.session.commit()
        await self.session.refresh(event)
        return event


def sanitize_audit_metadata(metadata: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return bounded metadata with sensitive values redacted."""

    if metadata is None:
        return {}
    return _sanitize_mapping(metadata, depth=0)


def _sanitize_mapping(metadata: Mapping[str, Any], *, depth: int) -> dict[str, Any]:
    if depth >= MAX_METADATA_DEPTH:
        return {"truncated": True}

    sanitized: dict[str, Any] = {}
    for index, (key, value) in enumerate(metadata.items()):
        if index >= MAX_METADATA_ITEMS:
            sanitized["truncated"] = True
            break

        clean_key = _truncate(str(key), MAX_METADATA_KEY_LENGTH)
        if _is_sensitive_key(clean_key):
            sanitized[clean_key] = "[redacted]"
            continue

        sanitized[clean_key] = _sanitize_value(value, depth=depth + 1)
    return sanitized


def _sanitize_value(value: Any, *, depth: int) -> Any:
    if depth >= MAX_METADATA_DEPTH:
        return "[truncated]"
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return _truncate(value, MAX_METADATA_STRING_LENGTH)
    if isinstance(value, Mapping):
        return _sanitize_mapping(value, depth=depth)
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        values = [_sanitize_value(item, depth=depth + 1) for item in value[:MAX_METADATA_ITEMS]]
        if len(value) > MAX_METADATA_ITEMS:
            values.append("[truncated]")
        return values
    return _truncate(str(value), MAX_METADATA_STRING_LENGTH)


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return any(part in normalized for part in SENSITIVE_METADATA_KEY_PARTS)


def _truncate(value: str, max_length: int) -> str:
    if len(value) <= max_length:
        return value
    return f"{value[: max_length - 15]}...[truncated]"


def _optional_truncated(value: str | None, max_length: int) -> str | None:
    if value is None:
        return None
    return _truncate(value, max_length)
