"""Audit helpers for API route handlers."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from fastapi import Request

from backend.api.security import Principal
from backend.services.audit import AuditEventService
from backend.storage.database import AsyncSessionLocal


logger = logging.getLogger(__name__)


async def record_route_audit_event(
    *,
    request: Request,
    principal: Principal | None,
    event_type: str,
    status: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> None:
    """Persist a route audit event without failing the completed API action."""

    try:
        async with AsyncSessionLocal() as audit_session:
            await AuditEventService(audit_session).create_event(
                event_type=event_type,
                status=status,
                actor_id=principal.id if principal is not None else None,
                actor_role=principal.role if principal is not None else None,
                resource_type=resource_type,
                resource_id=resource_id,
                request_id=_header_value(request, "x-request-id")
                or _header_value(request, "x-correlation-id"),
                ip_address=request.client.host if request.client is not None else None,
                user_agent=_header_value(request, "user-agent"),
                metadata=metadata,
            )
    except Exception as exc:  # Audit logging must not hide a successful domain action.
        logger.warning("Failed to persist audit event '%s' (%s)", event_type, type(exc).__name__)


def _header_value(request: Request, name: str) -> str | None:
    value = request.headers.get(name)
    if value is None or value == "":
        return None
    return value
