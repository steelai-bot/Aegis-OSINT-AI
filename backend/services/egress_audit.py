"""Persistence bridge for sanitized plugin egress events."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.events import Event, EventBus
from backend.services.audit import AuditEventService


logger = logging.getLogger(__name__)


class EgressAuditSubscriber:
    """Subscribe to sanitized egress events and persist audit readback rows."""

    event_name = "tool.execution.egress"

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    def subscribe(self, bus: EventBus) -> None:
        bus.subscribe(self.event_name, self.handle_event)

    def unsubscribe(self, bus: EventBus) -> None:
        bus.unsubscribe(self.event_name, self.handle_event)

    async def handle_event(self, event: Event) -> None:
        """Persist one sanitized egress decision without leaking raw request data."""

        payload = dict(event.payload or {})
        plugin_name = _optional_string(payload.get("egress_plugin_name"))
        status = _normalize_status(payload.get("egress_policy_status"))
        metadata = _egress_metadata(payload)
        try:
            await AuditEventService(self.session).create_event(
                event_type=self.event_name,
                status=status,
                resource_type="tool_egress",
                resource_id=plugin_name or "unknown_plugin",
                metadata=metadata,
            )
        except Exception as exc:  # Audit persistence must not block plugin execution.
            await self.session.rollback()
            logger.warning("Failed to persist egress audit event (%s)", type(exc).__name__)


def _normalize_status(value: Any) -> str:
    status = str(value or "unknown").strip().lower().replace("-", "_")
    if status in {"allowed", "blocked"}:
        return status
    return "unknown"


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _egress_metadata(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Return allowlisted egress fields only; never persist URL paths or secrets."""

    allowed_keys = {
        "egress_policy_status",
        "egress_policy_reason",
        "egress_plugin_name",
        "egress_scheme",
        "egress_host",
        "egress_matched_rule",
        "egress_allowed_hosts_count",
    }
    return {key: value for key, value in payload.items() if key in allowed_keys and value is not None}