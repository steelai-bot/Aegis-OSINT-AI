"""Async in-process event bus for investigation lifecycle events."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

EventHandler = Callable[["Event"], Awaitable[None]]


@dataclass(slots=True)
class Event:
    """A normalized event emitted by services, agents, and plugins."""

    name: str
    payload: dict[str, Any]
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class EventBus:
    """Simple async event bus.

    The implementation is intentionally local and replaceable. It gives agents
    a communication channel without allowing direct agent-to-agent calls.
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, list[EventHandler]] = defaultdict(list)
        self._events: list[Event] = []
        self._lock = asyncio.Lock()

    def subscribe(self, event_name: str, handler: EventHandler) -> None:
        self._subscribers[event_name].append(handler)

    def unsubscribe(self, event_name: str, handler: EventHandler) -> None:
        """Remove a previously registered handler when a scoped listener ends."""

        handlers = self._subscribers.get(event_name)
        if not handlers:
            return
        self._subscribers[event_name] = [registered for registered in handlers if registered != handler]

    async def publish(self, event_name: str, payload: dict[str, Any]) -> Event:
        event = Event(name=event_name, payload=payload)
        async with self._lock:
            self._events.append(event)
        handlers = [*self._subscribers.get(event_name, []), *self._subscribers.get("*", [])]
        if handlers:
            await asyncio.gather(*(handler(event) for handler in handlers))
        return event

    async def history(self) -> list[Event]:
        async with self._lock:
            return list(self._events)


event_bus = EventBus()
