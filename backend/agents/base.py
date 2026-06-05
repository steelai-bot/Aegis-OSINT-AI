"""Base classes for independent Aegis investigation agents."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from backend.core.events import EventBus, event_bus


@dataclass(slots=True)
class InvestigationContext:
    """Shared context passed into agents by the investigation engine."""

    investigation_id: UUID | None
    target: str
    target_type: str
    metadata: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class AgentResult:
    """Normalized result returned by every agent."""

    agent_name: str
    status: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseAgent(ABC):
    """Abstract base class for independent agents.

    Agents are prohibited from calling other agents directly. They receive an
    investigation context, publish events, and return task results.
    """

    name = "base"

    def __init__(self, bus: EventBus | None = None) -> None:
        self.event_bus = bus or event_bus

    async def execute(self, context: InvestigationContext) -> AgentResult:
        await self.event_bus.publish("agent.started", {"agent": self.name, "target": context.target})
        result = await self.run(context)
        await self.event_bus.publish(
            "agent.completed",
            {"agent": self.name, "target": context.target, "status": result.status},
        )
        return result

    @abstractmethod
    async def run(self, context: InvestigationContext) -> AgentResult:
        """Run the agent against the supplied investigation context."""
