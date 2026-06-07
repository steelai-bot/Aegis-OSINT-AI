"""Base plugin contract for configurable OSINT integrations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class PluginResult:
    plugin_name: str
    status: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class BasePlugin(ABC):
    name = "base"
    enabled = True
    threat_category = "general"
    indicator_types: tuple[str, ...] = ()
    execution_mode = "passive"
    requires_approval = False
    rate_limit_key: str | None = None

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}

    @abstractmethod
    async def execute(self, target: str, context: dict[str, Any] | None = None) -> PluginResult:
        """Execute the plugin and return normalized findings."""
