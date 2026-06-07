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
    egress_allowed_hosts: tuple[str, ...] = ()
    egress_allow_private_networks = False
    egress_max_response_bytes: int | None = None

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}

    def http_policy_kwargs(self, *, allowed_hosts: tuple[str, ...] | None = None) -> dict[str, Any]:
        """Return shared HTTP-client policy kwargs for this plugin."""

        configured_hosts = self.config.get("egress_allowed_hosts")
        merged_hosts = allowed_hosts if allowed_hosts is not None else self.egress_allowed_hosts
        if configured_hosts:
            extra_hosts = tuple(str(host) for host in configured_hosts if str(host).strip())
            merged_hosts = tuple(dict.fromkeys((*merged_hosts, *extra_hosts)))

        allow_private = bool(self.config.get("egress_allow_private_networks", self.egress_allow_private_networks))
        max_response_bytes = self.config.get("egress_max_response_bytes", self.egress_max_response_bytes)
        return {
            "plugin_name": self.name,
            "allowed_hosts": merged_hosts,
            "allow_private_networks": allow_private,
            "max_response_bytes": int(max_response_bytes) if max_response_bytes is not None else None,
        }

    @abstractmethod
    async def execute(self, target: str, context: dict[str, Any] | None = None) -> PluginResult:
        """Execute the plugin and return normalized findings."""
