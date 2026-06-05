"""WHOIS OSINT plugin."""

import asyncio
from typing import Any

from backend.plugins.base import BasePlugin, PluginResult


class WhoisPlugin(BasePlugin):
    name = "whois"

    async def execute(self, target: str, context: dict[str, Any] | None = None) -> PluginResult:
        import whois

        raw = await asyncio.to_thread(whois.whois, target)
        data = dict(raw) if hasattr(raw, "items") else {"raw": str(raw)}
        findings = [{"source": self.name, "type": "domain.whois", "value": target, "confidence": 0.8, "data": data}]
        return PluginResult(plugin_name=self.name, status="completed", findings=findings)
