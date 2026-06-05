"""Shodan host intelligence plugin."""

from typing import Any

from backend.core.config import get_settings
from backend.core.http import http_client
from backend.plugins.base import BasePlugin, PluginResult


class ShodanPlugin(BasePlugin):
    name = "shodan"

    async def execute(self, target: str, context: dict[str, Any] | None = None) -> PluginResult:
        settings = get_settings()
        if not settings.shodan_api_key:
            return PluginResult(plugin_name=self.name, status="skipped", metadata={"reason": "missing_api_key"})
        async with http_client(settings) as client:
            response = await client.get("https://api.shodan.io/shodan/host/search", params={"key": settings.shodan_api_key, "query": target})
        payload = response.json()
        findings = [
            {
                "source": self.name,
                "type": "host.service",
                "value": item.get("ip_str") or item.get("hostnames", [target])[0],
                "confidence": 0.75,
                "data": item,
            }
            for item in payload.get("matches", [])
        ]
        return PluginResult(plugin_name=self.name, status="completed", findings=findings, metadata={"total": payload.get("total", 0)})
