"""VirusTotal domain intelligence plugin."""

from typing import Any

from backend.core.config import get_settings
from backend.core.http import http_client
from backend.plugins.base import BasePlugin, PluginResult


class VirusTotalPlugin(BasePlugin):
    name = "virustotal"

    async def execute(self, target: str, context: dict[str, Any] | None = None) -> PluginResult:
        settings = get_settings()
        if not settings.virustotal_api_key:
            return PluginResult(plugin_name=self.name, status="skipped", metadata={"reason": "missing_api_key"})
        async with http_client(settings) as client:
            response = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{target}",
                headers={"x-apikey": settings.virustotal_api_key},
            )
        payload = response.json()
        stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        severity = "high" if stats.get("malicious", 0) else "info"
        finding = {"source": self.name, "type": "domain.reputation", "value": target, "confidence": 0.8, "severity": severity, "data": payload}
        return PluginResult(plugin_name=self.name, status="completed", findings=[finding])
