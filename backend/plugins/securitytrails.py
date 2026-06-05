"""SecurityTrails domain intelligence plugin."""

from typing import Any

from backend.core.config import get_settings
from backend.core.http import http_client
from backend.plugins.base import BasePlugin, PluginResult


class SecurityTrailsPlugin(BasePlugin):
    name = "securitytrails"

    async def execute(self, target: str, context: dict[str, Any] | None = None) -> PluginResult:
        settings = get_settings()
        if not settings.securitytrails_api_key:
            return PluginResult(plugin_name=self.name, status="skipped", metadata={"reason": "missing_api_key"})
        async with http_client(settings) as client:
            response = await client.get(
                f"https://api.securitytrails.com/v1/domain/{target}/subdomains",
                headers={"APIKEY": settings.securitytrails_api_key},
            )
        payload = response.json()
        findings = [
            {
                "source": self.name,
                "type": "domain.subdomain",
                "value": f"{subdomain}.{target}",
                "confidence": 0.8,
                "data": {"domain": target},
            }
            for subdomain in payload.get("subdomains", [])
        ]
        return PluginResult(plugin_name=self.name, status="completed", findings=findings)
