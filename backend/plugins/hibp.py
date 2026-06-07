"""HaveIBeenPwned breach metadata plugin."""

from typing import Any

from backend.core.config import get_settings
from backend.core.http import http_client
from backend.plugins.base import BasePlugin, PluginResult


class HaveIBeenPwnedPlugin(BasePlugin):
    name = "hibp"
    threat_category = "credential_leak"
    indicator_types = ("email",)
    egress_allowed_hosts = ("haveibeenpwned.com",)

    async def execute(self, target: str, context: dict[str, Any] | None = None) -> PluginResult:
        settings = get_settings()
        if not settings.hibp_api_key:
            return PluginResult(plugin_name=self.name, status="skipped", metadata={"reason": "missing_api_key"})
        async with http_client(settings, **self.http_policy_kwargs()) as client:
            response = await client.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}",
                headers={"hibp-api-key": settings.hibp_api_key},
                params={"truncateResponse": "false"},
            )
        payload = response.json()
        findings = [
            {
                "source": self.name,
                "type": "email.breach_exposure",
                "value": target,
                "confidence": 0.85,
                "severity": "medium",
                "data": breach,
            }
            for breach in payload if isinstance(payload, list)
        ]
        return PluginResult(plugin_name=self.name, status="completed", findings=findings)
