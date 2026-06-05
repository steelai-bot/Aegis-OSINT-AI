"""crt.sh certificate transparency plugin."""

from typing import Any

from backend.core.config import get_settings
from backend.core.http import http_client
from backend.plugins.base import BasePlugin, PluginResult


class CrtShPlugin(BasePlugin):
    name = "crtsh"

    async def execute(self, target: str, context: dict[str, Any] | None = None) -> PluginResult:
        settings = get_settings()
        async with http_client(settings) as client:
            response = await client.get("https://crt.sh/", params={"q": target, "output": "json"})
        rows = response.json()
        findings = []
        seen: set[str] = set()
        for row in rows if isinstance(rows, list) else []:
            for value in str(row.get("name_value", "")).splitlines():
                normalized = value.strip().lower().lstrip("*.")
                if normalized and normalized not in seen:
                    seen.add(normalized)
                    findings.append(
                        {
                            "source": self.name,
                            "type": "certificate.domain",
                            "value": normalized,
                            "confidence": 0.85,
                            "data": row,
                        }
                    )
        return PluginResult(plugin_name=self.name, status="completed", findings=findings)
