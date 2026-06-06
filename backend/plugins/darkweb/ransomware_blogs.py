"""Passive ransomware leak site monitoring plugin."""

from __future__ import annotations

import re
from typing import Any

import httpx

from backend.core.config import get_settings
from backend.core.http import http_client
from backend.plugins.base import BasePlugin, PluginResult


EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)


class RansomwareBlogScraperPlugin(BasePlugin):
    """Search configured public ransomware leak pages for organization mentions."""

    name = "ransomware_blog_scraper"
    threat_category = "darkweb_mention"
    indicator_types = ("domain", "email", "url", "keyword")

    async def execute(self, target: str, context: dict[str, Any] | None = None) -> PluginResult:
        sources = tuple(self.config.get("sources") or ())
        if not sources:
            return PluginResult(plugin_name=self.name, status="skipped", metadata={"reason": "no_sources_configured"})

        settings = get_settings()
        findings: list[dict[str, Any]] = []
        errors: dict[str, str] = {}
        async with http_client(settings) as client:
            for source_url in sources:
                try:
                    response = await client.get(str(source_url))
                    text = response.text
                except httpx.HTTPError as exc:
                    errors[str(source_url)] = str(exc)
                    continue
                if target.lower() not in text.lower():
                    continue
                findings.append(self._finding(target, "keyword", target, str(source_url), text))
                for email in sorted(set(EMAIL_RE.findall(text))):
                    findings.append(self._finding(target, "email", email, str(source_url), text))
                for url in sorted(set(URL_RE.findall(text))):
                    findings.append(self._finding(target, "url", url, str(source_url), text))

        return PluginResult(plugin_name=self.name, status="completed", findings=findings, metadata={"errors": errors})

    def _finding(self, target: str, indicator_type: str, value: str, source_url: str, text: str) -> dict[str, Any]:
        return {
            "source": self.name,
            "type": f"ransomware_leak_site.{indicator_type}",
            "value": value,
            "confidence": 0.75,
            "severity": "high" if indicator_type == "keyword" else "medium",
            "threat_category": self.threat_category,
            "indicator_type": indicator_type,
            "collector_plugin": self.name,
            "source_url": source_url,
            "data": {"target": target, "content_preview": self._snippet(text, target)},
            "raw_evidence": {"source_url": source_url, "content_length": len(text)},
        }

    def _snippet(self, text: str, target: str, radius: int = 240) -> str:
        offset = text.lower().find(target.lower())
        if offset < 0:
            return text[: radius * 2]
        start = max(offset - radius, 0)
        end = min(offset + len(target) + radius, len(text))
        return text[start:end]