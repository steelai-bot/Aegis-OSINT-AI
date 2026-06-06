"""Passive Telegram public channel monitoring plugin."""

from __future__ import annotations

import os
import re
from typing import Any

import httpx

from backend.core.config import get_settings
from backend.core.http import http_client
from backend.plugins.base import BasePlugin, PluginResult


EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
CRYPTO_RE = re.compile(r"\b(?:bc1[a-z0-9]{20,}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})\b")


class TelegramChannelMonitorPlugin(BasePlugin):
    """Collect mentions from authorized public Telegram channels via Bot API."""

    name = "telegram_channel_monitor"
    threat_category = "darkweb_mention"
    indicator_types = ("email", "url", "crypto_address", "keyword")

    async def execute(self, target: str, context: dict[str, Any] | None = None) -> PluginResult:
        token = self.config.get("bot_token") or os.getenv("AEGIS_TELEGRAM_BOT_TOKEN")
        channels = tuple(self.config.get("channels") or ())
        if not token:
            return PluginResult(plugin_name=self.name, status="skipped", metadata={"reason": "missing_bot_token"})
        if not channels:
            return PluginResult(plugin_name=self.name, status="skipped", metadata={"reason": "no_channels_configured"})

        settings = get_settings()
        findings: list[dict[str, Any]] = []
        errors: dict[str, str] = {}
        async with http_client(settings) as client:
            for channel in channels:
                try:
                    response = await client.get(
                        f"https://api.telegram.org/bot{token}/getChat",
                        params={"chat_id": channel},
                    )
                    chat = response.json().get("result", {})
                except (httpx.HTTPError, ValueError) as exc:
                    errors[str(channel)] = str(exc)
                    continue

                searchable = " ".join(str(chat.get(field, "")) for field in ("title", "username", "description"))
                if target.lower() not in searchable.lower():
                    continue
                findings.append(
                    self._finding(
                        target=target,
                        channel=str(channel),
                        indicator_type="keyword",
                        value=target,
                        evidence=chat,
                        source_url=self._channel_url(chat),
                    )
                )
                findings.extend(self._extract_indicators(target=target, channel=str(channel), text=searchable, evidence=chat))

        status = "completed" if findings else "completed_no_findings"
        return PluginResult(plugin_name=self.name, status=status, findings=findings, metadata={"errors": errors})

    def _extract_indicators(self, *, target: str, channel: str, text: str, evidence: dict[str, Any]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for email in sorted(set(EMAIL_RE.findall(text))):
            findings.append(self._finding(target=target, channel=channel, indicator_type="email", value=email, evidence=evidence))
        for url in sorted(set(URL_RE.findall(text))):
            findings.append(self._finding(target=target, channel=channel, indicator_type="url", value=url, evidence=evidence, source_url=url))
        for address in sorted(set(CRYPTO_RE.findall(text))):
            findings.append(
                self._finding(target=target, channel=channel, indicator_type="crypto_address", value=address, evidence=evidence)
            )
        return findings

    def _finding(
        self,
        *,
        target: str,
        channel: str,
        indicator_type: str,
        value: str,
        evidence: dict[str, Any],
        source_url: str | None = None,
    ) -> dict[str, Any]:
        return {
            "source": self.name,
            "type": f"telegram.{indicator_type}",
            "value": value,
            "confidence": 0.65,
            "severity": "medium",
            "threat_category": self.threat_category,
            "indicator_type": indicator_type,
            "collector_plugin": self.name,
            "source_url": source_url,
            "data": {"target": target, "channel": channel},
            "raw_evidence": evidence,
        }

    def _channel_url(self, chat: dict[str, Any]) -> str | None:
        username = chat.get("username")
        return f"https://t.me/{username}" if username else None