"""Certificate transparency monitoring for passive phishing indicators."""

from __future__ import annotations

from difflib import SequenceMatcher
from typing import Any

import httpx

from backend.core.config import get_settings
from backend.core.http import http_client
from backend.plugins.base import BasePlugin, PluginResult


class CertStreamMonitorPlugin(BasePlugin):
    """Query certificate transparency logs for suspicious domain registrations."""

    name = "certstream_monitor"
    threat_category = "phishing"
    indicator_types = ("domain", "certificate")
    egress_allowed_hosts = ("crt.sh",)

    async def execute(self, target: str, context: dict[str, Any] | None = None) -> PluginResult:
        domain = self._normalize_domain(target)
        settings = get_settings()
        try:
            async with http_client(settings, **self.http_policy_kwargs()) as client:
                response = await client.get("https://crt.sh/", params={"q": domain, "output": "json"})
            rows = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            return PluginResult(plugin_name=self.name, status="error", metadata={"error": str(exc)})

        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        for row in rows if isinstance(rows, list) else []:
            for name in str(row.get("name_value", "")).splitlines():
                candidate = self._normalize_domain(name)
                if not candidate or candidate in seen:
                    continue
                seen.add(candidate)
                if candidate == domain or candidate.endswith(f".{domain}"):
                    findings.append(self._finding(domain, candidate, row, "domain_monitoring", "low", 0.8))
                elif self._looks_like_typosquat(domain, candidate):
                    findings.append(self._finding(domain, candidate, row, self.threat_category, "high", 0.7))

        return PluginResult(plugin_name=self.name, status="completed", findings=findings)

    def _finding(
        self,
        target: str,
        candidate: str,
        evidence: dict[str, Any],
        threat_category: str,
        severity: str,
        confidence: float,
    ) -> dict[str, Any]:
        return {
            "source": self.name,
            "type": "certificate.domain",
            "value": candidate,
            "confidence": confidence,
            "severity": severity,
            "threat_category": threat_category,
            "indicator_type": "domain",
            "collector_plugin": self.name,
            "data": {"target": target, "matched_domain": candidate, "issuer": evidence.get("issuer_name")},
            "raw_evidence": evidence,
        }

    def _looks_like_typosquat(self, target: str, candidate: str) -> bool:
        target_label = target.split(".")[0]
        candidate_label = candidate.split(".")[0]
        if not target_label or target_label == candidate_label:
            return False
        return SequenceMatcher(None, target_label, candidate_label).ratio() >= 0.78

    def _normalize_domain(self, value: str) -> str:
        return value.lower().strip().removeprefix("http://").removeprefix("https://").split("/")[0].lstrip("*.")