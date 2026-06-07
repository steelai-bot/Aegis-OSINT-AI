"""Passive email exposure plugin for Aegis v2."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote_plus

from backend.core.config import get_settings
from backend.core.http import http_client
from backend.plugins.base import BasePlugin, PluginResult
from backend.plugins.email_exposure.classifiers import ExposureEvidence, redact_text
from backend.plugins.email_exposure.config import EmailExposureConfig
from backend.plugins.email_exposure.scrapers import ConfiguredPasteScraper, GitHubCodeSearchScraper, PassiveExposureScraper
from backend.plugins.email_exposure.scrapers.breach_databases import ExistingBreachPluginDelegation


class EmailExposurePlugin(BasePlugin):
    """Find email exposure evidence in approved passive public sources."""

    name = "email_exposure"
    threat_category = "credential_leak"
    indicator_types = ("email", "domain", "keyword")

    async def execute(self, target: str, context: dict[str, Any] | None = None) -> PluginResult:
        config = EmailExposureConfig.from_runtime(self.config, context)
        target_type = _normalize_target_type(str((context or {}).get("target_type") or _infer_target_type(target)))

        if not config.enabled:
            return PluginResult(plugin_name=self.name, status="skipped", metadata={"reason": "disabled"})
        if target_type not in self.indicator_types:
            return PluginResult(
                plugin_name=self.name,
                status="skipped",
                metadata={"reason": "unsupported_target_type", "target_type": target_type},
            )
        if not config.has_passive_sources:
            return PluginResult(plugin_name=self.name, status="skipped", metadata={"reason": "no_passive_sources_configured"})

        findings: list[dict[str, Any]] = []
        errors: dict[str, dict[str, str]] = {}
        scraper_metadata: dict[str, dict[str, Any]] = {}

        settings = get_settings()
        async with http_client(settings) as client:
            for scraper in self._build_scrapers(client, config):
                result = await scraper.search(target, target_type=target_type)
                scraper_metadata[result.scraper_name] = result.metadata
                if result.errors:
                    errors[result.scraper_name] = result.errors
                findings.extend(self._finding(evidence, target=target, target_type=target_type, config=config) for evidence in result.exposures)

        return PluginResult(
            plugin_name=self.name,
            status="completed",
            findings=findings,
            metadata={
                "intensity_requested": config.intensity,
                "intensity_used": "passive",
                "findings_count": len(findings),
                "errors": errors,
                "scrapers": scraper_metadata,
            },
        )

    def _build_scrapers(self, client: Any, config: EmailExposureConfig) -> tuple[PassiveExposureScraper, ...]:
        scrapers: list[PassiveExposureScraper] = []
        if config.source_urls or config.source_url_templates:
            scrapers.append(ConfiguredPasteScraper(client, config))
        if config.github_token:
            scrapers.append(GitHubCodeSearchScraper(client, config))
        scrapers.append(ExistingBreachPluginDelegation(client, config))
        return tuple(scrapers)

    def _finding(
        self,
        evidence: ExposureEvidence,
        *,
        target: str,
        target_type: str,
        config: EmailExposureConfig,
    ) -> dict[str, Any]:
        return {
            "source": self.name,
            "type": "email.exposure",
            "value": evidence.matched_value,
            "confidence": evidence.confidence,
            "severity": evidence.severity,
            "threat_category": self.threat_category,
            "indicator_type": "email" if evidence.email_domain else target_type,
            "source_url": _redacted_url(evidence.source_url, target=target, target_type=target_type),
            "collector_plugin": self.name,
            "data": {
                "target_type": target_type,
                "redacted_target": _redacted_target(target, target_type),
                "email_hash": evidence.matched_value if evidence.email_domain else None,
                "redacted_email": evidence.redacted_value if evidence.email_domain else None,
                "email_domain": evidence.email_domain,
                "platform": evidence.platform,
                "source_name": evidence.source_name,
                "data_types_found": list(evidence.data_types_found),
                "intensity_used": "passive",
                "intensity_requested": config.intensity,
            },
            "raw_evidence": {
                "evidence_hash": evidence.evidence_hash,
                "content_preview": evidence.content_preview,
                "source_url": _redacted_url(evidence.source_url, target=target, target_type=target_type),
                "metadata": evidence.raw_metadata,
            },
        }


def _infer_target_type(target: str) -> str:
    if "@" in target:
        return "email"
    if "." in target and " " not in target:
        return "domain"
    return "keyword"


def _normalize_target_type(target_type: str) -> str:
    return "keyword" if target_type == "brand" else target_type


def _redacted_target(target: str, target_type: str) -> str:
    if target_type != "email" or "@" not in target:
        return target
    local, _, domain = target.partition("@")
    return f"{local[:2]}***@{domain.lower()}"


def _redacted_url(url: str, *, target: str, target_type: str) -> str:
    redacted = redact_text(url, max_chars=2_000)
    if target_type == "email" and target:
        redacted_target = _redacted_target(target, target_type)
        redacted = redacted.replace(target, redacted_target)
        redacted = redacted.replace(quote_plus(target), quote_plus(redacted_target))
    return redacted