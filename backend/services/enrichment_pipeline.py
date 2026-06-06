"""Passive finding enrichment pipeline."""

from __future__ import annotations

from typing import Any

from backend.plugins.registry import PluginRegistry
from backend.services.risk_scoring import RiskScoringService


class EnrichmentPipeline:
    """Run selected passive enrichment plugins for collected indicators."""

    def __init__(self, registry: PluginRegistry | None = None, scorer: RiskScoringService | None = None) -> None:
        self.registry = registry or PluginRegistry()
        self.scorer = scorer or RiskScoringService()

    async def enrich(self, finding: dict[str, Any]) -> dict[str, Any]:
        enriched = dict(finding)
        indicator = str(enriched.get("value") or enriched.get("source_url") or "")
        indicator_type = str(enriched.get("indicator_type") or "")
        if not indicator:
            return self.scorer.apply(enriched)

        enrichment_data: dict[str, Any] = dict(enriched.get("enrichment_data") or {})
        for plugin in self.registry.enabled_plugins():
            if plugin.name == enriched.get("collector_plugin"):
                continue
            if not plugin.indicator_types or indicator_type not in plugin.indicator_types:
                continue
            result = await plugin.execute(indicator, context={"purpose": "enrichment", "source_finding": enriched})
            if result.status == "completed" and result.findings:
                enrichment_data[plugin.name] = {
                    "status": result.status,
                    "finding_count": len(result.findings),
                    "findings": result.findings[:10],
                    "metadata": result.metadata,
                }
            elif result.status == "skipped":
                enrichment_data[plugin.name] = {"status": result.status, "metadata": result.metadata}

        enriched["enriched"] = bool(enrichment_data)
        enriched["enrichment_data"] = enrichment_data
        return self.scorer.apply(enriched)