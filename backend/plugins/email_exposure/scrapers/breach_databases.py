"""Breach database integration notes for the email exposure plugin."""

from __future__ import annotations

from backend.plugins.email_exposure.scrapers.base import PassiveExposureScraper, ScrapeResult


class ExistingBreachPluginDelegation(PassiveExposureScraper):
    """No-op bridge documenting that HIBP is already covered by `hibp` plugin."""

    name = "existing_breach_plugin_delegation"

    async def search(self, target: str, *, target_type: str) -> ScrapeResult:
        return ScrapeResult(
            scraper_name=self.name,
            metadata={"skipped": "breach_database_sources_are_handled_by_existing_plugins", "target_type": target_type},
        )