"""Configured public text/paste source scraper."""

from __future__ import annotations

import httpx

from backend.plugins.email_exposure.classifiers import classify_text
from backend.plugins.email_exposure.config import EmailExposureConfig
from backend.plugins.email_exposure.discovery import PassiveSource, configured_sources
from backend.plugins.email_exposure.scrapers.base import AsyncGetClient, PassiveExposureScraper, ScrapeResult


class ConfiguredPasteScraper(PassiveExposureScraper):
    """Scan caller-configured public URLs and URL templates.

    The plugin does not crawl the web by default. Operators must explicitly
    provide approved source URLs/templates in plugin or job config.
    """

    name = "configured_public_text_sources"

    def __init__(self, client: AsyncGetClient, config: EmailExposureConfig, sources: tuple[PassiveSource, ...] | None = None) -> None:
        super().__init__(client, config)
        self.sources = sources

    async def search(self, target: str, *, target_type: str) -> ScrapeResult:
        result = ScrapeResult(scraper_name=self.name)
        sources = self.sources if self.sources is not None else configured_sources(self.config, target)

        for source in sources:
            try:
                text = await self._get_text(source.url)
            except httpx.HTTPError as exc:
                result.errors[source.url] = str(exc)
                continue

            result.exposures.extend(
                classify_text(
                    text,
                    target=target,
                    target_type=target_type,
                    source_name=source.name,
                    source_url=source.url,
                    platform=source.platform,
                    max_findings=self.config.max_findings_per_source,
                    preview_chars=self.config.content_preview_chars,
                )
            )

        result.metadata["sources_scanned"] = len(sources)
        return result