"""Shared scraper primitives for passive email exposure collection."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from backend.plugins.email_exposure.classifiers import ExposureEvidence
from backend.plugins.email_exposure.config import EmailExposureConfig


class AsyncGetClient(Protocol):
    async def get(self, url: str, **kwargs: Any) -> httpx.Response: ...


@dataclass(slots=True)
class ScrapeResult:
    scraper_name: str
    exposures: list[ExposureEvidence] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


class PassiveExposureScraper:
    """Base class for passive source scrapers using Aegis shared HTTP client."""

    name = "passive_exposure_scraper"

    def __init__(self, client: AsyncGetClient, config: EmailExposureConfig) -> None:
        self.client = client
        self.config = config

    async def search(self, target: str, *, target_type: str) -> ScrapeResult:  # pragma: no cover - interface
        raise NotImplementedError

    async def _get_text(self, url: str, *, headers: dict[str, str] | None = None, params: dict[str, Any] | None = None) -> str:
        response = await self.client.get(url, headers=headers, params=params)
        return response.text[: self.config.max_bytes]