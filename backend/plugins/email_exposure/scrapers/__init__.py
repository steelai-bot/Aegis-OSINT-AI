"""Passive email exposure scrapers."""

from backend.plugins.email_exposure.scrapers.base import PassiveExposureScraper, ScrapeResult
from backend.plugins.email_exposure.scrapers.code_repos import GitHubCodeSearchScraper
from backend.plugins.email_exposure.scrapers.document_sites import ConfiguredDocumentScraper
from backend.plugins.email_exposure.scrapers.paste_sites import ConfiguredPasteScraper

__all__ = [
    "ConfiguredDocumentScraper",
    "ConfiguredPasteScraper",
    "GitHubCodeSearchScraper",
    "PassiveExposureScraper",
    "ScrapeResult",
]