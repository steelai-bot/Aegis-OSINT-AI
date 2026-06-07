"""Document-source placeholder for Phase 1 passive email exposure collection."""

from __future__ import annotations

from backend.plugins.email_exposure.scrapers.paste_sites import ConfiguredPasteScraper


class ConfiguredDocumentScraper(ConfiguredPasteScraper):
    """Phase 1 document scraper for text-like public documents.

    Binary PDF parsing is intentionally deferred to a later phase where the
    legacy `scripts/pdf_extractor.py` logic can be migrated safely and tested.
    """

    name = "configured_document_sources"