"""Tests for the passive email exposure plugin."""

from __future__ import annotations

import pytest

import backend.plugins.email_exposure.plugin as plugin_module
from backend.core.config import Settings
from backend.plugins.email_exposure.classifiers import classify_text, hash_value, redact_email
from backend.plugins.email_exposure.plugin import EmailExposurePlugin


def test_redact_email_and_hash_value_are_stable() -> None:
    assert redact_email("Alice.Example@Example.COM") == "Al***@example.com"
    assert hash_value("Alice.Example@Example.COM") == hash_value("alice.example@example.com")


def test_classify_text_hashes_email_and_redacts_preview() -> None:
    evidence = classify_text(
        "leaked alice@example.com:Sup3rSecret! in public paste",
        target="example.com",
        target_type="domain",
        source_name="unit_source",
        source_url="https://example.test/paste",
        platform="pastebin",
    )

    assert len(evidence) == 1
    item = evidence[0]
    assert item.matched_value == hash_value("alice@example.com")
    assert item.redacted_value == "al***@example.com"
    assert "password" in item.data_types_found
    assert item.severity == "high"
    assert "alice@example.com" not in item.content_preview


@pytest.mark.asyncio
async def test_email_exposure_plugin_skips_without_passive_sources() -> None:
    result = await EmailExposurePlugin().execute("example.com", context={"target_type": "domain"})

    assert result.status == "skipped"
    assert result.metadata == {"reason": "no_passive_sources_configured"}
    assert result.findings == []


@pytest.mark.asyncio
async def test_email_exposure_plugin_scans_configured_public_url(monkeypatch) -> None:
    class FakeResponse:
        text = "public dump alice@example.com:Sup3rSecret!"

    class FakeClient:
        async def get(self, url: str, **kwargs):
            return FakeResponse()

    class FakeClientContext:
        async def __aenter__(self):
            return FakeClient()

        async def __aexit__(self, exc_type, exc, tb):
            return None

    monkeypatch.setattr(plugin_module, "get_settings", lambda: Settings())
    monkeypatch.setattr(plugin_module, "http_client", lambda settings: FakeClientContext())

    plugin = EmailExposurePlugin(config={"source_urls": ["https://example.test/paste"], "max_findings_per_source": 5})
    result = await plugin.execute("example.com", context={"target_type": "domain"})

    assert result.status == "completed"
    assert result.metadata["intensity_used"] == "passive"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding["source"] == "email_exposure"
    assert finding["type"] == "email.exposure"
    assert finding["value"] == hash_value("alice@example.com")
    assert finding["severity"] == "high"
    assert finding["data"]["redacted_email"] == "al***@example.com"
    assert "alice@example.com" not in finding["raw_evidence"]["content_preview"]


@pytest.mark.asyncio
async def test_email_exposure_plugin_treats_brand_jobs_as_keyword(monkeypatch) -> None:
    class FakeResponse:
        text = "A public page mentions Acme Corp without an email."

    class FakeClient:
        async def get(self, url: str, **kwargs):
            return FakeResponse()

    class FakeClientContext:
        async def __aenter__(self):
            return FakeClient()

        async def __aexit__(self, exc_type, exc, tb):
            return None

    monkeypatch.setattr(plugin_module, "get_settings", lambda: Settings())
    monkeypatch.setattr(plugin_module, "http_client", lambda settings: FakeClientContext())

    plugin = EmailExposurePlugin(config={"source_urls": ["https://example.test/search?q=Acme%20Corp"]})
    result = await plugin.execute("Acme Corp", context={"target_type": "brand"})

    assert result.status == "completed"
    assert len(result.findings) == 1
    assert result.findings[0]["indicator_type"] == "keyword"


@pytest.mark.asyncio
async def test_email_exposure_plugin_redacts_email_target_in_source_url(monkeypatch) -> None:
    class FakeResponse:
        text = "alice@example.com was observed in a public source"

    class FakeClient:
        async def get(self, url: str, **kwargs):
            return FakeResponse()

    class FakeClientContext:
        async def __aenter__(self):
            return FakeClient()

        async def __aexit__(self, exc_type, exc, tb):
            return None

    monkeypatch.setattr(plugin_module, "get_settings", lambda: Settings())
    monkeypatch.setattr(plugin_module, "http_client", lambda settings: FakeClientContext())

    plugin = EmailExposurePlugin(config={"source_url_templates": ["https://example.test/search?q={target_query}"]})
    result = await plugin.execute("alice@example.com", context={"target_type": "email"})

    assert result.status == "completed"
    assert len(result.findings) == 1
    assert "alice@example.com" not in result.findings[0]["source_url"]
    assert "alice%40example.com" not in result.findings[0]["source_url"]