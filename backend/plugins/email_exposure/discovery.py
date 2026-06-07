"""Passive source discovery for email exposure collection."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote_plus

from backend.plugins.email_exposure.config import EmailExposureConfig


@dataclass(frozen=True, slots=True)
class PassiveSource:
    name: str
    url: str
    platform: str


def configured_sources(config: EmailExposureConfig, target: str) -> tuple[PassiveSource, ...]:
    """Build the caller-approved passive URL list for this target."""

    sources: list[PassiveSource] = []
    for index, url in enumerate(config.source_urls, start=1):
        sources.append(PassiveSource(name=f"configured_url_{index}", url=url, platform=_platform(url)))

    quoted_target = quote_plus(target)
    for index, template in enumerate(config.source_url_templates, start=1):
        url = template.format(target=target, target_query=quoted_target)
        sources.append(PassiveSource(name=f"configured_template_{index}", url=url, platform=_platform(url)))

    return tuple(sources)


def _platform(url: str) -> str:
    lowered = url.lower()
    if "pastebin" in lowered:
        return "pastebin"
    if "gist.github" in lowered:
        return "github_gist"
    if "github" in lowered:
        return "github"
    if "gitlab" in lowered:
        return "gitlab"
    if lowered.endswith(".pdf") or "/pdf" in lowered:
        return "document"
    return "configured_public_source"