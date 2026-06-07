"""Configuration helpers for the passive email exposure plugin."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal


ExposureIntensity = Literal["passive", "balanced", "aggressive", "custom"]


@dataclass(frozen=True, slots=True)
class EmailExposureConfig:
    """Runtime config merged from plugin config and collection job config.

    Phase 1 intentionally supports only passive, caller-approved public sources.
    More intrusive sources (browser automation, Tor, authenticated breach APIs) can
    be added later without changing the plugin contract.
    """

    enabled: bool = True
    intensity: ExposureIntensity = "passive"
    source_urls: tuple[str, ...] = ()
    source_url_templates: tuple[str, ...] = ()
    github_token: str | None = None
    github_api_url: str = "https://api.github.com/search/code"
    github_max_results: int = 10
    max_bytes: int = 1_000_000
    max_findings_per_source: int = 25
    content_preview_chars: int = 320

    @classmethod
    def from_runtime(
        cls,
        plugin_config: dict[str, Any] | None,
        context: dict[str, Any] | None,
    ) -> "EmailExposureConfig":
        """Merge registry plugin config with optional collection job overrides."""

        merged: dict[str, Any] = dict(plugin_config or {})
        job_config = dict((context or {}).get("job_config") or {})
        plugin_job_config = dict(job_config.get("email_exposure") or {})

        # Allow both job.config={"email_exposure": {...}} and direct job config
        # keys for small manual runs.
        for key in (
            "enabled",
            "intensity",
            "source_urls",
            "source_url_templates",
            "github_token",
            "github_api_url",
            "github_max_results",
            "max_bytes",
            "max_findings_per_source",
            "content_preview_chars",
        ):
            if key in job_config:
                merged[key] = job_config[key]
        merged.update(plugin_job_config)

        return cls(
            enabled=bool(merged.get("enabled", True)),
            intensity=cls._intensity(merged.get("intensity", "passive")),
            source_urls=cls._tuple(merged.get("source_urls")),
            source_url_templates=cls._tuple(merged.get("source_url_templates")),
            github_token=cls._optional_str(merged.get("github_token")),
            github_api_url=str(merged.get("github_api_url") or "https://api.github.com/search/code"),
            github_max_results=max(1, min(int(merged.get("github_max_results", 10)), 50)),
            max_bytes=max(16_384, int(merged.get("max_bytes", 1_000_000))),
            max_findings_per_source=max(1, int(merged.get("max_findings_per_source", 25))),
            content_preview_chars=max(80, int(merged.get("content_preview_chars", 320))),
        )

    @staticmethod
    def _tuple(value: Any) -> tuple[str, ...]:
        if value is None:
            return ()
        if isinstance(value, str):
            return (value,)
        if isinstance(value, (list, tuple, set)):
            return tuple(str(item) for item in value if str(item).strip())
        return ()

    @staticmethod
    def _optional_str(value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    @staticmethod
    def _intensity(value: Any) -> ExposureIntensity:
        text = str(value or "passive").strip().lower()
        if text in {"passive", "balanced", "aggressive", "custom"}:
            return text  # type: ignore[return-value]
        return "passive"

    @property
    def has_passive_sources(self) -> bool:
        return bool(self.source_urls or self.source_url_templates or self.github_token)