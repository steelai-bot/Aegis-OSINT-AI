"""Passive code repository exposure scrapers."""

from __future__ import annotations

from typing import Any

import httpx

from backend.plugins.email_exposure.classifiers import classify_text
from backend.plugins.email_exposure.scrapers.base import PassiveExposureScraper, ScrapeResult


class GitHubCodeSearchScraper(PassiveExposureScraper):
    """Use GitHub Code Search when an operator supplies an authorized token."""

    name = "github_code_search"

    platform = "github"

    async def search(self, target: str, *, target_type: str) -> ScrapeResult:
        result = ScrapeResult(scraper_name=self.name)
        if not self.config.github_token:
            result.metadata["skipped"] = "missing_github_token"
            return result

        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.config.github_token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        params = {"q": f'"{target}"', "per_page": self.config.github_max_results}
        try:
            response = await self.client.get(self.config.github_api_url, headers=headers, params=params)
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            result.errors[self.config.github_api_url] = str(exc)
            return result

        items = payload.get("items", []) if isinstance(payload, dict) else []
        for item in items[: self.config.github_max_results]:
            if not isinstance(item, dict):
                continue
            source_url = str(item.get("html_url") or item.get("url") or self.config.github_api_url)
            searchable_text = _github_item_text(item)
            result.exposures.extend(
                classify_text(
                    searchable_text,
                    target=target,
                    target_type=target_type,
                    source_name=self.name,
                    source_url=source_url,
                    platform=self.platform,
                    max_findings=self.config.max_findings_per_source,
                    preview_chars=self.config.content_preview_chars,
                )
            )

        result.metadata["github_results"] = len(items)
        return result


def _github_item_text(item: dict[str, Any]) -> str:
    repo = item.get("repository") if isinstance(item.get("repository"), dict) else {}
    return " ".join(
        str(value)
        for value in [
            item.get("name"),
            item.get("path"),
            item.get("html_url"),
            repo.get("full_name") if isinstance(repo, dict) else None,
            repo.get("description") if isinstance(repo, dict) else None,
        ]
        if value
    )