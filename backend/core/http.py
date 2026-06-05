"""Shared secure async HTTP client utilities."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from backend.core.config import Settings, get_settings


class AsyncHttpClient:
    """Thin wrapper around httpx.AsyncClient with retries and safe defaults."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.settings.http_timeout_seconds),
            headers={"User-Agent": self.settings.http_user_agent},
            verify=True,
            follow_redirects=True,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        @retry(
            retry=retry_if_exception_type((httpx.TimeoutException, httpx.TransportError)),
            wait=wait_exponential(multiplier=self.settings.http_backoff_seconds, min=0.1, max=8),
            stop=stop_after_attempt(self.settings.http_max_retries),
            reraise=True,
        )
        async def _send() -> httpx.Response:
            response = await self._client.request(method, url, **kwargs)
            response.raise_for_status()
            return response

        return await _send()

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)


@asynccontextmanager
async def http_client(settings: Settings | None = None) -> AsyncIterator[AsyncHttpClient]:
    client = AsyncHttpClient(settings=settings)
    try:
        yield client
    finally:
        await client.aclose()
