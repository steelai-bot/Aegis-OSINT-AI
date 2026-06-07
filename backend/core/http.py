"""Shared secure async HTTP client utilities."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from backend.core.config import Settings, get_settings
from backend.core.events import EventBus, event_bus
from backend.services.egress_policy import EgressPolicy, EgressPolicyDecision


class EgressPolicyError(httpx.HTTPError):
    """Raised when the shared HTTP client blocks a plugin egress request."""

    def __init__(self, decision: EgressPolicyDecision) -> None:
        self.decision = decision
        super().__init__(f"egress policy blocked request: {decision.reason}")


class AsyncHttpClient:
    """Thin wrapper around httpx.AsyncClient with retries and safe defaults."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        plugin_name: str | None = None,
        allowed_hosts: tuple[str, ...] = (),
        allow_private_networks: bool = False,
        max_response_bytes: int | None = None,
        egress_policy: EgressPolicy | None = None,
        bus: EventBus | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.plugin_name = plugin_name
        self.allowed_hosts = allowed_hosts
        self.allow_private_networks = allow_private_networks
        self.max_response_bytes = max_response_bytes or self.settings.http_max_response_bytes
        self.egress_policy = egress_policy or EgressPolicy(self.settings)
        self.event_bus = bus or event_bus
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.settings.http_timeout_seconds),
            headers={"User-Agent": self.settings.http_user_agent},
            verify=True,
            follow_redirects=True,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        decision = await self.egress_policy.authorize(
            url,
            plugin_name=self.plugin_name,
            allowed_hosts=self.allowed_hosts,
            allow_private_networks=self.allow_private_networks,
        )
        await self._publish_egress_decision(decision)
        if not decision.allowed:
            raise EgressPolicyError(decision)

        @retry(
            retry=retry_if_exception_type((httpx.TimeoutException, httpx.TransportError)),
            wait=wait_exponential(multiplier=self.settings.http_backoff_seconds, min=0.1, max=8),
            stop=stop_after_attempt(self.settings.http_max_retries),
            reraise=True,
        )
        async def _send() -> httpx.Response:
            response = await self._client.request(method, url, **kwargs)
            response.raise_for_status()
            self._enforce_response_size(response)
            return response

        return await _send()

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    def _enforce_response_size(self, response: httpx.Response) -> None:
        if self.max_response_bytes <= 0:
            return
        if len(response.content) > self.max_response_bytes:
            raise httpx.HTTPError(f"response size exceeds configured limit ({self.max_response_bytes} bytes)")

    async def _publish_egress_decision(self, decision: EgressPolicyDecision) -> None:
        if self.plugin_name is None:
            return
        await self.event_bus.publish("tool.execution.egress", decision.audit_metadata())


@asynccontextmanager
async def http_client(
    settings: Settings | None = None,
    *,
    plugin_name: str | None = None,
    allowed_hosts: tuple[str, ...] = (),
    allow_private_networks: bool = False,
    max_response_bytes: int | None = None,
) -> AsyncIterator[AsyncHttpClient]:
    client = AsyncHttpClient(
        settings=settings,
        plugin_name=plugin_name,
        allowed_hosts=allowed_hosts,
        allow_private_networks=allow_private_networks,
        max_response_bytes=max_response_bytes,
    )
    try:
        yield client
    finally:
        await client.aclose()
