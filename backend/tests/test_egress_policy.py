"""Tests for per-plugin outbound egress policy controls."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from backend.core.config import Settings
from backend.core.http import AsyncHttpClient, EgressPolicyError
from backend.services.egress_policy import EgressPolicy, EgressPolicyDecision, allowed_hosts_from_urls


pytestmark = pytest.mark.asyncio


async def test_egress_policy_blocks_private_literal_ip_even_when_allowlisted() -> None:
    policy = EgressPolicy(Settings())

    decision = await policy.authorize(
        "http://127.0.0.1/admin?token=secret",
        plugin_name="unit_plugin",
        allowed_hosts=("127.0.0.1",),
    )

    assert not decision.allowed
    assert decision.reason == "private_ip_blocked"
    metadata = decision.audit_metadata()
    assert metadata["egress_host"] == "127.0.0.1"
    assert "token" not in str(metadata)
    assert "/admin" not in str(metadata)


async def test_egress_policy_blocks_hosts_outside_plugin_allowlist() -> None:
    policy = EgressPolicy(Settings(http_egress_deny_private_networks=False))

    decision = await policy.authorize(
        "https://evil.example/search?q=secret",
        plugin_name="unit_plugin",
        allowed_hosts=("api.example",),
    )

    assert not decision.allowed
    assert decision.reason == "host_not_in_plugin_allowlist"
    assert decision.audit_metadata()["egress_allowed_hosts_count"] == 1


async def test_egress_policy_allows_wildcard_public_host_when_private_denies_disabled() -> None:
    policy = EgressPolicy(Settings(http_egress_deny_private_networks=False))

    decision = await policy.authorize(
        "https://bucket.s3.amazonaws.com/",
        plugin_name="s3_scanner",
        allowed_hosts=("*.s3.amazonaws.com",),
    )

    assert decision.allowed
    assert decision.reason == "egress_policy_allowed"
    assert decision.matched_rule == "*.s3.amazonaws.com"


async def test_unscoped_provider_http_clients_are_not_treated_as_plugin_egress() -> None:
    policy = EgressPolicy(Settings())

    decision = await policy.authorize("http://localhost:11434/api/generate")

    assert decision.allowed
    assert decision.reason == "unscoped_http_client"


async def test_allowed_hosts_from_urls_extracts_sanitized_unique_hosts() -> None:
    assert allowed_hosts_from_urls(
        [
            "https://example.test/path?token=secret",
            "https://EXAMPLE.test/other",
            "not-a-url",
            "https://api.example.test/search",
        ]
    ) == ("example.test", "api.example.test")


async def test_async_http_client_emits_egress_event_and_enforces_response_size() -> None:
    class AllowingPolicy:
        async def authorize(self, url: str, **kwargs: Any) -> EgressPolicyDecision:
            return EgressPolicyDecision(
                allowed=True,
                reason="egress_policy_allowed",
                plugin_name=kwargs.get("plugin_name"),
                scheme="https",
                host="allowed.example",
                matched_rule="allowed.example",
            )

    class FakeBus:
        def __init__(self) -> None:
            self.events: list[tuple[str, dict[str, Any]]] = []

        async def publish(self, event_name: str, payload: dict[str, Any]):
            self.events.append((event_name, payload))
            return None

    bus = FakeBus()
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=b"x" * 32))
    client = AsyncHttpClient(
        Settings(),
        plugin_name="unit_plugin",
        allowed_hosts=("allowed.example",),
        max_response_bytes=16,
        egress_policy=AllowingPolicy(),  # type: ignore[arg-type]
        bus=bus,  # type: ignore[arg-type]
    )
    await client._client.aclose()
    client._client = httpx.AsyncClient(transport=transport)

    with pytest.raises(httpx.HTTPError, match="response size exceeds"):
        await client.get("https://allowed.example/data?token=secret")

    await client.aclose()
    assert bus.events == [
        (
            "tool.execution.egress",
            {
                "egress_policy_status": "allowed",
                "egress_policy_reason": "egress_policy_allowed",
                "egress_plugin_name": "unit_plugin",
                "egress_scheme": "https",
                "egress_host": "allowed.example",
                "egress_matched_rule": "allowed.example",
            },
        )
    ]


async def test_async_http_client_raises_policy_error_for_blocked_plugin_request() -> None:
    class BlockingPolicy:
        async def authorize(self, url: str, **kwargs: Any) -> EgressPolicyDecision:
            return EgressPolicyDecision(
                allowed=False,
                reason="host_not_in_plugin_allowlist",
                plugin_name=kwargs.get("plugin_name"),
                scheme="https",
                host="blocked.example",
            )

    client = AsyncHttpClient(Settings(), plugin_name="unit_plugin", egress_policy=BlockingPolicy())  # type: ignore[arg-type]
    try:
        with pytest.raises(EgressPolicyError) as exc_info:
            await client.get("https://blocked.example/path?token=secret")
    finally:
        await client.aclose()

    assert exc_info.value.decision.reason == "host_not_in_plugin_allowlist"
