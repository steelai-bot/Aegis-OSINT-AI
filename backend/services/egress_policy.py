"""Per-plugin outbound network policy controls.

The policy is intentionally small and explicit: plugins may declare host
allowlists, all plugin-scoped HTTP calls are screened for SSRF-sensitive private
and link-local destinations, and callers receive sanitized decision metadata that
does not include query strings, credentials, or token-bearing paths.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from backend.core.config import Settings, get_settings


PRIVATE_HOSTNAMES = frozenset({"localhost", "localhost.localdomain"})


@dataclass(frozen=True, slots=True)
class EgressPolicyDecision:
    """Sanitized outcome for a plugin-scoped outbound request."""

    allowed: bool
    reason: str
    plugin_name: str | None
    scheme: str | None
    host: str | None
    matched_rule: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def audit_metadata(self) -> dict[str, Any]:
        """Return metadata safe for events, logs, and plugin result summaries."""

        data = {
            "egress_policy_status": "allowed" if self.allowed else "blocked",
            "egress_policy_reason": self.reason,
            "egress_plugin_name": self.plugin_name,
            "egress_scheme": self.scheme,
            "egress_host": self.host,
            "egress_matched_rule": self.matched_rule,
            **self.metadata,
        }
        return {key: value for key, value in data.items() if value is not None}


class EgressPolicy:
    """Authorize plugin-scoped outbound HTTP destinations."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._resolution_cache: dict[str, tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...] | None] = {}

    async def authorize(
        self,
        url: str,
        *,
        plugin_name: str | None = None,
        allowed_hosts: tuple[str, ...] = (),
        allow_private_networks: bool = False,
    ) -> EgressPolicyDecision:
        """Return whether a URL may be requested by the given plugin."""

        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        host = _normalize_host(parsed.hostname)

        if not self.settings.http_egress_policy_enabled:
            return self._decision(True, "egress_policy_disabled", plugin_name, scheme, host)

        # LLM/provider calls intentionally remain outside the plugin egress
        # boundary; several local-provider configurations legitimately use
        # loopback endpoints. Plugin callers should always supply a
        # plugin name through backend.core.http.http_client(...).
        if plugin_name is None:
            return self._decision(True, "unscoped_http_client", plugin_name, scheme, host)

        if scheme not in {"http", "https"}:
            return self._decision(False, "unsupported_url_scheme", plugin_name, scheme, host)
        if not host:
            return self._decision(False, "missing_url_host", plugin_name, scheme, host)

        normalized_rules = tuple(_normalize_allowed_host(rule) for rule in allowed_hosts if str(rule).strip())
        if normalized_rules:
            matched_rule = _matching_host_rule(host, normalized_rules)
            if matched_rule is None:
                return self._decision(
                    False,
                    "host_not_in_plugin_allowlist",
                    plugin_name,
                    scheme,
                    host,
                    metadata={"egress_allowed_hosts_count": len(normalized_rules)},
                )
        else:
            matched_rule = "public_host_without_allowlist"

        if self.settings.http_egress_deny_private_networks and not allow_private_networks:
            private_reason = await self._private_destination_reason(host)
            if private_reason is not None:
                return self._decision(False, private_reason, plugin_name, scheme, host, matched_rule=matched_rule)

        return self._decision(True, "egress_policy_allowed", plugin_name, scheme, host, matched_rule=matched_rule)

    async def _private_destination_reason(self, host: str) -> str | None:
        if _is_private_hostname(host):
            return "private_hostname_blocked"

        literal_ip = _parse_ip(host)
        if literal_ip is not None:
            return "private_ip_blocked" if _is_private_ip(literal_ip) else None

        addresses = await self._resolve_addresses(host)
        if addresses is None:
            return None
        if any(_is_private_ip(address) for address in addresses):
            return "resolved_private_ip_blocked"
        return None

    async def _resolve_addresses(self, host: str) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...] | None:
        if host in self._resolution_cache:
            return self._resolution_cache[host]

        try:
            loop = asyncio.get_running_loop()
            infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except (OSError, socket.gaierror):
            self._resolution_cache[host] = None
            return None

        addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for info in infos:
            sockaddr = info[4]
            if not sockaddr:
                continue
            address = _parse_ip(str(sockaddr[0]))
            if address is not None:
                addresses.append(address)

        resolved = tuple(dict.fromkeys(addresses))
        self._resolution_cache[host] = resolved
        return resolved

    def _decision(
        self,
        allowed: bool,
        reason: str,
        plugin_name: str | None,
        scheme: str | None,
        host: str | None,
        *,
        matched_rule: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> EgressPolicyDecision:
        return EgressPolicyDecision(
            allowed=allowed,
            reason=reason,
            plugin_name=plugin_name,
            scheme=scheme or None,
            host=host,
            matched_rule=matched_rule,
            metadata=metadata or {},
        )


def allowed_hosts_from_urls(urls: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    """Extract normalized host allowlist entries from configured source URLs."""

    hosts: list[str] = []
    for url in urls:
        host = _normalize_host(urlparse(str(url)).hostname)
        if host:
            hosts.append(host)
    return tuple(dict.fromkeys(hosts))


def _normalize_host(host: str | None) -> str | None:
    if host is None:
        return None
    return host.strip().strip("[]").lower().rstrip(".") or None


def _normalize_allowed_host(rule: str) -> str:
    text = str(rule).strip().lower()
    if "://" in text:
        parsed = urlparse(text)
        text = parsed.hostname or text
    return text.strip().strip("[]").rstrip(".")


def _matching_host_rule(host: str, allowed_hosts: tuple[str, ...]) -> str | None:
    for rule in allowed_hosts:
        if rule == "*":
            return rule
        if rule.startswith("*."):
            suffix = rule[2:]
            if host == suffix or host.endswith(f".{suffix}"):
                return rule
            continue
        if host == rule:
            return rule
    return None


def _is_private_hostname(host: str) -> bool:
    return host in PRIVATE_HOSTNAMES or host.endswith(".localhost") or host.endswith(".local")


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _is_private_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(
        (
            address.is_private,
            address.is_loopback,
            address.is_link_local,
            address.is_multicast,
            address.is_reserved,
            address.is_unspecified,
        )
    )
