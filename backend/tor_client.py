"""
Optional Tor SOCKS5 proxy client for dark-web (.onion) sources.

Probes a local Tor proxy (default 127.0.0.1:9050) with a short TCP connect,
caches the result for a few minutes, and hands out httpx clients routed
through the proxy via httpx-socks. When Tor is not running (or disabled via
TOR_ENABLED=false) every consumer is expected to silently degrade to
clearnet sources only.
"""

import asyncio
import logging
import time

import httpx

from backend.config.settings import settings

logger = logging.getLogger(__name__)

_PROBE_TIMEOUT = 2.0
_CACHE_TTL = 300.0  # seconds


class TorUnavailableError(Exception):
    """Raised when the Tor SOCKS5 proxy is not reachable or is disabled."""


class TorClient:
    """Singleton manager for the optional local Tor proxy connection."""

    _instance: "TorClient | None" = None
    _initialized: bool

    def __new__(cls) -> "TorClient":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return
        self._cached_available: bool | None = None
        self._cached_at: float = 0.0
        self._initialized = True

    @classmethod
    def get_instance(cls) -> "TorClient":
        return cls()

    @property
    def address(self) -> str:
        return f"{settings.tor_proxy_host}:{settings.tor_proxy_port}"

    async def is_available(self, force: bool = False) -> bool:
        """Probe the SOCKS5 port with a plain TCP connect (cached for 5 min)."""
        if not settings.tor_enabled:
            return False

        now = time.monotonic()
        if not force and self._cached_available is not None and now - self._cached_at < _CACHE_TTL:
            return self._cached_available

        available = await self._probe()
        self._cached_available = available
        self._cached_at = now
        if available:
            logger.info(f"Tor proxy detected at {self.address} - .onion sources enabled")
        else:
            logger.debug(f"Tor proxy not reachable at {self.address} - clearnet sources only")
        return available

    async def _probe(self) -> bool:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(settings.tor_proxy_host, settings.tor_proxy_port),
                timeout=_PROBE_TIMEOUT,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            return False

    async def get_client(self) -> httpx.AsyncClient:
        """Return a new httpx client routed through the Tor SOCKS5 proxy.

        The caller owns the client and must close it (use async with).
        Raises TorUnavailableError when the proxy is not reachable.
        """
        if not await self.is_available():
            raise TorUnavailableError(f"Tor proxy not available at {self.address}")
        return httpx.AsyncClient(
            proxy=f"socks5://{self.address}",
            timeout=httpx.Timeout(60.0, connect=30.0),  # onion circuits are slow
            follow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
            },
        )

    async def status(self) -> dict:
        """Status dict for the UI badge."""
        available = await self.is_available()
        return {
            "available": available,
            "address": self.address,
            "enabled": settings.tor_enabled,
        }
