"""
Shared HTTP Client for all OSINT plugins
Provides connection pooling, circuit breakers, rate limiting, and automatic retries
"""

import asyncio
import logging

import httpx

from backend.infrastructure import (
    AsyncRetryWithBackoff,
    CircuitBreaker,
    CircuitBreakerConfig,
    InfrastructureManager,
    TokenBucketRateLimiter,
)

logger = logging.getLogger(__name__)


class EnhancedHTTPClient:
    """
    Production-grade HTTP client with advanced resilience patterns.
    Combines connection pooling with circuit breakers, rate limiters, and retries.
    """
    _instance = None
    _client: httpx.AsyncClient | None = None
    _lock = asyncio.Lock()

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    @classmethod
    async def get_instance(cls) -> 'EnhancedHTTPClient':
        """Get singleton instance"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._circuit_breakers: dict[str, CircuitBreaker] = {}
        self._rate_limiters: dict[str, TokenBucketRateLimiter] = {}
        self._retry_config: AsyncRetryWithBackoff | None = None
        self._infrastructure: InfrastructureManager | None = None
        self._initialized = True

    async def initialize(self):
        """Initialize infrastructure and HTTP client"""
        if self._client is not None:
            return

        async with self._lock:
            if self._client is None:
                # Get shared infrastructure manager
                self._infrastructure = await InfrastructureManager.get_instance()

                # Create enhanced HTTP client with larger connection pool
                self._client = httpx.AsyncClient(
                    timeout=httpx.Timeout(30.0, connect=10.0),
                    limits=httpx.Limits(
                        max_connections=100,          # Increased from 50
                        max_keepalive_connections=50   # Increased from 20
                    ),
                    follow_redirects=True,
                    headers={
                        'User-Agent': 'Aegis-OSINT-AI/2.0 (Enhanced)'
                    }
                )

                # Default retry configuration
                self._retry_config = self._infrastructure.get_retry_config(
                    "http_default",
                    max_retries=3,
                    base_delay=1.0
                )

                logger.info("EnhancedHTTPClient initialized with advanced resilience")

    def _get_circuit_breaker(self, domain: str) -> CircuitBreaker:
        """Get or create circuit breaker for specific domain"""
        if domain not in self._circuit_breakers:
            config = CircuitBreakerConfig(
                failure_threshold=5,
                success_threshold=3,
                timeout=60.0,
                half_open_max_calls=3
            )
            self._circuit_breakers[domain] = self._infrastructure.get_circuit_breaker(
                f"http_{domain}", config
            )
        return self._circuit_breakers[domain]

    def _get_rate_limiter(self, domain: str) -> TokenBucketRateLimiter:
        """Get or create rate limiter for specific domain"""
        if domain not in self._rate_limiters:
            # Default rate limits per domain
            self._rate_limiters[domain] = self._infrastructure.get_rate_limiter(
                f"http_{domain}",
                rate=10.0,
                capacity=100,
                adaptive=True
            )
        return self._rate_limiters[domain]

    async def get_client(self) -> httpx.AsyncClient:
        """Get underlying HTTP client"""
        if self._client is None:
            await self.initialize()
        return self._client

    async def request(
        self,
        method: str,
        url: str,
        use_circuit_breaker: bool = True,
        use_rate_limiter: bool = True,
        use_retry: bool = True,
        **kwargs
    ) -> httpx.Response:
        """
        Make HTTP request with full resilience stack.

        Args:
            method: HTTP method
            url: Target URL
            use_circuit_breaker: Enable circuit breaker protection
            use_rate_limiter: Enable rate limiting
            use_retry: Enable automatic retries
            **kwargs: Passed to httpx.request
        """
        from urllib.parse import urlparse

        if self._client is None:
            await self.initialize()

        # Extract domain for per-domain protection
        parsed = urlparse(url)
        domain = parsed.netloc or "default"

        # Get domain-specific protectors
        cb = self._get_circuit_breaker(domain) if use_circuit_breaker else None
        rl = self._get_rate_limiter(domain) if use_rate_limiter else None

        async def _make_request():
            # Rate limiting
            if rl:
                acquired = await rl.acquire(timeout=30.0)
                if not acquired:
                    raise httpx.TimeoutException(f"Rate limit timeout for {domain}")

            # Make request
            response = await self._client.request(method, url, **kwargs)

            # Adaptive rate limiting - detect rate limit headers
            if rl and rl.adaptive:
                recommended = rl.detect_rate_limit_headers(dict(response.headers))
                if recommended:
                    await rl.adjust_rate(recommended)

            return response

        # Wrap with circuit breaker
        if cb:
            wrapped_call = lambda: cb.call(_make_request)
        else:
            wrapped_call = _make_request

        # Execute with retry logic
        if use_retry and self._retry_config:
            return await self._retry_config.execute(
                wrapped_call,
                operation_name=f"{method} {url}"
            )
        else:
            result = wrapped_call()
            if asyncio.iscoroutine(result):
                return await result
            return result

    async def get(self, url: str, **kwargs) -> httpx.Response:
        """GET request with full resilience"""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        """POST request with full resilience"""
        return await self.request("POST", url, **kwargs)

    async def close(self):
        """Close HTTP client"""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
            logger.info("EnhancedHTTPClient closed")

    def get_stats(self) -> dict:
        """Get comprehensive statistics"""
        stats = {
            "client_initialized": self._client is not None,
            "circuit_breakers": {},
            "rate_limiters": {}
        }

        for name, cb in self._circuit_breakers.items():
            stats["circuit_breakers"][name] = cb.get_stats()

        for name, rl in self._rate_limiters.items():
            stats["rate_limiters"][name] = rl.get_stats()

        return stats


# Backward compatibility alias
SharedHTTPClient = EnhancedHTTPClient
