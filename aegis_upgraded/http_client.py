"""
Enhanced Shared HTTP Client for all OSINT plugins
Provides connection pooling, circuit breaker, rate limiting, and intelligent caching
"""

import asyncio
import hashlib
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

import httpx

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreaker:
    """Circuit breaker pattern implementation for resilient HTTP requests"""
    failure_threshold: int = 5
    recovery_timeout: float = 60.0
    half_open_max_calls: int = 3
    
    failures: int = field(default=0, init=False)
    last_failure_time: float = field(default=0.0, init=False)
    state: CircuitState = field(default=CircuitState.CLOSED, init=False)
    half_open_calls: int = field(default=0, init=False)
    half_open_successes: int = field(default=0, init=False)
    
    def can_execute(self) -> bool:
        """Check if request can be executed based on circuit state"""
        if self.state == CircuitState.CLOSED:
            return True
        
        if self.state == CircuitState.OPEN:
            if time.time() - self.last_failure_time >= self.recovery_timeout:
                self.state = CircuitState.HALF_OPEN
                self.half_open_calls = 0
                self.half_open_successes = 0
                logger.info("Circuit breaker transitioning to HALF_OPEN")
                return True
            return False
        
        # HALF_OPEN state
        if self.half_open_calls < self.half_open_max_calls:
            self.half_open_calls += 1
            return True
        return False
    
    def record_success(self):
        """Record successful execution"""
        if self.state == CircuitState.HALF_OPEN:
            self.half_open_successes += 1
            if self.half_open_successes >= self.half_open_max_calls:
                self.state = CircuitState.CLOSED
                self.failures = 0
                logger.info("Circuit breaker transitioned to CLOSED after successful recovery")
        elif self.state == CircuitState.CLOSED:
            self.failures = max(0, self.failures - 1)
    
    def record_failure(self):
        """Record failed execution"""
        self.failures += 1
        self.last_failure_time = time.time()
        
        if self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.OPEN
            logger.warning(f"Circuit breaker transitioned to OPEN after failure in HALF_OPEN")
        elif self.state == CircuitState.CLOSED and self.failures >= self.failure_threshold:
            self.state = CircuitState.OPEN
            logger.warning(f"Circuit breaker transitioned to OPEN after {self.failures} failures")


@dataclass
class RateLimiter:
    """Token bucket rate limiter for API rate limit compliance"""
    max_tokens: float = 100.0
    refill_rate: float = 10.0  # tokens per second
    
    tokens: float = field(default=100.0, init=False)
    last_refill: float = field(default_factory=time.time, init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)
    
    async def acquire(self, tokens: float = 1.0) -> bool:
        """Acquire tokens, waiting if necessary"""
        async with self._lock:
            now = time.time()
            elapsed = now - self.last_refill
            self.tokens = min(self.max_tokens, self.tokens + elapsed * self.refill_rate)
            self.last_refill = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            
            # Calculate wait time
            wait_time = (tokens - self.tokens) / self.refill_rate
            logger.debug(f"Rate limiter: waiting {wait_time:.2f}s for tokens")
        
        await asyncio.sleep(wait_time + 0.1)  # Small buffer
        return await self.acquire(tokens)


@dataclass
class CacheEntry:
    """Cache entry with TTL support"""
    value: Any
    expires_at: float
    hit_count: int = 0
    created_at: float = field(default_factory=time.time)


class LRUCache:
    """LRU cache with TTL and automatic cleanup"""
    def __init__(self, max_size: int = 1000, default_ttl: float = 3600.0):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = asyncio.Lock()
        self._cleanup_task: Optional[asyncio.Task] = None
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        async with self._lock:
            if key not in self._cache:
                return None
            
            entry = self._cache[key]
            if time.time() > entry.expires_at:
                del self._cache[key]
                return None
            
            # Move to end (most recently used)
            self._cache.move_to_end(key)
            entry.hit_count += 1
            return entry.value
    
    async def set(self, key: str, value: Any, ttl: Optional[float] = None):
        """Set value in cache with optional custom TTL"""
        async with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            
            self._cache[key] = CacheEntry(
                value=value,
                expires_at=time.time() + (ttl or self.default_ttl)
            )
            
            # Evict oldest if over capacity
            while len(self._cache) > self.max_size:
                self._cache.popitem(last=False)
    
    async def delete(self, key: str):
        """Delete key from cache"""
        async with self._lock:
            self._cache.pop(key, None)
    
    async def clear(self):
        """Clear all cache entries"""
        async with self._lock:
            self._cache.clear()
    
    async def start_cleanup_task(self, interval: float = 300.0):
        """Start background task to clean up expired entries"""
        async def cleanup_loop():
            while True:
                await asyncio.sleep(interval)
                await self._cleanup_expired()
        
        self._cleanup_task = asyncio.create_task(cleanup_loop())
        logger.info(f"Cache cleanup task started (interval: {interval}s)")
    
    async def _cleanup_expired(self):
        """Remove expired entries"""
        async with self._lock:
            now = time.time()
            expired_keys = [
                key for key, entry in self._cache.items()
                if now > entry.expires_at
            ]
            for key in expired_keys:
                del self._cache[key]
            
            if expired_keys:
                logger.debug(f"Cache cleanup: removed {len(expired_keys)} expired entries")
    
    def get_stats(self) -> dict:
        """Get cache statistics"""
        total_hits = sum(e.hit_count for e in self._cache.values())
        return {
            "size": len(self._cache),
            "max_size": self.max_size,
            "total_hits": total_hits,
            "hit_rate": total_hits / max(1, len(self._cache))
        }


@dataclass
class RequestMetrics:
    """Track request metrics for monitoring"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    cached_responses: int = 0
    total_latency_ms: float = 0.0
    
    def record_request(self, latency_ms: float, success: bool, cached: bool = False):
        self.total_requests += 1
        if cached:
            self.cached_responses += 1
        elif success:
            self.successful_requests += 1
        else:
            self.failed_requests += 1
        self.total_latency_ms += latency_ms
    
    @property
    def avg_latency_ms(self) -> float:
        return self.total_latency_ms / max(1, self.total_requests)
    
    @property
    def success_rate(self) -> float:
        return self.successful_requests / max(1, self.total_requests)
    
    @property
    def cache_hit_rate(self) -> float:
        return self.cached_responses / max(1, self.total_requests)


class EnhancedHTTPClient:
    """
    Enhanced singleton async HTTP client with:
    - Connection pooling (100 connections)
    - Per-domain circuit breakers
    - Per-domain rate limiters
    - Intelligent LRU caching with TTL
    - Automatic retries with exponential backoff
    - Request metrics and monitoring
    """
    _instance: Optional['EnhancedHTTPClient'] = None
    _client: httpx.AsyncClient | None = None
    _lock = asyncio.Lock()
    
    def __init__(self):
        self._circuit_breakers: dict[str, CircuitBreaker] = {}
        self._rate_limiters: dict[str, RateLimiter] = {}
        self._cache = LRUCache(max_size=500, default_ttl=600.0)
        self._metrics = RequestMetrics()
        self._domain_locks: dict[str, asyncio.Lock] = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def _get_circuit_breaker(self, domain: str) -> CircuitBreaker:
        """Get or create circuit breaker for domain"""
        if domain not in self._circuit_breakers:
            self._circuit_breakers[domain] = CircuitBreaker(
                failure_threshold=5,
                recovery_timeout=60.0
            )
        return self._circuit_breakers[domain]
    
    def _get_rate_limiter(self, domain: str) -> RateLimiter:
        """Get or create rate limiter for domain"""
        if domain not in self._rate_limiters:
            # Default conservative limits, can be overridden per domain
            limits = {
                "api.github.com": RateLimiter(max_tokens=60.0, refill_rate=1.0),
                "dns.google": RateLimiter(max_tokens=100.0, refill_rate=10.0),
                "api.shodan.io": RateLimiter(max_tokens=10.0, refill_rate=1.0),
            }
            self._rate_limiters[domain] = limits.get(
                domain, 
                RateLimiter(max_tokens=100.0, refill_rate=10.0)
            )
        return self._rate_limiters[domain]
    
    def _get_domain_lock(self, domain: str) -> asyncio.Lock:
        """Get or create lock for domain-specific operations"""
        if domain not in self._domain_locks:
            self._domain_locks[domain] = asyncio.Lock()
        return self._domain_locks[domain]
    
    @staticmethod
    def _extract_domain(url: str) -> str:
        """Extract domain from URL"""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc or parsed.path.split('/')[0]
    
    @staticmethod
    def _generate_cache_key(method: str, url: str, params: Optional[dict] = None) -> str:
        """Generate unique cache key for request"""
        key_data = f"{method}:{url}:{sorted(params.items()) if params else ''}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    async def initialize(self):
        """Initialize the HTTP client with optimized settings"""
        if self._client is None or self._client.is_closed:
            async with self._lock:
                if self._client is None or self._client.is_closed:
                    self._client = httpx.AsyncClient(
                        timeout=httpx.Timeout(30.0, connect=10.0),
                        limits=httpx.Limits(
                            max_connections=100,
                            max_keepalive_connections=50
                        ),
                        follow_redirects=True,
                        headers={
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                            'Accept': 'application/json, text/plain, */*',
                            'Accept-Language': 'en-US,en;q=0.9',
                            'Accept-Encoding': 'gzip, deflate, br',
                            'Connection': 'keep-alive',
                        },
                        transport=httpx.AsyncHTTPTransport(
                            retries=3,
                            verify=True
                        )
                    )
                    
                    # Start cache cleanup task
                    await self._cache.start_cleanup_task(interval=300.0)
                    
                    logger.info("Enhanced HTTP client initialized with advanced features")
        
        return self._client
    
    async def request(
        self,
        method: str,
        url: str,
        use_cache: bool = True,
        cache_ttl: Optional[float] = None,
        bypass_rate_limit: bool = False,
        **kwargs
    ) -> httpx.Response:
        """
        Make HTTP request with circuit breaker, rate limiting, and caching
        
        Args:
            method: HTTP method
            url: Request URL
            use_cache: Whether to use response caching
            cache_ttl: Custom cache TTL in seconds
            bypass_rate_limit: Skip rate limiting (for authenticated requests)
            **kwargs: Additional arguments passed to httpx
        
        Returns:
            httpx.Response object
        """
        client = await self.initialize()
        domain = self._extract_domain(url)
        circuit_breaker = self._get_circuit_breaker(domain)
        rate_limiter = self._get_rate_limiter(domain)
        domain_lock = self._get_domain_lock(domain)
        
        # Check cache first
        if use_cache:
            cache_key = self._generate_cache_key(method, url, kwargs.get('params'))
            cached_response = await self._cache.get(cache_key)
            if cached_response is not None:
                self._metrics.record_request(0.0, True, cached=True)
                logger.debug(f"Cache hit for {url}")
                # Return a mock response from cache
                return httpx.Response(
                    status_code=200,
                    json=cached_response,
                    request=httpx.Request(method, url)
                )
        
        # Check circuit breaker
        if not circuit_breaker.can_execute():
            logger.warning(f"Circuit breaker OPEN for {domain}, rejecting request")
            self._metrics.record_request(0.0, False)
            raise httpx.RequestError(f"Circuit breaker open for {domain}")
        
        # Apply rate limiting
        if not bypass_rate_limit:
            async with domain_lock:
                await rate_limiter.acquire()
        
        # Execute request with retry logic
        start_time = time.time()
        try:
            response = await self._execute_with_retry(client, method, url, **kwargs)
            latency_ms = (time.time() - start_time) * 1000
            
            # Check for rate limit headers and adjust limiter
            self._handle_rate_limit_headers(domain, response)
            
            if response.status_code == 200:
                circuit_breaker.record_success()
                self._metrics.record_request(latency_ms, True)
                
                # Cache successful responses
                if use_cache and response.status_code == 200:
                    try:
                        response_data = response.json()
                        await self._cache.set(cache_key, response_data, cache_ttl)
                    except Exception:
                        pass  # Don't cache non-JSON responses
                
                return response
            else:
                circuit_breaker.record_failure()
                self._metrics.record_request(latency_ms, False)
                return response
                
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            circuit_breaker.record_failure()
            self._metrics.record_request(latency_ms, False)
            logger.error(f"Request failed for {url}: {e}")
            raise
    
    async def _execute_with_retry(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        max_retries: int = 3,
        **kwargs
    ) -> httpx.Response:
        """Execute request with exponential backoff retry"""
        from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
        
        @retry(
            stop=stop_after_attempt(max_retries),
            wait=wait_exponential(multiplier=1, min=2, max=30),
            retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError, httpx.ReadTimeout))
        )
        async def do_request():
            return await client.request(method, url, **kwargs)
        
        return await do_request()
    
    def _handle_rate_limit_headers(self, domain: str, response: httpx.Response):
        """Detect and adapt to rate limit headers from response"""
        headers = response.headers
        
        # GitHub-style rate limit headers
        remaining = headers.get('X-RateLimit-Remaining')
        reset_timestamp = headers.get('X-RateLimit-Reset')
        
        if remaining and reset_timestamp:
            try:
                remaining_int = int(remaining)
                reset_time = int(reset_timestamp)
                now = int(time.time())
                
                if remaining_int < 10:
                    # Running low on rate limit, reduce token generation
                    rate_limiter = self._get_rate_limiter(domain)
                    rate_limiter.refill_rate = max(0.1, remaining_int / max(1, reset_time - now))
                    logger.debug(f"Adjusted rate limiter for {domain}: {rate_limiter.refill_rate} tokens/s")
            except (ValueError, TypeError):
                pass
    
    async def get(self, url: str, **kwargs) -> httpx.Response:
        """Convenience method for GET requests"""
        return await self.request('GET', url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> httpx.Response:
        """Convenience method for POST requests"""
        return await self.request('POST', url, **kwargs)
    
    async def close(self):
        """Close HTTP client"""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
            logger.info("Enhanced HTTP client closed")
    
    def get_metrics(self) -> dict:
        """Get request metrics and cache stats"""
        return {
            "requests": {
                "total": self._metrics.total_requests,
                "successful": self._metrics.successful_requests,
                "failed": self._metrics.failed_requests,
                "cached": self._metrics.cached_responses,
                "success_rate": f"{self._metrics.success_rate:.2%}",
                "cache_hit_rate": f"{self._metrics.cache_hit_rate:.2%}",
                "avg_latency_ms": f"{self._metrics.avg_latency_ms:.2f}"
            },
            "cache": self._cache.get_stats(),
            "circuit_breakers": {
                domain: cb.state.value 
                for domain, cb in self._circuit_breakers.items()
            }
        }


# Backward compatibility alias
SharedHTTPClient = EnhancedHTTPClient
