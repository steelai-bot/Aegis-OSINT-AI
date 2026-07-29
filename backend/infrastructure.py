"""
Advanced Infrastructure Components for Aegis-OSINT-AI
Includes: Circuit Breaker, LRU Cache with TTL, Adaptive Rate Limiter
"""

import asyncio
import logging
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Generic, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar('T')


class CircuitState(Enum):
    """Three-state circuit breaker pattern"""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing recovery


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker behavior"""
    failure_threshold: int = 5          # Failures before opening
    success_threshold: int = 3          # Successes to close from half-open
    timeout: float = 60.0               # Seconds before trying half-open
    half_open_max_calls: int = 3        # Max test calls in half-open state
    excluded_exceptions: tuple = field(default_factory=lambda: (asyncio.TimeoutError,))


class CircuitBreaker:
    """
    Advanced circuit breaker with three-state pattern.
    Prevents cascade failures and enables automatic recovery.
    """

    def __init__(self, name: str, config: CircuitBreakerConfig | None = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: float | None = None
        self._half_open_calls = 0
        self._lock = asyncio.Lock()
        self._state_change_callbacks: list[Callable] = []

    @property
    def state(self) -> CircuitState:
        return self._state

    @property
    def is_closed(self) -> bool:
        return self._state == CircuitState.CLOSED

    @property
    def is_open(self) -> bool:
        return self._state == CircuitState.OPEN

    @property
    def is_half_open(self) -> bool:
        return self._state == CircuitState.HALF_OPEN

    async def _transition_to(self, new_state: CircuitState):
        """Thread-safe state transition with callbacks"""
        if self._state == new_state:
            return

        old_state = self._state
        self._state = new_state
        logger.info(f"CircuitBreaker '{self.name}': {old_state.value} → {new_state.value}")

        for callback in self._state_change_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(new_state)
                else:
                    callback(new_state)
            except Exception as e:
                logger.error(f"Circuit breaker callback failed: {e}")

    async def call(self, func: Callable[..., T], *args, **kwargs) -> T:
        """
        Execute function through circuit breaker.
        Raises CircuitBreakerOpen if circuit is open.
        """
        async with self._lock:
            # Check if we should transition from OPEN to HALF_OPEN
            if self._state == CircuitState.OPEN:
                if self._last_failure_time and \
                   time.time() - self._last_failure_time >= self.config.timeout:
                    await self._transition_to(CircuitState.HALF_OPEN)
                    self._half_open_calls = 0
                else:
                    raise CircuitBreakerOpen(
                        f"Circuit '{self.name}' is OPEN. "
                        f"Retry after {self.config.timeout}s"
                    )

            # Check if we've exceeded half-open call limit
            if self._state == CircuitState.HALF_OPEN:
                if self._half_open_calls >= self.config.half_open_max_calls:
                    raise CircuitBreakerOpen(
                        f"Circuit '{self.name}' HALF_OPEN call limit reached"
                    )
                self._half_open_calls += 1

        # Execute the function
        try:
            result = func(*args, **kwargs)
            if asyncio.iscoroutine(result):
                result = await result

            await self._on_success()
            return result

        except self.config.excluded_exceptions:
            # Don't count these as failures
            raise
        except Exception:
            await self._on_failure()
            raise

    async def _on_success(self):
        """Handle successful call"""
        async with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.config.success_threshold:
                    self._failure_count = 0
                    self._success_count = 0
                    await self._transition_to(CircuitState.CLOSED)
            elif self._state == CircuitState.CLOSED:
                # Reset failure count on success
                self._failure_count = max(0, self._failure_count - 1)

    async def _on_failure(self):
        """Handle failed call"""
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()

            if self._state == CircuitState.HALF_OPEN:
                # Immediately back to open on failure during test
                await self._transition_to(CircuitState.OPEN)
                self._success_count = 0
            elif self._state == CircuitState.CLOSED:
                if self._failure_count >= self.config.failure_threshold:
                    await self._transition_to(CircuitState.OPEN)

    def on_state_change(self, callback: Callable):
        """Register callback for state changes"""
        self._state_change_callbacks.append(callback)

    def get_stats(self) -> dict[str, Any]:
        """Return current statistics"""
        return {
            "name": self.name,
            "state": self._state.value,
            "failure_count": self._failure_count,
            "success_count": self._success_count,
            "half_open_calls": self._half_open_calls,
            "last_failure_time": self._last_failure_time
        }


class CircuitBreakerOpen(Exception):
    """Raised when circuit breaker is open"""
    pass


@dataclass
class CacheEntry(Generic[T]):
    """Cache entry with metadata"""
    value: T
    created_at: float
    last_accessed: float
    access_count: int = 0
    ttl: float | None = None


class LRUCacheWithTTL(Generic[T]):
    """
    LRU cache with TTL expiration and background cleanup.
    Combines least-recently-used eviction with time-based expiration.
    """

    def __init__(
        self,
        max_size: int = 1000,
        default_ttl: float | None = 3600.0,
        cleanup_interval: float = 300.0
    ):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cleanup_interval = cleanup_interval
        self._cache: OrderedDict[str, CacheEntry[T]] = OrderedDict()
        self._lock = asyncio.Lock()
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._expirations = 0
        self._cleanup_task: asyncio.Task | None = None

    async def start_background_cleanup(self):
        """Start background task for periodic cleanup"""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            logger.info(f"LRUCache background cleanup started (interval={self.cleanup_interval}s)")

    async def _cleanup_loop(self):
        """Periodically remove expired entries"""
        while True:
            await asyncio.sleep(self.cleanup_interval)
            try:
                removed = await self.cleanup_expired()
                if removed > 0:
                    logger.debug(f"LRUCache cleaned up {removed} expired entries")
            except Exception as e:
                logger.error(f"LRUCache cleanup failed: {e}")

    async def cleanup_expired(self) -> int:
        """Remove all expired entries, return count removed"""
        async with self._lock:
            now = time.time()
            expired_keys = []

            for key, entry in self._cache.items():
                if entry.ttl is not None and now - entry.created_at > entry.ttl:
                    expired_keys.append(key)

            for key in expired_keys:
                del self._cache[key]
                self._expirations += 1

            return len(expired_keys)

    async def get(self, key: str) -> T | None:
        """Get value from cache, returns None if missing or expired"""
        async with self._lock:
            entry = self._cache.get(key)

            if entry is None:
                self._misses += 1
                return None

            # Check TTL expiration
            if entry.ttl is not None and time.time() - entry.created_at > entry.ttl:
                del self._cache[key]
                self._expirations += 1
                self._misses += 1
                return None

            # Update LRU order and access stats
            self._cache.move_to_end(key)
            entry.last_accessed = time.time()
            entry.access_count += 1
            self._hits += 1

            return entry.value

    async def set(
        self,
        key: str,
        value: T,
        ttl: float | None = None
    ):
        """Set value in cache with optional TTL override"""
        async with self._lock:
            now = time.time()

            # If key exists, update it
            if key in self._cache:
                entry = self._cache[key]
                entry.value = value
                entry.last_accessed = now
                entry.access_count += 1
                entry.ttl = ttl if ttl is not None else self.default_ttl
                self._cache.move_to_end(key)
            else:
                # Evict if at capacity
                if len(self._cache) >= self.max_size:
                    # Remove oldest (first) item
                    self._cache.popitem(last=False)
                    self._evictions += 1

                # Add new entry
                self._cache[key] = CacheEntry(
                    value=value,
                    created_at=now,
                    last_accessed=now,
                    access_count=1,
                    ttl=ttl if ttl is not None else self.default_ttl
                )

    async def delete(self, key: str) -> bool:
        """Delete key from cache, returns True if existed"""
        async with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False

    async def clear(self):
        """Clear all cache entries"""
        async with self._lock:
            self._cache.clear()

    def get_stats(self) -> dict[str, Any]:
        """Return cache statistics"""
        total_requests = self._hits + self._misses
        hit_rate = self._hits / total_requests if total_requests > 0 else 0.0

        return {
            "size": len(self._cache),
            "max_size": self.max_size,
            "hits": self._hits,
            "misses": self._misses,
            "evictions": self._evictions,
            "expirations": self._expirations,
            "hit_rate": round(hit_rate, 3)
        }

    async def stop(self):
        """Stop background cleanup task"""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass


class TokenBucketRateLimiter:
    """
    Adaptive rate limiter using token bucket algorithm.
    Supports dynamic rate adjustment based on response headers.
    """

    def __init__(
        self,
        rate: float = 10.0,           # Tokens per second
        capacity: int = 100,          # Max bucket size
        adaptive: bool = True         # Auto-adjust based on rate limit headers
    ):
        self.rate = rate
        self.capacity = capacity
        self.adaptive = adaptive
        self._tokens = float(capacity)
        self._last_update = time.time()
        self._lock = asyncio.Lock()
        self._total_requests = 0
        self._rate_limited_requests = 0
        self._adaptive_adjustments = 0

    async def acquire(self, tokens: int = 1, timeout: float | None = None) -> bool:
        """
        Acquire tokens from bucket.
        Returns True immediately if available, False if timeout expires.
        """
        start_time = time.time()

        while True:
            async with self._lock:
                self._refill()

                if self._tokens >= tokens:
                    self._tokens -= tokens
                    self._total_requests += 1
                    return True

                # Calculate wait time
                needed = tokens - self._tokens
                wait_time = needed / self.rate

            # Check timeout
            if timeout is not None:
                elapsed = time.time() - start_time
                if elapsed >= timeout:
                    self._rate_limited_requests += 1
                    return False

            # Wait and retry
            await asyncio.sleep(min(wait_time, 0.1))

    def _refill(self):
        """Refill tokens based on elapsed time"""
        now = time.time()
        elapsed = now - self._last_update
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._last_update = now

    async def adjust_rate(self, new_rate: float):
        """Dynamically adjust rate (for adaptive mode)"""
        async with self._lock:
            old_rate = self.rate
            self.rate = new_rate
            self._adaptive_adjustments += 1
            logger.debug(f"RateLimiter adjusted: {old_rate} → {new_rate} tokens/s")

    def detect_rate_limit_headers(self, headers: dict[str, str]) -> float | None:
        """
        Detect rate limit from HTTP response headers.
        Returns recommended rate or None if not found.
        """
        if not self.adaptive:
            return None

        # Common rate limit header patterns
        patterns = [
            ('x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset'),
            ('ratelimit-limit', 'ratelimit-remaining', 'ratelimit-reset'),
            ('x-rate-limit-limit', 'x-rate-limit-remaining', 'x-rate-limit-reset'),
        ]

        for limit_key, remaining_key, reset_key in patterns:
            if limit_key in headers and remaining_key in headers and reset_key in headers:
                try:
                    limit = int(headers[limit_key])
                    remaining = int(headers[remaining_key])
                    reset = int(headers[reset_key])

                    # Calculate recommended rate
                    if reset > 0:
                        recommended = remaining / reset
                        if recommended < self.rate * 0.5:
                            logger.warning(
                                f"Rate limit detected: {remaining}/{limit} remaining, "
                                f"adjusting to {recommended:.2f} req/s"
                            )
                            return recommended
                except (ValueError, KeyError):
                    pass

        return None

    def get_stats(self) -> dict[str, Any]:
        """Return rate limiter statistics"""
        return {
            "current_tokens": self._tokens,
            "capacity": self.capacity,
            "rate": self.rate,
            "total_requests": self._total_requests,
            "rate_limited_requests": self._rate_limited_requests,
            "adaptive_adjustments": self._adaptive_adjustments,
            "utilization": round(1.0 - (self._tokens / self.capacity), 3)
        }


class AsyncRetryWithBackoff:
    """
    Advanced retry mechanism with exponential backoff and jitter.
    """

    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        exponential_base: float = 2.0,
        jitter: bool = True,
        retryable_exceptions: tuple = field(default_factory=lambda: (
            asyncio.TimeoutError,
            ConnectionError,
            OSError
        ))
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter
        self.retryable_exceptions = retryable_exceptions
        self._retry_counts: dict[str, int] = {}

    async def execute(
        self,
        func: Callable[..., T],
        *args,
        operation_name: str = "operation",
        **kwargs
    ) -> T:
        """Execute function with retry logic"""
        import random

        last_exception = None

        for attempt in range(self.max_retries + 1):
            try:
                result = func(*args, **kwargs)
                if asyncio.iscoroutine(result):
                    result = await result

                if attempt > 0:
                    logger.info(f"{operation_name} succeeded after {attempt} retries")

                return result

            except self.retryable_exceptions as e:
                last_exception = e

                if attempt >= self.max_retries:
                    logger.error(f"{operation_name} failed after {self.max_retries} retries")
                    break

                # Calculate delay with exponential backoff
                delay = min(
                    self.base_delay * (self.exponential_base ** attempt),
                    self.max_delay
                )

                # Add jitter to prevent thundering herd
                if self.jitter:
                    delay *= (0.5 + random.random())

                logger.warning(
                    f"{operation_name} failed (attempt {attempt + 1}/{self.max_retries + 1}), "
                    f"retrying in {delay:.2f}s: {e}"
                )

                await asyncio.sleep(delay)

            except Exception as e:
                # Non-retryable exception
                logger.error(f"{operation_name} failed with non-retryable error: {e}")
                raise

        raise last_exception if last_exception else Exception("Unknown error")


# Singleton infrastructure manager
class InfrastructureManager:
    """
    Centralized manager for all infrastructure components.
    Provides shared instances across the application.
    """

    _instance = None
    _lock = asyncio.Lock()

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._circuit_breakers: dict[str, CircuitBreaker] = {}
        self._caches: dict[str, LRUCacheWithTTL] = {}
        self._rate_limiters: dict[str, TokenBucketRateLimiter] = {}
        self._retriers: dict[str, AsyncRetryWithBackoff] = {}
        self._initialized = True

        logger.info("InfrastructureManager initialized")

    @classmethod
    async def get_instance(cls) -> 'InfrastructureManager':
        """Get singleton instance"""
        if cls._instance is None:
            async with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def get_circuit_breaker(
        self,
        name: str,
        config: CircuitBreakerConfig | None = None
    ) -> CircuitBreaker:
        """Get or create circuit breaker by name"""
        if name not in self._circuit_breakers:
            self._circuit_breakers[name] = CircuitBreaker(name, config)
            logger.info(f"Created circuit breaker: {name}")
        return self._circuit_breakers[name]

    def get_cache(
        self,
        name: str,
        max_size: int = 1000,
        default_ttl: float | None = 3600.0
    ) -> LRUCacheWithTTL:
        """Get or create cache by name"""
        if name not in self._caches:
            self._caches[name] = LRUCacheWithTTL(max_size, default_ttl)
            logger.info(f"Created cache: {name} (max_size={max_size}, ttl={default_ttl})")
        return self._caches[name]

    def get_rate_limiter(
        self,
        name: str,
        rate: float = 10.0,
        capacity: int = 100,
        adaptive: bool = True
    ) -> TokenBucketRateLimiter:
        """Get or create rate limiter by name"""
        if name not in self._rate_limiters:
            self._rate_limiters[name] = TokenBucketRateLimiter(rate, capacity, adaptive)
            logger.info(f"Created rate limiter: {name} (rate={rate}, capacity={capacity})")
        return self._rate_limiters[name]

    def get_retry_config(
        self,
        name: str,
        max_retries: int = 3,
        base_delay: float = 1.0
    ) -> AsyncRetryWithBackoff:
        """Get or create retry config by name"""
        if name not in self._retriers:
            self._retriers[name] = AsyncRetryWithBackoff(max_retries, base_delay)
            logger.info(f"Created retry config: {name}")
        return self._retriers[name]

    async def start_all(self):
        """Start all background tasks"""
        for cache in self._caches.values():
            await cache.start_background_cleanup()
        logger.info("All infrastructure background tasks started")

    async def stop_all(self):
        """Stop all background tasks"""
        for cache in self._caches.values():
            await cache.stop()
        logger.info("All infrastructure background tasks stopped")

    def get_all_stats(self) -> dict[str, Any]:
        """Get comprehensive statistics"""
        return {
            "circuit_breakers": {
                name: cb.get_stats() for name, cb in self._circuit_breakers.items()
            },
            "caches": {
                name: cache.get_stats() for name, cache in self._caches.items()
            },
            "rate_limiters": {
                name: rl.get_stats() for name, rl in self._rate_limiters.items()
            }
        }
