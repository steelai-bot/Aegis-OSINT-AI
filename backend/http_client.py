"""
Shared HTTP Client for all OSINT plugins
Provides connection pooling and reuse across plugins
"""

import httpx
import asyncio
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class SharedHTTPClient:
    """
    Singleton async HTTP client with connection pooling.
    Shared across all plugins to eliminate connection overhead.
    """
    _instance: Optional['SharedHTTPClient'] = None
    _client: Optional[httpx.AsyncClient] = None
    _lock = asyncio.Lock()

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    async def get_client(cls) -> httpx.AsyncClient:
        """Get or create shared async client with connection pooling"""
        if cls._client is None or cls._client.is_closed:
            async with cls._lock:
                if cls._client is None or cls._client.is_closed:
                    cls._client = httpx.AsyncClient(
                        timeout=httpx.Timeout(30.0, connect=10.0),
                        limits=httpx.Limits(
                            max_connections=50,
                            max_keepalive_connections=20
                        ),
                        follow_redirects=True,
                        headers={
                            'User-Agent': 'Aegis-OSINT-AI/1.0'
                        }
                    )
                    logger.info("Shared HTTP client initialized with connection pooling")
        return cls._client

    @classmethod
    async def close(cls):
        """Close shared HTTP client"""
        if cls._client and not cls._client.is_closed:
            await cls._client.aclose()
            cls._client = None
            logger.info("Shared HTTP client closed")
