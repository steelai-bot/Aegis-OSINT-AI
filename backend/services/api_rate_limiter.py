"""API rate limiting middleware.

Provides per-IP rate limiting with an in-memory sliding window.
"""

from __future__ import annotations

import time
from collections import defaultdict

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class APIRateLimiterMiddleware(BaseHTTPMiddleware):
    """In-memory per-IP rate limiter for the API layer.

    Configure via AEGIS_API_RATE_LIMIT_PER_MINUTE (default 120).
    """

    def __init__(self, app, requests_per_minute: int = 120) -> None:
        super().__init__(app)
        self.rpm = requests_per_minute
        self._hits: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        ip = self._get_client_ip(request)
        now = time.time()
        window_start = now - 60.0

        hits = self._hits[ip]
        # Prune old entries outside the 1-minute window
        self._hits[ip] = [t for t in hits if t > window_start]
        hits = self._hits[ip]

        if len(hits) >= self.rpm:
            retry_after = int(hits[0] - window_start) + 1
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again shortly."},
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(self.rpm),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(retry_after)),
                },
            )

        self._hits[ip].append(now)
        remaining = self.rpm - len(self._hits[ip])

        response: Response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.rpm)
        response.headers["X-RateLimit-Remaining"] = str(max(0, remaining))
        response.headers["X-RateLimit-Reset"] = str(60)
        return response

    @staticmethod
    def _get_client_ip(request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "unknown"