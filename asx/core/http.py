"""Shared, rate-limited, non-destructive HTTP client wrapper."""
from __future__ import annotations

import httpx

from .rate_limit import RateLimiter

DEFAULT_UA = "AttackSurfaceX/0.1 (+safe-scanner; no-exploitation)"


class SafeHttpClient:
    """httpx wrapper that enforces timeouts, rate limiting and a fixed,
    self-identifying User-Agent. GET/HEAD only: the scanner never sends
    state-changing requests."""

    def __init__(
        self,
        rate_limiter: RateLimiter | None = None,
        timeout: float = 10.0,
        cookies: dict[str, str] | None = None,
    ) -> None:
        self.rl = rate_limiter or RateLimiter()
        self._client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": DEFAULT_UA},
            cookies=cookies,
            verify=True,
        )

    async def get(self, url: str, **kwargs) -> httpx.Response:
        await self.rl.acquire()
        return await self._client.get(url, **kwargs)

    async def head(self, url: str, **kwargs) -> httpx.Response:
        await self.rl.acquire()
        return await self._client.head(url, **kwargs)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "SafeHttpClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()
