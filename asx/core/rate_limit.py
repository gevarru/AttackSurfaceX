"""Async token-bucket rate limiter with concurrency control."""
from __future__ import annotations

import asyncio
import time


class RateLimiter:
    """Simple asyncio token bucket: `rate` tokens per second, plus a
    semaphore bounding concurrent operations."""

    def __init__(self, rate: float = 10.0, concurrency: int = 20) -> None:
        if rate <= 0:
            raise ValueError("rate must be positive")
        if concurrency <= 0:
            raise ValueError("concurrency must be positive")
        self.rate = float(rate)
        self._tokens = float(rate)
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()
        self._sem = asyncio.Semaphore(concurrency)

    async def acquire(self) -> None:
        async with self._sem:
            async with self._lock:
                now = time.monotonic()
                self._tokens = min(self.rate, self._tokens + (now - self._updated) * self.rate)
                self._updated = now
                if self._tokens < 1.0:
                    wait = (1.0 - self._tokens) / self.rate
                    await asyncio.sleep(wait)
                    self._tokens = 0.0
                else:
                    self._tokens -= 1.0
