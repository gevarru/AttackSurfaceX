"""Async token-bucket rate limiter with concurrency control."""
from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from typing import AsyncIterator


class RateLimiter:
    """Token bucket: `rate` tokens per second, plus a semaphore bounding
    concurrent operations.

    Two ways to use it:

    - ``await rl.acquire()`` — rate limiting only.
    - ``async with rl.hold():`` — rate limiting AND holds one of the
      `concurrency` slots for the duration of the block.
    """

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

    async def _take_token(self) -> None:
        async with self._lock:
            now = time.monotonic()
            self._tokens = min(self.rate, self._tokens + (now - self._updated) * self.rate)
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                self._updated = now
                return
            # Not enough tokens: pay with time. The timestamp is taken
            # AFTER the sleep so the elapsed time is not double-counted
            # as refill.
            wait = (1.0 - self._tokens) / self.rate
            await asyncio.sleep(wait)
            self._tokens = 0.0
            self._updated = time.monotonic()

    async def acquire(self) -> None:
        """Consume one token (rate limit only)."""
        await self._take_token()

    @asynccontextmanager
    async def hold(self) -> AsyncIterator[None]:
        """Consume one token and hold a concurrency slot for the block."""
        async with self._sem:
            await self._take_token()
            yield
