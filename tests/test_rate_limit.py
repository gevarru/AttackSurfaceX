"""Tests for the token-bucket rate limiter."""
import asyncio
import time

import pytest

from asx.core.rate_limit import RateLimiter


def test_invalid_params():
    with pytest.raises(ValueError):
        RateLimiter(rate=0)
    with pytest.raises(ValueError):
        RateLimiter(concurrency=0)


@pytest.mark.asyncio
async def test_rate_limit_throttles():
    rl = RateLimiter(rate=20, concurrency=20)
    start = time.monotonic()
    # burst of 20 drains the bucket; the next 20 must cost ~1 second
    for _ in range(40):
        await rl.acquire()
    elapsed = time.monotonic() - start
    assert elapsed >= 0.8


@pytest.mark.asyncio
async def test_concurrency_bounded():
    rl = RateLimiter(rate=1000, concurrency=2)
    active = 0
    peak = 0

    async def worker():
        nonlocal active, peak
        async with rl.hold():
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.02)
            active -= 1

    await asyncio.gather(*(worker() for _ in range(10)))
    assert peak <= 2
