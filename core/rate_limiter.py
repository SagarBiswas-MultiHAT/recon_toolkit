"""Asynchronous rate limiting utilities."""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict


class AsyncRateLimiter:
    """Simple async token interval limiter per key."""

    def __init__(self) -> None:
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._last_called: dict[str, float] = defaultdict(lambda: 0.0)

    async def wait(self, key: str, delay_seconds: float) -> None:
        """Wait if needed to respect a minimum delay between calls.

        Args:
            key: Logical source key (e.g., 'crtsh', 'wayback').
            delay_seconds: Minimum gap between calls.
        """

        if delay_seconds <= 0:
            return

        async with self._locks[key]:
            now = time.monotonic()
            elapsed = now - self._last_called[key]
            sleep_for = max(0.0, delay_seconds - elapsed)
            if sleep_for > 0:
                await asyncio.sleep(sleep_for)
            self._last_called[key] = time.monotonic()


class ConcurrencyLimiter:
    """Global semaphore wrapper for request concurrency."""

    def __init__(self, max_concurrent: int) -> None:
        if max_concurrent <= 0:
            raise ValueError("max_concurrent must be > 0")
        self._semaphore = asyncio.Semaphore(max_concurrent)

    async def __aenter__(self) -> ConcurrencyLimiter:
        await self._semaphore.acquire()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:  # type: ignore[override]
        self._semaphore.release()
