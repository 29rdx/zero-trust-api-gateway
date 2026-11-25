"""Thread-safe sliding-window rate limiter with stale-bucket pruning."""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Deque, Dict


@dataclass(frozen=True)
class RateLimitDecision:
    """Decision returned by the sliding-window rate limiter."""

    allowed: bool
    limit: int
    remaining: int
    retry_after_seconds: float


class SlidingWindowRateLimiter:
    """Thread-safe per-key sliding-window log rate limiter."""

    def __init__(
        self,
        max_requests: int,
        window_seconds: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_tracked_keys: int = 10_000,
    ) -> None:
        if max_requests <= 0:
            raise ValueError("max_requests must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.max_requests = max_requests
        self.window_seconds = float(window_seconds)
        self._clock = clock
        self._max_tracked_keys = max_tracked_keys
        self._buckets: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()

    def check_and_consume(self, key: str) -> RateLimitDecision:
        if not key or not isinstance(key, str):
            raise ValueError("Rate limit key must be a non-empty string")

        now = self._clock()
        cutoff = now - self.window_seconds

        with self._lock:
            if len(self._buckets) >= self._max_tracked_keys and key not in self._buckets:
                self._prune_stale_locked(cutoff)

            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = deque()
                self._buckets[key] = bucket

            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= self.max_requests:
                retry_after = max(0.0, (bucket[0] + self.window_seconds) - now)
                return RateLimitDecision(
                    allowed=False,
                    limit=self.max_requests,
                    remaining=0,
                    retry_after_seconds=round(retry_after, 4),
                )

            bucket.append(now)
            remaining = self.max_requests - len(bucket)
            return RateLimitDecision(
                allowed=True,
                limit=self.max_requests,
                remaining=remaining,
                retry_after_seconds=0.0,
            )

    def _prune_stale_locked(self, cutoff: float) -> int:
        stale_keys = [k for k, q in self._buckets.items() if not q or q[-1] <= cutoff]
        for k in stale_keys:
            del self._buckets[k]
        return len(stale_keys)

    def tracked_key_count(self) -> int:
        with self._lock:
            return len(self._buckets)
