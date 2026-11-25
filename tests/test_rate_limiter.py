"""Unit tests for thread-safe sliding-window rate limiter."""

import threading
from ztgw.rate_limiter import SlidingWindowRateLimiter


class FakeClock:
    def __init__(self, start: float = 100.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def test_allows_up_to_limit_and_blocks_excess():
    clock = FakeClock()
    limiter = SlidingWindowRateLimiter(max_requests=3, window_seconds=10.0, clock=clock)

    assert limiter.check_and_consume("ip:1.2.3.4").remaining == 2
    assert limiter.check_and_consume("ip:1.2.3.4").remaining == 1
    d3 = limiter.check_and_consume("ip:1.2.3.4")
    assert d3.allowed is True
    assert d3.remaining == 0

    blocked = limiter.check_and_consume("ip:1.2.3.4")
    assert blocked.allowed is False
    assert blocked.retry_after_seconds == 10.0

    # Advance past window
    clock.advance(10.1)
    recovered = limiter.check_and_consume("ip:1.2.3.4")
    assert recovered.allowed is True


def test_concurrent_threads_respect_exact_quota():
    limiter = SlidingWindowRateLimiter(max_requests=25, window_seconds=60.0)
    results = []
    lock = threading.Lock()

    def worker():
        res = limiter.check_and_consume("tenant:alpha")
        with lock:
            results.append(res.allowed)

    threads = [threading.Thread(target=worker) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sum(1 for r in results if r) == 25
    assert sum(1 for r in results if not r) == 25


def test_stale_buckets_pruned_at_capacity():
    clock = FakeClock()
    limiter = SlidingWindowRateLimiter(
        max_requests=2, window_seconds=5.0, clock=clock, max_tracked_keys=2
    )
    limiter.check_and_consume("k1")
    limiter.check_and_consume("k2")
    clock.advance(6.0)
    limiter.check_and_consume("k3")
    assert limiter.tracked_key_count() == 1
