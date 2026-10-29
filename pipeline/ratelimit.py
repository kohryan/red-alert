"""Rate limiting and concurrency control.

Two independent controls, both required:

* **rate** — at most N requests per minute across the whole run, shared by
  every worker thread, so adding concurrency never multiplies load on the
  origin;
* **concurrency** — at most K requests in flight at once, so the origin sees a
  bounded number of open connections.

Both are hard ceilings. Nothing in the pipeline can raise them at runtime.
"""

from __future__ import annotations

import threading
import time
from collections import deque


class RateLimiter:
    """Sliding-window limiter plus a bounded concurrency semaphore."""

    def __init__(
        self,
        requests_per_minute: int = 10,
        max_concurrency: int = 2,
        min_interval: float = 0.0,
        clock=time.monotonic,
        sleeper=time.sleep,
    ) -> None:
        if requests_per_minute < 1:
            raise ValueError("requests_per_minute must be at least 1")
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be at least 1")
        self.requests_per_minute = requests_per_minute
        self.max_concurrency = max_concurrency
        self.min_interval = max(0.0, min_interval)
        self._clock = clock
        self._sleeper = sleeper
        self._lock = threading.Lock()
        self._timestamps: deque[float] = deque()
        self._last_grant: float | None = None
        self._semaphore = threading.BoundedSemaphore(max_concurrency)
        self.waited_seconds = 0.0
        self.granted = 0

    # -------------------------------------------------------------- timing

    def _wait_for_slot(self) -> float:
        """Block until the next request may start. Returns seconds waited.

        Two independent ceilings apply: the sliding per-minute window, and the
        minimum interval between consecutive requests (used to honour a
        robots.txt Crawl-delay).
        """
        waited = 0.0
        while True:
            with self._lock:
                now = self._clock()
                window_start = now - 60.0
                while self._timestamps and self._timestamps[0] <= window_start:
                    self._timestamps.popleft()

                if len(self._timestamps) >= self.requests_per_minute:
                    sleep_for = 60.0 - (now - self._timestamps[0]) + 0.001
                elif self._last_grant is not None and self.min_interval > 0:
                    elapsed = now - self._last_grant
                    sleep_for = max(0.0, self.min_interval - elapsed)
                else:
                    sleep_for = 0.0

                if sleep_for <= 0:
                    self._timestamps.append(now)
                    self._last_grant = now
                    self.granted += 1
                    return waited

            self._sleeper(sleep_for)
            waited += sleep_for

    def acquire(self) -> float:
        """Acquire both a rate slot and a concurrency slot."""
        self._semaphore.acquire()
        try:
            return self._wait_for_slot()
        except BaseException:
            self._semaphore.release()
            raise

    def release(self) -> None:
        self._semaphore.release()

    def __enter__(self) -> "RateLimiter":
        self.acquire()
        return self

    def __exit__(self, *_exc) -> None:
        self.release()

    # ------------------------------------------------------------ reporting

    def stats(self) -> dict[str, float | int]:
        return {
            "requests_per_minute": self.requests_per_minute,
            "max_concurrency": self.max_concurrency,
            "granted": self.granted,
            "waited_seconds": round(self.waited_seconds, 3),
        }
