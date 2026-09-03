"""In-memory sliding-window counter; one relay instance, so process-local is sufficient."""

from __future__ import annotations

import time
from collections import defaultdict, deque


class SlidingWindowLimiter:
    def __init__(self, limit: int, window_s: float) -> None:
        self.limit = limit
        self.window_s = window_s
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def _prune(self, key: str, now: float) -> deque[float]:
        q = self._hits[key]
        while q and q[0] <= now - self.window_s:
            q.popleft()
        return q

    def record(self, key: str, now: float | None = None) -> None:
        now = time.time() if now is None else now
        self._prune(key, now).append(now)

    def is_blocked(self, key: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return len(self._prune(key, now)) >= self.limit
