from __future__ import annotations

import re
import threading
import time

from app.utils.errors import ApiError


class InMemoryRateLimiter:
    def __init__(self, *, window_seconds: int = 60, max_keys: int = 50_000):
        self._window_seconds = window_seconds
        self._max_keys = max_keys
        self._lock = threading.Lock()
        self._store: dict[str, tuple[int, int]] = {}

    @staticmethod
    def _parse_limit_per_minute(limit: str) -> int:
        m = re.match(r"^\s*(\d+)\s+per\s+minute\s*$", str(limit or ""), re.IGNORECASE)
        if not m:
            return 300
        return max(1, int(m.group(1)))

    def check(self, key: str, limit: str) -> None:
        max_per_minute = self._parse_limit_per_minute(limit)
        window_id = int(time.time() // self._window_seconds)

        with self._lock:
            if len(self._store) > self._max_keys:
                self._store.clear()

            current_window, current_count = self._store.get(key, (window_id, 0))
            if current_window != window_id:
                current_window, current_count = window_id, 0
            current_count += 1
            self._store[key] = (current_window, current_count)

            if current_count > max_per_minute:
                raise ApiError("RATE_LIMITED", "Rate limit exceeded", status=429)
