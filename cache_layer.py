from __future__ import annotations

import hashlib
import json
import os
import threading
from typing import Any, Optional

from cachetools import TTLCache


def _sha256_16(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def make_cache_key(namespace: str, *, scope: list[str] | None = None, params: dict[str, Any] | None = None) -> str:
    ns = str(namespace or "").strip().upper()
    scope = scope or []
    params = params or {}
    try:
        blob = json.dumps(params, sort_keys=True, separators=(",", ":"))
    except Exception:
        blob = str(params)
    digest = _sha256_16(blob)
    parts = [ns] + [str(s or "").strip() for s in scope if str(s or "").strip()] + [digest]
    return ":".join(parts)


class _InMemoryTTLCache:
    def __init__(self):
        ttl = int(os.getenv("CACHE_TTL_SECONDS", "30") or "30")
        max_items = int(os.getenv("CACHE_MAX_ITEMS", "10000") or "10000")
        ttl = max(1, min(3600, ttl))
        max_items = max(100, min(200_000, max_items))
        self._cache = TTLCache(maxsize=max_items, ttl=ttl)
        self._lock = threading.RLock()

    def get(self, key: str) -> Any:
        with self._lock:
            return self._cache.get(key)

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._cache[key] = value

    def invalidate_prefix(self, prefix: str) -> int:
        pfx = str(prefix or "")
        if not pfx:
            return 0
        removed = 0
        with self._lock:
            keys = [k for k in self._cache.keys() if str(k).startswith(pfx)]
            for k in keys:
                try:
                    del self._cache[k]
                    removed += 1
                except Exception:
                    pass
        return removed

    def clear(self) -> None:
        with self._lock:
            try:
                self._cache.clear()
            except Exception:
                pass


_cache = _InMemoryTTLCache()


def cache_get(key: str) -> Any:
    return _cache.get(key)


def cache_set(key: str, value: Any) -> None:
    _cache.set(key, value)


def cache_invalidate_prefix(prefix: str) -> int:
    return _cache.invalidate_prefix(prefix)


def cache_clear() -> None:
    _cache.clear()
