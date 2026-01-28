from __future__ import annotations

import hashlib
import json
import os
import threading
from typing import Any, Callable, Optional

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
        ttl = int(os.getenv("CACHE_TTL_SECONDS", "60") or "60")
        # Production default: 50k items for better hit rates
        max_items = int(os.getenv("CACHE_MAX_ITEMS", "50000") or "50000")
        ttl = max(1, min(3600, ttl))
        max_items = max(100, min(500_000, max_items))
        self._cache = TTLCache(maxsize=max_items, ttl=ttl)
        self._lock = threading.RLock()
        # Stats counters
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> Any:
        with self._lock:
            val = self._cache.get(key)
            if val is not None:
                self._hits += 1
            else:
                self._misses += 1
            return val

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._cache[key] = value

    def get_or_set(self, key: str, factory: Callable[[], Any]) -> Any:
        """Atomic get-or-compute pattern. Returns cached value or computes + caches it."""
        with self._lock:
            val = self._cache.get(key)
            if val is not None:
                self._hits += 1
                return val
            self._misses += 1
        # Compute outside lock to avoid blocking other operations
        computed = factory()
        with self._lock:
            # Double-check in case another thread computed it
            if key in self._cache:
                return self._cache[key]
            self._cache[key] = computed
        return computed

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
                self._hits = 0
                self._misses = 0
            except Exception:
                pass

    def stats(self) -> dict[str, Any]:
        """Returns cache statistics for monitoring."""
        with self._lock:
            total = self._hits + self._misses
            hit_rate = (self._hits / total * 100) if total > 0 else 0.0
            return {
                "size": len(self._cache),
                "maxsize": self._cache.maxsize,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": round(hit_rate, 2),
            }


_cache = _InMemoryTTLCache()


def cache_get(key: str) -> Any:
    return _cache.get(key)


def cache_set(key: str, value: Any) -> None:
    _cache.set(key, value)


def cache_get_or_set(key: str, factory: Callable[[], Any]) -> Any:
    """Atomic get-or-compute. Example: cache_get_or_set('user:123', lambda: db.get_user(123))"""
    return _cache.get_or_set(key, factory)


def cache_invalidate_prefix(prefix: str) -> int:
    return _cache.invalidate_prefix(prefix)


def cache_clear() -> None:
    _cache.clear()


def cache_stats() -> dict[str, Any]:
    """Returns cache stats: size, maxsize, hits, misses, hit_rate."""
    return _cache.stats()

