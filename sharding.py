from __future__ import annotations

import hashlib
from typing import Sequence


def pick_shard_index(owner_user_id: str, shard_count: int) -> int:
    """
    Consistent shard routing.

    Safe default: returns 0 when shard_count <= 1.
    """
    n = int(shard_count or 0)
    if n <= 1:
        return 0
    key = str(owner_user_id or "").strip() or "0"
    h = int(hashlib.sha256(key.encode("utf-8")).hexdigest(), 16)
    return int(h % n)


def pick_shard_url(owner_user_id: str, shard_urls: Sequence[str]) -> str:
    urls = [str(u or "").strip() for u in (shard_urls or []) if str(u or "").strip()]
    if not urls:
        return ""
    idx = pick_shard_index(owner_user_id, len(urls))
    return urls[idx]

