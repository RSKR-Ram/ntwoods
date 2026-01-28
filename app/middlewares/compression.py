from __future__ import annotations

import gzip
import os
from io import BytesIO

from flask import Flask, request


def _env_bool(name: str, default: bool = False) -> bool:
    raw = str(os.getenv(name, "") or "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default


def init_compression(app: Flask) -> None:
    """
    Gzip compression middleware for JSON responses.
    
    Enabled by default. Disable with ENABLE_COMPRESSION=0.
    Only compresses responses larger than min_size bytes.
    """
    if not _env_bool("ENABLE_COMPRESSION", True):
        return

    min_size = _env_int("COMPRESSION_MIN_SIZE", 500)
    compression_level = max(1, min(9, _env_int("COMPRESSION_LEVEL", 6)))

    @app.after_request
    def _compress(response):
        # Skip if client doesn't accept gzip
        if "gzip" not in request.headers.get("Accept-Encoding", "").lower():
            return response

        # Skip small responses, errors, and already-compressed content
        if (
            response.status_code < 200
            or response.status_code >= 300
            or response.direct_passthrough
            or "Content-Encoding" in response.headers
        ):
            return response

        # Only compress JSON responses
        content_type = response.headers.get("Content-Type", "").lower()
        if "application/json" not in content_type:
            return response

        # Check minimum size
        data = response.get_data()
        if len(data) < min_size:
            return response

        # Compress
        try:
            buf = BytesIO()
            with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=compression_level) as gz:
                gz.write(data)
            compressed = buf.getvalue()

            # Only use compressed version if it's actually smaller
            if len(compressed) < len(data):
                response.set_data(compressed)
                response.headers["Content-Encoding"] = "gzip"
                response.headers["Content-Length"] = len(compressed)
                response.headers["Vary"] = "Accept-Encoding"
        except Exception:
            # Fall back to uncompressed on any error
            pass

        return response
