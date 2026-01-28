from __future__ import annotations

import json
import logging
import time
from typing import Any

from flask import Flask, g, request


def init_request_logging(app: Flask) -> None:
    logger = logging.getLogger("app.request")

    @app.after_request
    def _log(resp):
        start = getattr(g, "start_ts", None)
        latency_ms = (
            int((time.monotonic() - start) * 1000) if isinstance(start, (int, float)) else None
        )

        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
        if ip and "," in ip:
            ip = ip.split(",", 1)[0].strip()

        data: dict[str, Any] = {
            "type": "request",
            "request_id": getattr(g, "request_id", ""),
            "method": request.method,
            "path": request.path,
            "status": resp.status_code,
            "latency_ms": latency_ms,
            "ip": ip,
        }

        logger.info(json.dumps(data, separators=(",", ":")))
        return resp
