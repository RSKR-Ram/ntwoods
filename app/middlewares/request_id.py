from __future__ import annotations

import os
import time

from flask import Flask, g, request


def init_request_id(app: Flask) -> None:
    @app.before_request
    def _set_request_id():
        incoming = str(request.headers.get("X-Request-ID") or "").strip()
        g.request_id = incoming or os.urandom(8).hex()
        g.start_ts = time.monotonic()

    @app.after_request
    def _add_header(resp):
        rid = getattr(g, "request_id", "")
        if rid:
            resp.headers["X-Request-ID"] = rid
        return resp
