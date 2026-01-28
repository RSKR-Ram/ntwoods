from __future__ import annotations

from flask import Flask, request

from app.utils.rate_limiter import InMemoryRateLimiter

_limiter = InMemoryRateLimiter()


def init_rate_limiting(app: Flask) -> None:
    cfg = app.config["CFG"]

    @app.before_request
    def _rate_limit():
        path = request.path or ""
        if path in {"/health", "/version"}:
            return None

        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
        if ip and "," in ip:
            ip = ip.split(",", 1)[0].strip()

        if path.startswith("/api/v1/auth/login"):
            _limiter.check(f"{ip}:LOGIN", cfg.RATE_LIMIT_LOGIN)
            return None

        if path.startswith("/api/v1/"):
            _limiter.check(f"{ip}:GLOBAL", cfg.RATE_LIMIT_GLOBAL)
            _limiter.check(f"{ip}:PATH:{path}", cfg.RATE_LIMIT_DEFAULT)
            return None

        return None
