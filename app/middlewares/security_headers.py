from __future__ import annotations

from flask import Flask, request


def init_security_headers(app: Flask) -> None:
    @app.after_request
    def _headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

        cfg = app.config.get("CFG")
        is_https = (
            request.is_secure
            or str(request.headers.get("X-Forwarded-Proto") or "").lower() == "https"
        )
        if getattr(cfg, "IS_PRODUCTION", False) and is_https:
            resp.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )

        return resp
