from __future__ import annotations

import logging
from typing import Any

from flask import Flask, g, jsonify
from werkzeug.exceptions import HTTPException

from app.utils.errors import ApiError


def init_error_handlers(app: Flask) -> None:
    @app.errorhandler(ApiError)
    def _api_error(err: ApiError):
        payload: dict[str, Any] = {
            "success": False,
            "error": {"code": err.code, "message": err.message, "details": err.details},
        }
        if getattr(g, "request_id", None):
            payload["request_id"] = g.request_id
        return jsonify(payload), err.status

    @app.errorhandler(HTTPException)
    def _http_error(err: HTTPException):
        code = f"HTTP_{int(err.code or 500)}"
        payload: dict[str, Any] = {
            "success": False,
            "error": {
                "code": code,
                "message": str(err.description or "HTTP error"),
                "details": None,
            },
        }
        if getattr(g, "request_id", None):
            payload["request_id"] = g.request_id
        return jsonify(payload), int(err.code or 500)

    @app.errorhandler(Exception)
    def _unhandled(err: Exception):
        logging.getLogger("app").exception(
            "Unhandled exception request_id=%s", getattr(g, "request_id", "")
        )
        payload: dict[str, Any] = {
            "success": False,
            "error": {"code": "INTERNAL", "message": "Unexpected error", "details": None},
        }
        if getattr(g, "request_id", None):
            payload["request_id"] = g.request_id
        return jsonify(payload), 500
