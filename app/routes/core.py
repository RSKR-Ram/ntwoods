from __future__ import annotations

import os

from flask import Blueprint, current_app, jsonify

from app.db import ping_db
from app.utils.datetime import iso_utc_now

core_bp = Blueprint("core", __name__)


def _ping_redis() -> bool:
    """Check Redis connectivity."""
    redis_url = os.getenv("REDIS_URL", "")
    if not redis_url:
        return True  # Redis not configured, skip check
    try:
        import redis
        r = redis.from_url(redis_url, socket_connect_timeout=2)
        r.ping()
        return True
    except Exception:
        return False


@core_bp.get("/health")
def health():
    """Lightweight health check (process alive)."""
    cfg = current_app.config["CFG"]
    return jsonify({
        "status": "ok",
        "time": iso_utc_now(),
        "version": cfg.APP_VERSION,
    })


@core_bp.get("/ready")
def ready():
    """
    Readiness check for load balancers.
    Checks database and Redis connectivity.
    """
    db = current_app.extensions.get("mongo_db")
    db_ok = bool(db) and ping_db(db)
    redis_ok = _ping_redis()
    
    cfg = current_app.config["CFG"]
    all_ok = db_ok and redis_ok
    status = 200 if all_ok else 503
    
    return (
        jsonify({
            "status": "ok" if all_ok else "degraded",
            "time": iso_utc_now(),
            "version": cfg.APP_VERSION,
            "checks": {
                "db": "ok" if db_ok else "error",
                "redis": "ok" if redis_ok else "error",
            }
        }),
        status,
    )


@core_bp.get("/version")
def version():
    cfg = current_app.config["CFG"]
    return jsonify({"version": cfg.APP_VERSION, "env": cfg.ENV, "time": iso_utc_now()})
