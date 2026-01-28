from __future__ import annotations

from flask import Blueprint, current_app, jsonify

from app.db import ping_db
from app.utils.datetime import iso_utc_now

core_bp = Blueprint("core", __name__)


@core_bp.get("/health")
def health():
    db = current_app.extensions.get("mongo_db")
    ok = bool(db) and ping_db(db)
    cfg = current_app.config["CFG"]
    status = 200 if ok else 503
    return (
        jsonify(
            {
                "status": "ok" if ok else "degraded",
                "time": iso_utc_now(),
                "version": cfg.APP_VERSION,
                "db": "ok" if ok else "error",
            }
        ),
        status,
    )


@core_bp.get("/version")
def version():
    cfg = current_app.config["CFG"]
    return jsonify({"version": cfg.APP_VERSION, "env": cfg.ENV, "time": iso_utc_now()})
