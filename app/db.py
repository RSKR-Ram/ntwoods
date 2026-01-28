from __future__ import annotations

import threading
from datetime import timezone

from flask import Flask
from pymongo import MongoClient


_client: MongoClient | None = None
_client_lock = threading.Lock()


def _create_client(mongodb_uri: str, *, server_selection_timeout_ms: int) -> MongoClient:
    if mongodb_uri.startswith("mongomock://"):
        import mongomock  # type: ignore[import-not-found]

        return mongomock.MongoClient(tz_aware=True, tzinfo=timezone.utc)

    return MongoClient(
        mongodb_uri,
        serverSelectionTimeoutMS=server_selection_timeout_ms,
        tz_aware=True,
        tzinfo=timezone.utc,
        retryWrites=True,
    )


def get_client(app: Flask) -> MongoClient:
    global _client
    cfg = app.config["CFG"]
    with _client_lock:
        if _client is None:
            _client = _create_client(cfg.MONGODB_URI, server_selection_timeout_ms=cfg.MONGO_SERVER_SELECTION_TIMEOUT_MS)
    return _client


def get_db(app: Flask):
    cfg = app.config["CFG"]
    return get_client(app)[cfg.DB_NAME]


def ping_db(db) -> bool:
    try:
        db.command("ping")
        return True
    except Exception:
        try:
            # Fallback for test doubles (e.g. mongomock) and restricted environments.
            _ = db.list_collection_names()
            return True
        except Exception:
            return False


def ensure_indexes(db) -> None:
    db.users.create_index([("email", 1)], unique=True, name="users_email_unique")
    # "auditlog/events" (convention): keep a single collection name for PyMongo.
    db.auditlog_events.create_index([("createdAt", -1)], name="auditlog_events_createdAt_desc")
    db.requirements.create_index([("status", 1), ("createdAt", -1)], name="requirements_status_createdAt")
    db.requirements.create_index([("requirementId", 1)], name="requirements_requirementId")
    db.candidates.create_index([("requirementId", 1), ("stage", 1), ("createdAt", -1)], name="candidates_req_stage_createdAt")
    db.candidates.create_index([("createdAt", -1)], name="candidates_createdAt_desc")


def init_mongo(app: Flask) -> None:
    db = get_db(app)
    app.extensions["mongo_db"] = db
    ensure_indexes(db)


def reset_client_for_tests() -> None:
    global _client
    with _client_lock:
        _client = None
