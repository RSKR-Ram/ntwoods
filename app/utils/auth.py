from __future__ import annotations

import functools
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, TypeVar

import bcrypt
import jwt
from bson import ObjectId
from flask import current_app, request

from app.utils.errors import ApiError


_T = TypeVar("_T", bound=Callable[..., Any])


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False


def create_access_token(app, user: dict[str, Any]) -> str:
    cfg = app.config["CFG"]
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user["_id"]),
        "email": str(user.get("email") or ""),
        "role": str(user.get("role") or ""),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=cfg.JWT_EXP_MINUTES)).timestamp()),
    }
    return jwt.encode(payload, cfg.JWT_SECRET, algorithm="HS256")


def _decode_token(token: str) -> dict[str, Any]:
    cfg = current_app.config["CFG"]
    try:
        return jwt.decode(token, cfg.JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError as e:
        raise ApiError("AUTH_INVALID", "Token expired", status=401) from e
    except jwt.InvalidTokenError as e:
        raise ApiError("AUTH_INVALID", "Invalid token", status=401) from e


def _bearer_token() -> str:
    authz = str(request.headers.get("Authorization") or "").strip()
    if authz.lower().startswith("bearer "):
        return authz.split(" ", 1)[1].strip()
    return ""


def get_current_user() -> dict[str, str]:
    token = _bearer_token()
    if not token:
        raise ApiError("AUTH_INVALID", "Missing bearer token", status=401)

    payload = _decode_token(token)
    sub = str(payload.get("sub") or "").strip()
    if not sub:
        raise ApiError("AUTH_INVALID", "Invalid token payload", status=401)

    try:
        user_id = ObjectId(sub)
    except Exception as e:
        raise ApiError("AUTH_INVALID", "Invalid token subject", status=401) from e

    db = current_app.extensions.get("mongo_db")
    if not db:
        raise ApiError("INTERNAL", "Database not initialized", status=500)

    user = db.users.find_one({"_id": user_id})
    if not user:
        raise ApiError("AUTH_INVALID", "User not found", status=401)
    if str(user.get("status") or "ACTIVE").upper() != "ACTIVE":
        raise ApiError("FORBIDDEN", "User is disabled", status=403)

    email = str(user.get("email") or "").strip().lower()
    role = str(user.get("role") or "").upper().strip()
    return {"id": str(user["_id"]), "email": email, "role": role}


def require_roles(roles: list[str]) -> Callable[[_T], _T]:
    allowed = {str(r or "").upper().strip() for r in (roles or []) if str(r or "").strip()}

    def _decorator(fn: _T) -> _T:
        @functools.wraps(fn)
        def _wrapped(*args, **kwargs):
            user = get_current_user()
            if allowed and user["role"] not in allowed:
                raise ApiError("FORBIDDEN", "Insufficient role", status=403, details={"required": sorted(allowed)})
            return fn(*args, **kwargs)

        return _wrapped  # type: ignore[return-value]

    return _decorator
