from __future__ import annotations

import os
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, request

from pymongo.errors import DuplicateKeyError

from app.utils.auth import create_access_token, get_current_user, hash_password, require_roles, verify_password
from app.utils.errors import ApiError
from app.utils.validators import require_json, validate_email, validate_password


auth_bp = Blueprint("auth", __name__)


@auth_bp.post("/bootstrap")
def bootstrap():
    bootstrap_token = str(os.getenv("BOOTSTRAP_TOKEN", "") or "").strip()
    if not bootstrap_token:
        raise ApiError("FORBIDDEN", "Bootstrap is disabled", status=403)

    provided = str(request.headers.get("X-Bootstrap-Token") or "").strip()
    if not provided or provided != bootstrap_token:
        raise ApiError("FORBIDDEN", "Invalid bootstrap token", status=403)

    db = current_app.extensions["mongo_db"]
    if db.users.count_documents({}) > 0:
        raise ApiError("CONFLICT", "Bootstrap already completed", status=409)

    body = require_json()
    email = validate_email(body.get("email"))
    password = validate_password(body.get("password"), allow_short=False)
    role = str(body.get("role") or "").strip().upper() or "OWNER"

    now = datetime.now(timezone.utc)
    db.users.insert_one(
        {
            "email": email,
            "passwordHash": hash_password(password),
            "role": role,
            "status": "ACTIVE",
            "createdAt": now,
            "updatedAt": now,
        }
    )

    return jsonify({"success": True, "data": {"email": email, "role": role}}), 201


@auth_bp.post("/login")
def login():
    body = require_json()
    email = validate_email(body.get("email"))
    password = validate_password(body.get("password"), allow_short=False)

    db = current_app.extensions["mongo_db"]
    user = db.users.find_one({"email": email})
    if not user:
        raise ApiError("AUTH_INVALID", "Invalid credentials", status=401)

    if str(user.get("status") or "ACTIVE").upper() != "ACTIVE":
        raise ApiError("FORBIDDEN", "User is disabled", status=403)

    if not verify_password(password, str(user.get("passwordHash") or "")):
        raise ApiError("AUTH_INVALID", "Invalid credentials", status=401)

    token = create_access_token(current_app, user)
    db.users.update_one({"_id": user["_id"]}, {"$set": {"lastLoginAt": datetime.now(timezone.utc)}})

    return jsonify(
        {
            "success": True,
            "data": {
                "access_token": token,
                "token_type": "bearer",
                "user": {"id": str(user["_id"]), "email": user["email"], "role": user.get("role", "")},
            },
        }
    )


@auth_bp.get("/me")
def me():
    user = get_current_user()
    return jsonify({"success": True, "data": {"id": user["id"], "email": user["email"], "role": user["role"]}})


@auth_bp.post("/users")
@require_roles(["ADMIN", "OWNER"])
def create_user():
    body = require_json()
    email = validate_email(body.get("email"))
    password = validate_password(body.get("password"), allow_short=False)
    role = str(body.get("role") or "").strip().upper() or "HR"

    now = datetime.now(timezone.utc)
    db = current_app.extensions["mongo_db"]
    try:
        db.users.insert_one(
            {
                "email": email,
                "passwordHash": hash_password(password),
                "role": role,
                "status": "ACTIVE",
                "createdAt": now,
                "updatedAt": now,
            }
        )
    except DuplicateKeyError as e:
        raise ApiError("CONFLICT", "Email already exists", status=409) from e

    return jsonify({"success": True, "data": {"email": email, "role": role}}), 201
