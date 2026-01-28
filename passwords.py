from __future__ import annotations

import re

from werkzeug.security import check_password_hash, generate_password_hash

from utils import ApiError


_HAS_LOWER = re.compile(r"[a-z]")
_HAS_UPPER = re.compile(r"[A-Z]")
_HAS_DIGIT = re.compile(r"\d")
_HAS_SPECIAL = re.compile(r"[^A-Za-z0-9]")


def validate_password_policy(password: str) -> str:
    pwd = str(password or "")
    if not pwd:
        raise ApiError("BAD_REQUEST", "Missing password", http_status=400)
    if len(pwd) < 12:
        raise ApiError("BAD_REQUEST", "Password must be at least 12 characters", http_status=400)
    if len(pwd) > 256:
        raise ApiError("BAD_REQUEST", "Password is too long", http_status=400)
    if not _HAS_LOWER.search(pwd) or not _HAS_UPPER.search(pwd) or not _HAS_DIGIT.search(pwd) or not _HAS_SPECIAL.search(pwd):
        raise ApiError(
            "BAD_REQUEST",
            "Password must include uppercase, lowercase, number, and special character",
            http_status=400,
        )
    return pwd


def hash_password(password: str) -> str:
    pwd = validate_password_policy(password)
    # Werkzeug 3 defaults to scrypt; pin explicitly for stability.
    return generate_password_hash(pwd, method="scrypt", salt_length=16)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return check_password_hash(str(password_hash or ""), str(password or ""))
    except Exception:
        return False

