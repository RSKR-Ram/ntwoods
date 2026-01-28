from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

from flask import request

from app.utils.errors import ApiError

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def require_json() -> dict[str, Any]:
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise ApiError("BAD_REQUEST", "JSON body must be an object", status=400)
    return body


def validate_email(value: Any) -> str:
    email = str(value or "").strip().lower()
    if not email or not _EMAIL_RE.match(email):
        raise ApiError("BAD_REQUEST", "Invalid email", status=400)
    return email


def validate_password(value: Any, *, allow_short: bool) -> str:
    password = str(value or "")
    if not password:
        raise ApiError("BAD_REQUEST", "Password required", status=400)
    if not allow_short and len(password) < 8:
        raise ApiError("BAD_REQUEST", "Password must be at least 8 characters", status=400)
    return password


def _parse_yyyy_mm_dd(value: str) -> datetime:
    try:
        dt = datetime.strptime(value, "%Y-%m-%d")
    except Exception as e:
        raise ApiError("BAD_REQUEST", "Date must be YYYY-MM-DD", status=400) from e
    return dt.replace(tzinfo=timezone.utc)


def parse_date_range(args) -> tuple[datetime, datetime, str, str]:
    from_s = str(args.get("from") or "").strip()
    to_s = str(args.get("to") or "").strip()
    if not from_s or not to_s:
        raise ApiError("BAD_REQUEST", "from and to are required (YYYY-MM-DD)", status=400)

    start_dt = _parse_yyyy_mm_dd(from_s)
    end_dt = _parse_yyyy_mm_dd(to_s) + timedelta(days=1)
    if end_dt <= start_dt:
        raise ApiError("BAD_REQUEST", "Invalid date range", status=400)
    return start_dt, end_dt, from_s, to_s
