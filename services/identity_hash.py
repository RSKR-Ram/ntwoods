from __future__ import annotations

import re
from typing import Any

from utils import ApiError, sha256_hex


_AADHAAR_DIGITS_RE = re.compile(r"\d+")


def parse_date_yyyy_mm_dd(value: Any) -> str:
    s = str(value or "").strip()
    if not s:
        return ""
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
        return s
    try:
        from dateutil import parser as dt_parser  # type: ignore

        dt = dt_parser.parse(s)
        return dt.date().isoformat()
    except Exception:
        return ""


def normalize_aadhaar(value: Any) -> str:
    s = str(value or "").strip()
    if not s:
        return ""
    digits = "".join(_AADHAAR_DIGITS_RE.findall(s))
    return digits


def aadhaar_last4(value: Any) -> str:
    a = normalize_aadhaar(value)
    if len(a) < 4:
        return ""
    return a[-4:]


def aadhaar_dob_hash(*, aadhaar: Any, dob: Any, salt: str) -> str:
    a = normalize_aadhaar(aadhaar)
    d = parse_date_yyyy_mm_dd(dob)
    if not a or len(a) != 12:
        raise ApiError("BAD_REQUEST", "Invalid Aadhaar (expected 12 digits)")
    if not d:
        raise ApiError("BAD_REQUEST", "Invalid dob (expected YYYY-MM-DD)")
    if not str(salt or "").strip():
        raise ApiError("INTERNAL", "Missing server salt for identity hashing")
    return sha256_hex(f"{a}|{d}|{str(salt).strip()}")

