from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select

from models import SLAConfig
from utils import parse_datetime_maybe, to_iso_utc


@dataclass(frozen=True)
class SlaState:
    stepName: str
    plannedMinutes: int
    startAt: str
    deadlineAt: str
    remainingSeconds: Optional[int]
    status: str


def normalize_step_name(step_name: str) -> str:
    return str(step_name or "").upper().strip().replace(" ", "_")


def get_sla_planned_minutes(db, step_name: str) -> int:
    step_u = normalize_step_name(step_name)
    if not step_u:
        return 0
    row = db.execute(select(SLAConfig).where(SLAConfig.stepName == step_u)).scalar_one_or_none()
    if not row:
        return 0
    if not bool(getattr(row, "enabled", True)):
        return 0
    try:
        planned = int(getattr(row, "plannedMinutes", 0) or 0)
    except Exception:
        planned = 0
    return max(0, planned)


def compute_sla(
    db,
    *,
    step_name: str,
    start_ts: str,
    app_timezone: str,
    now: Optional[datetime] = None,
    due_soon_seconds: int = 600,
) -> dict:
    step_u = normalize_step_name(step_name)
    planned = int(get_sla_planned_minutes(db, step_u) or 0)

    start_dt = parse_datetime_maybe(start_ts, app_timezone=app_timezone) if start_ts else None
    if not start_dt or planned <= 0:
        return {
            "stepName": step_u,
            "plannedMinutes": planned,
            "startAt": to_iso_utc(start_dt) if start_dt else "",
            "deadlineAt": "",
            "remainingSeconds": None,
            "status": "ON_TIME",
        }

    deadline_dt = start_dt + timedelta(minutes=planned)
    now_dt = now or datetime.now(timezone.utc)
    remaining = int((deadline_dt - now_dt).total_seconds())

    if remaining <= 0:
        status = "OVERDUE"
    elif remaining <= int(due_soon_seconds or 0):
        status = "DUE_SOON"
    else:
        status = "ON_TIME"

    return {
        "stepName": step_u,
        "plannedMinutes": planned,
        "startAt": to_iso_utc(start_dt),
        "deadlineAt": to_iso_utc(deadline_dt),
        "remainingSeconds": remaining,
        "status": status,
    }
