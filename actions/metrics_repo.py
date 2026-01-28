from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select

from models import SLAConfig, StepMetric
from utils import AuthContext, iso_utc_now, parse_datetime_maybe


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
        v = int(getattr(row, "plannedMinutes", 0) or 0)
    except Exception:
        v = 0
    return max(0, v)


def _ceil_minutes(delta: timedelta) -> int:
    secs = int(delta.total_seconds())
    if secs <= 0:
        return 0
    return int((secs + 59) // 60)


def record_step_metric(
    db,
    *,
    requirement_id: str,
    candidate_id: str,
    step_name: str,
    start_ts: str,
    end_ts: str,
    actor: AuthContext | None,
) -> None:
    step_u = normalize_step_name(step_name)
    if not step_u:
        return

    start_dt = parse_datetime_maybe(start_ts, app_timezone="UTC") if start_ts else None
    end_dt = parse_datetime_maybe(end_ts, app_timezone="UTC") if end_ts else None
    if not end_dt:
        end_ts = iso_utc_now()
        end_dt = parse_datetime_maybe(end_ts, app_timezone="UTC")
    if not start_dt:
        start_dt = end_dt
        start_ts = end_ts

    planned = get_sla_planned_minutes(db, step_u)
    actual = _ceil_minutes(end_dt - start_dt) if start_dt and end_dt else 0
    breached = bool(planned > 0 and actual > planned)

    now = iso_utc_now()
    db.add(
        StepMetric(
            requirementId=str(requirement_id or ""),
            candidateId=str(candidate_id or ""),
            stepName=step_u,
            plannedMinutes=int(planned or 0),
            startTs=str(start_ts or ""),
            endTs=str(end_ts or ""),
            actualMinutes=int(actual or 0),
            breached=bool(breached),
            actorUserId=str(actor.userId if actor else "SYSTEM"),
            actorRole=str(actor.role if actor else "SYSTEM"),
            createdAt=now,
        )
    )

