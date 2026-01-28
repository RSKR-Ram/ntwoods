from __future__ import annotations

from typing import Any

from sqlalchemy import select

from actions.metrics_repo import normalize_step_name
from cache_layer import cache_invalidate_prefix, cache_get, cache_set, make_cache_key
from models import SLAConfig, StepMetric
from utils import ApiError, AuthContext


def sla_config_get(data, auth: AuthContext | None, db, cfg):
    key = make_cache_key(
        "SLA_CONFIG_GET",
        scope=[str(getattr(auth, "userId", "") or ""), str(getattr(auth, "role", "") or "")],
    )
    cached = cache_get(key)
    if cached is not None:
        return cached

    rows = db.execute(select(SLAConfig)).scalars().all()
    items: list[dict[str, Any]] = []
    for r in rows:
        items.append(
            {
                "stepName": r.stepName,
                "plannedMinutes": int(r.plannedMinutes or 0),
                "enabled": bool(r.enabled),
                "updatedAt": r.updatedAt or "",
                "updatedBy": r.updatedBy or "",
            }
        )
    items.sort(key=lambda x: str(x.get("stepName") or ""))
    out = {"items": items}
    cache_set(key, out)
    return out


def sla_config_upsert(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    raw_items = (data or {}).get("items") or []
    if not isinstance(raw_items, list) or not raw_items:
        raise ApiError("BAD_REQUEST", "Missing items")

    from utils import iso_utc_now

    now = iso_utc_now()
    updated = 0
    for it in raw_items:
        if not isinstance(it, dict):
            continue
        step = normalize_step_name(str(it.get("stepName") or ""))
        if not step:
            continue
        try:
            planned = int(it.get("plannedMinutes") or 0)
        except Exception:
            planned = 0
        enabled = bool(it.get("enabled", True))

        row = db.execute(select(SLAConfig).where(SLAConfig.stepName == step)).scalar_one_or_none()
        if not row:
            row = SLAConfig(stepName=step, plannedMinutes=max(0, planned), enabled=enabled, updatedAt="", updatedBy="")
            db.add(row)
        else:
            row.plannedMinutes = max(0, planned)
            row.enabled = enabled

        row.updatedAt = now
        row.updatedBy = str(auth.userId or auth.email or "")
        updated += 1

    cache_invalidate_prefix("SLA_CONFIG_GET:")
    return {"updated": updated}


def step_metrics_query(data, auth: AuthContext | None, db, cfg):
    step_name = normalize_step_name(str((data or {}).get("stepName") or ""))
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    date_from = str((data or {}).get("dateFrom") or "").strip()
    date_to = str((data or {}).get("dateTo") or "").strip()

    q = select(StepMetric)
    if step_name:
        q = q.where(StepMetric.stepName == step_name)
    if requirement_id:
        q = q.where(StepMetric.requirementId == requirement_id)
    if candidate_id:
        q = q.where(StepMetric.candidateId == candidate_id)
    if date_from:
        q = q.where(StepMetric.createdAt >= date_from)
    if date_to:
        q = q.where(StepMetric.createdAt <= date_to)

    rows = db.execute(q.order_by(StepMetric.createdAt.desc())).scalars().all()
    items: list[dict[str, Any]] = []
    for r in rows:
        items.append(
            {
                "id": r.id,
                "requirementId": r.requirementId or "",
                "candidateId": r.candidateId or "",
                "stepName": r.stepName or "",
                "plannedMinutes": int(r.plannedMinutes or 0),
                "startTs": r.startTs or "",
                "endTs": r.endTs or "",
                "actualMinutes": int(r.actualMinutes or 0) if r.actualMinutes is not None else None,
                "breached": bool(r.breached),
                "actorUserId": r.actorUserId or "",
                "actorRole": r.actorRole or "",
                "createdAt": r.createdAt or "",
            }
        )
    return {"items": items, "total": len(items)}
