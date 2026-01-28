from __future__ import annotations

import json
import re
from typing import Any

from sqlalchemy import and_, delete, func, or_, select

from actions.helpers import append_audit
from auth import assert_permission
from models import (
    AuditLog,
    AtsStage,
    Candidate,
    CandidateActivity,
    CandidateNote,
    CandidateTag,
    CandidateTagMap,
    Requirement,
)
from pii import decrypt_pii, looks_like_sha256_hex, mask_name, mask_phone
from sla import compute_sla
from utils import ApiError, AuthContext, iso_utc_now, new_uuid, normalize_role, parse_datetime_maybe, parse_roles_csv, safe_json_string, to_iso_utc


def _clamp_int(value: Any, *, default: int, min_v: int, max_v: int) -> int:
    try:
        n = int(value)
    except Exception:
        n = int(default)
    return max(int(min_v), min(int(max_v), n))


def _parse_filters(data: dict[str, Any]) -> dict[str, str]:
    raw = (data or {}).get("filters") or {}
    if not isinstance(raw, dict):
        raw = {}

    job_role = str(raw.get("jobRole") or "").strip()
    requirement_id = str(raw.get("requirementId") or "").strip()
    source = str(raw.get("source") or "").strip()
    q = str(raw.get("q") or "").strip()
    return {"jobRole": job_role, "requirementId": requirement_id, "source": source, "q": q}


def _parse_options(data: dict[str, Any]) -> dict[str, Any]:
    raw = (data or {}).get("options") or {}
    if not isinstance(raw, dict):
        raw = {}
    limit = _clamp_int(raw.get("limitPerColumn"), default=50, min_v=1, max_v=200)
    include_counts = bool(raw.get("includeCounts", True))
    include_items = bool(raw.get("includeItems", True))
    return {"limitPerColumn": limit, "includeCounts": include_counts, "includeItems": include_items}


def _apply_filters_to_items(items: list[dict[str, Any]], *, filters: dict[str, str]) -> list[dict[str, Any]]:
    requirement_id = str(filters.get("requirementId") or "").strip()
    job_role = str(filters.get("jobRole") or "").strip()
    source = str(filters.get("source") or "").strip().lower()
    q = str(filters.get("q") or "").strip().lower()

    def _match(it: dict[str, Any]) -> bool:
        if requirement_id and str(it.get("requirementId") or "").strip() != requirement_id:
            return False
        if job_role and str(it.get("jobRole") or "").strip() != job_role:
            return False
        if source and source not in str(it.get("source") or "").lower():
            return False
        if q:
            hay = " ".join(
                [
                    str(it.get("candidateId") or ""),
                    str(it.get("candidateName") or ""),
                    str(it.get("mobile") or ""),
                    str(it.get("jobRole") or ""),
                    str(it.get("jobTitle") or ""),
                ]
            ).lower()
            if q not in hay:
                return False
        return True

    return [it for it in (items or []) if isinstance(it, dict) and _match(it)]


def _fill_candidate_fields(db, items: list[dict[str, Any]]) -> None:
    """
    ATS Board needs consistent card fields across columns.

    Some legacy list actions don't include `source` / `status` / `updatedAt` / `updatedBy`,
    so we enrich in one bulk query to avoid N+1 queries.
    """

    ids = [str(it.get("candidateId") or "").strip() for it in (items or []) if isinstance(it, dict)]
    ids = [x for x in ids if x]
    if not ids:
        return

    rows = db.execute(
        select(
            Candidate.candidateId,
            Candidate.status,
            Candidate.source,
            Candidate.updatedAt,
            Candidate.updatedBy,
        ).where(Candidate.candidateId.in_(ids))
    ).all()
    mp = {
        str(cid): {
            "status": str(st or ""),
            "source": str(src or ""),
            "updatedAt": str(uat or ""),
            "updatedBy": str(uby or ""),
        }
        for (cid, st, src, uat, uby) in rows
        if str(cid or "").strip()
    }

    for it in items:
        cid = str(it.get("candidateId") or "").strip()
        if not cid:
            continue
        extra = mp.get(cid) or {}
        if "status" not in it or not str(it.get("status") or "").strip():
            it["status"] = extra.get("status", "")
        if "source" not in it or not str(it.get("source") or "").strip():
            it["source"] = extra.get("source", "")
        if "updatedAt" not in it or not str(it.get("updatedAt") or "").strip():
            it["updatedAt"] = extra.get("updatedAt", "")
        if "updatedBy" not in it or not str(it.get("updatedBy") or "").strip():
            it["updatedBy"] = extra.get("updatedBy", "")


def _fetch_simple_column(
    db,
    cfg,
    *,
    statuses: set[str],
    filters: dict[str, str],
    limit: int,
    include_items: bool,
    include_counts: bool,
    sla_step: str | None,
    sla_start_field: str,
) -> dict[str, Any]:
    statuses_u = {str(s or "").upper().strip() for s in (statuses or set()) if str(s or "").strip()}
    statuses_u = statuses_u or set()

    requirement_id = str(filters.get("requirementId") or "").strip()
    job_role = str(filters.get("jobRole") or "").strip()
    source = str(filters.get("source") or "").strip()
    q = str(filters.get("q") or "").strip()

    base = select(Candidate, Requirement.jobTitle).join(
        Requirement, Requirement.requirementId == Candidate.requirementId, isouter=True
    )
    if statuses_u:
        base = base.where(func.upper(Candidate.status).in_(sorted(statuses_u)))
    if requirement_id:
        base = base.where(Candidate.requirementId == requirement_id)
    if job_role:
        base = base.where(Candidate.jobRole == job_role)
    if source:
        base = base.where(Candidate.source.ilike(f"%{source}%"))
    if q:
        like = f"%{q}%"
        base = base.where(
            or_(
                Candidate.candidateId.ilike(like),
                Candidate.candidateName.ilike(like),
                Candidate.mobile.ilike(like),
                Candidate.jobRole.ilike(like),
                Requirement.jobTitle.ilike(like),
            )
        )

    total = 0
    if include_counts:
        total = int(db.execute(select(func.count()).select_from(base.subquery())).scalar_one() or 0)

    items: list[dict[str, Any]] = []
    if include_items:
        rows = (
            db.execute(
                base.order_by(Candidate.updatedAt.desc(), Candidate.createdAt.desc()).limit(int(limit or 50))
            )
            .all()
        )
        for cand, job_title in rows:
            start_ts = ""
            if sla_start_field == "createdAt":
                start_ts = str(getattr(cand, "createdAt", "") or getattr(cand, "updatedAt", "") or "")
            elif sla_start_field == "updatedAt":
                start_ts = str(getattr(cand, "updatedAt", "") or getattr(cand, "createdAt", "") or "")
            else:
                start_ts = str(getattr(cand, "updatedAt", "") or getattr(cand, "createdAt", "") or "")

            item = {
                "candidateId": str(cand.candidateId or ""),
                "requirementId": str(cand.requirementId or ""),
                "jobRole": str(cand.jobRole or ""),
                "jobTitle": str(job_title or ""),
                "candidateName": str(cand.candidateName or ""),
                "mobile": str(cand.mobile or ""),
                "source": str(cand.source or ""),
                "status": str(cand.status or ""),
                "updatedAt": str(cand.updatedAt or ""),
                "updatedBy": str(cand.updatedBy or ""),
                "cvFileId": str(cand.cvFileId or ""),
                "cvFileName": str(cand.cvFileName or ""),
            }
            if sla_step:
                item["sla"] = compute_sla(db, step_name=sla_step, start_ts=start_ts, app_timezone=cfg.APP_TIMEZONE)
            items.append(item)

    if not include_counts:
        total = len(items)
    return {"total": total, "items": items}


def ats_board_get(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    filters = _parse_filters(data or {})
    options = _parse_options(data or {})
    limit = int(options["limitPerColumn"])
    include_items = bool(options["includeItems"])
    include_counts = bool(options["includeCounts"])

    # Reuse existing list handlers for pipeline-heavy columns so ATS stays consistent with
    # the rest of HRMS business rules (and avoids duplicating fragile stage eligibility logic).
    from actions.pipeline import (
        final_interview_list,
        hr_final_hold_list,
        inperson_pipeline_list,
        joining_list,
        precall_list,
        probation_list,
        tech_pending_list,
    )

    generated_at = iso_utc_now()

    columns: list[dict[str, Any]] = []

    # Early-stage columns (no dedicated list action yet).
    simple_defs = [
        ("SHORTLISTING", "Shortlisting", {"NEW"}, "SHORTLISTING", "createdAt"),
        ("HOLD", "Hold", {"HOLD"}, None, "updatedAt"),
        ("OWNER", "Owner Approval", {"OWNER", "OWNER_HOLD"}, "OWNER_APPROVAL", "updatedAt"),
        ("WALKIN_PENDING", "Walk-in Pending", {"WALKIN_PENDING"}, "WALKIN_SCHEDULE", "updatedAt"),
    ]
    for key, title, statuses, sla_step, sla_start_field in simple_defs:
        res = _fetch_simple_column(
            db,
            cfg,
            statuses=set(statuses),
            filters=filters,
            limit=limit,
            include_items=include_items,
            include_counts=include_counts,
            sla_step=sla_step,
            sla_start_field=sla_start_field,
        )
        columns.append({"key": key, "title": title, "total": int(res["total"]), "items": res["items"]})

    # Pipeline columns (existing list actions).
    job_role = str(filters.get("jobRole") or "").strip()
    precall_items = (precall_list({"jobRole": job_role, "date": "", "countOnly": False, "mode": ""}, auth, db, cfg) or {}).get("items") or []
    preinterview_items = (
        (precall_list({"jobRole": job_role, "date": "", "countOnly": False, "mode": "PREINTERVIEW"}, auth, db, cfg) or {}).get("items")
        or []
    )
    inperson_items = (
        (inperson_pipeline_list({"jobRole": job_role, "countOnly": False}, auth, db, cfg) or {}).get("items") or []
    )
    technical_items = (tech_pending_list({"countOnly": False}, auth, db, cfg) or {}).get("items") or []
    final_items = (final_interview_list({"countOnly": False}, auth, db, cfg) or {}).get("items") or []
    final_hold_items = (hr_final_hold_list({"countOnly": False}, auth, db, cfg) or {}).get("items") or []
    joining_items = (joining_list({"countOnly": False}, auth, db, cfg) or {}).get("items") or []
    probation_items = (probation_list({"countOnly": False}, auth, db, cfg) or {}).get("items") or []

    # Enrich missing fields in a single bulk query, then apply global filters + per-column limits.
    all_pipeline_items: list[dict[str, Any]] = []
    for lst in [precall_items, preinterview_items, inperson_items, technical_items, final_items, final_hold_items, joining_items, probation_items]:
        all_pipeline_items.extend([it for it in lst if isinstance(it, dict)])
    _fill_candidate_fields(db, all_pipeline_items)

    def _finalize_column(items: list[dict[str, Any]]) -> tuple[int, list[dict[str, Any]]]:
        filtered = _apply_filters_to_items(items, filters=filters)
        filtered.sort(key=lambda x: str(x.get("updatedAt") or ""), reverse=True)
        total = len(filtered) if include_counts else 0
        out_items = filtered[:limit] if include_items else []
        if not include_counts:
            total = len(out_items)
        return total, out_items

    tot, out_items = _finalize_column(precall_items)
    columns.append({"key": "PRECALL", "title": "Pre-call", "total": int(tot), "items": out_items})

    tot, out_items = _finalize_column(preinterview_items)
    columns.append({"key": "PRE_INTERVIEW", "title": "Pre-interview", "total": int(tot), "items": out_items})

    tot, out_items = _finalize_column(inperson_items)
    columns.append({"key": "IN_PERSON", "title": "In-person", "total": int(tot), "items": out_items})

    tot, out_items = _finalize_column(technical_items)
    columns.append({"key": "TECHNICAL", "title": "Technical", "total": int(tot), "items": out_items})

    tot, out_items = _finalize_column(final_items)
    columns.append({"key": "FINAL_INTERVIEW", "title": "Final Interview", "total": int(tot), "items": out_items})

    tot, out_items = _finalize_column(final_hold_items)
    columns.append({"key": "FINAL_HOLD", "title": "Final Hold", "total": int(tot), "items": out_items})

    tot, out_items = _finalize_column(joining_items)
    columns.append({"key": "JOINING", "title": "Joining", "total": int(tot), "items": out_items})

    tot, out_items = _finalize_column(probation_items)
    columns.append({"key": "PROBATION", "title": "Probation", "total": int(tot), "items": out_items})

    return {"columns": columns, "generatedAt": generated_at}


def ats_candidate_move(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    to = str((data or {}).get("to") or "").upper().strip()
    remark = str((data or {}).get("remark") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId", http_status=400)
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId", http_status=400)
    if not to:
        raise ApiError("BAD_REQUEST", "Missing to", http_status=400)
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    # Resolve current status (for audit + safety checks).
    cand = db.execute(
        select(Candidate).where(Candidate.candidateId == candidate_id).where(Candidate.requirementId == requirement_id)
    ).scalar_one_or_none()
    if not cand:
        raise ApiError("NOT_FOUND", "Candidate not found", http_status=404)
    from_status = str(cand.status or "").upper().strip()

    # Safe-move mapping to existing actions (no bypassing).
    mapped_action = ""
    handler = None
    handler_data: dict[str, Any] = {"requirementId": requirement_id, "candidateId": candidate_id}

    # Import lazily to avoid heavy module import cost on ATS board reads.
    from actions.candidates import hold_revert, shortlist_decide, shortlist_hold_revert

    if to == "HOLD":
        # NEW -> HOLD (remark required)
        if from_status != "NEW":
            raise ApiError("BAD_REQUEST", "Only NEW candidates can be moved to HOLD", http_status=400)
        if not remark:
            raise ApiError("BAD_REQUEST", "Remark required", http_status=400)
        mapped_action = "SHORTLIST_DECIDE"
        assert_permission(db, normalize_role(auth.role) or "", mapped_action)
        handler = shortlist_decide
        handler_data.update({"decision": "HOLD", "remark": remark})
    elif to == "OWNER":
        # NEW -> OWNER
        if from_status != "NEW":
            raise ApiError("BAD_REQUEST", "Only NEW candidates can be sent to OWNER", http_status=400)
        mapped_action = "SHORTLIST_DECIDE"
        assert_permission(db, normalize_role(auth.role) or "", mapped_action)
        handler = shortlist_decide
        handler_data.update({"decision": "OWNER_SEND", "remark": ""})
    elif to == "SHORTLISTING":
        # HOLD -> SHORTLISTING (revert hold)
        if from_status != "HOLD":
            raise ApiError("BAD_REQUEST", "Only HOLD candidates can be reverted to SHORTLISTING", http_status=400)
        mapped_action = "SHORTLIST_HOLD_REVERT"
        assert_permission(db, normalize_role(auth.role) or "", mapped_action)
        handler = shortlist_hold_revert
        handler_data.update({"remark": remark})
    elif to == "OWNER_REVERT":
        # OWNER_HOLD -> OWNER (revert owner hold)
        if from_status != "OWNER_HOLD":
            raise ApiError("BAD_REQUEST", "Only OWNER_HOLD candidates can be reverted to OWNER", http_status=400)
        mapped_action = "HOLD_REVERT"
        assert_permission(db, normalize_role(auth.role) or "", mapped_action)
        handler = hold_revert
        handler_data.update({"remark": remark})
    else:
        raise ApiError("BAD_REQUEST", "Invalid to", http_status=400)

    if not handler:
        raise ApiError("INTERNAL", "Move handler not configured", http_status=500)

    res = handler(handler_data, auth, db, cfg) or {}
    to_status = str(res.get("status") or "").upper().strip() or to

    # ATS move audit (additive, enterprise timeline).
    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="ATS_MOVE",
        fromState=from_status,
        toState=to_status,
        stageTag="ATS_MOVE",
        remark=remark or "",
        actor=auth,
        at=iso_utc_now(),
        meta={"requirementId": requirement_id, "mappedAction": mapped_action, "to": to},
    )

    return {"ok": True, "status": to_status}


def ats_note_add(data, auth: AuthContext | None, db, cfg):
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    note_text = str((data or {}).get("noteText") or "").strip()

    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId", http_status=400)
    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId", http_status=400)
    if not note_text:
        raise ApiError("BAD_REQUEST", "Missing noteText", http_status=400)
    if len(note_text) > 2000:
        raise ApiError("BAD_REQUEST", "Note is too long", http_status=400)
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="ATS_NOTE_ADD",
        stageTag="ATS_NOTE",
        remark=note_text,
        actor=auth,
        at=iso_utc_now(),
        meta={"requirementId": requirement_id},
    )

    return {"ok": True}


def ats_note_list(data, auth: AuthContext | None, db, cfg):
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    limit = _clamp_int((data or {}).get("limit"), default=50, min_v=1, max_v=200)

    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId", http_status=400)
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    actions = ["ATS_NOTE_ADD", "ATS_ASSIGN_SET", "ATS_MOVE"]

    total = int(
        db.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.entityType == "CANDIDATE")
            .where(AuditLog.entityId == candidate_id)
            .where(AuditLog.action.in_(actions))
        ).scalar_one()
        or 0
    )

    rows = (
        db.execute(
            select(AuditLog)
            .where(AuditLog.entityType == "CANDIDATE")
            .where(AuditLog.entityId == candidate_id)
            .where(AuditLog.action.in_(actions))
            .order_by(AuditLog.at.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )

    items = []
    for r in rows:
        meta = {}
        raw = str(getattr(r, "metaJson", "") or "").strip()
        if raw:
            try:
                obj = json.loads(raw)
                if isinstance(obj, dict):
                    meta = obj
            except Exception:
                meta = {}
        items.append(
            {
                "at": str(getattr(r, "at", "") or ""),
                "actorRole": str(getattr(r, "actorRole", "") or ""),
                "actorEmail": str(getattr(r, "actorEmail", "") or ""),
                "action": str(getattr(r, "action", "") or ""),
                "fromState": str(getattr(r, "fromState", "") or ""),
                "toState": str(getattr(r, "toState", "") or ""),
                "remark": str(getattr(r, "remark", "") or ""),
                "meta": meta,
            }
        )

    return {"items": items, "total": total}


def ats_assign_set(data, auth: AuthContext | None, db, cfg):
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    assignee_user_id = str((data or {}).get("assigneeUserId") or "").strip()
    assignee_email = str((data or {}).get("assigneeEmail") or "").strip()
    assignee_name = str((data or {}).get("assigneeName") or "").strip()

    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId", http_status=400)
    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId", http_status=400)
    if not (assignee_user_id or assignee_email or assignee_name):
        raise ApiError("BAD_REQUEST", "Missing assignee fields", http_status=400)
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="ATS_ASSIGN_SET",
        stageTag="ATS_ASSIGN",
        remark="",
        actor=auth,
        at=iso_utc_now(),
        meta={
            "requirementId": requirement_id,
            "assigneeUserId": assignee_user_id,
            "assigneeEmail": assignee_email,
            "assigneeName": assignee_name,
        },
    )
    return {"ok": True}


def ats_assign_get(data, auth: AuthContext | None, db, cfg):
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId", http_status=400)
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    row = (
        db.execute(
            select(AuditLog)
            .where(AuditLog.entityType == "CANDIDATE")
            .where(AuditLog.entityId == candidate_id)
            .where(AuditLog.action == "ATS_ASSIGN_SET")
            .order_by(AuditLog.at.desc())
            .limit(1)
        )
        .scalars()
        .first()
    )
    if not row:
        return {"assignment": None}

    meta = {}
    raw = str(getattr(row, "metaJson", "") or "").strip()
    if raw:
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                meta = obj
        except Exception:
            meta = {}

    return {
        "assignment": {
            "at": str(getattr(row, "at", "") or ""),
            "actorRole": str(getattr(row, "actorRole", "") or ""),
            "actorEmail": str(getattr(row, "actorEmail", "") or ""),
            "meta": meta,
        }
    }


def _norm_stage_key(value: Any) -> str:
    return str(value or "").strip().upper().replace(" ", "_")


def ats_stage_list(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    rows = (
        db.execute(select(AtsStage).where(AtsStage.isActive == True).order_by(AtsStage.orderNo.asc(), AtsStage.stageName.asc()))  # noqa: E712
        .scalars()
        .all()
    )

    items = []
    for r in rows:
        items.append(
            {
                "stageId": str(r.stageId or ""),
                "stageKey": str(r.stageKey or ""),
                "stageName": str(r.stageName or ""),
                "orderNo": int(r.orderNo or 0),
                "color": str(r.color or ""),
                "isActive": bool(r.isActive),
                "rolesCsv": str(r.rolesCsv or ""),
                "updatedAt": str(r.updatedAt or ""),
                "updatedBy": str(r.updatedBy or ""),
            }
        )
    return {"items": items}


def ats_stage_upsert(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")
    if normalize_role(auth.role) != "ADMIN":
        raise ApiError("FORBIDDEN", "Admin only", http_status=403)

    stage_id = str((data or {}).get("stageId") or "").strip()
    stage_key = _norm_stage_key((data or {}).get("stageKey") or "")
    stage_name = str((data or {}).get("stageName") or "").strip()
    color = str((data or {}).get("color") or "").strip()
    roles_csv = str((data or {}).get("rolesCsv") or "").strip()

    if not stage_key:
        raise ApiError("BAD_REQUEST", "Missing stageKey", http_status=400)
    if not stage_name:
        stage_name = stage_key.replace("_", " ").title()

    try:
        order_no = int((data or {}).get("orderNo") or 0)
    except Exception:
        raise ApiError("BAD_REQUEST", "Invalid orderNo", http_status=400)

    is_active = True
    if isinstance((data or {}).get("isActive"), bool):
        is_active = bool((data or {}).get("isActive"))

    now = iso_utc_now()
    actor = str(auth.userId or auth.email or "")

    row = None
    if stage_id:
        row = db.execute(select(AtsStage).where(AtsStage.stageId == stage_id)).scalar_one_or_none()
    if not row:
        row = db.execute(select(AtsStage).where(AtsStage.stageKey == stage_key)).scalar_one_or_none()

    created = False
    if not row:
        created = True
        stage_id = stage_id or f"ATSSTG-{new_uuid()}"
        row = AtsStage(
            stageId=stage_id,
            stageKey=stage_key,
            stageName=stage_name,
            orderNo=int(order_no or 0),
            color=color,
            isActive=bool(is_active),
            rolesCsv=roles_csv,
            createdAt=now,
            createdBy=actor,
            updatedAt=now,
            updatedBy=actor,
        )
        db.add(row)
    else:
        row.stageKey = stage_key
        row.stageName = stage_name
        row.orderNo = int(order_no or 0)
        row.color = color
        row.isActive = bool(is_active)
        row.rolesCsv = roles_csv
        row.updatedAt = now
        row.updatedBy = actor

    append_audit(
        db,
        entityType="ATS_STAGE",
        entityId=str(stage_id or ""),
        action="ATS_STAGE_UPSERT",
        stageTag="ATS_STAGE_UPSERT",
        actor=auth,
        at=now,
        meta={
            "mode": "create" if created else "update",
            "stageKey": stage_key,
            "stageName": stage_name,
            "orderNo": int(order_no or 0),
            "isActive": bool(is_active),
        },
    )

    return {
        "stage": {
            "stageId": str(stage_id or ""),
            "stageKey": stage_key,
            "stageName": stage_name,
            "orderNo": int(order_no or 0),
            "color": color,
            "isActive": bool(is_active),
            "rolesCsv": roles_csv,
        }
    }


def candidate_stage_set(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    candidate_id = str((data or {}).get("candidateId") or "").strip()
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    stage_key = _norm_stage_key((data or {}).get("stageKey") or "")
    remark = str((data or {}).get("remark") or "").strip()

    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId", http_status=400)
    if not stage_key:
        raise ApiError("BAD_REQUEST", "Missing stageKey", http_status=400)

    stage = db.execute(select(AtsStage).where(AtsStage.stageKey == stage_key).where(AtsStage.isActive == True)).scalar_one_or_none()  # noqa: E712
    if not stage:
        raise ApiError("NOT_FOUND", "Stage not found", http_status=404)

    allowed_roles = parse_roles_csv(getattr(stage, "rolesCsv", "") or "")
    role_u = normalize_role(auth.role) or ""

    if role_u != "ADMIN":
        if allowed_roles:
            if role_u not in allowed_roles:
                raise ApiError("FORBIDDEN", "Not allowed for this stage", http_status=403)
        elif role_u not in {"HR", "EA", "OWNER"}:
            raise ApiError("FORBIDDEN", "Not allowed", http_status=403)

    cand_q = select(Candidate).where(Candidate.candidateId == candidate_id)
    if requirement_id:
        cand_q = cand_q.where(Candidate.requirementId == requirement_id)
    cand = db.execute(cand_q).scalar_one_or_none()
    if not cand:
        raise ApiError("NOT_FOUND", "Candidate not found", http_status=404)

    now = iso_utc_now()
    from_stage = str(getattr(cand, "candidateStage", "") or getattr(cand, "status", "") or "").upper().strip()
    if not from_stage:
        from_stage = str(getattr(cand, "status", "") or "").upper().strip()

    # Use update_candidate to keep updatedAt/updatedBy consistent across the app.
    from actions.candidate_repo import update_candidate

    update_candidate(db, cand=cand, patch={"candidateStage": stage_key, "stageUpdatedAt": now}, auth=auth)

    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="CANDIDATE_STAGE_SET",
        fromState=from_stage,
        toState=stage_key,
        stageTag="ATS_STAGE_SET",
        remark=remark or "",
        actor=auth,
        at=now,
        meta={"requirementId": str(getattr(cand, "requirementId", "") or ""), "stageKey": stage_key},
    )

    payload = {"from": from_stage, "to": stage_key, "remark": remark or "", "stageId": str(getattr(stage, "stageId", "") or "")}
    db.add(
        CandidateActivity(
            activityId=f"ACT-{new_uuid()}",
            candidateId=str(getattr(cand, "candidateId", "") or ""),
            requirementId=str(getattr(cand, "requirementId", "") or ""),
            type="SYSTEM",
            payloadJson=safe_json_string(payload, "{}"),
            at=now,
            actorUserId=str(auth.userId or ""),
            actorRole=str(auth.role or ""),
        )
    )

    return {"ok": True, "candidateId": str(getattr(cand, "candidateId", "") or ""), "stageKey": stage_key, "stageUpdatedAt": now}


def candidate_note_add(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    candidate_id = str((data or {}).get("candidateId") or "").strip()
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    note_text = str((data or {}).get("noteText") or "").strip()
    visibility = str((data or {}).get("visibility") or "INTERNAL").upper().strip() or "INTERNAL"

    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId", http_status=400)
    if not note_text:
        raise ApiError("BAD_REQUEST", "Missing noteText", http_status=400)
    if len(note_text) > 2000:
        raise ApiError("BAD_REQUEST", "Note is too long", http_status=400)

    cand_q = select(Candidate).where(Candidate.candidateId == candidate_id)
    if requirement_id:
        cand_q = cand_q.where(Candidate.requirementId == requirement_id)
    cand = db.execute(cand_q).scalar_one_or_none()
    if not cand:
        raise ApiError("NOT_FOUND", "Candidate not found", http_status=404)

    if not requirement_id:
        requirement_id = str(getattr(cand, "requirementId", "") or "")

    now = iso_utc_now()
    note_id = f"NOTE-{new_uuid()}"

    db.add(
        CandidateNote(
            noteId=note_id,
            candidateId=candidate_id,
            requirementId=requirement_id,
            noteText=note_text,
            visibility=visibility,
            createdAt=now,
            createdBy=str(auth.userId or auth.email or ""),
        )
    )

    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="CANDIDATE_NOTE_ADD",
        stageTag="ATS_NOTE",
        remark=note_text,
        actor=auth,
        at=now,
        meta={"requirementId": requirement_id, "noteId": note_id, "visibility": visibility},
    )

    payload = {"noteId": note_id, "visibility": visibility}
    db.add(
        CandidateActivity(
            activityId=f"ACT-{new_uuid()}",
            candidateId=candidate_id,
            requirementId=requirement_id,
            type="NOTE",
            payloadJson=safe_json_string(payload, "{}"),
            at=now,
            actorUserId=str(auth.userId or ""),
            actorRole=str(auth.role or ""),
        )
    )

    return {"ok": True, "noteId": note_id}


def candidate_notes_list(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    candidate_id = str((data or {}).get("candidateId") or "").strip()
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId", http_status=400)

    limit = _clamp_int((data or {}).get("limit"), default=50, min_v=1, max_v=200)
    offset = _clamp_int((data or {}).get("offset"), default=0, min_v=0, max_v=100_000)

    total = int(db.execute(select(func.count()).select_from(CandidateNote).where(CandidateNote.candidateId == candidate_id)).scalar_one() or 0)
    rows = (
        db.execute(
            select(CandidateNote)
            .where(CandidateNote.candidateId == candidate_id)
            .order_by(CandidateNote.createdAt.desc())
            .offset(offset)
            .limit(limit)
        )
        .scalars()
        .all()
    )

    items = []
    for r in rows:
        items.append(
            {
                "noteId": str(getattr(r, "noteId", "") or ""),
                "candidateId": str(getattr(r, "candidateId", "") or ""),
                "requirementId": str(getattr(r, "requirementId", "") or ""),
                "noteText": str(getattr(r, "noteText", "") or ""),
                "visibility": str(getattr(r, "visibility", "") or ""),
                "createdAt": str(getattr(r, "createdAt", "") or ""),
                "createdBy": str(getattr(r, "createdBy", "") or ""),
            }
        )

    return {"items": items, "total": total}


def candidate_tags_set(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    candidate_id = str((data or {}).get("candidateId") or "").strip()
    tags_raw = (data or {}).get("tags") or []

    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId", http_status=400)
    if not isinstance(tags_raw, list):
        raise ApiError("BAD_REQUEST", "tags must be a list", http_status=400)

    cand = db.execute(select(Candidate).where(Candidate.candidateId == candidate_id)).scalar_one_or_none()
    if not cand:
        raise ApiError("NOT_FOUND", "Candidate not found", http_status=404)

    tags_norm: list[str] = []
    seen: set[str] = set()
    for t in tags_raw:
        s = str(t or "").strip()
        if not s:
            continue
        s = re.sub(r"\s+", " ", s)
        if len(s) > 40:
            raise ApiError("BAD_REQUEST", "Tag is too long", http_status=400)
        key = s.upper()
        if key in seen:
            continue
        seen.add(key)
        tags_norm.append(s)

    if len(tags_norm) > 25:
        raise ApiError("BAD_REQUEST", "Too many tags", http_status=400)

    existing: dict[str, CandidateTag] = {}
    if tags_norm:
        keys = [t.upper() for t in tags_norm]
        existing = {
            str(r.tagName or "").upper().strip(): r
            for r in db.execute(select(CandidateTag).where(CandidateTag.tagName.in_(keys))).scalars().all()
        }

    now = iso_utc_now()
    actor = str(auth.userId or auth.email or "")

    tag_rows: list[CandidateTag] = []
    for t in tags_norm:
        key = t.upper()
        row = existing.get(key)
        if not row:
            row = CandidateTag(tagId=f"TAG-{new_uuid()}", tagName=key, createdAt=now, createdBy=actor)
            db.add(row)
            existing[key] = row
        tag_rows.append(row)

    # Replace mapping (idempotent upsert).
    db.execute(delete(CandidateTagMap).where(CandidateTagMap.candidateId == candidate_id))
    for row in tag_rows:
        db.add(
            CandidateTagMap(
                candidateId=candidate_id,
                tagId=str(row.tagId or ""),
                createdAt=now,
                createdBy=actor,
            )
        )

    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="CANDIDATE_TAGS_SET",
        stageTag="ATS_TAGS",
        remark=", ".join([str(r.tagName or "") for r in tag_rows]),
        actor=auth,
        at=now,
        meta={"tags": [str(r.tagName or "") for r in tag_rows]},
    )

    db.add(
        CandidateActivity(
            activityId=f"ACT-{new_uuid()}",
            candidateId=candidate_id,
            requirementId=str(getattr(cand, "requirementId", "") or ""),
            type="SYSTEM",
            payloadJson=safe_json_string({"tags": [str(r.tagName or "") for r in tag_rows]}, "{}"),
            at=now,
            actorUserId=str(auth.userId or ""),
            actorRole=str(auth.role or ""),
        )
    )

    return {"ok": True, "tags": [str(r.tagName or "") for r in tag_rows]}


def candidate_tags_get(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    candidate_id = str((data or {}).get("candidateId") or "").strip()
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId", http_status=400)

    rows = (
        db.execute(
            select(CandidateTag.tagName)
            .join(CandidateTagMap, CandidateTagMap.tagId == CandidateTag.tagId)
            .where(CandidateTagMap.candidateId == candidate_id)
        )
        .scalars()
        .all()
    )
    tags = sorted({str(x or "").strip() for x in rows if str(x or "").strip()})
    return {"tags": tags}


def candidate_activity_list(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    candidate_id = str((data or {}).get("candidateId") or "").strip()
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId", http_status=400)

    limit = _clamp_int((data or {}).get("limit"), default=50, min_v=1, max_v=200)
    offset = _clamp_int((data or {}).get("offset"), default=0, min_v=0, max_v=100_000)

    total = int(db.execute(select(func.count()).select_from(CandidateActivity).where(CandidateActivity.candidateId == candidate_id)).scalar_one() or 0)
    rows = (
        db.execute(
            select(CandidateActivity)
            .where(CandidateActivity.candidateId == candidate_id)
            .order_by(CandidateActivity.at.desc())
            .offset(offset)
            .limit(limit)
        )
        .scalars()
        .all()
    )

    items = []
    for r in rows:
        payload = {}
        raw = str(getattr(r, "payloadJson", "") or "").strip()
        if raw:
            try:
                obj = json.loads(raw)
                if isinstance(obj, dict):
                    payload = obj
            except Exception:
                payload = {}

        items.append(
            {
                "activityId": str(getattr(r, "activityId", "") or ""),
                "candidateId": str(getattr(r, "candidateId", "") or ""),
                "requirementId": str(getattr(r, "requirementId", "") or ""),
                "type": str(getattr(r, "type", "") or ""),
                "payload": payload,
                "at": str(getattr(r, "at", "") or ""),
                "actorUserId": str(getattr(r, "actorUserId", "") or ""),
                "actorRole": str(getattr(r, "actorRole", "") or ""),
            }
        )

    return {"items": items, "total": total}


def candidate_search(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    def _looks_like_enc_value(value: str) -> bool:
        s = str(value or "").strip()
        return s.startswith("v1:") or s.startswith("v0:")

    filters = (data or {}).get("filters") if isinstance(data, dict) else None
    if not isinstance(filters, dict):
        filters = {}

    q = str(filters.get("q") or "").strip()
    job_role = str(filters.get("jobRole") or "").strip()
    requirement_id = str(filters.get("requirementId") or "").strip()
    status = str(filters.get("status") or "").strip().upper()
    stage_key = _norm_stage_key(filters.get("candidateStage") or filters.get("stageKey") or "")
    source = str(filters.get("source") or "").strip()

    from_raw = str(filters.get("dateFrom") or filters.get("from") or "").strip()
    to_raw = str(filters.get("dateTo") or filters.get("to") or "").strip()

    limit = _clamp_int((data or {}).get("limit"), default=50, min_v=1, max_v=200)
    offset = _clamp_int((data or {}).get("offset"), default=0, min_v=0, max_v=100_000)

    base = select(Candidate, Requirement.jobTitle).join(Requirement, Requirement.requirementId == Candidate.requirementId, isouter=True)

    if requirement_id:
        base = base.where(Candidate.requirementId == requirement_id)

    if job_role:
        base = base.where(
            or_(
                Candidate.jobRole == job_role,
                and_(Candidate.jobRole == "", Requirement.jobRole == job_role),
            )
        )

    if status:
        base = base.where(Candidate.status == status)

    if stage_key:
        base = base.where(or_(Candidate.candidateStage == stage_key, and_(Candidate.candidateStage == "", Candidate.status == stage_key)))

    if source:
        base = base.where(Candidate.source.ilike(f"%{source}%"))

    if q:
        like = f"%{q}%"
        base = base.where(
            or_(
                Candidate.candidateId.ilike(like),
                Candidate.candidateName.ilike(like),
                Candidate.name_masked.ilike(like),
                Candidate.mobile.ilike(like),
                Candidate.mobile_masked.ilike(like),
                Candidate.jobRole.ilike(like),
                Candidate.source.ilike(like),
                Candidate.status.ilike(like),
                Candidate.candidateStage.ilike(like),
                Requirement.jobTitle.ilike(like),
            )
        )

    from_dt = parse_datetime_maybe(from_raw, app_timezone=cfg.APP_TIMEZONE) if from_raw else None
    to_dt = parse_datetime_maybe(to_raw, app_timezone=cfg.APP_TIMEZONE) if to_raw else None
    if from_dt:
        base = base.where(Candidate.updatedAt >= to_iso_utc(from_dt))
    if to_dt:
        base = base.where(Candidate.updatedAt <= to_iso_utc(to_dt))

    total = int(db.execute(select(func.count()).select_from(base.subquery())).scalar_one() or 0)

    rows = (
        db.execute(base.order_by(Candidate.updatedAt.desc(), Candidate.candidateId.desc()).offset(offset).limit(limit))
        .all()
    )

    can_pii = bool(getattr(cfg, "PII_ENC_KEY", "").strip()) and bool(auth and auth.valid) and str(
        getattr(auth, "role", "") or ""
    ).upper() in set(getattr(cfg, "PII_VIEW_ROLES", []) or [])

    items = []
    for cand, job_title in rows:
        cand_stage = str(getattr(cand, "candidateStage", "") or "").strip() or str(getattr(cand, "status", "") or "").strip()

        masked_name = str(getattr(cand, "name_masked", "") or getattr(cand, "candidateName", "") or "").strip()
        if looks_like_sha256_hex(masked_name) or _looks_like_enc_value(masked_name):
            masked_name = ""
        if masked_name and "*" not in masked_name:
            masked_name = mask_name(masked_name)

        masked_mobile = str(getattr(cand, "mobile_masked", "") or getattr(cand, "mobile", "") or "").strip()
        if looks_like_sha256_hex(masked_mobile) or _looks_like_enc_value(masked_mobile):
            masked_mobile = ""
        if masked_mobile and not re.search(r"[x*]", masked_mobile, flags=re.IGNORECASE):
            masked_mobile = mask_phone(masked_mobile)

        items.append(
            {
                "candidateId": str(cand.candidateId or ""),
                "requirementId": str(cand.requirementId or ""),
                "candidateName": masked_name,
                "mobile": masked_mobile,
                "jobRole": str(cand.jobRole or ""),
                "jobTitle": str(job_title or ""),
                "status": str(cand.status or ""),
                "candidateStage": str(cand_stage or ""),
                "stageUpdatedAt": str(getattr(cand, "stageUpdatedAt", "") or ""),
                "source": str(cand.source or ""),
                "updatedAt": str(cand.updatedAt or ""),
                "updatedBy": str(cand.updatedBy or ""),
                "cvFileId": str(cand.cvFileId or ""),
                "cvFileName": str(cand.cvFileName or ""),
            }
        )

        if can_pii:
            name_full = decrypt_pii(getattr(cand, "name_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{cand.candidateId}:name")
            mobile_full = decrypt_pii(getattr(cand, "mobile_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{cand.candidateId}:mobile")
            if name_full:
                items[-1]["candidateNameFull"] = name_full
                items[-1]["candidateName"] = name_full
            if mobile_full:
                items[-1]["mobileFull"] = mobile_full
                items[-1]["mobile"] = mobile_full

    return {"items": items, "total": total, "limit": limit, "offset": offset}
