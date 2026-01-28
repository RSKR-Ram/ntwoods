from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import func, select

from actions.candidate_repo import find_candidate
from actions.helpers import append_audit, next_prefixed_id
from actions.metrics_repo import record_step_metric
from cache_layer import cache_invalidate_prefix, cache_get, cache_set, make_cache_key
from models import AssignedTraining, Candidate, CandidateTrainingState, Employee, TrainingLog, TrainingMaster, TrainingModule
from pii import decrypt_pii
from utils import ApiError, AuthContext, iso_utc_now, normalize_role, parse_datetime_maybe, safe_json_string, to_iso_utc


def _normalize_training_status(status: str) -> str:
    s = str(status or "").upper().strip()
    if s in {"IN-PROGRESS", "INPROGRESS"}:
        s = "IN_PROGRESS"
    if not s:
        return "PENDING"
    if s not in {"PENDING", "IN_PROGRESS", "COMPLETED", "OVERDUE"}:
        return "PENDING"
    return s


def _compute_overdue(status: str, due_date_iso: str, now: datetime) -> str:
    st = _normalize_training_status(status)
    if st == "COMPLETED":
        return "COMPLETED"
    due_dt = parse_datetime_maybe(due_date_iso) if due_date_iso else None
    if not due_dt:
        return st
    if due_dt < now and st in {"PENDING", "IN_PROGRESS"}:
        return "OVERDUE"
    return st


def _parse_documents_lines(raw) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(x or "").strip() for x in raw if str(x or "").strip()]
    s = str(raw or "")
    out = []
    for line in s.splitlines():
        line = str(line or "").strip()
        if line:
            out.append(line)
    return out


def _parse_video_links_input(raw) -> list[str]:
    if not raw:
        return []
    values = None
    if isinstance(raw, list):
        values = raw
    else:
        s = str(raw or "").strip()
        if not s:
            return []
        if s.startswith("[") and s.endswith("]"):
            try:
                v = json.loads(s)
            except Exception:
                v = None
            if isinstance(v, list):
                values = v
        if values is None:
            values = [s]

    out = []
    for x in values:
        u = str(x or "").strip()
        if not u:
            continue
        if u not in out:
            out.append(u)
    return out


def _validate_video_links(video_links: list[str]) -> list[str]:
    links = [str(u or "").strip() for u in (video_links or []) if str(u or "").strip()]
    if len(links) > 20:
        raise ApiError("BAD_REQUEST", "Max 20 video URLs per training")
    normalized: list[str] = []
    for u in links:
        if u.startswith(("http://", "https://")):
            normalized.append(u)
            continue
        if "://" in u:
            raise ApiError("BAD_REQUEST", "Invalid video URL")
        if " " in u:
            raise ApiError("BAD_REQUEST", "Invalid video URL")
        if "." in u:
            normalized.append("https://" + u)
            continue
        raise ApiError("BAD_REQUEST", "Invalid video URL")
    return normalized


def _read_training_master_map(db):
    rows = db.execute(select(TrainingMaster)).scalars().all()
    items = []
    by_id = {}
    for r in rows:
        tid = str(r.training_id or "").strip()
        if not tid:
            continue
        docs = []
        raw = str(r.documentsJson or "").strip()
        if raw:
            try:
                docs = json.loads(raw) or []
            except Exception:
                docs = []
        if not isinstance(docs, list):
            docs = []

        video_links = []
        raw_videos = str(getattr(r, "videoLinksJson", "") or "").strip()
        if raw_videos:
            try:
                video_links = json.loads(raw_videos) or []
            except Exception:
                video_links = []
        if not isinstance(video_links, list):
            video_links = []
        video_links = [str(x or "").strip() for x in video_links if str(x or "").strip()]
        if not video_links and str(getattr(r, "video_link", "") or "").strip():
            video_links = [str(getattr(r, "video_link", "") or "").strip()]

        obj = {
            "training_id": tid,
            "name": r.name or "",
            "department": r.department or "",
            "description": r.description or "",
            "video_link": (video_links[0] if video_links else "") or "",
            "video_links": video_links,
            "documents": docs,
            "created_by": r.created_by or "",
            "created_on": r.created_on or "",
        }
        items.append(obj)
        by_id[tid] = obj
    items.sort(key=lambda x: str(x.get("name") or ""))
    return {"items": items, "byId": by_id}


def training_master_list(data, auth: AuthContext | None, db, cfg):
    dept = str((data or {}).get("department") or "").strip()
    user_id = str(getattr(auth, "userId", "") or "PUBLIC")
    role = normalize_role(getattr(auth, "role", "") or "") or ""
    key = make_cache_key("TRAINING_MASTER_LIST", scope=[user_id, role, dept.upper() or "ALL"])
    cached = cache_get(key)
    if cached is not None:
        return cached

    res = _read_training_master_map(db)
    if not dept:
        out = {"items": res["items"]}
        cache_set(key, out)
        return out
    dept_u = dept.upper()
    filtered = [x for x in res["items"] if str(x.get("department") or "").upper() == dept_u]
    out = {"items": filtered}
    cache_set(key, out)
    return out


def training_master_upsert(data, auth: AuthContext | None, db, cfg):
    training_id = str((data or {}).get("training_id") or (data or {}).get("trainingId") or "").strip()
    name = str((data or {}).get("name") or (data or {}).get("training_name") or "").strip()
    department = str((data or {}).get("department") or "").strip()
    description = str((data or {}).get("description") or "").strip()
    video_links_in = _parse_video_links_input(
        (data or {}).get("video_links")
        or (data or {}).get("videoLinks")
        or (data or {}).get("video_urls")
        or (data or {}).get("videoUrls")
    )
    legacy_video = str((data or {}).get("video_link") or (data or {}).get("videoLink") or "").strip()
    if not video_links_in and legacy_video:
        video_links_in = [legacy_video]
    video_links = _validate_video_links(video_links_in)
    video_link = video_links[0] if video_links else ""
    documents = _parse_documents_lines((data or {}).get("documents") or (data or {}).get("documentsLines"))

    if not name:
        raise ApiError("BAD_REQUEST", "Missing training name")
    if not department:
        raise ApiError("BAD_REQUEST", "Missing department")

    now = iso_utc_now()
    actor = str((auth.userId or auth.email) if auth else "")

    if not training_id:
        existing_ids = [x for x in db.execute(select(TrainingMaster.training_id)).scalars().all()]
        training_id = next_prefixed_id(db, counter_key="TRN", prefix="TRN-", pad=5, existing_ids=existing_ids)
        now2 = now
        db.add(
            TrainingMaster(
                training_id=training_id,
                name=name,
                department=department,
                description=description,
                video_link=video_link,
                videoLinksJson=safe_json_string(video_links, "[]"),
                documentsJson=safe_json_string(documents, "[]"),
                created_by=actor,
                created_on=now,
            )
        )
        db.add(
            TrainingModule(
                moduleId=training_id,
                title=name,
                video_provider="URL",
                video_ref=video_link,
                active=True,
                createdAt=now2,
                createdBy=actor,
                updatedAt=now2,
                updatedBy=actor,
            )
        )
        db.add(
            TrainingLog(
                timestamp=now,
                candidate_id="",
                training_id=training_id,
                assigned_id="",
                action="TRAINING_TEMPLATE_CREATE",
                performed_by=actor,
                remarks="",
                metaJson=safe_json_string({"name": name, "department": department}, "{}"),
            )
        )
        cache_invalidate_prefix("TRAINING_MASTER_LIST:")
        return {"training_id": training_id}

    tpl = db.execute(select(TrainingMaster).where(TrainingMaster.training_id == training_id)).scalar_one_or_none()
    if not tpl:
        raise ApiError("NOT_FOUND", "Training not found")

    tpl.name = name
    tpl.department = department
    tpl.description = description
    tpl.video_link = video_link
    tpl.videoLinksJson = safe_json_string(video_links, "[]")
    tpl.documentsJson = safe_json_string(documents, "[]")

    tm = db.execute(select(TrainingModule).where(TrainingModule.moduleId == training_id)).scalar_one_or_none()
    if tm:
        tm.title = name
        tm.video_provider = "URL"
        tm.video_ref = video_link
        tm.active = True
        tm.updatedAt = now
        tm.updatedBy = actor
    else:
        db.add(
            TrainingModule(
                moduleId=training_id,
                title=name,
                video_provider="URL",
                video_ref=video_link,
                active=True,
                createdAt=now,
                createdBy=actor,
                updatedAt=now,
                updatedBy=actor,
            )
        )

    db.add(
        TrainingLog(
            timestamp=now,
            candidate_id="",
            training_id=training_id,
            assigned_id="",
            action="TRAINING_TEMPLATE_UPDATE",
            performed_by=actor,
            remarks="",
            metaJson=safe_json_string({"name": name, "department": department}, "{}"),
        )
    )
    cache_invalidate_prefix("TRAINING_MASTER_LIST:")
    return {"training_id": training_id}


def training_assign(data, auth: AuthContext | None, db, cfg):
    candidate_id = str((data or {}).get("candidate_id") or (data or {}).get("candidateId") or "").strip()
    training_id = str((data or {}).get("training_id") or (data or {}).get("trainingId") or "").strip()
    due_raw = (data or {}).get("due_date") or (data or {}).get("dueDate") or ""
    due_dt = parse_datetime_maybe(due_raw, app_timezone=cfg.APP_TIMEZONE)

    override_video_links_in = _parse_video_links_input(
        (data or {}).get("video_links")
        or (data or {}).get("videoLinks")
        or (data or {}).get("video_urls")
        or (data or {}).get("videoUrls")
    )
    override_video = str((data or {}).get("video_link") or (data or {}).get("videoLink") or "").strip()
    if not override_video_links_in and override_video:
        override_video_links_in = [override_video]
    override_video_links = _validate_video_links(override_video_links_in) if override_video_links_in else []
    override_description = str((data or {}).get("description") or "").strip()
    documents = _parse_documents_lines((data or {}).get("documents") or (data or {}).get("documentsLines"))

    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidate_id")
    if not training_id:
        raise ApiError("BAD_REQUEST", "Missing training_id")
    if not due_dt:
        raise ApiError("BAD_REQUEST", "Missing due_date")

    actor = str((auth.userId or auth.email) if auth else "")

    master = _read_training_master_map(db)
    tpl = master["byId"].get(training_id)
    if not tpl:
        raise ApiError("NOT_FOUND", "Training template not found")

    now = iso_utc_now()
    existing_ids = [x for x in db.execute(select(AssignedTraining.assigned_id)).scalars().all()]
    assigned_id = next_prefixed_id(db, counter_key="ASN", prefix="ASN-", pad=6, existing_ids=existing_ids)

    docs = documents if documents else (tpl.get("documents") or [])
    due_iso = to_iso_utc(due_dt)
    tpl_videos = tpl.get("video_links") or []
    tpl_videos = _parse_video_links_input(tpl_videos)
    final_videos = override_video_links if override_video_links else tpl_videos
    final_videos = _validate_video_links(final_videos) if final_videos else []

    db.add(
        AssignedTraining(
            assigned_id=assigned_id,
            candidate_id=candidate_id,
            training_id=training_id,
            training_name=tpl.get("name") or "",
            department=tpl.get("department") or "",
            description=override_description or tpl.get("description") or "",
            video_link=(final_videos[0] if final_videos else "") or "",
            videoLinksJson=safe_json_string(final_videos, "[]"),
            documentsJson=safe_json_string(docs, "[]"),
            status="PENDING",
            assigned_date=now,
            due_date=due_iso,
            start_time="",
            completion_time="",
            assigned_by=actor,
        )
    )

    db.add(
        TrainingLog(
            timestamp=now,
            candidate_id=candidate_id,
            training_id=training_id,
            assigned_id=assigned_id,
            action="ASSIGN",
            performed_by=actor,
            remarks="",
            metaJson=safe_json_string({"due_date": due_iso, "template": {"name": tpl.get("name"), "department": tpl.get("department")}}, "{}"),
        )
    )
    cache_invalidate_prefix("TRAINING_LIST:")
    cache_invalidate_prefix("TRAINING_DASHBOARD:")
    return {"assigned_id": assigned_id, "status": "PENDING"}


def training_list(data, auth: AuthContext | None, db, cfg):
    requested_candidate_id = str((data or {}).get("candidate_id") or (data or {}).get("candidateId") or "").strip()
    role = normalize_role(auth.role if auth else "")

    candidate_id = requested_candidate_id
    if role == "EMPLOYEE":
        emp_id = str(auth.userId or "").strip() if auth else ""
        emp = db.execute(select(Employee).where(Employee.employeeId == emp_id)).scalar_one_or_none()
        if not emp or not emp.candidateId:
            raise ApiError("AUTH_INVALID", "Employee missing")
        candidate_id = str(emp.candidateId or "").strip()
        if requested_candidate_id and requested_candidate_id != candidate_id:
            raise ApiError("FORBIDDEN", "Candidate mismatch")

    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidate_id")

    user_id = str(getattr(auth, "userId", "") or "PUBLIC")
    role_u = role or ""
    cache_key = make_cache_key("TRAINING_LIST", scope=[user_id, role_u, candidate_id])
    cached = cache_get(cache_key)
    if cached is not None:
        return cached

    # Include training workflow state for gating/visibility (backward compatible additive field).
    state_row = db.execute(select(CandidateTrainingState).where(CandidateTrainingState.candidateId == candidate_id)).scalar_one_or_none()
    state = {
        "candidateId": candidate_id,
        "requirementId": str(getattr(state_row, "requirementId", "") or "") if state_row else "",
        "markedCompleteAt": str(getattr(state_row, "markedCompleteAt", "") or "") if state_row else "",
        "markedCompleteBy": str(getattr(state_row, "markedCompleteBy", "") or "") if state_row else "",
        "closedAt": str(getattr(state_row, "closedAt", "") or "") if state_row else "",
        "closedBy": str(getattr(state_row, "closedBy", "") or "") if state_row else "",
    }

    # After HR/EA closes trainings, employee portal should not show *probation* trainings anymore.
    # However, future trainings may be assigned later (e.g. tech/product upskilling). To keep
    # the existing "close" behavior intact while enabling new trainings, we only hide items
    # assigned on/before closedAt and show any trainings assigned after closedAt.
    closed_at = str(state.get("closedAt") or "").strip()
    if role == "EMPLOYEE" and closed_at:
        rows = (
            db.execute(
                select(AssignedTraining)
                .where(AssignedTraining.candidate_id == candidate_id)
                .where(AssignedTraining.assigned_date != "")
                .where(AssignedTraining.assigned_date > closed_at)
            )
            .scalars()
            .all()
        )
    else:
        rows = db.execute(select(AssignedTraining).where(AssignedTraining.candidate_id == candidate_id)).scalars().all()
    if not rows:
        out2 = {"items": [], "state": state}
        cache_set(cache_key, out2)
        return out2

    now_dt = datetime.now(timezone.utc)
    now_iso = iso_utc_now()
    out = []

    for row in rows:
        status_norm = _normalize_training_status(row.status)
        effective = _compute_overdue(status_norm, row.due_date, now_dt)
        if effective != status_norm:
            # Persist overdue transition
            row.status = effective
            db.add(
                TrainingLog(
                    timestamp=now_iso,
                    candidate_id=candidate_id,
                    training_id=str(row.training_id or ""),
                    assigned_id=str(row.assigned_id or ""),
                    action="AUTO_OVERDUE",
                    performed_by="SYSTEM",
                    remarks="",
                    metaJson=safe_json_string({"from": status_norm, "to": effective}, "{}"),
                )
            )

        docs = []
        raw_docs = str(row.documentsJson or "").strip()
        if raw_docs:
            try:
                docs = json.loads(raw_docs) or []
            except Exception:
                docs = []
        if not isinstance(docs, list):
            docs = []

        video_links = []
        raw_videos = str(getattr(row, "videoLinksJson", "") or "").strip()
        if raw_videos:
            try:
                video_links = json.loads(raw_videos) or []
            except Exception:
                video_links = []
        if not isinstance(video_links, list):
            video_links = []
        video_links = [str(x or "").strip() for x in video_links if str(x or "").strip()]
        if not video_links and str(getattr(row, "video_link", "") or "").strip():
            video_links = [str(getattr(row, "video_link", "") or "").strip()]

        out.append(
            {
                "assigned_id": row.assigned_id,
                "candidate_id": candidate_id,
                "training_id": row.training_id,
                "training_name": row.training_name or "",
                "department": row.department or "",
                "description": row.description or "",
                "video_link": (video_links[0] if video_links else "") or "",
                "video_links": video_links,
                "documents": docs,
                "status": effective,
                "assigned_date": row.assigned_date or "",
                "due_date": row.due_date or "",
                "start_time": row.start_time or "",
                "completion_time": row.completion_time or "",
                "assigned_by": row.assigned_by or "",
            }
        )

    out.sort(key=lambda x: str(x.get("assigned_date") or ""), reverse=True)
    out2 = {"items": out, "state": state}
    cache_set(cache_key, out2)
    return out2


def training_status_update(data, auth: AuthContext | None, db, cfg):
    requested_candidate_id = str((data or {}).get("candidate_id") or (data or {}).get("candidateId") or "").strip()
    assigned_id = str((data or {}).get("assigned_id") or (data or {}).get("assignedId") or "").strip()
    op = str((data or {}).get("op") or "").upper().strip()
    status_in = str((data or {}).get("status") or "").upper().strip()
    remark = str((data or {}).get("remarks") or (data or {}).get("remark") or "").strip()

    role = normalize_role(auth.role if auth else "")
    candidate_id = requested_candidate_id
    if role == "EMPLOYEE":
        emp_id = str(auth.userId or "").strip() if auth else ""
        emp = db.execute(select(Employee).where(Employee.employeeId == emp_id)).scalar_one_or_none()
        if not emp or not emp.candidateId:
            raise ApiError("AUTH_INVALID", "Employee missing")
        candidate_id = str(emp.candidateId or "").strip()
        if requested_candidate_id and requested_candidate_id != candidate_id:
            raise ApiError("FORBIDDEN", "Candidate mismatch")

    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidate_id")
    if not assigned_id:
        raise ApiError("BAD_REQUEST", "Missing assigned_id")

    if op:
        if op in {"START", "RESUME", "OPEN"}:
            next_status = "IN_PROGRESS"
        elif op in {"COMPLETE", "MARK_COMPLETE"}:
            next_status = "COMPLETED"
        else:
            raise ApiError("BAD_REQUEST", "Invalid op")
    else:
        next_status = _normalize_training_status(status_in)
        if next_status not in {"IN_PROGRESS", "COMPLETED"}:
            raise ApiError("BAD_REQUEST", "Status can be IN_PROGRESS or COMPLETED")

    row = (
        db.execute(select(AssignedTraining).where(AssignedTraining.assigned_id == assigned_id).where(AssignedTraining.candidate_id == candidate_id))
        .scalars()
        .first()
    )
    if not row:
        raise ApiError("NOT_FOUND", "Assigned training not found")

    if role == "EMPLOYEE":
        # Preserve the existing "close" behavior for probation trainings while still allowing
        # future trainings to be completed after probation closes.
        state_row = db.execute(select(CandidateTrainingState).where(CandidateTrainingState.candidateId == candidate_id)).scalar_one_or_none()
        closed_at = str(getattr(state_row, "closedAt", "") or "").strip() if state_row else ""
        if closed_at:
            assigned_at = str(getattr(row, "assigned_date", "") or "").strip()
            assigned_dt = parse_datetime_maybe(assigned_at) if assigned_at else None
            closed_dt = parse_datetime_maybe(closed_at) if closed_at else None
            # If we cannot parse dates reliably, default to safest option: treat as closed.
            if not assigned_dt or not closed_dt or assigned_dt <= closed_dt:
                raise ApiError("FORBIDDEN", "Training is closed")

    now_dt = datetime.now(timezone.utc)
    now_iso = iso_utc_now()
    actor = str((auth.userId or auth.email) if auth else "")

    current = _normalize_training_status(row.status)
    current = _compute_overdue(current, row.due_date, now_dt)

    if next_status == "IN_PROGRESS":
        row.status = "IN_PROGRESS"
        if not row.start_time:
            row.start_time = now_iso
    elif next_status == "COMPLETED":
        # ENFORCE: Video must be watched before marking complete
        video_progress_raw = getattr(row, "video_progress", "") or ""
        video_links_raw = getattr(row, "videoLinksJson", "") or ""
        total_videos = 0
        try:
            if video_links_raw:
                links = json.loads(video_links_raw) if video_links_raw.startswith("[") else ([video_links_raw] if video_links_raw else [])
                total_videos = len([l for l in links if l and str(l).strip()])
        except Exception:
            total_videos = 0
        
        if total_videos > 0:
            completed_videos = 0
            try:
                if video_progress_raw:
                    progress = json.loads(video_progress_raw)
                    completed_videos = sum(1 for v in progress.values() if v.get("completed", False))
            except Exception:
                completed_videos = 0
            
            if completed_videos < total_videos:
                raise ApiError("BAD_REQUEST", f"Watch all videos first. {completed_videos}/{total_videos} videos completed.")
        
        row.status = "COMPLETED"
        if not row.start_time:
            row.start_time = now_iso
        if not row.completion_time:
            row.completion_time = now_iso

    db.add(
        TrainingLog(
            timestamp=now_iso,
            candidate_id=candidate_id,
            training_id=str(row.training_id or ""),
            assigned_id=assigned_id,
            action="IN_PROGRESS" if next_status == "IN_PROGRESS" else "COMPLETED",
            performed_by=actor,
            remarks=remark,
            metaJson=safe_json_string({"from": current, "to": next_status}, "{}"),
        )
    )
    cache_invalidate_prefix("TRAINING_LIST:")
    cache_invalidate_prefix("TRAINING_DASHBOARD:")
    return {"assigned_id": assigned_id, "status": str(row.status or "")}


def training_summary(data, auth: AuthContext | None, db, cfg):
    candidate_id = str((data or {}).get("candidate_id") or (data or {}).get("candidateId") or "").strip()
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidate_id")
    res = training_list({"candidate_id": candidate_id}, auth, db, cfg)
    items = res.get("items") or []
    counts = {"TOTAL": 0, "PENDING": 0, "IN_PROGRESS": 0, "COMPLETED": 0, "OVERDUE": 0}
    for it in items:
        s = _normalize_training_status(it.get("status"))
        counts["TOTAL"] += 1
        if s in counts:
            counts[s] += 1
    return {"candidate_id": candidate_id, "counts": counts, "items": items}


def training_dashboard(data, auth: AuthContext | None, db, cfg):
    scope = str((data or {}).get("scope") or "PROBATION").upper().strip()
    user_id = str(getattr(auth, "userId", "") or "PUBLIC")
    role = normalize_role(getattr(auth, "role", "") or "") or ""
    can_pii = bool(getattr(cfg, "PII_ENC_KEY", "").strip()) and role in set(getattr(cfg, "PII_VIEW_ROLES", []) or [])
    cache_key = make_cache_key("TRAINING_DASHBOARD", scope=[user_id, role, scope])
    cached = cache_get(cache_key)
    if cached is not None:
        return cached

    now_dt = datetime.now(timezone.utc)

    probation_candidate_map = {}
    if scope == "PROBATION":
        cands = db.execute(select(Candidate).where(Candidate.status == "PROBATION")).scalars().all()
        for c in cands:
            cid = str(c.candidateId or "").strip()
            if not cid:
                continue
            base = {
                "candidate_id": cid,
                "candidate_name": c.candidateName or "",
                "jobRole": c.jobRole or "",
                "mobile": c.mobile or "",
                "requirementId": c.requirementId or "",
            }
            if can_pii:
                name_full = decrypt_pii(getattr(c, "name_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{cid}:name")
                mobile_full = decrypt_pii(getattr(c, "mobile_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{cid}:mobile")
                if name_full:
                    base["candidate_name_full"] = name_full
                if mobile_full:
                    base["mobile_full"] = mobile_full
            probation_candidate_map[cid] = base

    rows = db.execute(select(AssignedTraining)).scalars().all()
    if not rows:
        out = {"totals": {"TOTAL": 0, "PENDING": 0, "IN_PROGRESS": 0, "COMPLETED": 0, "OVERDUE": 0}, "candidates": []}
        cache_set(cache_key, out)
        return out

    totals = {"TOTAL": 0, "PENDING": 0, "IN_PROGRESS": 0, "COMPLETED": 0, "OVERDUE": 0}
    by_candidate: dict[str, dict] = {}

    for row in rows:
        cid2 = str(row.candidate_id or "").strip()
        if not cid2:
            continue
        if scope == "PROBATION" and cid2 not in probation_candidate_map:
            continue

        st2 = _compute_overdue(row.status, row.due_date, now_dt)
        st2 = _normalize_training_status(st2)

        totals["TOTAL"] += 1
        if st2 in totals:
            totals[st2] += 1

        if cid2 not in by_candidate:
            base = probation_candidate_map.get(cid2, {"candidate_id": cid2})
            by_candidate[cid2] = {
                "candidate_id": cid2,
                "candidate_name": base.get("candidate_name", ""),
                "jobRole": base.get("jobRole", ""),
                "mobile": base.get("mobile", ""),
                "requirementId": base.get("requirementId", ""),
                "TOTAL": 0,
                "PENDING": 0,
                "IN_PROGRESS": 0,
                "COMPLETED": 0,
                "OVERDUE": 0,
            }

        by_candidate[cid2]["TOTAL"] += 1
        if st2 in by_candidate[cid2]:
            by_candidate[cid2][st2] += 1

    candidates = list(by_candidate.values())
    candidates.sort(
        key=lambda x: (
            -(x.get("OVERDUE") or 0),
            -(x.get("PENDING") or 0),
            str(x.get("candidate_name") or x.get("candidate_id") or ""),
        )
    )
    out = {"totals": totals, "candidates": candidates, "scope": scope}
    cache_set(cache_key, out)
    return out


def training_mark_complete(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or (data or {}).get("candidate_id") or "").strip()
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    req_id = str(cand.requirementId or "")

    now = iso_utc_now()
    actor = str(auth.userId or auth.email or "")

    row = db.execute(select(CandidateTrainingState).where(CandidateTrainingState.candidateId == candidate_id)).scalar_one_or_none()
    if not row:
        row = CandidateTrainingState(candidateId=candidate_id, requirementId=req_id)
        db.add(row)

    row.requirementId = req_id
    row.markedCompleteAt = now
    row.markedCompleteBy = actor
    row.updatedAt = now
    row.updatedBy = actor

    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="TRAINING_MARK_COMPLETE",
        fromState=str(cand.status or ""),
        toState=str(cand.status or ""),
        stageTag="Training Mark Complete",
        remark="",
        actor=auth,
        at=now,
        meta={"requirementId": req_id},
    )

    cache_invalidate_prefix("TRAINING_LIST:")
    cache_invalidate_prefix("TRAINING_DASHBOARD:")
    return {
        "candidateId": candidate_id,
        "requirementId": req_id,
        "markedCompleteAt": row.markedCompleteAt or "",
        "markedCompleteBy": row.markedCompleteBy or "",
        "closedAt": row.closedAt or "",
        "closedBy": row.closedBy or "",
    }


def training_close(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or (data or {}).get("candidate_id") or "").strip()
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    req_id = str(cand.requirementId or "")

    row = db.execute(select(CandidateTrainingState).where(CandidateTrainingState.candidateId == candidate_id)).scalar_one_or_none()
    if not row or not str(getattr(row, "markedCompleteAt", "") or "").strip():
        raise ApiError("BAD_REQUEST", "Training not marked complete yet")

    now = iso_utc_now()
    actor = str(auth.userId or auth.email or "")

    pending: list[dict] = []
    assigned = db.execute(select(AssignedTraining).where(AssignedTraining.candidate_id == candidate_id)).scalars().all()
    for t in assigned:
        st = _normalize_training_status(str(t.status or ""))
        if st != "COMPLETED":
            pending.append(
                {
                    "assigned_id": t.assigned_id,
                    "training_id": t.training_id,
                    "training_name": t.training_name,
                    "status": st,
                    "due_date": t.due_date or "",
                }
            )

    if pending:
        return {"closed": False, "pending": pending, "candidateId": candidate_id, "requirementId": req_id}

    row.closedAt = now
    row.closedBy = actor
    row.updatedAt = now
    row.updatedBy = actor

    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="TRAINING_CLOSE",
        fromState=str(cand.status or ""),
        toState=str(cand.status or ""),
        stageTag="Training Close",
        remark="",
        actor=auth,
        at=now,
        meta={"requirementId": req_id},
    )

    record_step_metric(
        db,
        requirement_id=req_id,
        candidate_id=candidate_id,
        step_name="TRAINING",
        start_ts=str(getattr(row, "markedCompleteAt", "") or now),
        end_ts=now,
        actor=auth,
    )

    cache_invalidate_prefix("TRAINING_LIST:")
    cache_invalidate_prefix("TRAINING_DASHBOARD:")
    return {
        "closed": True,
        "candidateId": candidate_id,
        "requirementId": req_id,
        "markedCompleteAt": row.markedCompleteAt or "",
        "markedCompleteBy": row.markedCompleteBy or "",
        "closedAt": row.closedAt or "",
        "closedBy": row.closedBy or "",
    }
