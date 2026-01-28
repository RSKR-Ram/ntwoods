from __future__ import annotations

# NOTE: This file is generated in multiple small patches to avoid tooling limits.
import json
import os
import random
import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any, Optional
from zoneinfo import ZoneInfo

from sqlalchemy import and_, func, or_, select

from actions.candidate_repo import (
    find_candidate,
    is_test_continued,
    reject_candidate_with_meta,
    upsert_test_decision,
    update_candidate,
)
from actions.helpers import append_audit, append_join_log, append_rejection_log, append_requirement_history
from actions.jobposting import assert_job_posting_complete
from actions.lifecycle_service import transition_candidate_status
from actions.metrics_repo import record_step_metric
from actions.dynamic_tests import required_tests_approved
from actions.exit_workflow import exit_terminate_init
from actions.training import training_summary
from models import (
    AssignedTraining,
    AuditLog,
    Candidate,
    CandidateTest,
    CandidateTrainingState,
    Employee,
    ExitCase,
    FailCandidate,
    OnlineTest,
    ProbationLog,
    Requirement,
    RoleHistory,
    Setting,
    TrainingLog,
)
from services.gas_uploader import gas_upload_file
from auth import revoke_user_sessions
from pii import decrypt_pii, looks_like_sha256_hex, mask_name, mask_phone
from sla import compute_sla
from utils import ApiError, AuthContext, decode_base64_to_bytes, iso_utc_now, parse_datetime_maybe, sanitize_filename, safe_json_string, to_iso_utc


def _get_setting_number(db, key: str, fallback: float) -> float:
    k = str(key or "").strip()
    if not k:
        return float(fallback)
    row = db.execute(select(Setting).where(Setting.key == k)).scalar_one_or_none()
    if not row:
        return float(fallback)
    raw = getattr(row, "value", "")
    try:
        s = str(raw or "").strip()
        if not s:
            return float(fallback)
        n = float(s)
        if n != n:  # NaN
            return float(fallback)
        return n
    except Exception:
        return float(fallback)


def _parse_ymd(date_iso: str) -> Optional[date]:
    s = str(date_iso or "").strip()
    if not s:
        return None
    parts = s.split("-")
    if len(parts) != 3:
        return None
    try:
        y = int(parts[0])
        m = int(parts[1])
        d = int(parts[2])
        return date(y, m, d)
    except Exception:
        return None


def _get_requirements_map(db) -> dict[str, dict[str, str]]:
    rows = db.execute(select(Requirement.requirementId, Requirement.jobRole, Requirement.jobTitle)).all()
    return {str(rid): {"jobRole": jr or "", "jobTitle": jt or ""} for rid, jr, jt in rows if str(rid or "").strip()}


def _normalize_job_role(s: Any) -> str:
    return str(s or "").strip().upper()


def _allowed_tech_tests_for_role(job_role: Any) -> list[str]:
    r = _normalize_job_role(job_role)
    if "ACCOUNTS" in r:
        return ["Tally", "Excel"]
    if r == "CRM" or r == "CCE" or r == "PC" or "CRM" in r or "CCE" in r or "PC" in r:
        return ["Excel", "Voice"]
    return ["Excel"]


def _parse_json_list(raw: Any) -> list[Any]:
    try:
        s = str(raw or "").strip()
        if not s:
            return []
        obj = json.loads(s)
        return obj if isinstance(obj, list) else []
    except Exception:
        return []


def _normalize_number(value: Any) -> Optional[float]:
    if value is None:
        return None
    s = str(value or "").strip()
    if not s:
        return None
    s = s.replace(",", "")
    try:
        n = float(s)
    except Exception:
        return None
    if n != n:  # NaN
        return None
    return n


def _make_question_set() -> list[dict[str, Any]]:
    q: list[dict[str, Any]] = []

    percents = [10, 20, 25, 30, 40, 50, 60, 75]
    p = random.choice(percents)
    base = random.randint(2, 10) * 20  # 40..200 step 20
    ans_p = (p * base) / 100
    q.append({"id": "D", "type": "number", "weight": 3, "prompt": f"What is {p}% of {base}?", "correct": ans_p})

    fracs = [{"a": 1, "b": 2}, {"a": 1, "b": 4}, {"a": 3, "b": 4}, {"a": 2, "b": 3}, {"a": 3, "b": 5}]
    f = random.choice(fracs)
    n_base = random.randint(2, 10) * int(f["b"])
    ans_f = (int(f["a"]) * n_base) / int(f["b"])
    q.append(
        {
            "id": "E",
            "type": "number",
            "weight": 3,
            "prompt": f"What is {int(f['a'])}/{int(f['b'])} of {n_base}?",
            "correct": ans_f,
        }
    )

    unit_cases = [
        {"from": "km", "to": "m", "mul": 1000},
        {"from": "m", "to": "cm", "mul": 100},
        {"from": "kg", "to": "g", "mul": 1000},
        {"from": "g", "to": "kg", "mul": 1 / 1000},
    ]
    uc = random.choice(unit_cases)
    amount = random.randint(1, 9) * (500 if uc["from"] == "g" else 2)
    if uc["from"] == "g":
        amount = random.randint(1, 9) * 500
    ans_u = amount * float(uc["mul"])
    q.append(
        {
            "id": "F",
            "type": "number",
            "weight": 2,
            "prompt": f"Convert {amount} {uc['from']} to {uc['to']}.",
            "correct": ans_u,
        }
    )

    per_item = random.randint(2, 10) * 5  # 10..55 step 5
    count = random.randint(3, 9)
    total = per_item * count
    q.append(
        {
            "id": "G",
            "type": "number",
            "weight": 2,
            "prompt": f"If {count} items cost {total}, what is the cost of 1 item?",
            "correct": per_item,
        }
    )

    return q


def _is_expired(expires_at: Any, *, cfg) -> bool:
    if not expires_at:
        return False
    dt = parse_datetime_maybe(expires_at, app_timezone=cfg.APP_TIMEZONE)
    if not dt:
        return False
    return dt < datetime.now(timezone.utc)


@dataclass(frozen=True)
class _PublicTokenValidation:
    valid: bool
    reason: str = ""
    expiresAt: str = ""
    candidateId: str = ""
    requirementId: str = ""
    submitted: bool = False


def _public_validate_test_token(db, token: str, cfg) -> _PublicTokenValidation:
    tok = str(token or "").strip()
    if not tok:
        return _PublicTokenValidation(valid=False, reason="MISSING_TOKEN")

    cand = db.execute(select(Candidate).where(Candidate.testToken == tok)).scalar_one_or_none()
    if not cand:
        return _PublicTokenValidation(valid=False, reason="INVALID_TOKEN")

    expires_at = str(getattr(cand, "testTokenExpiresAt", "") or "")
    if expires_at and _is_expired(expires_at, cfg=cfg):
        return _PublicTokenValidation(
            valid=False,
            reason="EXPIRED",
            expiresAt=expires_at,
            candidateId=str(cand.candidateId or ""),
            requirementId=str(cand.requirementId or ""),
        )

    row = db.execute(select(OnlineTest).where(OnlineTest.token == tok)).scalar_one_or_none()
    submitted = False
    if row:
        submitted = str(getattr(row, "status", "") or "").upper() == "SUBMITTED"

    return _PublicTokenValidation(
        valid=True,
        expiresAt=expires_at or "",
        candidateId=str(cand.candidateId or ""),
        requirementId=str(cand.requirementId or ""),
        submitted=submitted,
    )


def hr_walkin_schedule(data, auth: AuthContext | None, db, cfg):
    # Backward-compatible alias. Use WALKIN_SCHEDULE going forward.
    return walkin_schedule(data, auth, db, cfg)


def walkin_schedule(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    walkin_at_iso = str((data or {}).get("walkinAt") or "").strip()
    notes = str((data or {}).get("notes") or "").strip()

    candidate_id = str((data or {}).get("candidateId") or "").strip()
    candidate_ids = (data or {}).get("candidateIds") or []

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not walkin_at_iso:
        raise ApiError("BAD_REQUEST", "Missing walkinAt")

    if candidate_id:
        candidate_ids = [candidate_id]
    if not isinstance(candidate_ids, list) or len(candidate_ids) == 0:
        raise ApiError("BAD_REQUEST", "Missing candidateId(s)")
    if len(candidate_ids) > 50:
        raise ApiError("BAD_REQUEST", "Max 50 candidates")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    dt = parse_datetime_maybe(walkin_at_iso, app_timezone=cfg.APP_TIMEZONE)
    if not dt:
        raise ApiError("BAD_REQUEST", "Invalid walkinAt")
    walkin_at = to_iso_utc(dt)

    updated: list[dict[str, str]] = []
    errors: list[dict[str, Any]] = []

    for i, cid_raw in enumerate(candidate_ids):
        cid = str(cid_raw or "").strip()
        if not cid:
            errors.append({"index": i, "candidateId": "", "message": "Missing candidateId"})
            continue
        try:
            cand = find_candidate(db, candidate_id=cid, requirement_id=requirement_id)
            current_status = str(cand.status or "").upper()
            if current_status not in {"WALKIN_PENDING", "WALKIN_SCHEDULED"}:
                raise ApiError("BAD_REQUEST", "Owner approval required before scheduling walk-in")

            update_candidate(
                db,
                cand=cand,
                patch={"status": "WALKIN_SCHEDULED", "walkinAt": walkin_at, "walkinNotes": notes},
                auth=auth,
            )

            append_audit(
                db,
                entityType="CANDIDATE",
                entityId=cid,
                action="WALKIN_SCHEDULE",
                fromState=current_status,
                toState="WALKIN_SCHEDULED",
                stageTag="HR_WALKIN_SCHEDULE",
                remark=notes,
                actor=auth,
                at=iso_utc_now(),
                meta={"requirementId": requirement_id, "walkinAt": walkin_at},
            )

            updated.append({"candidateId": cid})
        except Exception as e:
            if isinstance(e, ApiError):
                msg = e.message
            else:
                msg = str(e) or "Failed"
            errors.append({"index": i, "candidateId": cid, "message": msg})

    return {"updated": updated, "errors": errors, "walkinAt": walkin_at}


def precall_list(data, auth: AuthContext | None, db, cfg):
    job_role_filter = str((data or {}).get("jobRole") or "").strip()
    date_iso = str((data or {}).get("date") or "").strip()
    count_only = bool((data or {}).get("countOnly"))
    mode = str((data or {}).get("mode") or "").upper().strip()

    can_pii = bool(getattr(cfg, "PII_ENC_KEY", "").strip()) and bool(auth and auth.valid) and str(getattr(auth, "role", "") or "").upper() in set(
        getattr(cfg, "PII_VIEW_ROLES", []) or []
    )

    date_field = "walkinAt"
    if mode in {"PREINTERVIEW", "PRE_INTERVIEW"}:
        date_field = "preCallAt"

    start_utc = None
    end_utc = None
    ymd = _parse_ymd(date_iso) if date_iso else None
    if ymd:
        try:
            tz = ZoneInfo(cfg.APP_TIMEZONE)
        except Exception:
            tz = timezone.utc
        start_local = datetime(ymd.year, ymd.month, ymd.day, 0, 0, 0, tzinfo=tz)
        end_local = datetime(ymd.year, ymd.month, ymd.day, 23, 59, 59, tzinfo=tz)
        start_utc = start_local.astimezone(timezone.utc)
        end_utc = end_local.astimezone(timezone.utc)

    req_map = None
    if not count_only or job_role_filter:
        req_map = _get_requirements_map(db)

    order_col = Candidate.walkinAt if date_field == "walkinAt" else Candidate.preCallAt
    rows = db.execute(select(Candidate).where(func.upper(Candidate.status) == "WALKIN_SCHEDULED").order_by(order_col)).scalars().all()
    items: list[dict[str, Any]] = []
    total = 0

    for c in rows:
        requirement_id = str(c.requirementId or "").strip()
        rm = (req_map or {}).get(requirement_id, {}) if requirement_id else {}
        job_role = str(c.jobRole or rm.get("jobRole", "") or "").strip()
        if job_role_filter and job_role != job_role_filter:
            continue

        dt_raw = str(getattr(c, date_field, "") or "").strip()
        dt_val = parse_datetime_maybe(dt_raw, app_timezone=cfg.APP_TIMEZONE) if dt_raw else None
        if start_utc and end_utc:
            # If date filter is active, candidates without a valid timestamp must not leak into results.
            if not dt_val:
                continue
            if dt_val < start_utc or dt_val > end_utc:
                continue

        total += 1
        if count_only:
            continue

        item = {
                "candidateId": c.candidateId,
                "requirementId": requirement_id,
                "candidateName": c.candidateName,
                "mobile": c.mobile,
                "source": c.source,
                "cvFileId": c.cvFileId or "",
                "cvFileName": c.cvFileName or "",
                "jobRole": job_role,
                "jobTitle": rm.get("jobTitle", "") if isinstance(rm, dict) else "",
                "walkinAt": c.walkinAt or "",
                "walkinNotes": c.walkinNotes or "",
                "notPickCount": int(c.notPickCount or 0),
                "preCallAt": c.preCallAt or "",
                "onlineTestScore": c.onlineTestScore or "",
                "onlineTestResult": c.onlineTestResult or "",
                "onlineTestSubmittedAt": c.onlineTestSubmittedAt or "",
                "testDecisionsJson": c.testDecisionsJson or "",
                "candidate_test_failed_but_manually_continued": bool(c.candidate_test_failed_but_manually_continued) or False,
                "sla": compute_sla(
                    db,
                    step_name="PRE_INTERVIEW" if date_field == "preCallAt" else "PRECALL",
                    start_ts=dt_raw,
                    app_timezone=cfg.APP_TIMEZONE,
                ),
                "updatedAt": c.updatedAt or "",
                "updatedBy": c.updatedBy or "",
            }

        if can_pii:
            name_full = decrypt_pii(getattr(c, "name_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{c.candidateId}:name")
            mobile_full = decrypt_pii(getattr(c, "mobile_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{c.candidateId}:mobile")
            if name_full:
                item["candidateNameFull"] = name_full
            if mobile_full:
                item["mobileFull"] = mobile_full

        items.append(item)

    def _walkin_sort_key(it: dict[str, Any]) -> datetime:
        dt0 = parse_datetime_maybe(it.get(date_field) or "", app_timezone=cfg.APP_TIMEZONE)
        return dt0 or datetime.min.replace(tzinfo=timezone.utc)

    items.sort(key=_walkin_sort_key)
    if count_only:
        return {"items": [], "total": total}
    return {"items": items, "total": len(items)}


def precall_update(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    op = str((data or {}).get("op") or "").upper().strip()
    remark = str((data or {}).get("remark") or "").strip()
    pre_call_at_iso = str((data or {}).get("preCallAt") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not op:
        raise ApiError("BAD_REQUEST", "Missing op")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status != "WALKIN_SCHEDULED":
        raise ApiError("BAD_REQUEST", "Candidate not scheduled")

    now = iso_utc_now()

    if op == "REJECT":
        if not remark:
            raise ApiError("BAD_REQUEST", "Remark required")
        return reject_candidate_with_meta(
            db,
            candidate_id=candidate_id,
            requirement_id=requirement_id,
            stage_tag="Reject On Call",
            remark=remark,
            reason_code="REJECT_ON_CALL",
            auth=auth,
            audit_action="PRECALL_UPDATE",
        )

    if op == "NOT_PICK":
        existing_count = int(cand.notPickCount or 0)
        if existing_count < 0:
            existing_count = 0
        next_count = existing_count + 1

        update_candidate(db, cand=cand, patch={"notPickCount": next_count}, auth=auth)
        append_audit(
            db,
            entityType="CANDIDATE",
            entityId=candidate_id,
            action="PRECALL_UPDATE",
            fromState=current_status,
            toState=current_status,
            stageTag="Not Pick",
            remark=str(next_count),
            actor=auth,
            at=now,
            meta={"requirementId": requirement_id, "notPickCount": next_count},
        )

        threshold = int(_get_setting_number(db, "NOT_PICK_THRESHOLD", 3))
        if next_count >= threshold:
            rej = reject_candidate_with_meta(
                db,
                candidate_id=candidate_id,
                requirement_id=requirement_id,
                stage_tag="Not Pick Auto Reject",
                remark="Threshold reached",
                reason_code="NOT_PICK_THRESHOLD",
                auth=None,
                audit_action="PRECALL_UPDATE",
            )
            rej.update({"notPickCount": next_count, "autoRejected": True, "threshold": threshold})
            return rej

        return {"ok": True, "status": current_status, "notPickCount": next_count, "autoRejected": False, "threshold": threshold}

    if op == "CALL_DONE":
        if not pre_call_at_iso:
            raise ApiError("BAD_REQUEST", "Missing preCallAt")
        dt = parse_datetime_maybe(pre_call_at_iso, app_timezone=cfg.APP_TIMEZONE)
        if not dt:
            raise ApiError("BAD_REQUEST", "Invalid preCallAt")
        pre_call_at = to_iso_utc(dt)

        update_candidate(db, cand=cand, patch={"preCallAt": pre_call_at}, auth=auth)
        append_audit(
            db,
            entityType="CANDIDATE",
            entityId=candidate_id,
            action="PRECALL_UPDATE",
            fromState=current_status,
            toState=current_status,
            stageTag="Call Done",
            remark="",
            actor=auth,
            at=now,
            meta={"requirementId": requirement_id, "preCallAt": pre_call_at},
        )
        return {"ok": True, "status": current_status, "preCallAt": pre_call_at}

    raise ApiError("BAD_REQUEST", "Invalid op")


def auto_reject_notpick(data, auth: AuthContext | None, db, cfg):
    threshold = int(_get_setting_number(db, "NOT_PICK_THRESHOLD", 3))
    rows = db.execute(select(Candidate)).scalars().all()
    scanned = len(rows)
    if not rows:
        return {"scanned": 0, "rejected": 0, "threshold": threshold}

    rejected = 0
    system = AuthContext(valid=True, userId="SYSTEM", email="SYSTEM", role="SYSTEM", expiresAt="")

    for c in rows:
        if str(c.status or "").upper() != "WALKIN_SCHEDULED":
            continue
        cnt = int(c.notPickCount or 0)
        if cnt < threshold:
            continue
        reject_candidate_with_meta(
            db,
            candidate_id=str(c.candidateId or ""),
            requirement_id=str(c.requirementId or ""),
            stage_tag="Not Pick Auto Reject",
            remark="Threshold reached",
            reason_code="NOT_PICK_THRESHOLD",
            auth=None,
            audit_action="AUTO_REJECT_NOTPICK",
        )
        rejected += 1

    return {"scanned": scanned, "rejected": rejected, "threshold": threshold}


def preinterview_status(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    op = str((data or {}).get("op") or "").upper().strip()
    remark = str((data or {}).get("remark") or "").strip()
    pre_interview_at_iso = str((data or {}).get("preInterviewAt") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not op:
        raise ApiError("BAD_REQUEST", "Missing op")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status == "REJECTED":
        raise ApiError("BAD_REQUEST", "Candidate already rejected")

    now = iso_utc_now()

    if op == "APPEARED":
        pre_at = str(cand.preCallAt or "").strip()
        if not pre_at:
            raise ApiError("BAD_REQUEST", "Pre-interview datetime not set")
        update_candidate(db, cand=cand, patch={"preInterviewStatus": "APPEARED"}, auth=auth)
        append_audit(
            db,
            entityType="CANDIDATE",
            entityId=candidate_id,
            action="PREINTERVIEW_STATUS",
            fromState=current_status,
            toState=current_status,
            stageTag="PreInterview Appeared",
            remark="",
            actor=auth,
            at=now,
            meta={"requirementId": requirement_id},
        )
        return {"ok": True, "status": current_status, "preInterviewStatus": "APPEARED"}

    if op == "RESCHEDULE":
        if not pre_interview_at_iso:
            raise ApiError("BAD_REQUEST", "Missing preInterviewAt")
        dt = parse_datetime_maybe(pre_interview_at_iso, app_timezone=cfg.APP_TIMEZONE)
        if not dt:
            raise ApiError("BAD_REQUEST", "Invalid preInterviewAt")
        pre_interview_at = to_iso_utc(dt)

        update_candidate(db, cand=cand, patch={"preCallAt": pre_interview_at, "preInterviewStatus": "SCHEDULED"}, auth=auth)
        append_audit(
            db,
            entityType="CANDIDATE",
            entityId=candidate_id,
            action="PREINTERVIEW_STATUS",
            fromState=current_status,
            toState=current_status,
            stageTag="PreInterview Reschedule",
            remark="",
            actor=auth,
            at=now,
            meta={"requirementId": requirement_id, "preInterviewAt": pre_interview_at},
        )
        return {"ok": True, "status": current_status, "preInterviewAt": pre_interview_at, "preInterviewStatus": "SCHEDULED"}

    if op == "REJECT":
        if not remark:
            raise ApiError("BAD_REQUEST", "Remark required")
        return reject_candidate_with_meta(
            db,
            candidate_id=candidate_id,
            requirement_id=requirement_id,
            stage_tag="PreInterview Reject",
            remark=remark,
            reason_code="PREINTERVIEW_REJECT",
            auth=auth,
            audit_action="PREINTERVIEW_STATUS",
        )

    raise ApiError("BAD_REQUEST", "Invalid op")


def preinterview_marks_save(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    marks = (data or {}).get("marks") if isinstance(data, dict) else ""

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status == "REJECTED":
        raise ApiError("BAD_REQUEST", "Candidate rejected")

    current_pi_status = str(cand.preInterviewStatus or "").upper()
    if current_pi_status != "APPEARED":
        raise ApiError("BAD_REQUEST", "Candidate not marked Appeared")

    now = iso_utc_now()
    marks_val = "" if marks is None or marks == "" else str(marks)
    update_candidate(db, cand=cand, patch={"preInterviewMarks": marks_val, "preInterviewMarksAt": now}, auth=auth)

    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="PREINTERVIEW_MARKS_SAVE",
        fromState=current_status,
        toState=current_status,
        stageTag="PreInterview Marks Save",
        remark="" if marks_val == "" else str(marks_val),
        actor=auth,
        at=now,
        meta={"requirementId": requirement_id},
    )
    return {"ok": True, "status": current_status, "preInterviewMarks": marks_val, "preInterviewMarksAt": now}


def test_link_create(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status == "REJECTED":
        raise ApiError("BAD_REQUEST", "Candidate rejected")

    marks = getattr(cand, "preInterviewMarks", "")
    if marks is None or str(marks).strip() == "":
        raise ApiError("BAD_REQUEST", "Save marks first")

    submitted_at = str(getattr(cand, "onlineTestSubmittedAt", "") or "").strip()
    if submitted_at:
        raise ApiError("CONFLICT", "Online test already submitted")

    submitted_row = db.execute(
        select(OnlineTest).where(
            OnlineTest.candidateId == str(cand.candidateId or ""),
            OnlineTest.requirementId == str(cand.requirementId or ""),
            func.upper(OnlineTest.status) == "SUBMITTED",
        )
    ).scalar_one_or_none()
    if submitted_row:
        raise ApiError("CONFLICT", "Online test already submitted")

    now_dt = datetime.now(timezone.utc)
    now_iso = iso_utc_now()
    expires_iso = to_iso_utc(now_dt + timedelta(days=1))
    token = "TST-" + os.urandom(16).hex()

    update_candidate(db, cand=cand, patch={"testToken": token, "testTokenExpiresAt": expires_iso}, auth=auth)
    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="TEST_LINK_CREATE",
        fromState=current_status,
        toState=current_status,
        stageTag="TEST_LINK_CREATE",
        remark="",
        actor=auth,
        at=now_iso,
        meta={"requirementId": requirement_id, "tokenPrefix": token[:8], "expiresAt": expires_iso},
    )

    return {"ok": True, "token": token, "expiresAt": expires_iso}


def test_token_validate(data, auth: AuthContext | None, db, cfg):
    token = str((data or {}).get("token") or "").strip()
    v = _public_validate_test_token(db, token, cfg)
    if not v.valid:
        out = {"valid": False, "reason": v.reason}
        if v.reason == "EXPIRED":
            out.update({"expiresAt": v.expiresAt, "candidateId": v.candidateId, "requirementId": v.requirementId})
        return out

    return {
        "valid": True,
        "expiresAt": v.expiresAt,
        "candidateId": v.candidateId,
        "requirementId": v.requirementId,
        "submitted": bool(v.submitted),
    }


def test_questions_get(data, auth: AuthContext | None, db, cfg):
    token = str((data or {}).get("token") or "").strip()
    v = _public_validate_test_token(db, token, cfg)
    if not v.valid:
        raise ApiError("BAD_REQUEST", v.reason)

    cand = db.execute(select(Candidate).where(Candidate.testToken == token)).scalar_one_or_none()
    if not cand:
        raise ApiError("BAD_REQUEST", "INVALID_TOKEN")

    test_row = db.execute(select(OnlineTest).where(OnlineTest.token == token)).scalar_one_or_none()
    if not test_row:
        now = iso_utc_now()
        test_row = OnlineTest(
            testId="TSTROW-" + os.urandom(16).hex(),
            token=token,
            candidateId=str(cand.candidateId or ""),
            requirementId=str(cand.requirementId or ""),
            issuedAt=now,
            expiresAt=str(getattr(cand, "testTokenExpiresAt", "") or ""),
            status="ISSUED",
            fullName="",
            applyingFor="",
            source="",
            questionsJson="",
            answersJson="",
            score=None,
            result="",
            submittedAt="",
            updatedAt=now,
        )
        db.add(test_row)

    if str(getattr(test_row, "status", "") or "").upper() == "SUBMITTED":
        return {"alreadySubmitted": True}

    questions = _parse_json_list(getattr(test_row, "questionsJson", "") or "")
    if not questions:
        questions = _make_question_set()
        test_row.questionsJson = json.dumps(questions)
        test_row.updatedAt = iso_utc_now()

    public_questions: list[dict[str, Any]] = []
    for x in questions:
        if not isinstance(x, dict):
            continue
        public_questions.append(
            {
                "id": x.get("id"),
                "prompt": x.get("prompt"),
                "type": x.get("type") or "text",
                "weight": int(_normalize_number(x.get("weight")) or 1),
            }
        )

    return {
        "expiresAt": v.expiresAt,
        "candidateId": v.candidateId,
        "requirementId": v.requirementId,
        "fixed": {"fullName": "", "applyingFor": "", "source": ""},
        "questions": public_questions,
    }


def _upsert_fail_candidate(
    db,
    *,
    candidate_id: str,
    requirement_id: str,
    stage_name: str,
    reason: str,
    score: int | None,
    failed_at: str,
    actor: AuthContext | None,
    meta: dict[str, Any] | None = None,
):
    stage_u = str(stage_name or "").upper().strip()
    if not stage_u:
        return

    row = (
        db.execute(
            select(FailCandidate)
            .where(FailCandidate.candidateId == candidate_id)
            .where(func.upper(FailCandidate.stageName) == stage_u)
            .where(FailCandidate.resolvedAt == "")
            .order_by(FailCandidate.failedAt.desc())
        )
        .scalars()
        .first()
    )
    meta_json = safe_json_string(meta or {}, "{}")

    if row:
        row.requirementId = str(requirement_id or "")
        row.reason = str(reason or "")
        row.score = int(score) if score is not None else None
        row.failedAt = str(failed_at or "")
        row.actorUserId = str(actor.userId if actor else "SYSTEM")
        row.actorRole = str(actor.role if actor else "SYSTEM")
        row.metaJson = meta_json
        return

    db.add(
        FailCandidate(
            candidateId=str(candidate_id or ""),
            requirementId=str(requirement_id or ""),
            stageName=stage_u,
            reason=str(reason or ""),
            score=int(score) if score is not None else None,
            failedAt=str(failed_at or ""),
            actorUserId=str(actor.userId if actor else "SYSTEM"),
            actorRole=str(actor.role if actor else "SYSTEM"),
            resolvedAt="",
            resolvedBy="",
            resolution="",
            metaJson=meta_json,
        )
    )


def _resolve_fail_candidate(
    db,
    *,
    candidate_id: str,
    stage_name: str,
    resolution: str,
    resolved_at: str,
    resolved_by: str,
):
    stage_u = str(stage_name or "").upper().strip()
    if not stage_u:
        return
    row = (
        db.execute(
            select(FailCandidate)
            .where(FailCandidate.candidateId == candidate_id)
            .where(func.upper(FailCandidate.stageName) == stage_u)
            .where(FailCandidate.resolvedAt == "")
            .order_by(FailCandidate.failedAt.desc())
        )
        .scalars()
        .first()
    )
    if not row:
        return
    row.resolvedAt = str(resolved_at or "")
    row.resolvedBy = str(resolved_by or "")
    row.resolution = str(resolution or "").upper().strip()


def _has_open_fail_candidate(db, *, candidate_id: str, stage_name: str) -> bool:
    cid = str(candidate_id or "").strip()
    stage_u = str(stage_name or "").upper().strip()
    if not cid or not stage_u:
        return False
    row = (
        db.execute(
            select(FailCandidate.id)
            .where(FailCandidate.candidateId == cid)
            .where(func.upper(FailCandidate.stageName) == stage_u)
            .where(FailCandidate.resolvedAt == "")
        )
        .scalars()
        .first()
    )
    return bool(row)


def test_submit_public(data, auth: AuthContext | None, db, cfg):
    token = str((data or {}).get("token") or "").strip()
    if not token:
        raise ApiError("BAD_REQUEST", "MISSING_TOKEN")

    cand = db.execute(select(Candidate).where(Candidate.testToken == token)).scalar_one_or_none()
    if not cand:
        raise ApiError("BAD_REQUEST", "INVALID_TOKEN")

    expires_at = str(getattr(cand, "testTokenExpiresAt", "") or "")
    if expires_at and _is_expired(expires_at, cfg=cfg):
        raise ApiError("BAD_REQUEST", "EXPIRED")

    test_row = db.execute(select(OnlineTest).where(OnlineTest.token == token)).scalar_one_or_none()
    if not test_row:
        now = iso_utc_now()
        test_row = OnlineTest(
            testId="TSTROW-" + os.urandom(16).hex(),
            token=token,
            candidateId=str(cand.candidateId or ""),
            requirementId=str(cand.requirementId or ""),
            issuedAt=now,
            expiresAt=expires_at,
            status="ISSUED",
            fullName="",
            applyingFor="",
            source="",
            questionsJson="",
            answersJson="",
            score=None,
            result="",
            submittedAt="",
            updatedAt=now,
        )
        db.add(test_row)

    if str(getattr(test_row, "status", "") or "").upper() == "SUBMITTED":
        raise ApiError("BAD_REQUEST", "ALREADY_SUBMITTED")

    full_name = str((data or {}).get("fullName") or "").strip()
    applying_for = str((data or {}).get("applyingFor") or "").strip()
    source = str((data or {}).get("source") or "").strip()
    answers = (data or {}).get("answers") or {}

    questions_json = str(getattr(test_row, "questionsJson", "") or "").strip()
    if not questions_json:
        raise ApiError("BAD_REQUEST", "QUESTIONS_NOT_READY")
    try:
        questions = json.loads(questions_json)
    except Exception:
        questions = None
    if not isinstance(questions, list) or len(questions) == 0:
        raise ApiError("BAD_REQUEST", "QUESTIONS_NOT_READY")

    score = 0
    total = 0
    for q in questions:
        if not isinstance(q, dict):
            continue
        w = int(_normalize_number(q.get("weight")) or 1)
        total += w

        user_raw = answers.get(q.get("id")) if isinstance(answers, dict) else None
        user_n = _normalize_number(user_raw)
        corr_n = _normalize_number(q.get("correct"))
        ok2 = False
        if user_n is not None and corr_n is not None:
            ok2 = abs(user_n - corr_n) <= 0.0001
        if ok2:
            score += w

    pass_marks = _get_setting_number(db, "ONLINE_TEST_PASS_MARK", 6)
    result = "PASS" if score >= pass_marks else "FAIL"
    now = iso_utc_now()

    test_row.status = "SUBMITTED"
    test_row.fullName = full_name
    test_row.applyingFor = applying_for
    test_row.source = source
    test_row.answersJson = json.dumps(answers or {})
    test_row.score = int(score)
    test_row.result = result
    test_row.submittedAt = now
    test_row.updatedAt = now

    append_audit(
        db,
        entityType="ONLINE_TEST",
        entityId=str(cand.candidateId or ""),
        action="TEST_SUBMIT_PUBLIC",
        fromState="",
        toState=result,
        stageTag="Online Test Submit",
        remark=f"Score {score}/{total}",
        actor=None,
        at=now,
        meta={"tokenPrefix": token[:8], "requirementId": str(cand.requirementId or "")},
    )

    system = AuthContext(valid=True, userId="SYSTEM", email="SYSTEM", role="SYSTEM", expiresAt="")
    update_candidate(
        db,
        cand=cand,
        patch={"onlineTestScore": int(score), "onlineTestResult": result, "onlineTestSubmittedAt": now},
        auth=system,
    )

    if result == "FAIL":
        _upsert_fail_candidate(
            db,
            candidate_id=str(cand.candidateId or ""),
            requirement_id=str(cand.requirementId or ""),
            stage_name="ONLINE_TEST",
            reason=f"Online Test FAIL ({score}/{total}, pass ≥ {pass_marks})",
            score=int(score),
            failed_at=now,
            actor=system,
            meta={"passMark": pass_marks, "score": int(score), "total": int(total)},
        )
    else:
        _resolve_fail_candidate(
            db,
            candidate_id=str(cand.candidateId or ""),
            stage_name="ONLINE_TEST",
            resolution="AUTO_PASS",
            resolved_at=now,
            resolved_by="SYSTEM",
        )

    record_step_metric(
        db,
        requirement_id=str(cand.requirementId or ""),
        candidate_id=str(cand.candidateId or ""),
        step_name="ONLINE_TEST",
        start_ts=str(getattr(test_row, "issuedAt", "") or now),
        end_ts=now,
        actor=system,
    )

    return {"ok": True, "submittedAt": now}


def test_result_get(data, auth: AuthContext | None, db, cfg):
    token = str((data or {}).get("token") or "").strip()
    if not token:
        raise ApiError("BAD_REQUEST", "MISSING_TOKEN")

    test_row = db.execute(select(OnlineTest).where(OnlineTest.token == token)).scalar_one_or_none()
    if not test_row:
        raise ApiError("BAD_REQUEST", "NOT_FOUND")

    if str(getattr(test_row, "status", "") or "").upper() != "SUBMITTED":
        raise ApiError("BAD_REQUEST", "NOT_SUBMITTED")

    return {"ok": True, "submittedAt": getattr(test_row, "submittedAt", "") or ""}


# __PIPELINE_GEN_MARKER__


def joining_list(data, auth: AuthContext | None, db, cfg):
    count_only = bool((data or {}).get("countOnly"))
    can_pii = bool(getattr(cfg, "PII_ENC_KEY", "").strip()) and bool(auth and auth.valid) and str(getattr(auth, "role", "") or "").upper() in set(
        getattr(cfg, "PII_VIEW_ROLES", []) or []
    )
    req_map = None
    if not count_only:
        req_map = _get_requirements_map(db)

    rows = db.execute(select(Candidate).where(func.upper(Candidate.status).in_(["SELECTED", "JOINING"]))).scalars().all()
    items: list[dict[str, Any]] = []
    total = 0

    selected_at_by_cid: dict[str, str] = {}
    join_set_at_by_cid: dict[str, str] = {}
    if not count_only and rows:
        cand_ids = [str(getattr(c, "candidateId", "") or "").strip() for c in rows]
        cand_ids = [x for x in cand_ids if x]

        def _keep_earliest(mp: dict[str, str], cid: str, at: str) -> None:
            prev = mp.get(cid)
            if not prev or at < prev:
                mp[cid] = at

        if cand_ids:
            audits = (
                db.execute(
                    select(AuditLog)
                    .where(AuditLog.entityType == "CANDIDATE")
                    .where(AuditLog.entityId.in_(cand_ids))
                    .where(AuditLog.action.in_(["OWNER_FINAL_DECIDE", "JOINING_SET_DATE"]))
                )
                .scalars()
                .all()
            )
            for a in audits:
                cid = str(getattr(a, "entityId", "") or "").strip()
                at = str(getattr(a, "at", "") or "").strip()
                if not cid or not at:
                    continue
                action = str(getattr(a, "action", "") or "").upper().strip()
                to_state = str(getattr(a, "toState", "") or "").upper().strip()
                if action == "OWNER_FINAL_DECIDE" and to_state == "SELECTED":
                    _keep_earliest(selected_at_by_cid, cid, at)
                if action == "JOINING_SET_DATE" or to_state == "JOINING":
                    _keep_earliest(join_set_at_by_cid, cid, at)

    for c in rows:
        total += 1
        if count_only:
            continue
        requirement_id = str(c.requirementId or "").strip()
        rm = (req_map or {}).get(requirement_id, {}) if requirement_id else {}
        status_u = str(c.status or "").upper().strip()
        cid = str(c.candidateId or "").strip()
        stage_start = ""
        if status_u == "JOINING":
            stage_start = join_set_at_by_cid.get(cid) or selected_at_by_cid.get(cid) or ""
        elif status_u == "SELECTED":
            stage_start = selected_at_by_cid.get(cid) or ""
        if not stage_start:
            stage_start = str(c.updatedAt or c.createdAt or "")

        item = {
            "candidateId": c.candidateId,
            "requirementId": requirement_id,
            "candidateName": c.candidateName,
            "mobile": c.mobile,
            "jobRole": c.jobRole,
            "jobTitle": rm.get("jobTitle", "") if isinstance(rm, dict) else "",
            "status": c.status or "",
            "cvFileId": c.cvFileId,
            "cvFileName": c.cvFileName,
            "joiningAt": c.joiningAt or "",
            "docs": _parse_json_list(c.docsJson or ""),
            "docsCompleteAt": c.docsCompleteAt or "",
            "joinedAt": c.joinedAt or "",
            "sla": compute_sla(db, step_name="JOINING", start_ts=stage_start, app_timezone=cfg.APP_TIMEZONE),
            "docsSla": compute_sla(db, step_name="DOCS", start_ts=stage_start, app_timezone=cfg.APP_TIMEZONE),
            "updatedAt": c.updatedAt or "",
            "updatedBy": c.updatedBy or "",
        }
        if can_pii:
            name_full = decrypt_pii(getattr(c, "name_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{c.candidateId}:name")
            mobile_full = decrypt_pii(getattr(c, "mobile_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{c.candidateId}:mobile")
            if name_full:
                item["candidateNameFull"] = name_full
            if mobile_full:
                item["mobileFull"] = mobile_full

        items.append(item)

    items.sort(
        key=lambda x: parse_datetime_maybe(x.get("updatedAt") or "", app_timezone=cfg.APP_TIMEZONE)
        or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )

    if count_only:
        return {"items": [], "total": total}
    return {"items": items, "total": len(items)}


def joining_set_date(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    joining_at_iso = str((data or {}).get("joiningAt") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not joining_at_iso:
        raise ApiError("BAD_REQUEST", "Missing joiningAt")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    dt = parse_datetime_maybe(joining_at_iso, app_timezone=cfg.APP_TIMEZONE)
    if not dt:
        raise ApiError("BAD_REQUEST", "Invalid joiningAt")
    joining_at = to_iso_utc(dt)

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status not in {"SELECTED", "JOINING"}:
        raise ApiError("BAD_REQUEST", "Candidate not in Joining workflow")

    transition_candidate_status(
        db,
        candidate_id=candidate_id,
        requirement_id=requirement_id,
        to_status="JOINING",
        action="JOINING_SET_DATE",
        stage_tag="JOINING_SET_DATE",
        auth=auth,
        remark="",
        patch={"joiningAt": joining_at},
        require_from={"SELECTED", "JOINING"},
        meta={"joiningAt": joining_at},
    )

    return {"ok": True, "status": "JOINING", "joiningAt": joining_at}


def docs_upload(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    docs = (data or {}).get("docs") or []

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not isinstance(docs, list) or len(docs) == 0:
        raise ApiError("BAD_REQUEST", "Missing docs")
    if len(docs) > 10:
        raise ApiError("BAD_REQUEST", "Max 10 docs")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status not in {"SELECTED", "JOINING"}:
        raise ApiError("BAD_REQUEST", "Candidate not in Joining workflow")

    existing = _parse_json_list(cand.docsJson or "")
    uploaded: list[dict[str, Any]] = []

    mode = str(cfg.FILE_STORAGE_MODE or "").lower()
    if mode != "gas":
        os.makedirs(cfg.UPLOAD_DIR, exist_ok=True)
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    for i, d in enumerate(docs):
        d = d or {}
        filename = str(d.get("filename") or "").strip() or "doc"
        mime_type = str(d.get("mimeType") or "").strip() or "application/octet-stream"
        base64 = str(d.get("base64") or "").strip()
        doc_type = str(d.get("docType") or "").strip()

        if not base64:
            raise ApiError("BAD_REQUEST", f"Missing base64 for doc index {i}")

        safe_name = sanitize_filename(filename)
        type_part = sanitize_filename(doc_type) + "_" if doc_type else ""
        out_name = f"DOC_{requirement_id}_{candidate_id}_{type_part}{stamp}_{safe_name}"
        file_id = ""

        if mode == "gas":
            up = gas_upload_file(
                cfg=cfg,
                file_base64=base64,
                file_name=out_name,
                mime_type=mime_type,
                extra={
                    "requirementId": requirement_id,
                    "candidateId": candidate_id,
                    "docType": doc_type,
                    "sourceAction": "DOCS_UPLOAD",
                    "uploadedBy": auth.userId,
                },
            )
            file_id = str(up.get("fileId") or "").strip()
        else:
            bytes_ = decode_base64_to_bytes(base64)
            file_id = os.urandom(16).hex()
            out_path = os.path.join(cfg.UPLOAD_DIR, f"{file_id}_{out_name}")
            with open(out_path, "wb") as f:
                f.write(bytes_)

        uploaded.append(
            {
                "docType": doc_type or "",
                "fileId": file_id,
                "fileName": safe_name,
                "mimeType": mime_type,
                "uploadedAt": iso_utc_now(),
            }
        )

    next_docs = existing + uploaded
    update_candidate(db, cand=cand, patch={"docsJson": json.dumps(next_docs), "docsCompleteAt": ""}, auth=auth)

    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="DOCS_UPLOAD",
        fromState=current_status,
        toState=current_status,
        stageTag="DOCS_UPLOAD",
        remark=f"Uploaded {len(uploaded)} doc(s)",
        actor=auth,
        at=iso_utc_now(),
        meta={"requirementId": requirement_id, "count": len(uploaded)},
    )

    return {"ok": True, "uploaded": uploaded, "totalDocs": len(next_docs)}


def docs_complete(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    aadhaar = str((data or {}).get("aadhaar") or "").strip()
    dob = str((data or {}).get("dob") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status not in {"SELECTED", "JOINING"}:
        raise ApiError("BAD_REQUEST", "Candidate not in Joining workflow")

    docs = _parse_json_list(cand.docsJson or "")
    if not docs:
        raise ApiError("BAD_REQUEST", "No docs uploaded")

    required = [
        ("AADHAR_CARD", "Aadhar Card"),
        ("PAN_CARD", "Pan Card"),
        ("BANK_PASSBOOK", "Bank Passbook"),
        ("EDUCATION_CERTIFICATE", "Education Certificate"),
        ("PREV_COMPANY_DOCS", "Previous Company offer letter / Experience letter / Resign letter (Approved)"),
        ("SALARY_STATEMENT_6M", "Last Six Months Salary Statement"),
        ("ESI_FAMILY_AADHAR_PHOTOS", "ESI: Father/Mother/Children/Wife Aadhar + Passport size photos"),
        ("PASSPORT_PHOTOS_4", "4 Passport size photo"),
    ]
    required_keys = {k for k, _ in required}
    label_to_key = {lbl.upper().strip(): k for k, lbl in required}

    def _infer_doc_type(doc_type: Any, file_name: Any) -> str:
        dt_raw = str(doc_type or "").strip()
        if dt_raw:
            dt_u = dt_raw.upper().strip()
            if dt_u in required_keys:
                return dt_u
            if dt_u in label_to_key:
                return label_to_key[dt_u]
            return dt_u

        fn = str(file_name or "").lower()
        if not fn:
            return ""
        if "aadhar" in fn or "adhar" in fn:
            return "AADHAR_CARD"
        if re.search(r"\bpan\b", fn):
            return "PAN_CARD"
        if "passbook" in fn or ("bank" in fn and "passbook" in fn):
            return "BANK_PASSBOOK"
        if "education" in fn or "certificate" in fn:
            return "EDUCATION_CERTIFICATE"
        if "offer" in fn or "experience" in fn or "resign" in fn:
            return "PREV_COMPANY_DOCS"
        if "salary" in fn and ("statement" in fn or "6" in fn or "six" in fn or "month" in fn):
            return "SALARY_STATEMENT_6M"
        if "esi" in fn:
            return "ESI_FAMILY_AADHAR_PHOTOS"
        if "passport" in fn or "photo" in fn:
            return "PASSPORT_PHOTOS_4"
        return ""

    present: set[str] = set()
    for d in docs:
        if not isinstance(d, dict):
            continue
        dt = _infer_doc_type(d.get("docType"), d.get("fileName") or "")
        if dt in required_keys:
            present.add(dt)

    missing_labels = [lbl for k, lbl in required if k not in present]
    if missing_labels:
        raise ApiError("BAD_REQUEST", f"Missing required docs: {', '.join(missing_labels)}")

    now = iso_utc_now()
    patch: dict[str, Any] = {"docsCompleteAt": now}

    # Optional: capture Aadhaar+DOB uniqueness hash at joining time (never store full Aadhaar/DOB).
    if aadhaar or dob:
        from services.identity_hash import aadhaar_dob_hash, aadhaar_last4

        salt = str(getattr(cfg, "SERVER_SALT", "") or getattr(cfg, "PEPPER", "") or "").strip()
        h = aadhaar_dob_hash(aadhaar=aadhaar, dob=dob, salt=salt)
        last4 = aadhaar_last4(aadhaar)

        existing_emp = db.execute(select(Employee).where(Employee.aadhaar_dob_hash == h)).scalar_one_or_none()
        if existing_emp:
            raise ApiError("CONFLICT", "Duplicate employee identity detected", http_status=409)

        patch["aadhaar_last4"] = last4
        patch["aadhaar_dob_hash"] = h

    update_candidate(db, cand=cand, patch=patch, auth=auth)
    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="DOCS_COMPLETE",
        fromState=current_status,
        toState=current_status,
        stageTag="DOCS_COMPLETE",
        remark="",
        actor=auth,
        at=now,
        meta={"requirementId": requirement_id, "aadhaarCaptured": bool(patch.get("aadhaar_dob_hash"))},
    )

    return {"ok": True, "status": current_status, "docsCompleteAt": now}


def _increment_requirement_joined_count(db, requirement_id: str, auth: AuthContext) -> dict[str, Any]:
    req = (
        db.execute(select(Requirement).where(Requirement.requirementId == requirement_id).with_for_update(of=Requirement))
        .scalars()
        .first()
    )
    if not req:
        raise ApiError("NOT_FOUND", "Requirement not found")

    required_count = int(req.requiredCount or 0)
    joined_count = int(req.joinedCount or 0)
    if required_count <= 0:
        raise ApiError("BAD_REQUEST", "Invalid requiredCount")
    if joined_count < 0:
        joined_count = 0
    if joined_count >= required_count:
        raise ApiError("BAD_REQUEST", "Requirement already filled")

    now = iso_utc_now()
    next_joined = joined_count + 1
    req.joinedCount = next_joined
    req.updatedAt = now
    req.updatedBy = auth.userId

    append_requirement_history(
        db,
        requirementId=requirement_id,
        fromStatus="",
        toStatus="",
        stageTag="JOINED_COUNT_INC",
        remark="",
        actor=auth,
        meta={"joinedCount": next_joined, "requiredCount": required_count},
    )
    append_audit(
        db,
        entityType="REQUIREMENT",
        entityId=requirement_id,
        action="JOINED_COUNT_INC",
        fromState="",
        toState="",
        stageTag="JOINED_COUNT_INC",
        remark="",
        actor=auth,
        at=now,
        meta={"joinedCount": next_joined, "requiredCount": required_count},
    )

    status = str(req.status or "").upper()
    auto_closed = False
    if next_joined == required_count and status != "CLOSED":
        req.status = "CLOSED"
        req.latestRemark = "Auto closed (JoinedCount reached RequiredCount)"
        req.updatedAt = now
        req.updatedBy = auth.userId

        append_requirement_history(
            db,
            requirementId=requirement_id,
            fromStatus=status,
            toStatus="CLOSED",
            stageTag="REQUIREMENT_AUTO_CLOSE",
            remark="Auto closed",
            actor=auth,
            meta={"joinedCount": next_joined, "requiredCount": required_count},
        )
        append_audit(
            db,
            entityType="REQUIREMENT",
            entityId=requirement_id,
            action="REQUIREMENT_AUTO_CLOSE",
            fromState=status,
            toState="CLOSED",
            stageTag="REQUIREMENT_AUTO_CLOSE",
            remark="Auto closed",
            actor=auth,
            at=now,
            meta={"joinedCount": next_joined, "requiredCount": required_count},
        )
        status = "CLOSED"
        auto_closed = True

    return {
        "ok": True,
        "requirementId": requirement_id,
        "joinedCount": next_joined,
        "requiredCount": required_count,
        "status": status,
        "autoClosed": auto_closed,
    }


def mark_join(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    remark = str((data or {}).get("remark") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status != "JOINING":
        raise ApiError("BAD_REQUEST", "Candidate not in JOINING")
    if not str(cand.joiningAt or "").strip():
        raise ApiError("BAD_REQUEST", "Set joining date first")
    if not str(cand.docsCompleteAt or "").strip():
        raise ApiError("BAD_REQUEST", "Docs not complete")

    now = iso_utc_now()
    _cand2, inc = transition_candidate_status(
        db,
        candidate_id=candidate_id,
        requirement_id=requirement_id,
        to_status="JOINED",
        action="MARK_JOIN",
        stage_tag="MARK_JOIN",
        auth=auth,
        remark=remark or "",
        patch={"joinedAt": now},
        require_from={"JOINING"},
    )

    append_join_log(
        db,
        candidateId=candidate_id,
        requirementId=requirement_id,
        action="MARK_JOIN",
        stageTag="MARK_JOIN",
        remark=remark or "",
        actor=auth,
    )

    inc = inc or {}
    return {
        "ok": True,
        "status": "JOINED",
        "joinedAt": now,
        "requirement": {
            "requirementId": requirement_id,
            "joinedCount": inc.get("joinedCount"),
            "requiredCount": inc.get("requiredCount"),
            "status": inc.get("status"),
            "autoClosed": inc.get("autoClosed"),
        },
    }


def requirement_auto_close(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    req = (
        db.execute(select(Requirement).where(Requirement.requirementId == requirement_id).with_for_update(of=Requirement))
        .scalars()
        .first()
    )
    if not req:
        raise ApiError("NOT_FOUND", "Requirement not found")

    required_count = int(req.requiredCount or 0)
    joined_count = int(req.joinedCount or 0)
    current_status = str(req.status or "").upper()
    if required_count <= 0:
        raise ApiError("BAD_REQUEST", "Invalid requiredCount")
    if joined_count < 0:
        joined_count = 0

    if current_status == "CLOSED":
        return {"ok": True, "requirementId": requirement_id, "closed": True, "status": "CLOSED", "joinedCount": joined_count, "requiredCount": required_count}
    if joined_count != required_count:
        return {"ok": True, "requirementId": requirement_id, "closed": False, "status": current_status, "joinedCount": joined_count, "requiredCount": required_count}

    now = iso_utc_now()
    req.status = "CLOSED"
    req.latestRemark = "Auto closed (JoinedCount reached RequiredCount)"
    req.updatedAt = now
    req.updatedBy = auth.userId

    append_requirement_history(
        db,
        requirementId=requirement_id,
        fromStatus=current_status,
        toStatus="CLOSED",
        stageTag="REQUIREMENT_AUTO_CLOSE",
        remark="Auto closed",
        actor=auth,
        meta={"joinedCount": joined_count, "requiredCount": required_count},
    )
    append_audit(
        db,
        entityType="REQUIREMENT",
        entityId=requirement_id,
        action="REQUIREMENT_AUTO_CLOSE",
        fromState=current_status,
        toState="CLOSED",
        stageTag="REQUIREMENT_AUTO_CLOSE",
        remark="Auto closed",
        actor=auth,
        at=now,
        meta={"joinedCount": joined_count, "requiredCount": required_count},
    )

    return {"ok": True, "requirementId": requirement_id, "closed": True, "status": "CLOSED", "joinedCount": joined_count, "requiredCount": required_count}



def final_interview_list(data, auth: AuthContext | None, db, cfg):
    count_only = bool((data or {}).get("countOnly"))
    limit_raw = (data or {}).get("limit") if isinstance(data, dict) else None
    offset_raw = (data or {}).get("offset") if isinstance(data, dict) else None

    limit = None
    if limit_raw is not None and limit_raw != "":
        try:
            limit = int(limit_raw)
        except Exception:
            raise ApiError("BAD_REQUEST", "Invalid limit", http_status=400)
        limit = max(1, min(500, limit))

    offset = 0
    if offset_raw is not None and offset_raw != "":
        try:
            offset = int(offset_raw)
        except Exception:
            raise ApiError("BAD_REQUEST", "Invalid offset", http_status=400)
        offset = max(0, offset)

    can_pii = bool(getattr(cfg, "PII_ENC_KEY", "").strip()) and bool(auth and auth.valid) and str(getattr(auth, "role", "") or "").upper() in set(
        getattr(cfg, "PII_VIEW_ROLES", []) or []
    )

    excluded = {"SELECTED", "JOINING", "JOINED", "PROBATION", "EMPLOYEE", "FINAL_HOLD"}

    # Push the expensive filters into SQL first (status blocks, required-tests approval, unresolved online-fail blocks).
    open_online_fail_exists = (
        select(1)
        .select_from(FailCandidate)
        .where(FailCandidate.candidateId == Candidate.candidateId)
        .where(func.upper(FailCandidate.stageName) == "ONLINE_TEST")
        .where(FailCandidate.resolvedAt == "")
        .exists()
    )

    required_not_approved_exists = (
        select(1)
        .select_from(CandidateTest)
        .where(CandidateTest.candidateId == Candidate.candidateId)
        .where(CandidateTest.isRequired == True)  # noqa: E712
        .where(func.upper(CandidateTest.status) != "APPROVED")
        .exists()
    )

    base = (
        select(Candidate, Requirement.jobTitle, Requirement.jobRole)
        .join(Requirement, Requirement.requirementId == Candidate.requirementId, isouter=True)
        .where(Candidate.status != "REJECTED")
        .where(~Candidate.status.in_(sorted(excluded)))
        .where(Candidate.inPersonMarks.isnot(None))
        .where(~open_online_fail_exists)
        .where(~required_not_approved_exists)
        .order_by(Candidate.techEvaluatedAt.desc(), Candidate.updatedAt.desc(), Candidate.candidateId.asc())
    )

    if count_only:
        total = 0
        for c, _jt, _jr in db.execute(base):
            online_res = str(c.onlineTestResult or "").upper().strip()
            if online_res and online_res != "PASS" and not (online_res == "FAIL" and is_test_continued(c, "ONLINE_TEST")):
                continue

            marks = c.inPersonMarks
            if marks is None:
                continue
            if int(marks) < 6 and not is_test_continued(c, "INPERSON_MARKS"):
                continue

            total += 1
        return {"items": [], "total": total}

    q = base
    if limit is not None:
        q = q.limit(limit).offset(offset)
    elif offset > 0:
        q = q.offset(offset)

    items: list[dict[str, Any]] = []
    for c, job_title, req_job_role in db.execute(q):
        online_res = str(c.onlineTestResult or "").upper().strip()
        if online_res and online_res != "PASS" and not (online_res == "FAIL" and is_test_continued(c, "ONLINE_TEST")):
            continue

        marks = c.inPersonMarks
        if marks is None:
            continue
        if int(marks) < 6 and not is_test_continued(c, "INPERSON_MARKS"):
            continue

        job_role = str(c.jobRole or req_job_role or "").strip()
        item = {
            "candidateId": c.candidateId,
            "requirementId": str(c.requirementId or ""),
            "candidateName": c.candidateName,
            "mobile": c.mobile,
            "jobRole": job_role,
            "jobTitle": str(job_title or ""),
            "cvFileId": c.cvFileId or "",
            "cvFileName": c.cvFileName or "",
            "status": c.status or "",
            "inPersonMarks": c.inPersonMarks or "",
            "techSelectedTests": c.techSelectedTestsJson or "",
            "tallyMarks": c.tallyMarks or "",
            "voiceMarks": c.voiceMarks or "",
            "techReview": c.techReview or "",
            "excelMarks": c.excelMarks or "",
            "excelReview": c.excelReview or "",
            "techEvaluatedAt": c.techEvaluatedAt or "",
            "testDecisionsJson": c.testDecisionsJson or "",
            "candidate_test_failed_but_manually_continued": bool(c.candidate_test_failed_but_manually_continued) or False,
            "sla": compute_sla(
                db,
                step_name="FINAL_INTERVIEW",
                start_ts=str(c.techEvaluatedAt or c.updatedAt or ""),
                app_timezone=cfg.APP_TIMEZONE,
            ),
        }
        if can_pii:
            name_full = decrypt_pii(getattr(c, "name_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{c.candidateId}:name")
            mobile_full = decrypt_pii(getattr(c, "mobile_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{c.candidateId}:mobile")
            if name_full:
                item["candidateNameFull"] = name_full
            if mobile_full:
                item["mobileFull"] = mobile_full

        items.append(item)

    return {"items": items, "total": len(items)}


def final_send_owner(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status == "REJECTED":
        raise ApiError("BAD_REQUEST", "Candidate is rejected")
    if current_status == "FINAL_OWNER_PENDING":
        return {"ok": True, "status": "FINAL_OWNER_PENDING"}

    if _has_open_fail_candidate(db, candidate_id=candidate_id, stage_name="ONLINE_TEST"):
        raise ApiError("BAD_REQUEST", "Candidate not allowed for final (online test failed)")

    online_res = str(cand.onlineTestResult or "").upper()
    if online_res and online_res != "PASS" and not (online_res == "FAIL" and is_test_continued(cand, "ONLINE_TEST")):
        raise ApiError("BAD_REQUEST", "Candidate not allowed for final (online test not cleared)")

    marks = cand.inPersonMarks
    if marks is None:
        raise ApiError("BAD_REQUEST", "Candidate not allowed for final (in-person marks missing)")
    if int(marks) < 6 and not is_test_continued(cand, "INPERSON_MARKS"):
        raise ApiError("BAD_REQUEST", "Candidate not allowed for final (in-person marks not cleared)")

    if not required_tests_approved(db, candidate_id=candidate_id):
        raise ApiError("BAD_REQUEST", "Candidate not allowed for final (required tests not approved)")

    transition_candidate_status(
        db,
        candidate_id=candidate_id,
        requirement_id=requirement_id,
        to_status="FINAL_OWNER_PENDING",
        action="FINAL_SEND_OWNER",
        stage_tag="FINAL_SEND_OWNER",
        auth=auth,
        remark="",
        meta={"requirementId": requirement_id},
    )

    return {"ok": True, "status": "FINAL_OWNER_PENDING"}


def hr_final_hold_list(data, auth: AuthContext | None, db, cfg):
    count_only = bool((data or {}).get("countOnly"))
    can_pii = bool(getattr(cfg, "PII_ENC_KEY", "").strip()) and bool(auth and auth.valid) and str(getattr(auth, "role", "") or "").upper() in set(
        getattr(cfg, "PII_VIEW_ROLES", []) or []
    )
    req_map = None
    if not count_only:
        req_map = _get_requirements_map(db)

    rows = db.execute(select(Candidate).where(func.upper(Candidate.status) == "FINAL_HOLD")).scalars().all()
    items: list[dict[str, Any]] = []
    total = 0

    for c in rows:
        total += 1
        if count_only:
            continue

        requirement_id = str(c.requirementId or "")
        rm = (req_map or {}).get(requirement_id, {}) if requirement_id else {}
        item = {
            "candidateId": c.candidateId,
            "requirementId": requirement_id,
            "candidateName": c.candidateName,
            "mobile": c.mobile,
            "jobRole": c.jobRole,
            "jobTitle": rm.get("jobTitle", "") if isinstance(rm, dict) else "",
            "status": c.status or "",
            "cvFileId": c.cvFileId,
            "cvFileName": c.cvFileName,
            "finalHoldAt": c.finalHoldAt or "",
            "finalHoldRemark": c.finalHoldRemark or "",
            "sla": compute_sla(
                db,
                step_name="FINAL_INTERVIEW",
                start_ts=str(c.finalHoldAt or c.updatedAt or ""),
                app_timezone=cfg.APP_TIMEZONE,
            ),
            "updatedAt": c.updatedAt or "",
            "updatedBy": c.updatedBy or "",
        }
        if can_pii:
            name_full = decrypt_pii(getattr(c, "name_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{c.candidateId}:name")
            mobile_full = decrypt_pii(getattr(c, "mobile_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{c.candidateId}:mobile")
            if name_full:
                item["candidateNameFull"] = name_full
            if mobile_full:
                item["mobileFull"] = mobile_full

        items.append(item)

    items.sort(
        key=lambda x: parse_datetime_maybe(x.get("updatedAt") or "", app_timezone=cfg.APP_TIMEZONE)
        or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    if count_only:
        return {"items": [], "total": total}
    return {"items": items, "total": len(items)}


def hr_hold_schedule(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    final_hold_at_iso = str((data or {}).get("finalHoldAt") or "").strip()
    remark = str((data or {}).get("remark") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not final_hold_at_iso:
        raise ApiError("BAD_REQUEST", "Missing finalHoldAt")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    dt = parse_datetime_maybe(final_hold_at_iso, app_timezone=cfg.APP_TIMEZONE)
    if not dt:
        raise ApiError("BAD_REQUEST", "Invalid finalHoldAt")
    final_hold_at = to_iso_utc(dt)

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status != "FINAL_HOLD":
        raise ApiError("BAD_REQUEST", "Candidate not in Final Hold")

    update_candidate(
        db,
        cand=cand,
        patch={"finalHoldAt": final_hold_at, "finalHoldRemark": remark or (cand.finalHoldRemark or "")},
        auth=auth,
    )
    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="HR_HOLD_SCHEDULE",
        fromState=current_status,
        toState=current_status,
        stageTag="Final Hold",
        remark=remark or "",
        actor=auth,
        at=iso_utc_now(),
        meta={"requirementId": requirement_id, "finalHoldAt": final_hold_at},
    )

    return {"ok": True, "status": current_status, "finalHoldAt": final_hold_at}


def auto_reject_final_noshow(data, auth: AuthContext | None, db, cfg):
    rows = db.execute(select(Candidate)).scalars().all()
    scanned = len(rows)
    now_dt = datetime.now(timezone.utc)
    now_iso = iso_utc_now()
    rejected = 0

    for c in rows:
        if str(c.status or "").upper() != "FINAL_HOLD":
            continue
        hold_at_raw = str(c.finalHoldAt or "").strip()
        if not hold_at_raw:
            continue
        hold_at = parse_datetime_maybe(hold_at_raw, app_timezone=cfg.APP_TIMEZONE)
        if not hold_at:
            continue
        if hold_at > now_dt:
            continue
        try:
            res = reject_candidate_with_meta(
                db,
                candidate_id=str(c.candidateId or ""),
                requirement_id=str(c.requirementId or ""),
                stage_tag="Final Hold No-show",
                remark="Auto rejected (Final Hold No-show)",
                reason_code="FINAL_NOSHOW",
                auth=None,
            )
            if res and res.get("ok"):
                rejected += 1
        except Exception:
            pass

    return {"scanned": scanned, "rejected": rejected, "at": now_iso}


# __PIPELINE_GEN_MARKER__

def tech_pending_list(data, auth: AuthContext | None, db, cfg):
    count_only = bool((data or {}).get("countOnly"))
    limit_raw = (data or {}).get("limit") if isinstance(data, dict) else None
    offset_raw = (data or {}).get("offset") if isinstance(data, dict) else None

    limit = None
    if limit_raw is not None and limit_raw != "":
        try:
            limit = int(limit_raw)
        except Exception:
            raise ApiError("BAD_REQUEST", "Invalid limit", http_status=400)
        limit = max(1, min(500, limit))

    offset = 0
    if offset_raw is not None and offset_raw != "":
        try:
            offset = int(offset_raw)
        except Exception:
            raise ApiError("BAD_REQUEST", "Invalid offset", http_status=400)
        offset = max(0, offset)

    can_pii = bool(getattr(cfg, "PII_ENC_KEY", "").strip()) and bool(auth and auth.valid) and str(getattr(auth, "role", "") or "").upper() in set(
        getattr(cfg, "PII_VIEW_ROLES", []) or []
    )

    base = (
        select(Candidate, Requirement.jobTitle, Requirement.jobRole)
        .join(Requirement, Requirement.requirementId == Candidate.requirementId, isouter=True)
        .where(Candidate.status != "REJECTED")
        .where(func.upper(Candidate.onlineTestResult).in_(["PASS", "FAIL"]))
        .where(Candidate.inPersonMarks.isnot(None))
        .where(Candidate.techSelectedTestsJson != "")
        .where(func.upper(Candidate.techResult) != "PASS")
        .order_by(Candidate.candidateId.asc())
    )

    def _eligible(c: Candidate) -> bool:
        online_res = str(c.onlineTestResult or "").upper()
        if online_res == "FAIL" and not is_test_continued(c, "ONLINE_TEST"):
            return False

        in_marks = c.inPersonMarks
        if in_marks is None:
            return False
        if int(in_marks) < 6 and not is_test_continued(c, "INPERSON_MARKS"):
            return False

        tech_result = str(c.techResult or "").upper()
        if tech_result == "FAIL" and is_test_continued(c, "TECHNICAL"):
            return False

        return True

    if count_only:
        total = 0
        for c, _jt, _jr in db.execute(base):
            if _eligible(c):
                total += 1
        return {"items": [], "total": total}

    q = base
    if limit is not None:
        q = q.limit(limit).offset(offset)
    elif offset > 0:
        q = q.offset(offset)

    items: list[dict[str, Any]] = []
    for c, job_title, req_job_role in db.execute(q):
        if not _eligible(c):
            continue

        selected = _parse_json_list(str(c.techSelectedTestsJson or ""))
        job_role = str(c.jobRole or req_job_role or "").strip()
        item = {
            "candidateId": c.candidateId,
            "requirementId": str(c.requirementId or ""),
            "candidateName": c.candidateName,
            "mobile": c.mobile,
            "jobRole": job_role,
            "jobTitle": str(job_title or ""),
            "cvFileId": c.cvFileId or "",
            "cvFileName": c.cvFileName or "",
            "inPersonMarks": c.inPersonMarks or "",
            "selectedTests": selected,
            "techSelectedAt": c.techSelectedAt or "",
            "tallyMarks": c.tallyMarks or "",
            "voiceMarks": c.voiceMarks or "",
            "techReview": c.techReview or "",
            "excelMarks": c.excelMarks or "",
            "excelReview": c.excelReview or "",
            "techResult": c.techResult or "",
            "techEvaluatedAt": c.techEvaluatedAt or "",
            "testDecisionsJson": c.testDecisionsJson or "",
            "candidate_test_failed_but_manually_continued": bool(c.candidate_test_failed_but_manually_continued) or False,
            "sla": compute_sla(
                db,
                step_name="TECHNICAL",
                start_ts=str(c.techSelectedAt or c.updatedAt or ""),
                app_timezone=cfg.APP_TIMEZONE,
            ),
            "updatedAt": c.updatedAt or "",
            "updatedBy": c.updatedBy or "",
        }
        if can_pii:
            name_full = decrypt_pii(getattr(c, "name_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{c.candidateId}:name")
            mobile_full = decrypt_pii(getattr(c, "mobile_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{c.candidateId}:mobile")
            if name_full:
                item["candidateNameFull"] = name_full
            if mobile_full:
                item["mobileFull"] = mobile_full

        items.append(item)

    return {"items": items, "total": len(items)}


def ea_tech_marks_submit(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    review = str((data or {}).get("review") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")

    tally_raw = (data or {}).get("tallyMarks") if isinstance(data, dict) else None
    voice_raw = (data or {}).get("voiceMarks") if isinstance(data, dict) else None

    tally = None
    voice = None
    if tally_raw is not None:
        try:
            tally = float(tally_raw)
        except Exception:
            raise ApiError("BAD_REQUEST", "Invalid tallyMarks")
        if tally < 0 or tally > 10:
            raise ApiError("BAD_REQUEST", "Invalid tallyMarks")
    if voice_raw is not None:
        try:
            voice = float(voice_raw)
        except Exception:
            raise ApiError("BAD_REQUEST", "Invalid voiceMarks")
        if voice < 0 or voice > 10:
            raise ApiError("BAD_REQUEST", "Invalid voiceMarks")

    if not review:
        raise ApiError("BAD_REQUEST", "Test Review required")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    status = str(cand.status or "").upper()
    if status == "REJECTED":
        raise ApiError("BAD_REQUEST", "Candidate rejected")

    patch: dict[str, Any] = {"techReview": review}
    if tally is not None:
        patch["tallyMarks"] = int(tally)
    if voice is not None:
        patch["voiceMarks"] = int(voice)

    update_candidate(db, cand=cand, patch=patch, auth=auth)

    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="EA_TECH_MARKS_SUBMIT",
        fromState=status,
        toState=status,
        stageTag="EA Tech Marks Submit",
        remark=review,
        actor=auth,
        at=iso_utc_now(),
        meta={"requirementId": requirement_id, "tallyMarks": tally, "voiceMarks": voice, "review": review},
    )

    return passfail_evaluate({"requirementId": requirement_id, "candidateId": candidate_id}, auth, db, cfg)


def admin_excel_marks_submit(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    review = str((data or {}).get("review") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")

    excel_raw = (data or {}).get("excelMarks") if isinstance(data, dict) else None
    if excel_raw is None:
        raise ApiError("BAD_REQUEST", "Invalid excelMarks")
    try:
        excel = float(excel_raw)
    except Exception:
        raise ApiError("BAD_REQUEST", "Invalid excelMarks")
    if excel < 0 or excel > 10:
        raise ApiError("BAD_REQUEST", "Invalid excelMarks")
    if not review:
        raise ApiError("BAD_REQUEST", "Test Review required")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    status = str(cand.status or "").upper()
    if status == "REJECTED":
        raise ApiError("BAD_REQUEST", "Candidate rejected")

    update_candidate(db, cand=cand, patch={"excelMarks": int(excel), "excelReview": review}, auth=auth)
    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="ADMIN_EXCEL_MARKS_SUBMIT",
        fromState=status,
        toState=status,
        stageTag="Admin Excel Marks Submit",
        remark=review,
        actor=auth,
        at=iso_utc_now(),
        meta={"requirementId": requirement_id, "excelMarks": excel, "review": review},
    )

    return passfail_evaluate({"requirementId": requirement_id, "candidateId": candidate_id}, auth, db, cfg)


def _evaluate_technical(db, cand: Candidate) -> dict[str, Any]:
    selected = _parse_json_list(cand.techSelectedTestsJson or "")
    if not selected:
        return {"state": "NO_SELECTION", "selected": []}

    thresholds = {
        "Tally": _get_setting_number(db, "TALLY_PASS_MARK", 6),
        "Voice": _get_setting_number(db, "VOICE_PASS_MARK", 6),
        "Excel": _get_setting_number(db, "EXCEL_PASS_MARK", 6),
    }
    marks_map = {"Tally": cand.tallyMarks, "Voice": cand.voiceMarks, "Excel": cand.excelMarks}

    missing: list[str] = []
    failed: list[dict[str, Any]] = []
    for t in selected:
        tt = str(t or "").strip()
        if not tt:
            continue
        th = float(thresholds.get(tt, 6))
        m = marks_map.get(tt)
        if m is None or str(m).strip() == "":
            missing.append(tt)
            continue
        try:
            mn = float(m)
        except Exception:
            missing.append(tt)
            continue
        if mn < th:
            failed.append({"test": tt, "marks": mn, "threshold": th})

    if missing:
        return {"state": "PENDING", "selected": selected, "missing": missing, "thresholds": thresholds}
    if failed:
        return {"state": "FAIL", "selected": selected, "failed": failed, "thresholds": thresholds}
    return {"state": "PASS", "selected": selected, "thresholds": thresholds}


def passfail_evaluate(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    status = str(cand.status or "").upper()
    if status == "REJECTED":
        return {"ok": True, "status": "REJECTED", "techResult": "FAIL"}

    eval_res = _evaluate_technical(db, cand)
    now = iso_utc_now()

    if eval_res.get("state") == "PENDING":
        return {"ok": True, "status": status, "state": "PENDING", "missing": eval_res.get("missing"), "selected": eval_res.get("selected")}

    if eval_res.get("state") == "FAIL":
        update_candidate(db, cand=cand, patch={"techResult": "FAIL", "techEvaluatedAt": now}, auth=auth)
        failed = eval_res.get("failed") or []
        stage_tag = "Technical Tests"
        if isinstance(failed, list) and len(failed) == 1 and isinstance(failed[0], dict):
            stage_tag = f"{str(failed[0].get('test') or '')} Test".strip() or "Technical Tests"
        return {
            "ok": True,
            "status": status,
            "techResult": "FAIL",
            "failed": failed,
            "passFail": "FAIL",
            "decisionRequired": True,
            "testType": "TECHNICAL",
            "stageTag": stage_tag,
        }

    if eval_res.get("state") == "PASS":
        update_candidate(db, cand=cand, patch={"techResult": "PASS", "techEvaluatedAt": now}, auth=auth)
        append_audit(
            db,
            entityType="CANDIDATE",
            entityId=candidate_id,
            action="PASSFAIL_EVALUATE",
            fromState=status,
            toState=status,
            stageTag="Technical Pass",
            remark="",
            actor=auth,
            at=now,
            meta={"requirementId": requirement_id, "selected": eval_res.get("selected") or []},
        )
        return {"ok": True, "status": status, "techResult": "PASS", "selected": eval_res.get("selected") or [], "techEvaluatedAt": now}

    return {"ok": True, "status": status, "state": eval_res.get("state")}


def test_fail_decide(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    test_type = str((data or {}).get("testType") or "").strip()
    decision = str((data or {}).get("decision") or "").upper().strip()
    remark = str((data or {}).get("remark") or "").strip()
    stage_tag = str((data or {}).get("stageTag") or "").strip()
    meta = (data or {}).get("meta") or {}

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not test_type:
        raise ApiError("BAD_REQUEST", "Missing testType")
    if decision not in {"CONTINUE", "REJECT"}:
        raise ApiError("BAD_REQUEST", "Invalid decision")
    if decision == "REJECT" and not remark:
        raise ApiError("BAD_REQUEST", "Remark required")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    status = str(cand.status or "").upper()
    if status == "REJECTED":
        raise ApiError("BAD_REQUEST", "Candidate rejected")

    if not stage_tag:
        if test_type == "ONLINE_TEST":
            stage_tag = "Online Test"
        elif test_type == "INPERSON_MARKS":
            stage_tag = "In-person Marks"
        elif test_type == "TECHNICAL":
            try:
                failed = meta.get("failed") if isinstance(meta, dict) else None
                if isinstance(failed, list) and len(failed) == 1 and isinstance(failed[0], dict):
                    stage_tag = f"{str(failed[0].get('test') or '')} Test".strip()
            except Exception:
                pass
            if not stage_tag:
                stage_tag = "Technical Tests"
        else:
            stage_tag = test_type

    decision_meta = {
        "stageTag": stage_tag,
        "marks": meta.get("marks") if isinstance(meta, dict) else "",
        "passFail": "FAIL",
        "failed": meta.get("failed") if isinstance(meta, dict) else None,
    }

    if decision == "CONTINUE":
        return upsert_test_decision(
            db,
            candidate_id=candidate_id,
            requirement_id=requirement_id,
            test_type=test_type,
            decision=decision,
            remark=remark,
            meta=decision_meta,
            auth=auth,
        )

    upsert_test_decision(
        db,
        candidate_id=candidate_id,
        requirement_id=requirement_id,
        test_type=test_type,
        decision=decision,
        remark=remark,
        meta=decision_meta,
        auth=auth,
    )

    reason_code = "TEST_FAIL_MANUAL"
    if test_type == "ONLINE_TEST":
        reason_code = "ONLINE_TEST_FAIL_MANUAL"
    elif test_type == "TECHNICAL":
        reason_code = "TECH_FAIL_MANUAL"
    elif test_type == "INPERSON_MARKS":
        reason_code = "INPERSON_FAIL_MANUAL"

    rej = reject_candidate_with_meta(
        db,
        candidate_id=candidate_id,
        requirement_id=requirement_id,
        stage_tag=stage_tag,
        remark=remark,
        reason_code=reason_code,
        auth=auth,
    )
    return {"ok": True, "decision": "REJECT", "status": "REJECTED", "rejectedReasonCode": reason_code, "rejection": rej}


# __PIPELINE_GEN_MARKER__

def inperson_pipeline_list(data, auth: AuthContext | None, db, cfg):
    job_role_filter = str((data or {}).get("jobRole") or "").strip()
    count_only = bool((data or {}).get("countOnly"))
    limit_raw = (data or {}).get("limit") if isinstance(data, dict) else None
    offset_raw = (data or {}).get("offset") if isinstance(data, dict) else None

    limit = None
    if limit_raw is not None and limit_raw != "":
        try:
            limit = int(limit_raw)
        except Exception:
            raise ApiError("BAD_REQUEST", "Invalid limit", http_status=400)
        limit = max(1, min(500, limit))

    offset = 0
    if offset_raw is not None and offset_raw != "":
        try:
            offset = int(offset_raw)
        except Exception:
            raise ApiError("BAD_REQUEST", "Invalid offset", http_status=400)
        offset = max(0, offset)

    can_pii = bool(getattr(cfg, "PII_ENC_KEY", "").strip()) and bool(auth and auth.valid) and str(getattr(auth, "role", "") or "").upper() in set(
        getattr(cfg, "PII_VIEW_ROLES", []) or []
    )

    excluded = {"FINAL_OWNER_PENDING", "FINAL_HOLD", "SELECTED", "JOINING", "JOINED", "PROBATION", "EMPLOYEE"}

    base = (
        select(Candidate, Requirement.jobTitle, Requirement.jobRole)
        .join(Requirement, Requirement.requirementId == Candidate.requirementId, isouter=True)
        .where(Candidate.status != "REJECTED")
        .where(~Candidate.status.in_(sorted(excluded)))
        .where(func.upper(Candidate.onlineTestResult).in_(["PASS", "FAIL"]))
        .order_by(Candidate.onlineTestSubmittedAt.desc(), Candidate.updatedAt.desc(), Candidate.candidateId.asc())
    )

    if job_role_filter:
        base = base.where(
            or_(
                Candidate.jobRole == job_role_filter,
                and_(Candidate.jobRole == "", Requirement.jobRole == job_role_filter),
            )
        )

    def _eligible(c: Candidate) -> bool:
        online_res = str(c.onlineTestResult or "").upper()
        if online_res == "FAIL" and not is_test_continued(c, "ONLINE_TEST"):
            return False
        return True

    if count_only:
        total = 0
        for c, _jt, _jr in db.execute(base):
            if _eligible(c):
                total += 1
        return {"items": [], "total": total}

    q = base
    if limit is not None:
        q = q.limit(limit).offset(offset)
    elif offset > 0:
        q = q.offset(offset)

    items: list[dict[str, Any]] = []
    for c, job_title, req_job_role in db.execute(q):
        if not _eligible(c):
            continue

        job_role = str(c.jobRole or req_job_role or "").strip()
        item = {
            "candidateId": c.candidateId,
            "requirementId": str(c.requirementId or ""),
            "candidateName": c.candidateName,
            "mobile": c.mobile,
            "source": c.source,
            "cvFileId": c.cvFileId or "",
            "cvFileName": c.cvFileName or "",
            "jobRole": job_role,
            "jobTitle": str(job_title or ""),
            "onlineTestScore": c.onlineTestScore or "",
            "onlineTestResult": c.onlineTestResult or "",
            "onlineTestSubmittedAt": c.onlineTestSubmittedAt or "",
            "testDecisionsJson": c.testDecisionsJson or "",
            "candidate_test_failed_but_manually_continued": bool(c.candidate_test_failed_but_manually_continued) or False,
            "inPersonMarks": c.inPersonMarks or "",
            "inPersonMarksAt": c.inPersonMarksAt or "",
            "techSelectedTests": _parse_json_list(c.techSelectedTestsJson or ""),
            "techSelectedAt": c.techSelectedAt or "",
            "allowedTechTests": _allowed_tech_tests_for_role(job_role),
            "sla": compute_sla(
                db,
                step_name="IN_PERSON",
                start_ts=str(c.onlineTestSubmittedAt or c.updatedAt or ""),
                app_timezone=cfg.APP_TIMEZONE,
            ),
            "updatedAt": c.updatedAt or "",
            "updatedBy": c.updatedBy or "",
        }
        if can_pii:
            name_full = decrypt_pii(getattr(c, "name_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{c.candidateId}:name")
            mobile_full = decrypt_pii(getattr(c, "mobile_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{c.candidateId}:mobile")
            if name_full:
                item["candidateNameFull"] = name_full
            if mobile_full:
                item["mobileFull"] = mobile_full

        items.append(item)

    return {"items": items, "total": len(items)}


def inperson_marks_save(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    marks_raw = (data or {}).get("marks") if isinstance(data, dict) else ""

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    try:
        marks = float(marks_raw)
    except Exception:
        raise ApiError("BAD_REQUEST", "Invalid marks")
    if marks < 0 or marks > 10:
        raise ApiError("BAD_REQUEST", "Marks must be 0-10")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status == "REJECTED":
        raise ApiError("BAD_REQUEST", "Candidate rejected")

    online_res = str(cand.onlineTestResult or "").upper()
    if online_res != "PASS" and not (online_res == "FAIL" and is_test_continued(cand, "ONLINE_TEST")):
        raise ApiError("BAD_REQUEST", "Online test not allowed")

    now = iso_utc_now()
    update_candidate(db, cand=cand, patch={"inPersonMarks": int(marks), "inPersonMarksAt": now}, auth=auth)

    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="INPERSON_MARKS_SAVE",
        fromState=current_status,
        toState=current_status,
        stageTag="In-person Marks Save",
        remark=str(int(marks)),
        actor=auth,
        at=now,
        meta={"requirementId": requirement_id},
    )

    if marks < 6:
        return {
            "ok": True,
            "status": current_status,
            "inPersonMarks": int(marks),
            "passFail": "FAIL",
            "decisionRequired": True,
            "testType": "INPERSON_MARKS",
            "stageTag": "In-person Marks",
            "marksScale": "0-10",
        }

    return {"ok": True, "status": current_status, "inPersonMarks": int(marks), "passFail": "PASS", "decisionRequired": False}


def tech_select(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    tests = (data or {}).get("tests") or []

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not isinstance(tests, list):
        raise ApiError("BAD_REQUEST", "Invalid tests")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status == "REJECTED":
        raise ApiError("BAD_REQUEST", "Candidate rejected")

    online_res = str(cand.onlineTestResult or "").upper()
    if online_res != "PASS" and not (online_res == "FAIL" and is_test_continued(cand, "ONLINE_TEST")):
        raise ApiError("BAD_REQUEST", "Online test not allowed")

    marks = cand.inPersonMarks
    if marks is None:
        raise ApiError("BAD_REQUEST", "In-person marks missing")
    if int(marks) < 6 and not is_test_continued(cand, "INPERSON_MARKS"):
        raise ApiError("BAD_REQUEST", "In-person marks must be >=6 (or HR override)")

    allowed = _allowed_tech_tests_for_role(cand.jobRole)
    uniq: set[str] = set()
    selected: list[str] = []
    for t in tests:
        x = str(t or "").strip()
        if not x:
            continue
        if x not in allowed:
            raise ApiError("BAD_REQUEST", f"Invalid test: {x}")
        if x not in uniq:
            uniq.add(x)
            selected.append(x)

    if len(selected) == 0:
        raise ApiError("BAD_REQUEST", "Select at least one test")

    now = iso_utc_now()
    update_candidate(db, cand=cand, patch={"techSelectedTestsJson": json.dumps(selected), "techSelectedAt": now}, auth=auth)
    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="TECH_SELECT",
        fromState=current_status,
        toState=current_status,
        stageTag="Tech Select",
        remark=", ".join(selected),
        actor=auth,
        at=now,
        meta={"requirementId": requirement_id, "tests": selected},
    )
    return {"ok": True, "tests": selected, "techSelectedAt": now}


def auto_reject_inperson_low(data, auth: AuthContext | None, db, cfg):
    scanned = db.execute(select(func.count()).select_from(Candidate)).scalar_one() or 0
    return {"scanned": int(scanned), "rejected": 0, "disabled": True}


def probation_list(data, auth: AuthContext | None, db, cfg):
    count_only = bool((data or {}).get("countOnly"))
    can_pii = bool(getattr(cfg, "PII_ENC_KEY", "").strip()) and bool(auth and auth.valid) and str(getattr(auth, "role", "") or "").upper() in set(
        getattr(cfg, "PII_VIEW_ROLES", []) or []
    )
    req_map = None
    if not count_only:
        req_map = _get_requirements_map(db)

    rows = db.execute(select(Candidate).where(func.upper(Candidate.status).in_(["JOINED", "PROBATION"]))).scalars().all()

    training_state_map: dict[str, dict[str, Any]] = {}
    if not count_only:
        ids = [str(c.candidateId or "").strip() for c in rows]
        ids = [x for x in ids if x]
        if ids:
            st_rows = db.execute(select(CandidateTrainingState).where(CandidateTrainingState.candidateId.in_(ids))).scalars().all()
            for st in st_rows:
                cid = str(st.candidateId or "").strip()
                if not cid:
                    continue
                training_state_map[cid] = {
                    "candidateId": cid,
                    "requirementId": str(getattr(st, "requirementId", "") or ""),
                    "markedCompleteAt": str(getattr(st, "markedCompleteAt", "") or ""),
                    "markedCompleteBy": str(getattr(st, "markedCompleteBy", "") or ""),
                    "closedAt": str(getattr(st, "closedAt", "") or ""),
                    "closedBy": str(getattr(st, "closedBy", "") or ""),
                }

    items: list[dict[str, Any]] = []
    total = 0

    for c in rows:
        total += 1
        if count_only:
            continue

        requirement_id = str(c.requirementId or "").strip()
        rm = (req_map or {}).get(requirement_id, {}) if requirement_id else {}
        tr_state = training_state_map.get(str(c.candidateId or "").strip()) or {
            "candidateId": str(c.candidateId or "").strip(),
            "requirementId": requirement_id,
            "markedCompleteAt": "",
            "markedCompleteBy": "",
            "closedAt": "",
            "closedBy": "",
        }
        tr_state["requirementId"] = requirement_id

        item = {
            "candidateId": c.candidateId,
            "requirementId": requirement_id,
            "candidateName": c.candidateName,
            "mobile": c.mobile,
            "source": c.source,
            "jobRole": c.jobRole or "",
            "jobTitle": rm.get("jobTitle", "") if isinstance(rm, dict) else "",
            "status": c.status or "",
            "cvFileId": c.cvFileId,
            "cvFileName": c.cvFileName,
            "joiningAt": c.joiningAt or "",
            "joinedAt": c.joinedAt or "",
            "probationStartAt": c.probationStartAt or "",
            "probationEndsAt": c.probationEndsAt or "",
            "employeeId": c.employeeId or "",
            "trainingState": tr_state,
            "sla": compute_sla(
                db,
                step_name="PROBATION",
                start_ts=str(c.probationStartAt or c.joinedAt or c.updatedAt or ""),
                app_timezone=cfg.APP_TIMEZONE,
            ),
            "updatedAt": c.updatedAt or "",
            "updatedBy": c.updatedBy or "",
        }

        if can_pii:
            name_full = decrypt_pii(getattr(c, "name_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{c.candidateId}:name")
            mobile_full = decrypt_pii(getattr(c, "mobile_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{c.candidateId}:mobile")
            if name_full:
                item["candidateNameFull"] = name_full
            if mobile_full:
                item["mobileFull"] = mobile_full

        items.append(item)

    items.sort(
        key=lambda x: parse_datetime_maybe(x.get("updatedAt") or "", app_timezone=cfg.APP_TIMEZONE)
        or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )

    if count_only:
        return {"items": [], "total": total}
    return {"items": items, "total": len(items)}


def _build_candidate_timeline(db, candidate_id: str, requirement_id: str) -> list[dict[str, Any]]:
    from models import AuditLog, HoldLog, JoinLog, RejectionLog

    entries: list[dict[str, Any]] = []

    for a in (
        db.execute(select(AuditLog).where(func.upper(AuditLog.entityType) == "CANDIDATE").where(AuditLog.entityId == candidate_id))
        .scalars()
        .all()
    ):
        entries.append(
            {
                "at": a.at or "",
                "source": "AUDIT",
                "stageTag": a.stageTag or "",
                "action": a.action or "",
                "fromState": a.fromState or "",
                "toState": a.toState or "",
                "remark": a.remark or "",
                "actorRole": a.actorRole or "",
                "actorUserId": a.actorUserId or "",
                "metaJson": a.metaJson or "",
            }
        )

    for j in (
        db.execute(select(JoinLog).where(JoinLog.candidateId == candidate_id).where(JoinLog.requirementId == requirement_id))
        .scalars()
        .all()
    ):
        entries.append(
            {
                "at": j.at or "",
                "source": "JOIN",
                "stageTag": j.stageTag or "",
                "action": j.action or "",
                "remark": j.remark or "",
                "actorRole": j.actorRole or "",
                "actorUserId": j.actorUserId or "",
            }
        )

    for h in (
        db.execute(select(HoldLog).where(HoldLog.candidateId == candidate_id).where(HoldLog.requirementId == requirement_id))
        .scalars()
        .all()
    ):
        entries.append(
            {
                "at": h.at or "",
                "source": "HOLD",
                "stageTag": h.stageTag or "",
                "action": h.action or "",
                "remark": h.remark or "",
                "actorRole": h.actorRole or "",
                "actorUserId": h.actorUserId or "",
                "holdUntil": h.holdUntil or "",
            }
        )

    for r in (
        db.execute(select(RejectionLog).where(RejectionLog.candidateId == candidate_id).where(RejectionLog.requirementId == requirement_id))
        .scalars()
        .all()
    ):
        entries.append(
            {
                "at": r.at or "",
                "source": "REJECT",
                "stageTag": r.stageTag or "",
                "action": "REJECT",
                "remark": r.remark or "",
                "actorRole": r.actorRole or "",
                "actorUserId": r.actorUserId or "",
                "rejectionType": r.rejectionType or "",
                "autoRejectCode": r.autoRejectCode or "",
            }
        )

    def _ts(x: dict[str, Any]) -> datetime:
        return parse_datetime_maybe(x.get("at") or "", app_timezone="UTC") or datetime.min.replace(tzinfo=timezone.utc)

    entries.sort(key=_ts)
    return entries


def _create_employee_from_candidate(db, candidate_id: str, requirement_id: str, auth: AuthContext) -> dict[str, Any]:
    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    existing = str(cand.employeeId or "").strip()
    if existing:
        return {"ok": True, "employeeId": existing, "alreadyExists": True}

    joined_at = str(cand.joinedAt or "").strip()
    if not joined_at:
        raise ApiError("BAD_REQUEST", "Candidate not marked joined")

    # Enforce uniqueness (Aadhaar+DOB hash) if captured at joining time.
    cand_hash = str(getattr(cand, "aadhaar_dob_hash", "") or "").strip()
    if cand_hash:
        existing_emp = db.execute(select(Employee).where(Employee.aadhaar_dob_hash == cand_hash)).scalar_one_or_none()
        if existing_emp:
            raise ApiError("CONFLICT", "Duplicate employee identity detected", http_status=409)

    timeline = _build_candidate_timeline(db, candidate_id, requirement_id)
    req = db.execute(select(Requirement).where(Requirement.requirementId == requirement_id)).scalar_one_or_none()
    job_title = (req and (req.jobTitle or "")) or ""

    employee_id = "EMP-" + os.urandom(16).hex()[:8].upper()
    now = iso_utc_now()

    db.add(
        Employee(
            employeeId=employee_id,
            employee_id=employee_id,
            candidateId=candidate_id,
            requirementId=requirement_id,
            employeeName=cand.candidateName or "",
            mobile=cand.mobile or "",
            jobRole=cand.jobRole or "",
            currentRole=cand.jobRole or "",
            jobTitle=job_title,
            source=cand.source or "",
            cvFileId=cand.cvFileId or "",
            cvFileName=cand.cvFileName or "",
            joinedAt=joined_at,
            probationStartAt=cand.probationStartAt or "",
            probationEndsAt=cand.probationEndsAt or "",
            status="ACTIVE",
            exitAt="",
            exit_date="",
            rejoin_date="",
            is_active=True,
            auth_version=0,
            password_hash="",
            password_reset_required=True,
            password_changed_at="",
            aadhaar_last4=str(getattr(cand, "aadhaar_last4", "") or ""),
            aadhaar_dob_hash=cand_hash,
            createdAt=now,
            createdBy=auth.userId,
            timelineJson=json.dumps(timeline),
        )
    )

    # Role history: initial join role (best-effort, additive)
    if str(cand.jobRole or "").strip():
        db.add(
            RoleHistory(
                employee_id=employee_id,
                role=str(cand.jobRole or ""),
                start_at=joined_at,
                end_at="",
                changed_by=str(auth.userId or auth.email or ""),
                remark="Joined",
            )
        )

    update_candidate(db, cand=cand, patch={"employeeId": employee_id}, auth=auth)

    append_audit(
        db,
        entityType="EMPLOYEE",
        entityId=employee_id,
        action="EMPLOYEE_CREATE_FROM_CANDIDATE",
        fromState="",
        toState="",
        stageTag="EMPLOYEE_CREATE_FROM_CANDIDATE",
        remark="",
        actor=auth,
        at=now,
        meta={"candidateId": candidate_id, "requirementId": requirement_id},
    )

    return {"ok": True, "employeeId": employee_id, "alreadyExists": False, "timeline": timeline}


def probation_set(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    try:
        days = float((data or {}).get("probationDays") or 0)
    except Exception:
        days = 0

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not (days and days > 0 and days <= 365):
        raise ApiError("BAD_REQUEST", "Invalid probationDays")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status not in {"JOINED", "PROBATION"}:
        raise ApiError("BAD_REQUEST", "Candidate not in Probation flow")
    if not str(cand.joinedAt or "").strip():
        raise ApiError("BAD_REQUEST", "Candidate not marked joined")

    now_dt = datetime.now(timezone.utc)
    now = iso_utc_now()
    ends = to_iso_utc(now_dt + timedelta(days=int(days)))

    transition_candidate_status(
        db,
        candidate_id=candidate_id,
        requirement_id=requirement_id,
        to_status="PROBATION",
        action="PROBATION_SET",
        stage_tag="PROBATION_SET",
        auth=auth,
        remark=f"{int(days)} day(s)",
        patch={"probationStartAt": now, "probationEndsAt": ends},
        require_from={"JOINED", "PROBATION"},
        meta={"probationDays": int(days), "probationEndsAt": ends},
    )

    emp = _create_employee_from_candidate(db, candidate_id, requirement_id, auth)
    return {
        "ok": True,
        "status": "PROBATION",
        "probationStartAt": now,
        "probationEndsAt": ends,
        "probationDays": int(days),
        "employeeId": emp.get("employeeId"),
    }


def probation_complete(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status != "PROBATION":
        raise ApiError("BAD_REQUEST", "Candidate not in PROBATION")

    if not str(cand.probationStartAt or "").strip() or not str(cand.probationEndsAt or "").strip():
        raise ApiError("BAD_REQUEST", "Probation not set")

    state = db.execute(select(CandidateTrainingState).where(CandidateTrainingState.candidateId == candidate_id)).scalar_one_or_none()
    if not state or not str(getattr(state, "closedAt", "") or "").strip():
        raise ApiError("BAD_REQUEST", "Training not closed yet")

    ts = training_summary({"candidateId": candidate_id}, auth, db, cfg)
    counts = (ts or {}).get("counts") if isinstance(ts, dict) else None
    items = (ts or {}).get("items") if isinstance(ts, dict) else None
    if not counts or not counts.get("TOTAL"):
        raise ApiError("BAD_REQUEST", "Training not assigned")
    open_count = int(counts.get("PENDING") or 0) + int(counts.get("IN_PROGRESS") or 0) + int(counts.get("OVERDUE") or 0)
    if open_count > 0:
        raise ApiError("BAD_REQUEST", "Training pending")

    employee_id = str(cand.employeeId or "").strip()
    if not employee_id:
        created = _create_employee_from_candidate(db, candidate_id, requirement_id, auth)
        employee_id = str(created.get("employeeId") or "").strip()

    now = iso_utc_now()

    # Snapshot candidate profile (MIS-friendly JSON).
    profile_snapshot: dict[str, Any] = {}
    try:
        for col in cand.__table__.columns:  # type: ignore[attr-defined]
            profile_snapshot[col.name] = getattr(cand, col.name)
    except Exception:
        profile_snapshot = {"candidateId": candidate_id, "requirementId": requirement_id}

    # Snapshot trainings with completion metadata.
    assigned = db.execute(select(AssignedTraining).where(AssignedTraining.candidate_id == candidate_id)).scalars().all()
    logs = db.execute(select(TrainingLog).where(TrainingLog.candidate_id == candidate_id)).scalars().all()
    completed_map: dict[str, dict[str, str]] = {}
    for l in logs:
        if str(l.action or "").upper().strip() != "COMPLETED":
            continue
        aid = str(l.assigned_id or "").strip()
        if not aid:
            continue
        prev = completed_map.get(aid)
        ts2 = str(l.timestamp or "").strip()
        if prev and prev.get("completedAt") and prev.get("completedAt") >= ts2:
            continue
        completed_map[aid] = {
            "completedAt": ts2,
            "completedBy": str(l.performed_by or ""),
            "remarks": str(l.remarks or ""),
        }

    trainings_snapshot: list[dict[str, Any]] = []
    for t in assigned:
        base = {
            "assigned_id": t.assigned_id,
            "training_id": t.training_id,
            "training_name": t.training_name,
            "department": t.department,
            "status": t.status,
            "assigned_date": t.assigned_date,
            "due_date": t.due_date,
            "start_time": t.start_time,
            "completion_time": t.completion_time,
            "assigned_by": t.assigned_by,
        }
        comp = completed_map.get(str(t.assigned_id or "").strip())
        if comp:
            base.update(comp)
        trainings_snapshot.append(base)

    db.add(
        ProbationLog(
            candidateId=candidate_id,
            employeeId=employee_id,
            requirementId=requirement_id,
            profileSnapshotJson=json.dumps(profile_snapshot),
            trainingsSnapshotJson=json.dumps(trainings_snapshot),
            probationStartAt=str(cand.probationStartAt or ""),
            probationEndsAt=str(cand.probationEndsAt or ""),
            decision="COMPLETE",
            decidedAt=now,
            actorUserId=str(auth.userId or auth.email or ""),
            actorRole=str(auth.role or ""),
            createdAt=now,
        )
    )

    transition_candidate_status(
        db,
        candidate_id=candidate_id,
        requirement_id=requirement_id,
        to_status="EMPLOYEE",
        action="PROBATION_COMPLETE",
        stage_tag="PROBATION_COMPLETE",
        auth=auth,
        remark="",
        require_from={"PROBATION"},
        meta={"employeeId": employee_id},
    )

    # Refresh employee snapshot/timeline so Employee Profile reflects the full journey
    # (employee is created earlier at PROBATION_SET; without this it becomes stale).
    emp_row = db.execute(select(Employee).where(Employee.employeeId == employee_id)).scalar_one_or_none()
    if emp_row:
        req = db.execute(select(Requirement).where(Requirement.requirementId == requirement_id)).scalar_one_or_none()
        emp_row.employeeName = cand.candidateName or (emp_row.employeeName or "")
        emp_row.mobile = cand.mobile or (emp_row.mobile or "")
        emp_row.jobRole = cand.jobRole or (emp_row.jobRole or "")
        if req and str(getattr(req, "jobTitle", "") or "").strip():
            emp_row.jobTitle = str(getattr(req, "jobTitle", "") or "")
        emp_row.source = cand.source or (emp_row.source or "")
        emp_row.cvFileId = cand.cvFileId or (emp_row.cvFileId or "")
        emp_row.cvFileName = cand.cvFileName or (emp_row.cvFileName or "")
        emp_row.joinedAt = cand.joinedAt or (emp_row.joinedAt or "")
        emp_row.probationStartAt = cand.probationStartAt or (emp_row.probationStartAt or "")
        emp_row.probationEndsAt = cand.probationEndsAt or (emp_row.probationEndsAt or "")

        # SessionLocal has autoflush=False; ensure the audit row is visible before rebuilding timeline.
        db.flush()
        emp_row.timelineJson = json.dumps(_build_candidate_timeline(db, candidate_id, requirement_id))

    record_step_metric(
        db,
        requirement_id=requirement_id,
        candidate_id=candidate_id,
        step_name="PROBATION",
        start_ts=str(cand.probationStartAt or now),
        end_ts=now,
        actor=auth,
    )

    return {"ok": True, "status": "EMPLOYEE", "employeeId": employee_id}


def probation_decide(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    decision = str((data or {}).get("decision") or "").upper().strip()
    remark = str((data or {}).get("remark") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not decision:
        raise ApiError("BAD_REQUEST", "Missing decision")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status != "PROBATION":
        raise ApiError("BAD_REQUEST", "Candidate not in PROBATION")

    if decision == "REJECT":
        if not remark:
            raise ApiError("BAD_REQUEST", "Remark required")
        employee_id = str(getattr(cand, "employeeId", "") or "").strip()
        rej = reject_candidate_with_meta(
            db,
            candidate_id=candidate_id,
            requirement_id=requirement_id,
            stage_tag="Probation Reject",
            remark=remark,
            reason_code="PROBATION_REJECT",
            auth=auth,
            audit_action="PROBATION_DECIDE",
        )

        # If a probation candidate already has an Employee profile, lock the account immediately and start a TERMINATED exit case.
        # This prevents rejected probation employees from accessing Employee Portal or appearing as ACTIVE in directories.
        if employee_id:
            now = str(rej.get("rejectedAt") or iso_utc_now())
            try:
                active_exit = (
                    db.execute(
                        select(ExitCase.id)
                        .where(ExitCase.employee_id == employee_id)
                        .where(ExitCase.exit_completed_at == "")
                        .order_by(ExitCase.created_at.desc())
                        .limit(1)
                    )
                    .scalars()
                    .first()
                )
                if not active_exit:
                    exit_terminate_init(
                        {"employeeId": employee_id, "lastWorkingDay": now, "remark": f"Probation reject: {remark}"},
                        auth,
                        db,
                        cfg,
                    )
            except ApiError as e:
                # If an exit case already exists, keep the latest one and proceed with account lock.
                if str(getattr(e, "code", "") or "") != "CONFLICT":
                    raise

            emp = (
                db.execute(select(Employee).where(Employee.employeeId == employee_id).with_for_update(of=Employee))
                .scalars()
                .first()
            )
            if emp:
                before = {
                    "status": str(getattr(emp, "status", "") or ""),
                    "is_active": bool(getattr(emp, "is_active", True)),
                    "exitAt": str(getattr(emp, "exitAt", "") or ""),
                    "exit_date": str(getattr(emp, "exit_date", "") or ""),
                    "auth_version": int(getattr(emp, "auth_version", 0) or 0),
                }

                # Mark INACTIVE (blocked) until HR completes exit workflow, or explicitly re-joins the employee.
                emp.status = "INACTIVE"
                emp.exitAt = now
                emp.exit_date = now
                emp.is_active = False
                emp.auth_version = int(getattr(emp, "auth_version", 0) or 0) + 1

                revoked = revoke_user_sessions(
                    db,
                    user_id=str(emp.employeeId or ""),
                    role="EMPLOYEE",
                    revoked_by=str(auth.userId or auth.email or ""),
                )

                append_audit(
                    db,
                    entityType="EMPLOYEE",
                    entityId=employee_id,
                    action="PROBATION_REJECT_EXIT",
                    stageTag="PROBATION",
                    remark=remark,
                    actor=auth,
                    at=now,
                    meta={
                        "candidateId": candidate_id,
                        "requirementId": requirement_id,
                        "revokedSessions": int(revoked or 0),
                    },
                    before=before,
                    after={
                        "status": "INACTIVE",
                        "is_active": False,
                        "exitAt": now,
                        "exit_date": now,
                        "auth_version": int(getattr(emp, "auth_version", 0) or 0),
                    },
                )
                rej["employeeId"] = employee_id
        return rej

    if decision == "COMPLETE":
        return probation_complete({"requirementId": requirement_id, "candidateId": candidate_id}, auth, db, cfg)

    raise ApiError("BAD_REQUEST", "Invalid decision")


def role_change(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    next_role = str((data or {}).get("jobRole") or "").strip()
    remark = str((data or {}).get("remark") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not next_role:
        raise ApiError("BAD_REQUEST", "Missing jobRole")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status not in {"JOINED", "PROBATION"}:
        raise ApiError("BAD_REQUEST", "Candidate not in Probation flow")

    update_candidate(
        db,
        cand=cand,
        patch={"jobRole": next_role, "status": "JOINED", "probationStartAt": "", "probationEndsAt": ""},
        auth=auth,
    )
    employee_id = str(getattr(cand, "employeeId", "") or "").strip()
    if employee_id:
        emp = db.execute(select(Employee).where(Employee.employeeId == employee_id)).scalar_one_or_none()
        if emp:
            prev_emp_role = str(getattr(emp, "currentRole", "") or "").strip() or str(emp.jobRole or "").strip()
            emp.jobRole = next_role
            emp.currentRole = next_role

            # Best-effort role history (close open + append new)
            now = iso_utc_now()
            open_row = (
                db.execute(
                    select(RoleHistory)
                    .where(RoleHistory.employee_id == employee_id)
                    .where(RoleHistory.end_at == "")
                    .order_by(RoleHistory.start_at.desc())
                )
                .scalars()
                .first()
            )
            if open_row:
                open_row.end_at = now
            db.add(
                RoleHistory(
                    employee_id=employee_id,
                    role=str(next_role or ""),
                    start_at=now,
                    end_at="",
                    changed_by=str(auth.userId or auth.email or ""),
                    remark=remark or "",
                )
            )
            append_audit(
                db,
                entityType="EMPLOYEE",
                entityId=employee_id,
                action="EMPLOYEE_ROLE_CHANGE",
                fromState=prev_emp_role,
                toState=next_role,
                stageTag="ROLE_CHANGE",
                remark=remark or next_role,
                actor=auth,
                at=now,
                meta={"requirementId": requirement_id, "jobRole": next_role},
            )
    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="ROLE_CHANGE",
        fromState=current_status,
        toState="JOINED",
        stageTag="ROLE_CHANGE",
        remark=remark or next_role,
        actor=auth,
        at=iso_utc_now(),
        meta={"requirementId": requirement_id, "jobRole": next_role},
    )
    return {"ok": True, "status": "JOINED", "jobRole": next_role}


def employee_create_from_candidate(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)
    return _create_employee_from_candidate(db, candidate_id, requirement_id, auth)


def employee_list(data, auth: AuthContext | None, db, cfg):
    """
    List employees created from candidates.

    Backward compatible: additive API (does not change existing DB schema or flows).
    """
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    q = str((data or {}).get("q") or "").strip().lower()
    include_inactive = bool((data or {}).get("includeInactive"))
    include_exited = bool((data or {}).get("includeExited"))
    try:
        page = int((data or {}).get("page") or 1)
    except Exception:
        page = 1
    try:
        page_size = int((data or {}).get("pageSize") or 50)
    except Exception:
        page_size = 50
    page = max(1, page)
    page_size = max(10, min(200, page_size))

    can_pii = bool(getattr(cfg, "PII_ENC_KEY", "").strip()) and str(getattr(auth, "role", "") or "").upper() in set(
        getattr(cfg, "PII_VIEW_ROLES", []) or []
    )

    # Default: return only ACTIVE employees (directory of current employees).
    q_emp = select(Employee)
    if not include_inactive and not include_exited:
        q_emp = q_emp.where(Employee.status == "ACTIVE").where(Employee.is_active == True)  # noqa: E712
    rows = db.execute(q_emp).scalars().all()
    req_map = _get_requirements_map(db)

    cand_by_id: dict[str, Candidate] = {}
    if can_pii:
        cand_ids = [str(getattr(r, "candidateId", "") or "").strip() for r in rows]
        cand_ids = [x for x in cand_ids if x]
        if cand_ids:
            cand_rows = db.execute(select(Candidate).where(Candidate.candidateId.in_(cand_ids))).scalars().all()
            cand_by_id = {str(c.candidateId or "").strip(): c for c in cand_rows if str(c.candidateId or "").strip()}

    items: list[dict[str, Any]] = []
    for emp in rows:
        employee_id = str(emp.employeeId or "").strip()
        if not employee_id:
            continue

        requirement_id = str(emp.requirementId or "").strip()
        rm = (req_map or {}).get(requirement_id, {}) if requirement_id else {}
        job_title = str(emp.jobTitle or "").strip()
        if not job_title and isinstance(rm, dict):
            job_title = str(rm.get("jobTitle") or "").strip()

        employee_name = str(emp.employeeName or "")
        mobile = str(emp.mobile or "")

        candidate_id = str(emp.candidateId or "").strip()
        if can_pii and candidate_id:
            cand = cand_by_id.get(candidate_id)
            if cand:
                name_full = decrypt_pii(getattr(cand, "name_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{cand.candidateId}:name")
                mobile_full = decrypt_pii(getattr(cand, "mobile_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{cand.candidateId}:mobile")
                if name_full:
                    employee_name = name_full
                if mobile_full:
                    mobile = mobile_full
        if can_pii:
            if "*" in employee_name:
                employee_name = emp.employeeId or employee_name
            if "*" in mobile or "x" in mobile.lower():
                mobile = ""

        item = {
            "employeeId": employee_id,
            "candidateId": candidate_id,
            "requirementId": requirement_id,
            "employeeName": employee_name,
            "mobile": mobile,
            "jobRole": emp.jobRole or "",
            "jobTitle": job_title,
            "source": emp.source or "",
            "joinedAt": emp.joinedAt or "",
            "probationStartAt": emp.probationStartAt or "",
            "probationEndsAt": emp.probationEndsAt or "",
            "status": str(getattr(emp, "status", "") or "ACTIVE"),
            "exitAt": str(getattr(emp, "exitAt", "") or ""),
            "isActive": bool(getattr(emp, "is_active", True)),
            "createdAt": emp.createdAt or "",
            "createdBy": emp.createdBy or "",
        }

        if q:
            hay = (
                f"{item.get('employeeId','')} {item.get('candidateId','')} {item.get('requirementId','')} "
                f"{item.get('employeeName','')} {item.get('mobile','')} {item.get('jobRole','')} {item.get('jobTitle','')} {item.get('source','')}"
            ).lower()
            if q not in hay:
                continue

        items.append(item)

    items.sort(
        key=lambda x: parse_datetime_maybe(x.get("createdAt") or "", app_timezone=cfg.APP_TIMEZONE)
        or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )

    total = len(items)
    start = (page - 1) * page_size
    paged = items[start : start + page_size]
    return {"items": paged, "total": total, "page": page, "pageSize": page_size}


def employee_get(data, auth: AuthContext | None, db, cfg):
    employee_id = str((data or {}).get("employeeId") or "").strip()
    if not employee_id:
        raise ApiError("BAD_REQUEST", "Missing employeeId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    emp = db.execute(select(Employee).where(Employee.employeeId == employee_id)).scalar_one_or_none()
    if not emp:
        raise ApiError("NOT_FOUND", "Employee not found")

    can_pii = bool(getattr(cfg, "PII_ENC_KEY", "").strip()) and str(getattr(auth, "role", "") or "").upper() in set(
        getattr(cfg, "PII_VIEW_ROLES", []) or []
    )

    timeline = _parse_json_list(emp.timelineJson or "")
    requirement_id = str(emp.requirementId or "").strip()
    job_title = emp.jobTitle or ""
    if not job_title and requirement_id:
        req = db.execute(select(Requirement).where(Requirement.requirementId == requirement_id)).scalar_one_or_none()
        job_title = (req and (req.jobTitle or "")) or ""

    employee_name = emp.employeeName or ""
    mobile = emp.mobile or ""
    if can_pii and str(emp.candidateId or "").strip():
        cand = db.execute(select(Candidate).where(Candidate.candidateId == str(emp.candidateId or ""))).scalar_one_or_none()
        if cand:
            name_full = decrypt_pii(getattr(cand, "name_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{cand.candidateId}:name")
            mobile_full = decrypt_pii(getattr(cand, "mobile_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{cand.candidateId}:mobile")
            if name_full:
                employee_name = name_full
            if mobile_full:
                mobile = mobile_full
    if can_pii:
        if "*" in employee_name:
            employee_name = emp.employeeId or employee_name
        if "*" in mobile or "x" in mobile.lower():
            mobile = ""

    return {
        "employeeId": employee_id,
        "candidateId": emp.candidateId or "",
        "requirementId": requirement_id,
        "employeeName": employee_name,
        "mobile": mobile,
        "jobRole": emp.jobRole or "",
        "currentRole": str(getattr(emp, "currentRole", "") or "").strip() or (emp.jobRole or ""),
        "jobTitle": job_title,
        "source": emp.source or "",
        "cvFileId": emp.cvFileId or "",
        "cvFileName": emp.cvFileName or "",
        "joinedAt": emp.joinedAt or "",
        "probationStartAt": emp.probationStartAt or "",
        "probationEndsAt": emp.probationEndsAt or "",
        "status": str(getattr(emp, "status", "") or "ACTIVE"),
        "exitAt": str(getattr(emp, "exitAt", "") or ""),
        "aadhaarLast4": str(getattr(emp, "aadhaar_last4", "") or ""),
        "createdAt": emp.createdAt or "",
        "createdBy": emp.createdBy or "",
        "timeline": timeline,
    }


def vacancy_fullfill_list(data, auth: AuthContext | None, db, cfg):
    """
    List leftover candidates for requirements that are already filled (Requirement.status=CLOSED).

    Use-case: after a vacancy is filled, the remaining candidates for that requirement should still be visible
    in a dedicated view with their marks/remarks for future reuse.
    """
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    requirement_filter = str((data or {}).get("requirementId") or "").strip()
    q = str((data or {}).get("q") or "").strip().lower()
    include_candidates = (data or {}).get("includeCandidates")
    include_candidates = True if include_candidates is None else bool(include_candidates)
    try:
        limit = int((data or {}).get("limit") or 50)
    except Exception:
        limit = 50
    limit = max(1, min(200, limit))

    can_pii = bool(getattr(cfg, "PII_ENC_KEY", "").strip()) and str(getattr(auth, "role", "") or "").upper() in set(
        getattr(cfg, "PII_VIEW_ROLES", []) or []
    )

    req_q = select(Requirement).where(func.upper(Requirement.status) == "CLOSED")
    if requirement_filter:
        req_q = req_q.where(Requirement.requirementId == requirement_filter)
    req_rows = db.execute(req_q.order_by(Requirement.updatedAt.desc()).limit(limit)).scalars().all()
    if not req_rows:
        return {"items": [], "total": 0}

    req_ids = [str(r.requirementId or "").strip() for r in req_rows if str(r.requirementId or "").strip()]
    req_ids_set = set(req_ids)
    candidates_by_req: dict[str, list[dict[str, Any]]] = {rid: [] for rid in req_ids}

    if include_candidates and req_ids:
        # Exclude joined candidates and already reused candidates
        cand_rows = (
            db.execute(
                select(Candidate)
                .where(Candidate.requirementId.in_(req_ids))
                .where(Candidate.joinedAt == "")
                .where(func.upper(func.coalesce(Candidate.rejectedReasonCode, "")) != "REUSED")
            )
            .scalars()
            .all()
        )

        cand_ids = [str(c.candidateId or "").strip() for c in cand_rows if str(c.candidateId or "").strip()]
        latest_audit: dict[str, dict[str, Any]] = {}
        if cand_ids:
            audits = (
                db.execute(
                    select(AuditLog)
                    .where(func.upper(AuditLog.entityType) == "CANDIDATE")
                    .where(AuditLog.entityId.in_(cand_ids))
                    .order_by(AuditLog.at.desc())
                )
                .scalars()
                .all()
            )
            for a in audits:
                cid = str(getattr(a, "entityId", "") or "").strip()
                if not cid or cid in latest_audit:
                    continue
                latest_audit[cid] = {
                    "at": a.at or "",
                    "stageTag": a.stageTag or "",
                    "action": a.action or "",
                    "fromState": a.fromState or "",
                    "toState": a.toState or "",
                    "remark": a.remark or "",
                    "actorRole": a.actorRole or "",
                    "actorUserId": a.actorUserId or "",
                }

        for c in cand_rows:
            rid = str(c.requirementId or "").strip()
            cid = str(c.candidateId or "").strip()
            if not rid or rid not in req_ids_set:
                continue
            if not cid:
                continue

            item: dict[str, Any] = {
                "candidateId": cid,
                "candidateMasterId": c.candidateMasterId or "",  # For identity tracking
                "requirementId": rid,
                "candidateName": c.candidateName or "",
                "mobile": c.mobile or "",
                "source": c.source or "",
                "jobRole": c.jobRole or "",
                "status": c.status or "",
                # CV details for preview/download
                "cvFileId": c.cvFileId or "",
                "cvFileName": c.cvFileName or "",
                # Evaluation data
                "preInterviewStatus": c.preInterviewStatus or "",
                "preInterviewMarks": c.preInterviewMarks or "",
                "onlineTestScore": c.onlineTestScore,
                "onlineTestResult": c.onlineTestResult or "",
                "inPersonMarks": c.inPersonMarks,
                "tallyMarks": c.tallyMarks,
                "voiceMarks": c.voiceMarks,
                "excelMarks": c.excelMarks,
                "techResult": c.techResult or "",
                "techReview": c.techReview or "",
                "excelReview": c.excelReview or "",
                "finalHoldAt": c.finalHoldAt or "",
                "finalHoldRemark": c.finalHoldRemark or "",
                # Stage history (where candidate was before close)
                "rejectedFromStatus": c.rejectedFromStatus or "",
                "rejectedReasonCode": c.rejectedReasonCode or "",
                "rejectedAt": c.rejectedAt or "",
                # Timestamps
                "createdAt": c.createdAt or "",
                "updatedAt": c.updatedAt or "",
                "updatedBy": c.updatedBy or "",
                # Latest audit entry for tracking
                "latest": latest_audit.get(cid) or None,
            }

            if can_pii:
                name_full = decrypt_pii(getattr(c, "name_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{c.candidateId}:name")
                mobile_full = decrypt_pii(getattr(c, "mobile_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{c.candidateId}:mobile")
                if name_full:
                    item["candidateNameFull"] = name_full
                if mobile_full:
                    item["mobileFull"] = mobile_full

            if q:
                hay = (
                    f"{cid} {rid} {item.get('candidateNameFull','')} {item.get('candidateName','')} "
                    f"{item.get('mobileFull','')} {item.get('mobile','')} {item.get('status','')} {item.get('jobRole','')} "
                    f"{item.get('source','')} {item.get('techReview','')} {item.get('excelReview','')} "
                    f"{item.get('finalHoldRemark','')} {item.get('rejectedReasonCode','')}"
                ).lower()
                if q not in hay:
                    continue

            candidates_by_req[rid].append(item)

    out_items: list[dict[str, Any]] = []
    for r in req_rows:
        rid = str(r.requirementId or "").strip()
        if not rid:
            continue
        candidates = candidates_by_req.get(rid) if include_candidates else []
        candidates = candidates or []
        status_counts: dict[str, int] = {}
        for c in candidates:
            st = str(c.get("status") or "").upper().strip() or "UNKNOWN"
            status_counts[st] = int(status_counts.get(st, 0) or 0) + 1

        out_items.append(
            {
                "requirementId": rid,
                "jobRole": r.jobRole or "",
                "jobTitle": r.jobTitle or "",
                "status": r.status or "",
                "requiredCount": int(r.requiredCount or 0),
                "joinedCount": int(r.joinedCount or 0),
                "latestRemark": r.latestRemark or "",
                "updatedAt": r.updatedAt or "",
                "updatedBy": r.updatedBy or "",
                "leftoverCount": int(len(candidates)),
                "statusCounts": status_counts,
                "candidates": candidates,
            }
        )

    out_items.sort(
        key=lambda x: parse_datetime_maybe(x.get("updatedAt") or "", app_timezone=cfg.APP_TIMEZONE)
        or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    return {"items": out_items, "total": len(out_items)}


def auto_reschedule_no_show(data, auth: AuthContext | None, db, cfg):
    dry_run = bool((data or {}).get("dryRun"))
    try:
        limit = int((data or {}).get("limit") or 500)
    except Exception:
        limit = 500
    limit = max(1, min(2000, limit))

    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    # Reschedule candidates whose scheduled day has passed (Asia/Kolkata) and are still pending.
    try:
        tz = ZoneInfo(cfg.APP_TIMEZONE)
    except Exception:
        tz = timezone.utc

    now_local = datetime.now(tz)
    start_local = datetime(now_local.year, now_local.month, now_local.day, 0, 0, 0, tzinfo=tz)
    cutoff_utc = start_local.astimezone(timezone.utc)
    cutoff_iso = to_iso_utc(cutoff_utc)

    system = AuthContext(valid=True, userId="SYSTEM", email="SYSTEM", role="SYSTEM", expiresAt="")

    walkin_updated = 0
    preinterview_updated = 0
    updates: list[dict[str, Any]] = []

    # WALKIN / PRECALL pending: still waiting on pre-call (preCallAt not set).
    walkin_rows = (
        db.execute(
            select(Candidate)
            .where(func.upper(Candidate.status) == "WALKIN_SCHEDULED")
            .where(Candidate.preCallAt == "")
            .where(Candidate.walkinAt != "")
            .where(Candidate.walkinAt < cutoff_iso)
            .limit(limit)
        )
        .scalars()
        .all()
    )

    for c in walkin_rows:
        old_iso = str(c.walkinAt or "").strip()
        old_dt = parse_datetime_maybe(old_iso, app_timezone=cfg.APP_TIMEZONE) if old_iso else None
        if not old_dt:
            continue

        next_dt = old_dt
        while next_dt < cutoff_utc:
            next_dt = next_dt + timedelta(days=1)
        next_iso = to_iso_utc(next_dt)
        if next_iso == old_iso:
            continue

        if not dry_run:
            update_candidate(db, cand=c, patch={"walkinAt": next_iso}, auth=system)
            append_audit(
                db,
                entityType="CANDIDATE",
                entityId=str(c.candidateId or ""),
                action="AUTO_RESCHEDULE_NO_SHOW",
                fromState=str(c.status or ""),
                toState=str(c.status or ""),
                stageTag="Auto Reschedule No-show",
                remark="walkinAt",
                actor=system,
                at=iso_utc_now(),
                meta={"requirementId": str(c.requirementId or ""), "from": old_iso, "to": next_iso, "field": "walkinAt"},
            )
        walkin_updated += 1
        updates.append({"candidateId": str(c.candidateId or ""), "field": "walkinAt", "from": old_iso, "to": next_iso})

    # PRE-INTERVIEW pending: preCallAt is used as pre-interview datetime until APPEARED.
    pi_rows = (
        db.execute(
            select(Candidate)
            .where(func.upper(Candidate.status) == "WALKIN_SCHEDULED")
            .where(Candidate.preCallAt != "")
            .where(Candidate.preCallAt < cutoff_iso)
            .where(func.upper(Candidate.preInterviewStatus) != "APPEARED")
            .limit(limit)
        )
        .scalars()
        .all()
    )

    for c in pi_rows:
        old_iso = str(c.preCallAt or "").strip()
        old_dt = parse_datetime_maybe(old_iso, app_timezone=cfg.APP_TIMEZONE) if old_iso else None
        if not old_dt:
            continue

        next_dt = old_dt
        while next_dt < cutoff_utc:
            next_dt = next_dt + timedelta(days=1)
        next_iso = to_iso_utc(next_dt)
        if next_iso == old_iso:
            continue

        if not dry_run:
            update_candidate(db, cand=c, patch={"preCallAt": next_iso, "preInterviewStatus": "SCHEDULED"}, auth=system)
            append_audit(
                db,
                entityType="CANDIDATE",
                entityId=str(c.candidateId or ""),
                action="AUTO_RESCHEDULE_NO_SHOW",
                fromState=str(c.status or ""),
                toState=str(c.status or ""),
                stageTag="Auto Reschedule No-show",
                remark="preInterviewAt",
                actor=system,
                at=iso_utc_now(),
                meta={"requirementId": str(c.requirementId or ""), "from": old_iso, "to": next_iso, "field": "preCallAt"},
            )
        preinterview_updated += 1
        updates.append({"candidateId": str(c.candidateId or ""), "field": "preCallAt", "from": old_iso, "to": next_iso})

    return {
        "ok": True,
        "dryRun": dry_run,
        "cutoffIso": cutoff_iso,
        "walkinUpdated": walkin_updated,
        "preinterviewUpdated": preinterview_updated,
        "updates": updates,
    }


def hold_expiry_cron(data, auth: AuthContext | None, db, cfg):
    values = db.execute(select(Candidate)).scalars().all()
    scanned = len(values)
    expired = 0
    now_dt = datetime.now(timezone.utc)
    system = AuthContext(valid=True, userId="SYSTEM", email="SYSTEM", role="SYSTEM", expiresAt="")

    for c in values:
        if str(c.status or "").upper() != "OWNER_HOLD":
            continue
        hold_until = str(c.holdUntil or "").strip()
        if not hold_until:
            continue
        hold_dt = parse_datetime_maybe(hold_until, app_timezone=cfg.APP_TIMEZONE)
        if not hold_dt:
            continue
        if hold_dt <= now_dt:
            reject_candidate_with_meta(
                db,
                candidate_id=str(c.candidateId or ""),
                requirement_id=str(c.requirementId or ""),
                stage_tag="Owner Hold Expired",
                remark="Hold expired",
                reason_code="HOLD_EXPIRED",
                auth=None,
                audit_action="HOLD_EXPIRY_CRON",
            )
            # Preserve legacy behavior (clear holdUntil).
            update_candidate(db, cand=c, patch={"holdUntil": ""}, auth=system)
            expired += 1

    return {"scanned": scanned, "expired": expired}


def candidate_reuse(data, auth: AuthContext | None, db, cfg):
    """
    Reuse a candidate from a closed requirement in a new requirement.
    Creates a new Candidate record linked to the same CandidateMaster.
    
    IMPORTANT: Reused candidate follows EXACT same workflow as new candidate:
    - Starts with status "NEW" (not SHORTLISTED)
    - All evaluation fields are empty (no data carried over)
    - Job posting must be complete
    - Goes through full pipeline: NEW -> SHORTLISTED -> WALKIN_SCHEDULED -> etc.
    """
    import uuid
    from actions.candidate_repo import has_duplicate_candidate_in_requirement
    from actions.jobposting import assert_job_posting_complete

    source_candidate_id = str((data or {}).get("sourceCandidateId") or "").strip()
    target_requirement_id = str((data or {}).get("targetRequirementId") or "").strip()

    if not source_candidate_id:
        raise ApiError("BAD_REQUEST", "Missing sourceCandidateId")
    if not target_requirement_id:
        raise ApiError("BAD_REQUEST", "Missing targetRequirementId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    # Verify source candidate exists and is from a closed requirement
    source_cand = db.execute(
        select(Candidate).where(Candidate.candidateId == source_candidate_id)
    ).scalar_one_or_none()

    if not source_cand:
        raise ApiError("NOT_FOUND", "Source candidate not found")

    source_req = db.execute(
        select(Requirement).where(Requirement.requirementId == source_cand.requirementId)
    ).scalar_one_or_none()

    if not source_req or str(source_req.status or "").upper() != "CLOSED":
        raise ApiError("BAD_REQUEST", "Source candidate must be from a closed requirement")

    # Verify target requirement exists and is APPROVED
    target_req = db.execute(
        select(Requirement).where(Requirement.requirementId == target_requirement_id)
    ).scalar_one_or_none()

    if not target_req:
        raise ApiError("NOT_FOUND", "Target requirement not found")
    target_status = str(target_req.status or "").upper()
    if target_status not in {"APPROVED", "ACTIVE"}:
        raise ApiError("BAD_REQUEST", "Target requirement must be approved or active")

    # SAME VALIDATION AS NEW CANDIDATE: Job posting must be complete
    assert_job_posting_complete(db, target_requirement_id)

    # Check for duplicate in target requirement (via CandidateMaster)
    if source_cand.candidateMasterId:
        dup = db.execute(
            select(Candidate.candidateId)
            .where(Candidate.requirementId == target_requirement_id)
            .where(Candidate.candidateMasterId == str(source_cand.candidateMasterId or "").strip())
        ).scalars().first()
        if dup:
            raise ApiError("CONFLICT", "Candidate already exists in this requirement (same identity)")
    
    # Also check by hash
    if has_duplicate_candidate_in_requirement(
        db,
        requirement_id=target_requirement_id,
        name_hash=source_cand.name_hash or "",
        mobile_hash=source_cand.mobile_hash or "",
    ):
        raise ApiError("BAD_REQUEST", "Candidate already exists in target requirement")

    # Create new candidate linked to same CandidateMaster
    # STARTS WITH "NEW" STATUS - EXACTLY LIKE NEW CANDIDATE
    now = iso_utc_now()
    new_candidate_id = f"C{datetime.now().strftime('%Y')}-{uuid.uuid4().hex[:8].upper()}"

    # Re-encrypt PII with new candidate ID's AAD for proper decryption
    new_name_enc = ""
    new_mobile_enc = ""
    pii_key = str(getattr(cfg, "PII_ENC_KEY", "") or "").strip()
    if pii_key and (source_cand.name_enc or source_cand.mobile_enc):
        from pii import decrypt_pii, encrypt_pii
        # Decrypt using source candidate's AAD
        source_name = decrypt_pii(
            source_cand.name_enc or "",
            key=pii_key,
            aad=f"candidate:{source_candidate_id}:name"
        )
        source_mobile = decrypt_pii(
            source_cand.mobile_enc or "",
            key=pii_key,
            aad=f"candidate:{source_candidate_id}:mobile"
        )
        # Re-encrypt with new candidate's AAD
        if source_name:
            new_name_enc = encrypt_pii(source_name, key=pii_key, aad=f"candidate:{new_candidate_id}:name")
        if source_mobile:
            new_mobile_enc = encrypt_pii(source_mobile, key=pii_key, aad=f"candidate:{new_candidate_id}:mobile")

    # Create candidate with ALL evaluation fields empty - fresh start
    new_cand = Candidate(
        candidateId=new_candidate_id,
        candidateMasterId=source_cand.candidateMasterId or "",
        requirementId=target_requirement_id,
        candidateName=source_cand.candidateName or "",
        jobRole=target_req.jobRole or source_cand.jobRole or "",
        mobile=source_cand.mobile or "",
        name_hash=source_cand.name_hash or "",
        mobile_hash=source_cand.mobile_hash or "",
        name_masked=source_cand.name_masked or "",
        mobile_masked=source_cand.mobile_masked or "",
        name_enc=new_name_enc or source_cand.name_enc or "",  # Use re-encrypted or fallback
        mobile_enc=new_mobile_enc or source_cand.mobile_enc or "",
        source=f"REUSED:{source_candidate_id}",
        cvFileId=source_cand.cvFileId or "",  # CV preserved for convenience
        cvFileName=source_cand.cvFileName or "",
        # START WITH "NEW" STATUS - SAME AS NEW CANDIDATE
        status="NEW",
        # All evaluation fields empty - candidate goes through full pipeline
        notPickCount=0,
        createdAt=now,
        createdBy=auth.userId,
        updatedAt=now,
        updatedBy=auth.userId,
    )

    db.add(new_cand)

    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=new_candidate_id,
        action="CANDIDATE_REUSE",
        fromState="",
        toState="NEW",  # Changed from SHORTLISTED to NEW
        stageTag="CANDIDATE_REUSE",
        remark="Reused candidate - follows full new candidate workflow",
        actor=auth,
        at=now,
        meta={
            "sourceId": source_candidate_id,
            "sourceRequirementId": source_cand.requirementId,
            "targetRequirementId": target_requirement_id,
            "candidateMasterId": source_cand.candidateMasterId or "",
            "workflow": "IDENTICAL_TO_NEW_CANDIDATE",
        },
    )

    # Mark source candidate as REUSED - removes from Vacancy Fulfilled tab
    old_reason = source_cand.rejectedReasonCode or ""
    source_cand.rejectedReasonCode = "REUSED"
    source_cand.updatedAt = now
    source_cand.updatedBy = auth.userId

    # Audit log for source candidate
    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=source_candidate_id,
        action="CANDIDATE_REUSED_OUT",
        fromState=old_reason,
        toState="REUSED",
        stageTag="CANDIDATE_REUSE",
        remark=f"Reused to {target_requirement_id} as {new_candidate_id}",
        actor=auth,
        at=now,
        meta={
            "newCandidateId": new_candidate_id,
            "targetRequirementId": target_requirement_id,
        },
    )

    return {
        "ok": True,
        "candidateId": new_candidate_id,
        "requirementId": target_requirement_id,
        "sourceCandidateId": source_candidate_id,
        "status": "NEW",  # Confirm the starting status
    }


def candidate_get_detail(data, auth: AuthContext | None, db, cfg):
    """
    Get full candidate details including CV and all evaluation data.
    """
    candidate_id = str((data or {}).get("candidateId") or "").strip()

    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    cand = db.execute(
        select(Candidate).where(Candidate.candidateId == candidate_id)
    ).scalar_one_or_none()

    if not cand:
        raise ApiError("NOT_FOUND", "Candidate not found")

    # Get requirement info
    req = db.execute(
        select(Requirement).where(Requirement.requirementId == cand.requirementId)
    ).scalar_one_or_none()

    # Get audit trail
    audits = (
        db.execute(
            select(AuditLog)
            .where(func.upper(AuditLog.entityType) == "CANDIDATE")
            .where(AuditLog.entityId == candidate_id)
            .order_by(AuditLog.at.desc())
            .limit(50)
        )
        .scalars()
        .all()
    )

    timeline = [
        {
            "at": a.at or "",
            "action": a.action or "",
            "stageTag": a.stageTag or "",
            "fromState": a.fromState or "",
            "toState": a.toState or "",
            "remark": a.remark or "",
            "actorUserId": a.actorUserId or "",
        }
        for a in audits
    ]

    def _looks_like_enc_value(value: str) -> bool:
        s = str(value or "").strip()
        return s.startswith("v1:") or s.startswith("v0:")

    # PII handling
    can_pii = bool(getattr(cfg, "PII_ENC_KEY", "").strip()) and str(
        getattr(auth, "role", "") or ""
    ).upper() in set(getattr(cfg, "PII_VIEW_ROLES", []) or [])

    # Always return display-safe values (never raw hashes/ciphertext).
    candidate_name = str(getattr(cand, "name_masked", "") or cand.candidateName or "").strip()
    mobile = str(getattr(cand, "mobile_masked", "") or cand.mobile or "").strip()

    if candidate_name and (looks_like_sha256_hex(candidate_name) or _looks_like_enc_value(candidate_name)):
        candidate_name = ""
    if candidate_name and "*" not in candidate_name:
        candidate_name = mask_name(candidate_name)

    if mobile and (looks_like_sha256_hex(mobile) or _looks_like_enc_value(mobile)):
        mobile = ""
    if mobile and not re.search(r"[x*]", mobile, flags=re.IGNORECASE):
        mobile = mask_phone(mobile)

    if can_pii:
        name_full = decrypt_pii(
            getattr(cand, "name_enc", "") or "",
            key=cfg.PII_ENC_KEY,
            aad=f"candidate:{cand.candidateId}:name",
        )
        mobile_full = decrypt_pii(
            getattr(cand, "mobile_enc", "") or "",
            key=cfg.PII_ENC_KEY,
            aad=f"candidate:{cand.candidateId}:mobile",
        )
        if name_full:
            candidate_name = name_full
        if mobile_full:
            mobile = mobile_full

    return {
        "candidateId": candidate_id,
        "candidateMasterId": cand.candidateMasterId or "",
        "requirementId": cand.requirementId or "",
        "candidateName": candidate_name,
        "mobile": mobile,
        "jobRole": cand.jobRole or "",
        "source": cand.source or "",
        "status": cand.status or "",
        "candidateStage": getattr(cand, "candidateStage", "") or "",
        "stageUpdatedAt": getattr(cand, "stageUpdatedAt", "") or "",
        "cvFileId": cand.cvFileId or "",
        "cvFileName": cand.cvFileName or "",
        "requirement": {
            "requirementId": req.requirementId if req else "",
            "jobRole": req.jobRole if req else "",
            "jobTitle": req.jobTitle if req else "",
            "status": req.status if req else "",
        }
        if req
        else None,
        # Evaluation data
        "preInterviewStatus": cand.preInterviewStatus or "",
        "preInterviewMarks": cand.preInterviewMarks or "",
        "onlineTestScore": cand.onlineTestScore,
        "onlineTestResult": cand.onlineTestResult or "",
        "inPersonMarks": cand.inPersonMarks,
        "tallyMarks": cand.tallyMarks,
        "voiceMarks": cand.voiceMarks,
        "excelMarks": cand.excelMarks,
        "techResult": cand.techResult or "",
        "techReview": cand.techReview or "",
        "excelReview": cand.excelReview or "",
        "finalHoldAt": cand.finalHoldAt or "",
        "finalHoldRemark": cand.finalHoldRemark or "",
        # Rejection info
        "rejectedFromStatus": cand.rejectedFromStatus or "",
        "rejectedReasonCode": cand.rejectedReasonCode or "",
        "rejectedAt": cand.rejectedAt or "",
        # Timestamps
        "createdAt": cand.createdAt or "",
        "updatedAt": cand.updatedAt or "",
        "timeline": timeline,
    }
