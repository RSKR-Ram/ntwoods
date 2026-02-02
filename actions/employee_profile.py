from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select

from actions.helpers import append_audit
from models import Candidate, Employee, EmployeeDoc, ExitCase, ExitTask, RoleHistory, Requirement
from pii import decrypt_pii
from services.identity_hash import aadhaar_dob_hash
from utils import ApiError, AuthContext, iso_utc_now, normalize_role, parse_datetime_maybe, to_iso_utc


def _parse_json_list(raw: Any) -> list[Any]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    s = str(raw or "").strip()
    if not s:
        return []
    if not s.startswith("["):
        return []
    try:
        v = json.loads(s)
    except Exception:
        return []
    return v if isinstance(v, list) else []


def employee_duplicate_check(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    aadhaar = str((data or {}).get("aadhaar") or "").strip()
    dob = str((data or {}).get("dob") or "").strip()

    salt = str(getattr(cfg, "SERVER_SALT", "") or getattr(cfg, "PEPPER", "") or "").strip()
    h = aadhaar_dob_hash(aadhaar=aadhaar, dob=dob, salt=salt)

    existing = db.execute(select(Employee).where(Employee.aadhaar_dob_hash == h)).scalars().all()
    items = [{"employeeId": str(e.employeeId or "").strip(), "status": str(getattr(e, "status", "") or "")} for e in existing]
    return {"duplicate": bool(items), "matches": items}


def _serialize_employee_core(*, emp: Employee, auth: AuthContext, db, cfg) -> dict[str, Any]:
    can_pii = bool(getattr(cfg, "PII_ENC_KEY", "").strip()) and normalize_role(auth.role) in set(getattr(cfg, "PII_VIEW_ROLES", []) or [])

    requirement_id = str(emp.requirementId or "").strip()
    job_title = str(emp.jobTitle or "")
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

    current_role = str(getattr(emp, "currentRole", "") or "").strip() or str(emp.jobRole or "").strip()

    return {
        "employeeId": str(emp.employeeId or "").strip(),
        "candidateId": str(emp.candidateId or "").strip(),
        "requirementId": requirement_id,
        "employeeName": employee_name,
        "mobile": mobile,
        "jobRole": str(emp.jobRole or ""),
        "currentRole": current_role,
        "jobTitle": job_title,
        "source": str(emp.source or ""),
        "cvFileId": str(emp.cvFileId or ""),
        "cvFileName": str(emp.cvFileName or ""),
        "joinedAt": str(emp.joinedAt or ""),
        "probationStartAt": str(emp.probationStartAt or ""),
        "probationEndsAt": str(emp.probationEndsAt or ""),
        "status": str(getattr(emp, "status", "") or "ACTIVE"),
        "exitAt": str(getattr(emp, "exitAt", "") or ""),
        "aadhaarLast4": str(getattr(emp, "aadhaar_last4", "") or ""),
        "createdAt": str(emp.createdAt or ""),
        "createdBy": str(emp.createdBy or ""),
    }


def _serialize_joining_docs(*, emp: Employee, db) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []

    cv_id = str(getattr(emp, "cvFileId", "") or "").strip()
    if cv_id:
        docs.append(
            {
                "source": "CV",
                "docType": "CV",
                "docId": cv_id,
                "storageKey": cv_id,
                "fileName": str(getattr(emp, "cvFileName", "") or ""),
                "mimeType": "",
                "size": 0,
                "uploadedAt": str(getattr(emp, "createdAt", "") or ""),
                "uploadedBy": str(getattr(emp, "createdBy", "") or ""),
                "visibility": "INTERNAL",
                "version": 1,
            }
        )

    cand_id = str(getattr(emp, "candidateId", "") or "").strip()
    if not cand_id:
        return docs

    cand = db.execute(select(Candidate).where(Candidate.candidateId == cand_id)).scalar_one_or_none()
    if not cand:
        return docs

    raw = str(getattr(cand, "docsJson", "") or "").strip()
    entries = _parse_json_list(raw)
    for d in entries:
        if not isinstance(d, dict):
            continue
        file_id = str(d.get("fileId") or "").strip()
        if not file_id:
            continue
        docs.append(
            {
                "source": "JOINING",
                "docType": str(d.get("docType") or ""),
                "docId": file_id,
                "storageKey": file_id,
                "fileName": str(d.get("fileName") or ""),
                "mimeType": str(d.get("mimeType") or ""),
                "size": 0,
                "uploadedAt": str(d.get("uploadedAt") or ""),
                "uploadedBy": "",
                "visibility": "INTERNAL",
                "version": 1,
            }
        )

    return docs


def employee_docs_list(data, auth: AuthContext | None, db, cfg):
    employee_id = str((data or {}).get("employeeId") or "").strip()
    if not employee_id:
        raise ApiError("BAD_REQUEST", "Missing employeeId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    role = normalize_role(auth.role) or ""
    if role == "EMPLOYEE" and employee_id != str(auth.userId or "").strip():
        raise ApiError("FORBIDDEN", "Not allowed", http_status=403)

    emp = db.execute(select(Employee).where(Employee.employeeId == employee_id)).scalar_one_or_none()
    if not emp:
        raise ApiError("NOT_FOUND", "Employee not found")

    joining_docs = _serialize_joining_docs(emp=emp, db=db)

    rows = (
        db.execute(select(EmployeeDoc).where(EmployeeDoc.employee_id == employee_id).order_by(EmployeeDoc.uploaded_at.desc()))
        .scalars()
        .all()
    )
    uploads = [
        {
            "source": "UPLOAD",
            "docType": str(r.doc_type or ""),
            "docId": str(r.id or ""),
            "storageKey": str(r.storage_key or ""),
            "fileName": str(r.file_name or ""),
            "mimeType": str(r.mime_type or ""),
            "size": int(r.size or 0),
            "uploadedAt": str(r.uploaded_at or ""),
            "uploadedBy": str(r.uploaded_by or ""),
            "visibility": str(r.visibility or "INTERNAL"),
            "version": int(r.version or 1),
        }
        for r in rows
    ]

    return {"employeeId": employee_id, "items": joining_docs + uploads, "joiningDocs": joining_docs, "uploadedDocs": uploads}


def _serialize_role_history(*, employee_id: str, emp: Employee, db) -> list[dict[str, Any]]:
    rows = (
        db.execute(select(RoleHistory).where(RoleHistory.employee_id == employee_id).order_by(RoleHistory.start_at.asc()))
        .scalars()
        .all()
    )
    if rows:
        return [
            {
                "role": str(r.role or ""),
                "startAt": str(r.start_at or ""),
                "endAt": str(r.end_at or ""),
                "changedBy": str(r.changed_by or ""),
                "remark": str(r.remark or ""),
            }
            for r in rows
        ]

    role = str(getattr(emp, "currentRole", "") or "").strip() or str(getattr(emp, "jobRole", "") or "").strip()
    joined_at = str(getattr(emp, "joinedAt", "") or "").strip()
    if not role and not joined_at:
        return []
    return [
        {
            "role": role,
            "startAt": joined_at,
            "endAt": "",
            "changedBy": "",
            "remark": "Joined",
        }
    ]


def _serialize_exit_case(*, employee_id: str, db) -> dict[str, Any] | None:
    row = (
        db.execute(select(ExitCase).where(ExitCase.employee_id == employee_id).order_by(ExitCase.created_at.desc()))
        .scalars()
        .first()
    )
    if not row:
        return None
    return {
        "exitId": str(row.id or ""),
        "employeeId": str(row.employee_id or ""),
        "exitType": str(row.exit_type or ""),
        "state": str(row.state or ""),
        "noticeStart": str(row.notice_start or ""),
        "noticeDays": int(row.notice_days or 0),
        "noticeEnd": str(row.notice_end or ""),
        "lastWorkingDay": str(row.last_working_day or ""),
        "absentSince": str(row.absent_since or ""),
        "settlementCleared": bool(row.settlement_cleared),
        "settlementDocId": str(row.settlement_doc_id or ""),
        "terminationLetterDocId": str(row.termination_letter_doc_id or ""),
        "exitCompletedAt": str(row.exit_completed_at or ""),
        "createdAt": str(row.created_at or ""),
        "createdBy": str(row.created_by or ""),
        "updatedAt": str(row.updated_at or ""),
        "updatedBy": str(row.updated_by or ""),
    }


def _serialize_exit_tasks(*, exit_id: str, db) -> list[dict[str, Any]]:
    eid = str(exit_id or "").strip()
    if not eid:
        return []
    tasks = db.execute(select(ExitTask).where(ExitTask.exit_id == eid).order_by(ExitTask.id.asc())).scalars().all()
    out: list[dict[str, Any]] = []
    for t in tasks:
        out.append(
            {
                "id": int(getattr(t, "id", 0) or 0),
                "exitId": str(getattr(t, "exit_id", "") or ""),
                "taskKey": str(getattr(t, "task_key", "") or ""),
                "label": str(getattr(t, "label", "") or ""),
                "department": str(getattr(t, "department", "") or ""),
                "required": bool(getattr(t, "required", False)),
                "status": str(getattr(t, "status", "") or ""),
                "assignedRole": str(getattr(t, "assigned_role", "") or ""),
                "assignedTo": str(getattr(t, "assigned_to", "") or ""),
                "docId": str(getattr(t, "doc_id", "") or ""),
                "note": str(getattr(t, "note", "") or ""),
                "completedBy": str(getattr(t, "completed_by", "") or ""),
                "completedAt": str(getattr(t, "completed_at", "") or ""),
                "updatedAt": str(getattr(t, "updated_at", "") or ""),
                "updatedBy": str(getattr(t, "updated_by", "") or ""),
            }
        )
    return out


def employee_profile_get(data, auth: AuthContext | None, db, cfg):
    employee_id = str((data or {}).get("employeeId") or "").strip()
    if not employee_id:
        raise ApiError("BAD_REQUEST", "Missing employeeId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    role = normalize_role(auth.role) or ""
    if role == "EMPLOYEE" and employee_id != str(auth.userId or "").strip():
        raise ApiError("FORBIDDEN", "Not allowed", http_status=403)

    emp = db.execute(select(Employee).where(Employee.employeeId == employee_id)).scalar_one_or_none()
    if not emp:
        raise ApiError("NOT_FOUND", "Employee not found")

    employee = _serialize_employee_core(emp=emp, auth=auth, db=db, cfg=cfg)
    docs = employee_docs_list({"employeeId": employee_id}, auth, db, cfg)
    role_history = _serialize_role_history(employee_id=employee_id, emp=emp, db=db)
    exit_case = _serialize_exit_case(employee_id=employee_id, db=db)
    exit_tasks = _serialize_exit_tasks(exit_id=(exit_case or {}).get("exitId") or "", db=db) if exit_case else []

    # Lightweight status badges: current role + joined/exit
    badges = {
        "currentRole": employee.get("currentRole") or employee.get("jobRole") or "",
        "joinedAt": employee.get("joinedAt") or "",
        "exitAt": employee.get("exitAt") or "",
        "status": employee.get("status") or "",
    }

    return {
        "employee": employee,
        "docs": docs,
        "roleHistory": role_history,
        "exitCase": exit_case,
        "exitTasks": exit_tasks,
        "badges": badges,
    }


def employee_role_change(data, auth: AuthContext | None, db, cfg):
    employee_id = str((data or {}).get("employeeId") or "").strip()
    new_role = str((data or {}).get("newRole") or "").strip()
    effective_at_raw = (data or {}).get("effectiveAt") or ""
    remark = str((data or {}).get("remark") or "").strip()

    if not employee_id:
        raise ApiError("BAD_REQUEST", "Missing employeeId")
    if not new_role:
        raise ApiError("BAD_REQUEST", "Missing newRole")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    emp = (
        db.execute(select(Employee).where(Employee.employeeId == employee_id).with_for_update(of=Employee))
        .scalars()
        .first()
    )
    if not emp:
        raise ApiError("NOT_FOUND", "Employee not found")

    now = iso_utc_now()
    if effective_at_raw:
        dt = parse_datetime_maybe(effective_at_raw, app_timezone=getattr(cfg, "APP_TIMEZONE", "Asia/Kolkata"))
        if not dt:
            raise ApiError("BAD_REQUEST", "Invalid effectiveAt")
        effective_at = to_iso_utc(dt)
    else:
        effective_at = now

    prev_role = str(getattr(emp, "currentRole", "") or "").strip() or str(emp.jobRole or "").strip()
    prev_job_role = str(emp.jobRole or "")
    if prev_role.strip().upper() == new_role.strip().upper():
        return {"ok": True, "employeeId": employee_id, "currentRole": prev_role, "changed": False}

    # Close current open record (if any)
    open_row = (
        db.execute(
            select(RoleHistory)
            .where(RoleHistory.employee_id == employee_id)
            .where(RoleHistory.end_at == "")
            .order_by(RoleHistory.start_at.desc())
            .with_for_update(of=RoleHistory)
        )
        .scalars()
        .first()
    )
    if open_row:
        start_dt = parse_datetime_maybe(open_row.start_at, app_timezone="UTC") if str(open_row.start_at or "").strip() else None
        eff_dt = parse_datetime_maybe(effective_at, app_timezone="UTC")
        if start_dt and eff_dt and eff_dt < start_dt:
            raise ApiError("BAD_REQUEST", "effectiveAt cannot be before current role start")
        open_row.end_at = effective_at

    db.add(
        RoleHistory(
            employee_id=employee_id,
            role=str(new_role or ""),
            start_at=effective_at,
            end_at="",
            changed_by=str(auth.userId or auth.email or ""),
            remark=remark,
        )
    )

    emp.currentRole = new_role
    emp.jobRole = new_role

    append_audit(
        db,
        entityType="EMPLOYEE",
        entityId=employee_id,
        action="EMPLOYEE_ROLE_CHANGE",
        stageTag="EMPLOYEE_ROLE_CHANGE",
        actor=auth,
        at=now,
        remark=remark or new_role,
        before={"currentRole": prev_role, "jobRole": prev_job_role},
        after={"currentRole": new_role, "jobRole": new_role, "effectiveAt": effective_at},
        meta={"employeeId": employee_id, "effectiveAt": effective_at, "remark": remark},
    )

    return {"ok": True, "employeeId": employee_id, "currentRole": new_role, "effectiveAt": effective_at, "changed": True}
