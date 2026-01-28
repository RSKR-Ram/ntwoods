from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from actions.helpers import append_audit, next_prefixed_id
from auth import revoke_user_sessions
from models import Employee, EmployeeDoc, ExitCase, Setting
from utils import ApiError, AuthContext, iso_utc_now, normalize_role, parse_datetime_maybe, to_iso_utc


EXIT_TYPES = {"SELF", "ABSCONDED", "TERMINATED"}

SELF_STATES = {"DRAFT", "NOTICE_STARTED", "SETTLEMENT_PENDING", "READY_TO_EXIT", "EXITED"}
ABSCONDED_STATES = {"MARKED_ABSCONDED", "REVIEW_PENDING", "EXITED"}
TERMINATED_STATES = {"TERMINATION_INIT", "SETTLEMENT_PENDING", "LETTER_PENDING", "EXITED"}


def _setting_int(db, key: str, default: int) -> int:
    k = str(key or "").strip()
    if not k:
        return int(default)
    row = db.execute(select(Setting).where(Setting.key == k)).scalar_one_or_none()
    raw = str(getattr(row, "value", "") or "").strip() if row else ""
    if not raw:
        return int(default)
    try:
        return int(float(raw))
    except Exception:
        return int(default)


def _setting_bool(db, key: str, default: bool) -> bool:
    k = str(key or "").strip()
    if not k:
        return bool(default)
    row = db.execute(select(Setting).where(Setting.key == k)).scalar_one_or_none()
    raw = str(getattr(row, "value", "") or "").strip().lower() if row else ""
    if not raw:
        return bool(default)
    return raw in {"1", "true", "yes", "y", "on"}


def _new_exit_id(db) -> str:
    year = datetime.now(timezone.utc).strftime("%Y")
    prefix = f"EXIT-{year}-"
    existing = [str(x or "") for x in db.execute(select(ExitCase.id).where(ExitCase.id.like(f"{prefix}%"))).scalars().all()]
    return next_prefixed_id(db, counter_key=f"EXIT_{year}", prefix=prefix, pad=5, existing_ids=existing)


def _serialize_exit_case(row: ExitCase) -> dict:
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


def _get_active_case_for_employee(db, employee_id: str) -> ExitCase | None:
    return (
        db.execute(
            select(ExitCase)
            .where(ExitCase.employee_id == employee_id)
            .where(ExitCase.exit_completed_at == "")
            .order_by(ExitCase.created_at.desc())
        )
        .scalars()
        .first()
    )


def exit_start_notice(data, auth: AuthContext | None, db, cfg):
    employee_id = str((data or {}).get("employeeId") or "").strip()
    try:
        notice_days_in = int((data or {}).get("noticeDays") or 0)
    except Exception:
        notice_days_in = 0

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

    active = _get_active_case_for_employee(db, employee_id)
    if active:
        raise ApiError("CONFLICT", "An active exit case already exists", http_status=409)

    default_notice = _setting_int(db, "EXIT_NOTICE_DAYS_DEFAULT", 30)
    notice_days = notice_days_in if notice_days_in > 0 else default_notice
    if notice_days <= 0 or notice_days > 365:
        raise ApiError("BAD_REQUEST", "Invalid noticeDays")

    now_dt = datetime.now(timezone.utc)
    now = iso_utc_now()
    notice_end = to_iso_utc(now_dt + timedelta(days=int(notice_days)))

    exit_id = _new_exit_id(db)
    row = ExitCase(
        id=exit_id,
        employee_id=employee_id,
        exit_type="SELF",
        state="NOTICE_STARTED",
        notice_start=now,
        notice_days=int(notice_days),
        notice_end=notice_end,
        last_working_day="",
        absent_since="",
        settlement_cleared=False,
        settlement_doc_id="",
        termination_letter_doc_id="",
        exit_completed_at="",
        created_at=now,
        created_by=str(auth.userId or auth.email or ""),
        updated_at=now,
        updated_by=str(auth.userId or auth.email or ""),
    )
    db.add(row)

    append_audit(
        db,
        entityType="EXIT_CASE",
        entityId=exit_id,
        action="EXIT_START_NOTICE",
        stageTag="EXIT_START_NOTICE",
        actor=auth,
        at=now,
        meta={"employeeId": employee_id, "noticeDays": int(notice_days), "noticeEnd": notice_end},
    )

    return {"ok": True, "exitCase": _serialize_exit_case(row)}


def exit_mark_absconded(data, auth: AuthContext | None, db, cfg):
    employee_id = str((data or {}).get("employeeId") or "").strip()
    absent_since_raw = str((data or {}).get("absentSince") or "").strip()
    remark = str((data or {}).get("remark") or "").strip()

    if not employee_id:
        raise ApiError("BAD_REQUEST", "Missing employeeId")
    if not absent_since_raw:
        raise ApiError("BAD_REQUEST", "Missing absentSince")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    emp = db.execute(select(Employee).where(Employee.employeeId == employee_id)).scalar_one_or_none()
    if not emp:
        raise ApiError("NOT_FOUND", "Employee not found")

    active = _get_active_case_for_employee(db, employee_id)
    if active:
        raise ApiError("CONFLICT", "An active exit case already exists", http_status=409)

    dt = parse_datetime_maybe(absent_since_raw, app_timezone=getattr(cfg, "APP_TIMEZONE", "Asia/Kolkata"))
    if not dt:
        raise ApiError("BAD_REQUEST", "Invalid absentSince")
    absent_since = to_iso_utc(dt)

    now = iso_utc_now()
    exit_id = _new_exit_id(db)
    row = ExitCase(
        id=exit_id,
        employee_id=employee_id,
        exit_type="ABSCONDED",
        state="REVIEW_PENDING",
        notice_start="",
        notice_days=0,
        notice_end="",
        last_working_day="",
        absent_since=absent_since,
        settlement_cleared=False,
        settlement_doc_id="",
        termination_letter_doc_id="",
        exit_completed_at="",
        created_at=now,
        created_by=str(auth.userId or auth.email or ""),
        updated_at=now,
        updated_by=str(auth.userId or auth.email or ""),
    )
    db.add(row)

    append_audit(
        db,
        entityType="EXIT_CASE",
        entityId=exit_id,
        action="EXIT_MARK_ABSCONDED",
        stageTag="EXIT_MARK_ABSCONDED",
        actor=auth,
        at=now,
        remark=remark,
        meta={"employeeId": employee_id, "absentSince": absent_since, "remark": remark},
    )

    return {"ok": True, "exitCase": _serialize_exit_case(row)}


def exit_terminate_init(data, auth: AuthContext | None, db, cfg):
    employee_id = str((data or {}).get("employeeId") or "").strip()
    last_working_day_raw = str((data or {}).get("lastWorkingDay") or "").strip()
    remark = str((data or {}).get("remark") or "").strip()

    if not employee_id:
        raise ApiError("BAD_REQUEST", "Missing employeeId")
    if not last_working_day_raw:
        raise ApiError("BAD_REQUEST", "Missing lastWorkingDay")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    emp = db.execute(select(Employee).where(Employee.employeeId == employee_id)).scalar_one_or_none()
    if not emp:
        raise ApiError("NOT_FOUND", "Employee not found")

    active = _get_active_case_for_employee(db, employee_id)
    if active:
        raise ApiError("CONFLICT", "An active exit case already exists", http_status=409)

    dt = parse_datetime_maybe(last_working_day_raw, app_timezone=getattr(cfg, "APP_TIMEZONE", "Asia/Kolkata"))
    if not dt:
        raise ApiError("BAD_REQUEST", "Invalid lastWorkingDay")
    last_working_day = to_iso_utc(dt)

    now = iso_utc_now()
    exit_id = _new_exit_id(db)
    row = ExitCase(
        id=exit_id,
        employee_id=employee_id,
        exit_type="TERMINATED",
        state="TERMINATION_INIT",
        notice_start="",
        notice_days=0,
        notice_end="",
        last_working_day=last_working_day,
        absent_since="",
        settlement_cleared=False,
        settlement_doc_id="",
        termination_letter_doc_id="",
        exit_completed_at="",
        created_at=now,
        created_by=str(auth.userId or auth.email or ""),
        updated_at=now,
        updated_by=str(auth.userId or auth.email or ""),
    )
    db.add(row)

    append_audit(
        db,
        entityType="EXIT_CASE",
        entityId=exit_id,
        action="EXIT_TERMINATE_INIT",
        stageTag="EXIT_TERMINATE_INIT",
        actor=auth,
        at=now,
        remark=remark,
        meta={"employeeId": employee_id, "lastWorkingDay": last_working_day, "remark": remark},
    )

    return {"ok": True, "exitCase": _serialize_exit_case(row)}


def exit_settlement_clear(data, auth: AuthContext | None, db, cfg):
    exit_id = str((data or {}).get("exitId") or "").strip()
    settlement_doc_id = str((data or {}).get("settlementDocId") or "").strip()
    if not exit_id:
        raise ApiError("BAD_REQUEST", "Missing exitId")
    if not settlement_doc_id:
        raise ApiError("BAD_REQUEST", "Missing settlementDocId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    row = (
        db.execute(select(ExitCase).where(ExitCase.id == exit_id).with_for_update(of=ExitCase))
        .scalars()
        .first()
    )
    if not row:
        raise ApiError("NOT_FOUND", "Exit case not found")
    if str(row.exit_completed_at or "").strip():
        raise ApiError("BAD_REQUEST", "Exit case already completed")

    doc = db.execute(select(EmployeeDoc).where(EmployeeDoc.id == settlement_doc_id)).scalar_one_or_none()
    if not doc:
        raise ApiError("NOT_FOUND", "Settlement document not found")
    if str(doc.employee_id or "").strip() != str(row.employee_id or "").strip():
        raise ApiError("BAD_REQUEST", "Settlement document does not belong to this employee")

    before = _serialize_exit_case(row)

    now_dt = datetime.now(timezone.utc)
    now = iso_utc_now()

    row.settlement_cleared = True
    row.settlement_doc_id = settlement_doc_id

    exit_type = str(row.exit_type or "").upper().strip()
    if exit_type == "SELF":
        if str(row.state or "") not in {"NOTICE_STARTED", "SETTLEMENT_PENDING", "READY_TO_EXIT"}:
            raise ApiError("BAD_REQUEST", "Invalid state for settlement clear")
        notice_end_dt = parse_datetime_maybe(row.notice_end, app_timezone="UTC") if str(row.notice_end or "").strip() else None
        if notice_end_dt and now_dt >= notice_end_dt:
            row.state = "READY_TO_EXIT"
        else:
            row.state = "SETTLEMENT_PENDING"
    elif exit_type == "TERMINATED":
        if str(row.state or "") not in {"TERMINATION_INIT", "SETTLEMENT_PENDING", "LETTER_PENDING"}:
            raise ApiError("BAD_REQUEST", "Invalid state for settlement clear")
        row.state = "LETTER_PENDING"
    elif exit_type == "ABSCONDED":
        # Settlement is optional by default for ABSCONDED; keep state.
        pass
    else:
        raise ApiError("BAD_REQUEST", "Invalid exitType")

    row.updated_at = now
    row.updated_by = str(auth.userId or auth.email or "")

    after = _serialize_exit_case(row)
    append_audit(
        db,
        entityType="EXIT_CASE",
        entityId=exit_id,
        action="EXIT_SETTLEMENT_CLEAR",
        stageTag="EXIT_SETTLEMENT_CLEAR",
        actor=auth,
        at=now,
        before=before,
        after=after,
        meta={"exitId": exit_id, "settlementDocId": settlement_doc_id},
    )

    return {"ok": True, "exitCase": after}


def exit_attach_termination_letter(data, auth: AuthContext | None, db, cfg):
    exit_id = str((data or {}).get("exitId") or "").strip()
    letter_doc_id = str((data or {}).get("terminationLetterDocId") or "").strip()
    if not exit_id:
        raise ApiError("BAD_REQUEST", "Missing exitId")
    if not letter_doc_id:
        raise ApiError("BAD_REQUEST", "Missing terminationLetterDocId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    row = (
        db.execute(select(ExitCase).where(ExitCase.id == exit_id).with_for_update(of=ExitCase))
        .scalars()
        .first()
    )
    if not row:
        raise ApiError("NOT_FOUND", "Exit case not found")
    if str(row.exit_completed_at or "").strip():
        raise ApiError("BAD_REQUEST", "Exit case already completed")
    if str(row.exit_type or "").upper().strip() != "TERMINATED":
        raise ApiError("BAD_REQUEST", "Termination letter is only for TERMINATED exits")
    if str(row.state or "").strip() not in {"LETTER_PENDING", "SETTLEMENT_PENDING", "TERMINATION_INIT"}:
        raise ApiError("BAD_REQUEST", "Invalid state for termination letter")

    doc = db.execute(select(EmployeeDoc).where(EmployeeDoc.id == letter_doc_id)).scalar_one_or_none()
    if not doc:
        raise ApiError("NOT_FOUND", "Termination letter document not found")
    if str(doc.employee_id or "").strip() != str(row.employee_id or "").strip():
        raise ApiError("BAD_REQUEST", "Termination letter document does not belong to this employee")

    before = _serialize_exit_case(row)
    now = iso_utc_now()

    row.termination_letter_doc_id = letter_doc_id
    row.state = "LETTER_PENDING"
    row.updated_at = now
    row.updated_by = str(auth.userId or auth.email or "")

    after = _serialize_exit_case(row)
    append_audit(
        db,
        entityType="EXIT_CASE",
        entityId=exit_id,
        action="EXIT_ATTACH_TERMINATION_LETTER",
        stageTag="EXIT_ATTACH_TERMINATION_LETTER",
        actor=auth,
        at=now,
        before=before,
        after=after,
        meta={"exitId": exit_id, "terminationLetterDocId": letter_doc_id},
    )

    return {"ok": True, "exitCase": after}


def exit_complete(data, auth: AuthContext | None, db, cfg):
    exit_id = str((data or {}).get("exitId") or "").strip()
    if not exit_id:
        raise ApiError("BAD_REQUEST", "Missing exitId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    row = (
        db.execute(select(ExitCase).where(ExitCase.id == exit_id).with_for_update(of=ExitCase))
        .scalars()
        .first()
    )
    if not row:
        raise ApiError("NOT_FOUND", "Exit case not found")
    if str(row.exit_completed_at or "").strip():
        return {"ok": True, "exitCase": _serialize_exit_case(row), "alreadyExited": True}

    emp = (
        db.execute(select(Employee).where(Employee.employeeId == str(row.employee_id or "")).with_for_update(of=Employee))
        .scalars()
        .first()
    )
    if not emp:
        raise ApiError("NOT_FOUND", "Employee not found")

    before = _serialize_exit_case(row)

    now_dt = datetime.now(timezone.utc)
    now = iso_utc_now()

    exit_type = str(row.exit_type or "").upper().strip()
    if exit_type == "SELF":
        notice_end_dt = parse_datetime_maybe(row.notice_end, app_timezone="UTC") if str(row.notice_end or "").strip() else None
        if not notice_end_dt:
            raise ApiError("BAD_REQUEST", "Notice end not set")
        if now_dt < notice_end_dt:
            raise ApiError("BAD_REQUEST", "Notice period not completed yet")
        if not bool(row.settlement_cleared) or not str(row.settlement_doc_id or "").strip():
            raise ApiError("BAD_REQUEST", "Settlement not cleared")
        if not db.execute(select(EmployeeDoc).where(EmployeeDoc.id == str(row.settlement_doc_id or ""))).scalar_one_or_none():
            raise ApiError("BAD_REQUEST", "Settlement document not found")
    elif exit_type == "ABSCONDED":
        require_settlement = _setting_bool(db, "EXIT_ABSCONDED_REQUIRE_SETTLEMENT", False)
        if require_settlement:
            if not bool(row.settlement_cleared) or not str(row.settlement_doc_id or "").strip():
                raise ApiError("BAD_REQUEST", "Settlement not cleared")
            if not db.execute(select(EmployeeDoc).where(EmployeeDoc.id == str(row.settlement_doc_id or ""))).scalar_one_or_none():
                raise ApiError("BAD_REQUEST", "Settlement document not found")
    elif exit_type == "TERMINATED":
        if not bool(row.settlement_cleared) or not str(row.settlement_doc_id or "").strip():
            raise ApiError("BAD_REQUEST", "Settlement not cleared")
        if not str(row.termination_letter_doc_id or "").strip():
            raise ApiError("BAD_REQUEST", "Termination letter not attached")
        if not db.execute(select(EmployeeDoc).where(EmployeeDoc.id == str(row.settlement_doc_id or ""))).scalar_one_or_none():
            raise ApiError("BAD_REQUEST", "Settlement document not found")
        if not db.execute(select(EmployeeDoc).where(EmployeeDoc.id == str(row.termination_letter_doc_id or ""))).scalar_one_or_none():
            raise ApiError("BAD_REQUEST", "Termination letter document not found")
    else:
        raise ApiError("BAD_REQUEST", "Invalid exitType")

    row.state = "EXITED"
    row.exit_completed_at = now
    row.updated_at = now
    row.updated_by = str(auth.userId or auth.email or "")

    emp.status = "EXITED"
    emp.exitAt = now
    emp.exit_date = now
    emp.is_active = False
    emp.auth_version = int(getattr(emp, "auth_version", 0) or 0) + 1

    revoked = revoke_user_sessions(db, user_id=str(emp.employeeId or ""), role="EMPLOYEE", revoked_by=str(auth.userId or auth.email or ""))

    after = _serialize_exit_case(row)
    append_audit(
        db,
        entityType="EXIT_CASE",
        entityId=exit_id,
        action="EXIT_COMPLETE",
        stageTag="EXIT_COMPLETE",
        actor=auth,
        at=now,
        before=before,
        after=after,
        meta={"employeeId": str(row.employee_id or ""), "exitType": exit_type},
    )

    append_audit(
        db,
        entityType="EMPLOYEE",
        entityId=str(row.employee_id or ""),
        action="EMPLOYEE_EXITED",
        stageTag="EXIT_COMPLETE",
        actor=auth,
        at=now,
        meta={"exitId": exit_id, "exitType": exit_type, "revokedSessions": int(revoked or 0)},
        before={"status": "ACTIVE", "is_active": True, "exitAt": "", "exit_date": ""},
        after={"status": "EXITED", "is_active": False, "exitAt": now, "exit_date": now},
    )

    return {"ok": True, "exitCase": after, "employee": {"employeeId": str(emp.employeeId or ""), "status": "EXITED", "exitAt": now}}
