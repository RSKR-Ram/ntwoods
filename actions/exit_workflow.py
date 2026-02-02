from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from actions.helpers import append_audit, next_prefixed_id
from auth import revoke_user_sessions
from models import Candidate, Employee, EmployeeDoc, ExitCase, ExitTask, Setting
from utils import ApiError, AuthContext, iso_utc_now, normalize_role, parse_datetime_maybe, to_iso_utc


EXIT_TYPES = {"SELF", "ABSCONDED", "TERMINATED"}

SELF_STATES = {"DRAFT", "NOTICE_STARTED", "SETTLEMENT_PENDING", "READY_TO_EXIT", "EXITED"}
ABSCONDED_STATES = {"MARKED_ABSCONDED", "REVIEW_PENDING", "EXITED"}
TERMINATED_STATES = {"TERMINATION_INIT", "SETTLEMENT_PENDING", "LETTER_PENDING", "EXITED"}

_EXIT_TASK_STATUS = {"PENDING", "DONE", "NA", "BLOCKED"}


def _exit_task_defs(exit_type: str) -> list[dict]:
    """
    Default enterprise clearance checklist.
    Roles:
      - HR -> HR/ADMIN
      - IT -> MIS/ADMIN
      - FINANCE -> ACCOUNTS/ADMIN
      - ADMIN -> ADMIN
    """

    et = str(exit_type or "").upper().strip()
    is_absconded = et == "ABSCONDED"
    is_terminated = et == "TERMINATED"

    tasks: list[dict] = [
        {"key": "HR_EXIT_INTERVIEW", "label": "Exit interview / reason capture", "department": "HR", "role": "HR", "required": not is_absconded},
        {"key": "HR_HANDOVER", "label": "Handover & knowledge transfer", "department": "HR", "role": "HR", "required": not is_absconded},
        {"key": "IT_ASSET_RETURN", "label": "IT assets returned (laptop/ID etc)", "department": "IT", "role": "MIS", "required": not is_absconded},
        {"key": "IT_ACCESS_REVOKE", "label": "Disable email / revoke system access", "department": "IT", "role": "MIS", "required": True},
        {"key": "FINANCE_CLEARANCE", "label": "Finance clearance (advances/recovery)", "department": "FINANCE", "role": "ACCOUNTS", "required": True},
        {"key": "FINANCE_SETTLEMENT", "label": "Final settlement processed", "department": "FINANCE", "role": "ACCOUNTS", "required": True},
        {"key": "ADMIN_ID_CARD_RETURN", "label": "ID card / office assets returned", "department": "ADMIN", "role": "ADMIN", "required": not is_absconded},
    ]
    if is_terminated:
        tasks.append(
            {"key": "HR_TERMINATION_LETTER", "label": "Termination letter issued", "department": "HR", "role": "HR", "required": True}
        )
    return tasks


def _create_exit_tasks_if_missing(*, db, exit_id: str, exit_type: str, auth: AuthContext | None, now: str) -> int:
    existing = db.execute(select(ExitTask).where(ExitTask.exit_id == exit_id)).scalars().first()
    if existing:
        return 0

    actor = str((auth.userId if auth else "") or (auth.email if auth else "") or "").strip()
    rows = []
    for d in _exit_task_defs(exit_type):
        rows.append(
            ExitTask(
                exit_id=exit_id,
                task_key=str(d["key"]),
                label=str(d["label"]),
                department=str(d["department"]),
                required=bool(d.get("required", True)),
                status="PENDING",
                assigned_role=str(d.get("role") or ""),
                assigned_to="",
                doc_id="",
                note="",
                completed_by="",
                completed_at="",
                created_at=now,
                created_by=actor,
                updated_at=now,
                updated_by=actor,
            )
        )
    db.add_all(rows)
    return len(rows)


def _serialize_exit_task(row: ExitTask) -> dict:
    return {
        "id": int(row.id or 0),
        "exitId": str(row.exit_id or ""),
        "taskKey": str(row.task_key or ""),
        "label": str(row.label or ""),
        "department": str(row.department or ""),
        "required": bool(row.required),
        "status": str(row.status or ""),
        "assignedRole": str(row.assigned_role or ""),
        "assignedTo": str(row.assigned_to or ""),
        "docId": str(row.doc_id or ""),
        "note": str(row.note or ""),
        "completedBy": str(row.completed_by or ""),
        "completedAt": str(row.completed_at or ""),
        "updatedAt": str(row.updated_at or ""),
        "updatedBy": str(row.updated_by or ""),
    }


def _task_allowed_roles(department: str) -> set[str]:
    dep = str(department or "").upper().strip()
    if dep == "IT":
        return {"MIS", "ADMIN"}
    if dep == "FINANCE":
        return {"ACCOUNTS", "ADMIN"}
    if dep == "HR":
        return {"HR", "ADMIN"}
    if dep == "ADMIN":
        return {"ADMIN"}
    return {"ADMIN"}


def _enforce_exit_tasks(db, *, exit_id: str) -> None:
    """
    Enterprise rule: required tasks must be DONE/NA before exit can complete.
    Controlled by setting EXIT_TASKS_ENFORCED (default true).
    """

    enforced = _setting_bool(db, "EXIT_TASKS_ENFORCED", True)
    if not enforced:
        return

    tasks = db.execute(select(ExitTask).where(ExitTask.exit_id == exit_id)).scalars().all()
    if not tasks:
        # If tasks were never created for this exit case, don't block legacy flows.
        return

    pending_required = [
        t for t in tasks if bool(getattr(t, "required", False)) and str(t.status or "").upper().strip() not in {"DONE", "NA"}
    ]
    if pending_required:
        raise ApiError("BAD_REQUEST", f"Exit clearance pending: {len(pending_required)} task(s) not completed")


def _assert_probation_completed(db, *, employee_id: str) -> None:
    """
    Guardrail: do not allow Exit workflow while employee is still on probation.

    The Employee record is created during PROBATION_SET. Until PROBATION_COMPLETE,
    the linked Candidate status remains PROBATION, and exiting must be blocked.
    """

    emp = db.execute(select(Employee).where(Employee.employeeId == employee_id)).scalar_one_or_none()
    if not emp:
        raise ApiError("NOT_FOUND", "Employee not found")

    # Fast-path: employee status is explicitly tracked.
    if str(getattr(emp, "status", "") or "").upper().strip() == "PROBATION":
        raise ApiError("BAD_REQUEST", "Exit workflow is not allowed until probation is completed")

    cand_id = str(getattr(emp, "candidateId", "") or "").strip()
    if not cand_id:
        return

    cand = db.execute(select(Candidate).where(Candidate.candidateId == cand_id)).scalar_one_or_none()
    if not cand:
        return

    if str(getattr(cand, "status", "") or "").upper().strip() != "EMPLOYEE":
        raise ApiError("BAD_REQUEST", "Exit workflow is not allowed until probation is completed")


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

    _assert_probation_completed(db, employee_id=employee_id)

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

    _create_exit_tasks_if_missing(db=db, exit_id=exit_id, exit_type="SELF", auth=auth, now=now)

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

    _assert_probation_completed(db, employee_id=employee_id)

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

    _create_exit_tasks_if_missing(db=db, exit_id=exit_id, exit_type="ABSCONDED", auth=auth, now=now)

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

    bypass = bool((data or {}).get("_bypassProbationGuard"))
    if not bypass:
        _assert_probation_completed(db, employee_id=employee_id)
    else:
        # Internal/system usage (e.g. probation reject) is allowed to terminate, but only for HR/Admin actors.
        role_u = normalize_role(auth.role) if auth else ""
        if role_u not in {"ADMIN", "HR"}:
            raise ApiError("FORBIDDEN", "Not allowed", http_status=403)

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

    _create_exit_tasks_if_missing(db=db, exit_id=exit_id, exit_type="TERMINATED", auth=auth, now=now)

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

    # If enterprise tasks exist, automatically mark the settlement task as done.
    task = (
        db.execute(select(ExitTask).where(ExitTask.exit_id == exit_id).where(ExitTask.task_key == "FINANCE_SETTLEMENT").with_for_update(of=ExitTask))
        .scalars()
        .first()
    )
    if task and str(task.status or "").upper().strip() != "DONE":
        task.status = "DONE"
        task.doc_id = settlement_doc_id
        task.completed_by = str(auth.userId or auth.email or "")
        task.completed_at = now
        task.updated_at = now
        task.updated_by = str(auth.userId or auth.email or "")

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

    # If enterprise tasks exist, automatically mark the termination letter task as done.
    task = (
        db.execute(select(ExitTask).where(ExitTask.exit_id == exit_id).where(ExitTask.task_key == "HR_TERMINATION_LETTER").with_for_update(of=ExitTask))
        .scalars()
        .first()
    )
    if task and str(task.status or "").upper().strip() != "DONE":
        task.status = "DONE"
        task.doc_id = letter_doc_id
        task.completed_by = str(auth.userId or auth.email or "")
        task.completed_at = now
        task.updated_at = now
        task.updated_by = str(auth.userId or auth.email or "")

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

    # Enterprise enforcement (if tasks exist for this case).
    _enforce_exit_tasks(db, exit_id=exit_id)

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


def exit_tasks_get(data, auth: AuthContext | None, db, cfg):
    exit_id = str((data or {}).get("exitId") or "").strip()
    if not exit_id:
        raise ApiError("BAD_REQUEST", "Missing exitId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    row = db.execute(select(ExitCase).where(ExitCase.id == exit_id)).scalar_one_or_none()
    if not row:
        raise ApiError("NOT_FOUND", "Exit case not found")

    role = normalize_role(auth.role) or ""
    if role == "EMPLOYEE" and str(row.employee_id or "").strip() != str(auth.userId or "").strip():
        raise ApiError("FORBIDDEN", "Not allowed", http_status=403)

    tasks = db.execute(select(ExitTask).where(ExitTask.exit_id == exit_id).order_by(ExitTask.id.asc())).scalars().all()
    out = [_serialize_exit_task(t) for t in tasks]
    required = [t for t in tasks if bool(getattr(t, "required", False))]
    done = [t for t in required if str(t.status or "").upper().strip() in {"DONE", "NA"}]
    return {
        "ok": True,
        "exitId": exit_id,
        "tasks": out,
        "summary": {"required": len(required), "requiredDone": len(done), "pending": max(0, len(required) - len(done))},
    }


def exit_task_update(data, auth: AuthContext | None, db, cfg):
    exit_id = str((data or {}).get("exitId") or "").strip()
    task_key = str((data or {}).get("taskKey") or "").strip()
    status_in = str((data or {}).get("status") or "").upper().strip()
    note = str((data or {}).get("note") or "").strip()
    doc_id = str((data or {}).get("docId") or "").strip()

    if not exit_id:
        raise ApiError("BAD_REQUEST", "Missing exitId")
    if not task_key:
        raise ApiError("BAD_REQUEST", "Missing taskKey")
    if status_in and status_in not in _EXIT_TASK_STATUS:
        raise ApiError("BAD_REQUEST", "Invalid status")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    exit_row = (
        db.execute(select(ExitCase).where(ExitCase.id == exit_id).with_for_update(of=ExitCase))
        .scalars()
        .first()
    )
    if not exit_row:
        raise ApiError("NOT_FOUND", "Exit case not found")
    if str(exit_row.exit_completed_at or "").strip():
        raise ApiError("BAD_REQUEST", "Exit case already completed")

    task = (
        db.execute(select(ExitTask).where(ExitTask.exit_id == exit_id).where(ExitTask.task_key == task_key).with_for_update(of=ExitTask))
        .scalars()
        .first()
    )
    if not task:
        raise ApiError("NOT_FOUND", "Exit task not found")

    role = normalize_role(auth.role) or ""
    allowed_roles = _task_allowed_roles(str(task.department or ""))
    if role not in allowed_roles:
        raise ApiError("FORBIDDEN", "Not allowed to update this task", http_status=403)

    assigned_to = str(task.assigned_to or "").strip()
    if assigned_to and str(auth.userId or "").strip() != assigned_to and role != "ADMIN":
        raise ApiError("FORBIDDEN", "Task is assigned to another user", http_status=403)

    before = _serialize_exit_task(task)
    now = iso_utc_now()
    actor = str(auth.userId or auth.email or "")

    if status_in:
        task.status = status_in
        if status_in in {"DONE", "NA"}:
            task.completed_by = actor
            task.completed_at = now
        elif status_in in {"PENDING", "BLOCKED"}:
            task.completed_by = ""
            task.completed_at = ""

    if note or note == "":
        task.note = note
    if doc_id:
        # optional integrity check
        doc = db.execute(select(EmployeeDoc).where(EmployeeDoc.id == doc_id)).scalar_one_or_none()
        if not doc:
            raise ApiError("NOT_FOUND", "Document not found")
        if str(doc.employee_id or "").strip() != str(exit_row.employee_id or "").strip():
            raise ApiError("BAD_REQUEST", "Document does not belong to this employee")
        task.doc_id = doc_id

    task.updated_at = now
    task.updated_by = actor

    after = _serialize_exit_task(task)
    append_audit(
        db,
        entityType="EXIT_TASK",
        entityId=f"{exit_id}:{task_key}",
        action="EXIT_TASK_UPDATE",
        stageTag="EXIT_TASK_UPDATE",
        actor=auth,
        at=now,
        before=before,
        after=after,
        meta={"exitId": exit_id, "taskKey": task_key},
    )

    return {"ok": True, "task": after}


def exit_clearance_queue(data, auth: AuthContext | None, db, cfg):
    """
    Department clearance queue for MIS/ACCOUNTS/HR/ADMIN.

    Returns only active (not completed) exit cases with task progress for the
    caller's department.
    """

    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    role = normalize_role(auth.role) or ""
    dep = ""
    if role == "MIS":
        dep = "IT"
    elif role == "ACCOUNTS":
        dep = "FINANCE"
    elif role == "HR":
        dep = "HR"
    elif role == "ADMIN":
        dep = ""
    else:
        raise ApiError("FORBIDDEN", "Not allowed", http_status=403)

    # Limit to prevent accidental full-table scans in production.
    rows = (
        db.execute(select(ExitCase).where(ExitCase.exit_completed_at == "").order_by(ExitCase.updated_at.desc()).limit(200))
        .scalars()
        .all()
    )
    if not rows:
        return {"ok": True, "items": [], "total": 0}

    exit_ids = [str(r.id or "") for r in rows if str(r.id or "").strip()]
    tasks = db.execute(select(ExitTask).where(ExitTask.exit_id.in_(exit_ids))).scalars().all()
    tasks_by_exit: dict[str, list[ExitTask]] = {}
    for t in tasks:
        tasks_by_exit.setdefault(str(t.exit_id or ""), []).append(t)

    # Employee name is not strictly required for clearance, but helps identify the record.
    emp_ids = [str(r.employee_id or "") for r in rows if str(r.employee_id or "").strip()]
    emp_by_id = {str(e.employeeId or ""): e for e in db.execute(select(Employee).where(Employee.employeeId.in_(emp_ids))).scalars().all()}

    items = []
    for r in rows:
        eid = str(r.id or "")
        emp_id = str(r.employee_id or "")
        emp = emp_by_id.get(emp_id)
        all_tasks = tasks_by_exit.get(eid, [])
        dept_tasks = [t for t in all_tasks if not dep or str(t.department or "").upper().strip() == dep]
        required = [t for t in dept_tasks if bool(getattr(t, "required", False))]
        required_done = [t for t in required if str(t.status or "").upper().strip() in {"DONE", "NA"}]
        pending = [t for t in required if str(t.status or "").upper().strip() not in {"DONE", "NA"}]

        # If tasks are not created (legacy exits), surface only to HR/Admin (they can decide).
        if not all_tasks and role in {"MIS", "ACCOUNTS"}:
            continue

        items.append(
            {
                "exitId": eid,
                "employeeId": emp_id,
                "employeeName": str(getattr(emp, "employeeName", "") or ""),
                "exitType": str(r.exit_type or ""),
                "state": str(r.state or ""),
                "noticeEnd": str(r.notice_end or ""),
                "lastWorkingDay": str(r.last_working_day or ""),
                "absentSince": str(r.absent_since or ""),
                "updatedAt": str(r.updated_at or ""),
                "dept": dep or "ALL",
                "counts": {"required": len(required), "done": len(required_done), "pending": len(pending)},
            }
        )

    # Sort by pending desc, then recent updates.
    items.sort(key=lambda x: (-int((x.get("counts") or {}).get("pending") or 0), str(x.get("updatedAt") or "")), reverse=False)
    return {"ok": True, "items": items, "total": len(items)}


def exit_clearance_get(data, auth: AuthContext | None, db, cfg):
    exit_id = str((data or {}).get("exitId") or "").strip()
    if not exit_id:
        raise ApiError("BAD_REQUEST", "Missing exitId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    role = normalize_role(auth.role) or ""
    if role not in {"ADMIN", "HR", "MIS", "ACCOUNTS"}:
        raise ApiError("FORBIDDEN", "Not allowed", http_status=403)

    row = db.execute(select(ExitCase).where(ExitCase.id == exit_id)).scalar_one_or_none()
    if not row:
        raise ApiError("NOT_FOUND", "Exit case not found")

    emp = db.execute(select(Employee).where(Employee.employeeId == str(row.employee_id or ""))).scalar_one_or_none()
    tasks = db.execute(select(ExitTask).where(ExitTask.exit_id == exit_id).order_by(ExitTask.id.asc())).scalars().all()

    return {
        "ok": True,
        "exitCase": _serialize_exit_case(row),
        "employee": {
            "employeeId": str(getattr(emp, "employeeId", "") or str(row.employee_id or "")),
            "employeeName": str(getattr(emp, "employeeName", "") or ""),
            "jobRole": str(getattr(emp, "jobRole", "") or ""),
            "jobTitle": str(getattr(emp, "jobTitle", "") or ""),
            "status": str(getattr(emp, "status", "") or ""),
        },
        "tasks": [_serialize_exit_task(t) for t in tasks],
    }
