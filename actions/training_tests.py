from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select

from actions.helpers import append_audit
from models import AssignedTraining, Employee, TrainingAttempt, TrainingModule, TrainingQuestion, TrainingSetting, TrainingMaster
from utils import ApiError, AuthContext, iso_utc_now, normalize_role, parse_datetime_maybe, safe_json_string


def _serialize_settings(row: TrainingSetting | None) -> dict[str, Any]:
    if not row:
        return {"passMarks": 0, "timeLimitMin": 0, "maxAttempts": 0, "randomize": False}
    return {
        "passMarks": int(getattr(row, "passMarks", 0) or 0),
        "timeLimitMin": int(getattr(row, "timeLimitMin", 0) or 0),
        "maxAttempts": int(getattr(row, "maxAttempts", 0) or 0),
        "randomize": bool(getattr(row, "randomize", False)),
    }


def _require_employee_training_completed(db, *, employee_id: str, module_id: str) -> None:
    emp = db.execute(select(Employee).where(Employee.employeeId == employee_id)).scalar_one_or_none()
    if not emp:
        raise ApiError("NOT_FOUND", "Employee not found")
    cand_id = str(getattr(emp, "candidateId", "") or "").strip()
    if not cand_id:
        raise ApiError("FORBIDDEN", "Training mapping not found", http_status=403)

    row = (
        db.execute(select(AssignedTraining).where(AssignedTraining.candidate_id == cand_id).where(AssignedTraining.training_id == module_id))
        .scalars()
        .first()
    )
    if not row:
        raise ApiError("FORBIDDEN", "Training not assigned", http_status=403)
    status = str(getattr(row, "status", "") or "").upper().strip()
    if status != "COMPLETED":
        raise ApiError("FORBIDDEN", "Training must be completed before taking the test", http_status=403)


def training_modules_get(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    modules = db.execute(select(TrainingModule).order_by(TrainingModule.title.asc())).scalars().all()
    settings_rows = db.execute(select(TrainingSetting)).scalars().all()
    settings_by_id = {str(s.moduleId or "").strip(): s for s in settings_rows if str(s.moduleId or "").strip()}

    q_counts = dict(
        db.execute(
            select(TrainingQuestion.moduleId, func.count(TrainingQuestion.id))
            .where(TrainingQuestion.active == True)  # noqa: E712
            .group_by(TrainingQuestion.moduleId)
        ).all()
    )

    if modules:
        items = []
        for m in modules:
            mid = str(m.moduleId or "").strip()
            if not mid:
                continue
            items.append(
                {
                    "moduleId": mid,
                    "title": str(m.title or ""),
                    "videoProvider": str(m.video_provider or ""),
                    "videoRef": str(m.video_ref or ""),
                    "active": bool(getattr(m, "active", True)),
                    "settings": _serialize_settings(settings_by_id.get(mid)),
                    "questionCount": int(q_counts.get(mid, 0) or 0),
                }
            )
        return {"items": items}

    # Fallback: if training_modules wasn't backfilled yet, expose trainings_master as modules.
    masters = db.execute(select(TrainingMaster)).scalars().all()
    items = []
    for t in masters:
        mid = str(getattr(t, "training_id", "") or "").strip()
        if not mid:
            continue
        items.append(
            {
                "moduleId": mid,
                "title": str(getattr(t, "name", "") or "") or mid,
                "videoProvider": "URL",
                "videoRef": str(getattr(t, "video_link", "") or ""),
                "active": True,
                "settings": _serialize_settings(settings_by_id.get(mid)),
                "questionCount": int(q_counts.get(mid, 0) or 0),
            }
        )
    items.sort(key=lambda x: str(x.get("title") or ""))
    return {"items": items}


def training_admin_save_questions(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")
    if normalize_role(auth.role) != "ADMIN":
        raise ApiError("FORBIDDEN", "Admin only", http_status=403)

    module_id = str((data or {}).get("moduleId") or "").strip()
    if not module_id:
        raise ApiError("BAD_REQUEST", "Missing moduleId")

    settings_in = (data or {}).get("settings") or {}
    questions_in = (data or {}).get("questions") or []
    if not isinstance(settings_in, dict):
        raise ApiError("BAD_REQUEST", "settings must be an object")
    if not isinstance(questions_in, list):
        raise ApiError("BAD_REQUEST", "questions must be a list")

    module = db.execute(select(TrainingModule).where(TrainingModule.moduleId == module_id)).scalar_one_or_none()
    if not module:
        raise ApiError("NOT_FOUND", "Training module not found")

    before_settings = db.execute(select(TrainingSetting).where(TrainingSetting.moduleId == module_id)).scalar_one_or_none()
    before_questions = (
        db.execute(select(TrainingQuestion).where(TrainingQuestion.moduleId == module_id).where(TrainingQuestion.active == True))  # noqa: E712
        .scalars()
        .all()
    )

    def _as_int(v: Any, default: int = 0) -> int:
        try:
            return int(v)
        except Exception:
            return int(default)

    pass_marks = _as_int(settings_in.get("passMarks"), 0)
    time_limit_min = _as_int(settings_in.get("timeLimitMin"), 0)
    max_attempts = _as_int(settings_in.get("maxAttempts"), 0)
    randomize = bool(settings_in.get("randomize", False))

    if pass_marks < 0 or pass_marks > 10_000:
        raise ApiError("BAD_REQUEST", "Invalid passMarks")
    if time_limit_min < 0 or time_limit_min > 24 * 60:
        raise ApiError("BAD_REQUEST", "Invalid timeLimitMin")
    if max_attempts < 0 or max_attempts > 100:
        raise ApiError("BAD_REQUEST", "Invalid maxAttempts")

    now = iso_utc_now()
    actor = str(auth.userId or auth.email or "")

    row = before_settings
    if not row:
        row = TrainingSetting(moduleId=module_id, passMarks=pass_marks, timeLimitMin=time_limit_min, maxAttempts=max_attempts, randomize=randomize, updatedAt=now, updatedBy=actor)
        db.add(row)
    else:
        row.passMarks = pass_marks
        row.timeLimitMin = time_limit_min
        row.maxAttempts = max_attempts
        row.randomize = randomize
        row.updatedAt = now
        row.updatedBy = actor

    # Upsert questions by qId; deactivate missing.
    existing = {str(q.qId or "").strip(): q for q in db.execute(select(TrainingQuestion).where(TrainingQuestion.moduleId == module_id)).scalars().all()}
    for q in existing.values():
        q.active = False

    used_qids: set[str] = set()
    upserted = 0

    for idx, item in enumerate(questions_in):
        if not isinstance(item, dict):
            continue
        qid = str(item.get("qId") or "").strip() or f"Q{idx + 1}"
        if qid in used_qids:
            raise ApiError("BAD_REQUEST", f"Duplicate qId: {qid}")
        used_qids.add(qid)

        question = str(item.get("question") or "").strip()
        options = item.get("options") or item.get("optionsJSON") or []
        if isinstance(options, str):
            try:
                options = json.loads(options)
            except Exception:
                options = []
        if not isinstance(options, list):
            raise ApiError("BAD_REQUEST", f"Invalid options for {qid}")
        options_clean = [str(x or "").strip() for x in options if str(x or "").strip()]
        if len(options_clean) < 2:
            raise ApiError("BAD_REQUEST", f"Min 2 options required for {qid}")
        if len(options_clean) > 10:
            raise ApiError("BAD_REQUEST", f"Max 10 options allowed for {qid}")

        correct = item.get("correctOption")
        if isinstance(correct, int):
            correct_idx = correct
        else:
            try:
                correct_idx = int(str(correct or "").strip())
            except Exception:
                correct_idx = -1
        if correct_idx < 0 or correct_idx >= len(options_clean):
            raise ApiError("BAD_REQUEST", f"Invalid correctOption for {qid}")

        marks = _as_int(item.get("marks"), 1)
        if marks < 0 or marks > 1000:
            raise ApiError("BAD_REQUEST", f"Invalid marks for {qid}")
        if not question:
            raise ApiError("BAD_REQUEST", f"Missing question for {qid}")

        row_q = existing.get(qid)
        if not row_q:
            row_q = TrainingQuestion(moduleId=module_id, qId=qid, question=question, optionsJSON=safe_json_string(options_clean, "[]"), correctOption=str(correct_idx), marks=marks, active=True, updatedAt=now, updatedBy=actor)
            db.add(row_q)
            existing[qid] = row_q
        else:
            row_q.question = question
            row_q.optionsJSON = safe_json_string(options_clean, "[]")
            row_q.correctOption = str(correct_idx)
            row_q.marks = marks
            row_q.active = True
            row_q.updatedAt = now
            row_q.updatedBy = actor
        upserted += 1

    append_audit(
        db,
        entityType="TRAINING_TEST",
        entityId=module_id,
        action="TRAINING_ADMIN_SAVE_QUESTIONS",
        stageTag="TRAINING_ADMIN_SAVE_QUESTIONS",
        actor=auth,
        at=now,
        before={
            "settings": _serialize_settings(before_settings),
            "questionCount": len(before_questions),
        },
        after={
            "settings": _serialize_settings(row),
            "questionCount": upserted,
        },
        meta={"moduleId": module_id, "upserted": upserted},
    )

    return {"ok": True, "moduleId": module_id, "saved": upserted, "settings": _serialize_settings(row)}


def training_admin_get_questions(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")
    if normalize_role(auth.role) != "ADMIN":
        raise ApiError("FORBIDDEN", "Admin only", http_status=403)

    module_id = str((data or {}).get("moduleId") or "").strip()
    if not module_id:
        raise ApiError("BAD_REQUEST", "Missing moduleId")

    module = db.execute(select(TrainingModule).where(TrainingModule.moduleId == module_id)).scalar_one_or_none()
    if not module:
        raise ApiError("NOT_FOUND", "Training module not found")

    settings_row = db.execute(select(TrainingSetting).where(TrainingSetting.moduleId == module_id)).scalar_one_or_none()
    rows = db.execute(select(TrainingQuestion).where(TrainingQuestion.moduleId == module_id).order_by(TrainingQuestion.id.asc())).scalars().all()

    questions = []
    for q in rows:
        try:
            opts = json.loads(str(q.optionsJSON or "").strip() or "[]")
        except Exception:
            opts = []
        if not isinstance(opts, list):
            opts = []
        questions.append(
            {
                "qId": str(q.qId or ""),
                "question": str(q.question or ""),
                "options": [str(x or "").strip() for x in opts if str(x or "").strip()],
                "correctOption": str(q.correctOption or ""),
                "marks": int(q.marks or 0),
                "active": bool(getattr(q, "active", True)),
            }
        )

    return {"moduleId": module_id, "settings": _serialize_settings(settings_row), "questions": questions}


def training_start_test(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    module_id = str((data or {}).get("moduleId") or "").strip()
    employee_id = str((data or {}).get("employeeId") or "").strip()

    role = normalize_role(auth.role) or ""
    if role == "EMPLOYEE":
        employee_id = str(auth.userId or "").strip()

    if not module_id:
        raise ApiError("BAD_REQUEST", "Missing moduleId")
    if not employee_id:
        raise ApiError("BAD_REQUEST", "Missing employeeId")

    module = db.execute(select(TrainingModule).where(TrainingModule.moduleId == module_id)).scalar_one_or_none()
    if not module or not bool(getattr(module, "active", True)):
        raise ApiError("NOT_FOUND", "Training module not found")

    # Strict rule: employees can only take tests after completing assigned training.
    if role == "EMPLOYEE":
        _require_employee_training_completed(db, employee_id=employee_id, module_id=module_id)

    settings_row = db.execute(select(TrainingSetting).where(TrainingSetting.moduleId == module_id)).scalar_one_or_none()
    settings = _serialize_settings(settings_row)

    rows = (
        db.execute(select(TrainingQuestion).where(TrainingQuestion.moduleId == module_id).where(TrainingQuestion.active == True))  # noqa: E712
        .scalars()
        .all()
    )
    if not rows:
        raise ApiError("BAD_REQUEST", "No questions configured for this module")

    max_attempts = int(settings.get("maxAttempts") or 0)
    current_max = db.execute(
        select(func.max(TrainingAttempt.attemptNo)).where(TrainingAttempt.employeeId == employee_id).where(TrainingAttempt.moduleId == module_id)
    ).scalar_one_or_none()
    next_attempt = int(current_max or 0) + 1
    if max_attempts > 0 and next_attempt > max_attempts:
        raise ApiError("CONFLICT", "Max attempts exceeded", http_status=409)

    now = iso_utc_now()
    attempt = TrainingAttempt(
        employeeId=employee_id,
        moduleId=module_id,
        attemptNo=next_attempt,
        score=0,
        passFail="IN_PROGRESS",
        submittedAt="",
        metaJson=safe_json_string({"startedAt": now, "settings": settings}, "{}"),
    )
    db.add(attempt)

    items = []
    for q in rows:
        try:
            opts = json.loads(str(q.optionsJSON or "").strip() or "[]")
        except Exception:
            opts = []
        if not isinstance(opts, list):
            opts = []
        opts_clean = [str(x or "").strip() for x in opts if str(x or "").strip()]
        items.append(
            {
                "qId": str(q.qId or ""),
                "question": str(q.question or ""),
                "options": opts_clean,
                "marks": int(q.marks or 0),
            }
        )

    if bool(settings.get("randomize")):
        random.shuffle(items)

    append_audit(
        db,
        entityType="TRAINING_ATTEMPT",
        entityId=f"{employee_id}:{module_id}:{next_attempt}",
        action="TRAINING_START_TEST",
        stageTag="TRAINING_START_TEST",
        actor=auth,
        at=now,
        meta={"employeeId": employee_id, "moduleId": module_id, "attemptNo": next_attempt},
    )

    return {
        "employeeId": employee_id,
        "moduleId": module_id,
        "attemptNo": next_attempt,
        "startedAt": now,
        "settings": settings,
        "questions": items,
    }


def training_submit_test(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    module_id = str((data or {}).get("moduleId") or "").strip()
    employee_id = str((data or {}).get("employeeId") or "").strip()
    try:
        attempt_no = int((data or {}).get("attemptNo") or 0)
    except Exception:
        attempt_no = 0
    answers_in = (data or {}).get("answers") or {}

    role = normalize_role(auth.role) or ""
    if role == "EMPLOYEE":
        employee_id = str(auth.userId or "").strip()

    if not module_id:
        raise ApiError("BAD_REQUEST", "Missing moduleId")
    if not employee_id:
        raise ApiError("BAD_REQUEST", "Missing employeeId")
    if attempt_no <= 0:
        raise ApiError("BAD_REQUEST", "Missing attemptNo")
    if not isinstance(answers_in, dict):
        raise ApiError("BAD_REQUEST", "answers must be an object")

    # Strict rule: employees can only take tests after completing assigned training.
    if role == "EMPLOYEE":
        _require_employee_training_completed(db, employee_id=employee_id, module_id=module_id)

    attempt = (
        db.execute(
            select(TrainingAttempt)
            .where(TrainingAttempt.employeeId == employee_id)
            .where(TrainingAttempt.moduleId == module_id)
            .where(TrainingAttempt.attemptNo == attempt_no)
            .with_for_update(of=TrainingAttempt)
        )
        .scalars()
        .first()
    )
    if not attempt:
        raise ApiError("NOT_FOUND", "Attempt not found")

    if str(getattr(attempt, "submittedAt", "") or "").strip():
        return {"ok": True, "alreadySubmitted": True, "score": int(getattr(attempt, "score", 0) or 0), "passFail": str(getattr(attempt, "passFail", "") or "")}

    settings_row = db.execute(select(TrainingSetting).where(TrainingSetting.moduleId == module_id)).scalar_one_or_none()
    settings = _serialize_settings(settings_row)
    time_limit_min = int(settings.get("timeLimitMin") or 0)
    pass_marks = int(settings.get("passMarks") or 0)

    started_at = ""
    try:
        meta = json.loads(str(getattr(attempt, "metaJson", "") or "").strip() or "{}")
    except Exception:
        meta = {}
    if isinstance(meta, dict):
        started_at = str(meta.get("startedAt") or "").strip()

    if time_limit_min > 0 and started_at:
        st_dt = parse_datetime_maybe(started_at, app_timezone="UTC")
        if st_dt:
            now_dt = datetime.now(timezone.utc)
            deadline = st_dt + timedelta(minutes=int(time_limit_min))
            if now_dt > deadline:
                submitted_at = iso_utc_now()
                attempt.score = 0
                attempt.passFail = "FAIL_TIMEOUT"
                attempt.submittedAt = submitted_at
                attempt.metaJson = safe_json_string(
                    {"startedAt": started_at, "timeLimitMin": int(time_limit_min), "reason": "TIME_LIMIT_EXCEEDED", "answers": answers_in},
                    "{}",
                )
                append_audit(
                    db,
                    entityType="TRAINING_ATTEMPT",
                    entityId=f"{employee_id}:{module_id}:{attempt_no}",
                    action="TRAINING_SUBMIT_TEST",
                    stageTag="TRAINING_SUBMIT_TEST",
                    actor=auth,
                    at=submitted_at,
                    meta={"employeeId": employee_id, "moduleId": module_id, "attemptNo": attempt_no, "score": 0, "passFail": "FAIL_TIMEOUT"},
                )
                return {
                    "ok": True,
                    "employeeId": employee_id,
                    "moduleId": module_id,
                    "attemptNo": attempt_no,
                    "score": 0,
                    "passFail": "FAIL_TIMEOUT",
                    "passMarks": pass_marks,
                    "submittedAt": submitted_at,
                    "reason": "TIME_LIMIT_EXCEEDED",
                }

    # Load active questions and evaluate.
    rows = (
        db.execute(select(TrainingQuestion).where(TrainingQuestion.moduleId == module_id).where(TrainingQuestion.active == True))  # noqa: E712
        .scalars()
        .all()
    )
    if not rows:
        raise ApiError("BAD_REQUEST", "No questions configured for this module")

    score = 0
    total = 0
    answered = 0

    for q in rows:
        qid = str(q.qId or "").strip()
        if not qid:
            continue
        total += int(q.marks or 0)
        ans_raw = answers_in.get(qid)
        if ans_raw is None:
            continue
        try:
            ans_idx = int(ans_raw)
        except Exception:
            ans_idx = -1
        answered += 1
        try:
            correct_idx = int(str(q.correctOption or "").strip())
        except Exception:
            correct_idx = -2
        if ans_idx == correct_idx:
            score += int(q.marks or 0)

    pass_fail = "PASS" if score >= pass_marks else "FAIL"
    submitted_at = iso_utc_now()

    attempt.score = int(score)
    attempt.passFail = pass_fail
    attempt.submittedAt = submitted_at
    attempt.metaJson = safe_json_string({"startedAt": started_at, "answered": answered, "totalMarks": total, "answers": answers_in}, "{}")

    append_audit(
        db,
        entityType="TRAINING_ATTEMPT",
        entityId=f"{employee_id}:{module_id}:{attempt_no}",
        action="TRAINING_SUBMIT_TEST",
        stageTag="TRAINING_SUBMIT_TEST",
        actor=auth,
        at=submitted_at,
        meta={"employeeId": employee_id, "moduleId": module_id, "attemptNo": attempt_no, "score": score, "passFail": pass_fail},
    )

    return {"ok": True, "employeeId": employee_id, "moduleId": module_id, "attemptNo": attempt_no, "score": score, "passFail": pass_fail, "passMarks": pass_marks, "submittedAt": submitted_at}
