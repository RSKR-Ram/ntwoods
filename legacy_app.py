from __future__ import annotations

import glob
import json
import logging
import mimetypes
import os
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from dotenv import load_dotenv
from flask import Blueprint, Flask, Response, current_app, g, redirect, request, send_file, stream_with_context
from flask_cors import CORS
import requests
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError
from zoneinfo import ZoneInfo

from actions import dispatch
from auth import assert_permission, is_public_action, role_or_public, validate_session_token
from config import Config
from db import SessionLocal, init_engine
from models import AuditLog, AtsStage, Permission, Role, SLAConfig, TestMaster
from utils import ApiError, AuthContext, SimpleRateLimiter, err, iso_utc_now, new_uuid, now_monotonic, ok, parse_json_body, redact_for_audit


rest_api = Blueprint("rest_api", __name__)


def _rest_token() -> str:
    authz = str(request.headers.get("Authorization") or "").strip()
    if authz.lower().startswith("bearer "):
        return authz.split(" ", 1)[1].strip()
    return (
        str(request.headers.get("X-Session-Token") or "").strip()
        or str(request.args.get("token") or "").strip()
        or str((request.get_json(silent=True) or {}).get("token") or "").strip()
    )


def _rest_handle(action: str, data: dict, *, allow_internal: bool = False):
    from db import SessionLocal

    if SessionLocal is None:
        raise RuntimeError("DB not initialized")

    cfg = current_app.config["CFG"]
    token = _rest_token()
    action_u = str(action or "").upper().strip()

    db = None
    auth_ctx = None
    try:
        db = SessionLocal()

        if allow_internal:
            internal = str(request.headers.get("X-Internal-Token") or "").strip()
            internal_expected = str(os.getenv("INTERNAL_CRON_TOKEN", "") or "").strip()
            if internal_expected and internal and internal == internal_expected:
                auth_ctx = AuthContext(valid=True, userId="SYSTEM", email="SYSTEM", role="ADMIN", expiresAt="")
            else:
                auth_ctx = validate_session_token(db, token, action=action_u)
        else:
            auth_ctx = validate_session_token(db, token, action=action_u)

        if not auth_ctx or not auth_ctx.valid:
            raise ApiError("AUTH_INVALID", "Invalid or expired session")

        role = role_or_public(auth_ctx)
        assert_permission(db, role, action_u)

        out = dispatch(action_u, data or {}, auth_ctx, db, cfg)

        try:
            db.add(
                AuditLog(
                    logId=f"LOG-{os.urandom(16).hex()}",
                    entityType="API",
                    entityId=str(auth_ctx.userId or auth_ctx.email or ""),
                    action=action_u,
                    fromState="",
                    toState="",
                    stageTag="API_CALL_REST",
                    remark="",
                    actorUserId=str(auth_ctx.userId),
                    actorRole=str(auth_ctx.role),
                    actorEmail=str(getattr(auth_ctx, "email", "") or ""),
                    at=iso_utc_now(),
                    correlationId=str(getattr(g, "request_id", "") or ""),
                    metaJson=json.dumps({"data": redact_for_audit(data or {})}),
                )
            )
        except Exception:
            pass

        db.commit()
        return ok(out)[0]
    except ApiError as e:
        if db is not None:
            db.rollback()
        _write_error_audit(cfg, action_u, auth_ctx, data, e)
        return err(e.code, e.message, http_status=e.http_status)[0], e.http_status
    except Exception:
        if db is not None:
            db.rollback()
        api_err = ApiError("INTERNAL", "Unexpected error")
        _write_error_audit(cfg, action_u, auth_ctx, data, api_err)
        logging.getLogger("api").exception("rest action=%s", action_u)
        return err(api_err.code, api_err.message)[0]
    finally:
        if db is not None:
            db.close()


def _maybe_start_internal_scheduler(cfg: Config):
    """
    Daily scheduler (Asia/Kolkata) for lightweight maintenance jobs.

    Production recommendation: run a single instance via cron/Task Scheduler calling
    `POST /api/jobs/auto-reschedule-no-show` with `X-Internal-Token` = `INTERNAL_CRON_TOKEN`.

    For simple deployments you can enable the in-process scheduler:
    - ENABLE_SCHEDULER=1
    - SCHEDULER_RESCHEDULE_HOUR=0
    - SCHEDULER_RESCHEDULE_MINUTE=10
    """

    if str(os.getenv("ENABLE_SCHEDULER", "0") or "").strip() != "1":
        return

    try:
        hour = int(os.getenv("SCHEDULER_RESCHEDULE_HOUR", "0"))
        minute = int(os.getenv("SCHEDULER_RESCHEDULE_MINUTE", "10"))
    except Exception:
        hour, minute = 0, 10

    hour = max(0, min(23, hour))
    minute = max(0, min(59, minute))

    try:
        tz = ZoneInfo(cfg.APP_TIMEZONE)
    except Exception:
        tz = timezone.utc

    def _loop():
        from db import SessionLocal

        while True:
            now_local = datetime.now(tz)
            next_run = datetime(now_local.year, now_local.month, now_local.day, hour, minute, 0, tzinfo=tz)
            if next_run <= now_local:
                next_run = next_run + timedelta(days=1)
            delay = max(1.0, (next_run - now_local).total_seconds())
            time.sleep(delay)

            db = None
            try:
                if SessionLocal is None:
                    continue
                db = SessionLocal()
                system = AuthContext(valid=True, userId="SYSTEM", email="SYSTEM", role="ADMIN", expiresAt="")
                auto_res = dispatch("AUTO_RESCHEDULE_NO_SHOW", {"dryRun": False}, system, db, cfg)
                db.commit()
                logging.getLogger("scheduler").info("AUTO_RESCHEDULE_NO_SHOW ok=%s", bool(auto_res and auto_res.get("ok")))
            except Exception:
                if db is not None:
                    db.rollback()
                logging.getLogger("scheduler").exception("AUTO_RESCHEDULE_NO_SHOW failed")
            finally:
                if db is not None:
                    db.close()

    t = threading.Thread(target=_loop, name="scheduler", daemon=True)
    t.start()


@rest_api.get("/api/test-master")
def rest_test_master_get():
    return _rest_handle("TEST_MASTER_GET", {"activeOnly": True})


@rest_api.post("/api/candidates/<candidate_id>/required-tests")
def rest_candidate_required_tests(candidate_id: str):
    body = request.get_json(silent=True) or {}
    return _rest_handle(
        "CANDIDATE_REQUIRED_TESTS_SET",
        {
            "candidateId": candidate_id,
            "requirementId": body.get("requirementId") or "",
            "testKeys": body.get("testKeys") or [],
        },
    )


@rest_api.post("/api/candidates/<candidate_id>/tests/<test_key>/submit")
def rest_candidate_test_submit(candidate_id: str, test_key: str):
    body = request.get_json(silent=True) or {}
    return _rest_handle(
        "CANDIDATE_TEST_SUBMIT",
        {
            "candidateId": candidate_id,
            "requirementId": body.get("requirementId") or "",
            "testKey": test_key,
            "marks": body.get("marks"),
            "remarks": body.get("remarks") or "",
        },
    )


@rest_api.post("/api/candidates/<candidate_id>/tests/<test_key>/review")
def rest_candidate_test_review(candidate_id: str, test_key: str):
    body = request.get_json(silent=True) or {}
    return _rest_handle(
        "CANDIDATE_TEST_REVIEW",
        {
            "candidateId": candidate_id,
            "requirementId": body.get("requirementId") or "",
            "testKey": test_key,
            "decision": body.get("decision") or "",
            "remarks": body.get("remarks") or "",
        },
    )


@rest_api.get("/api/candidates/fail")
def rest_fail_candidates_list():
    stage = str(request.args.get("stageName") or "").strip()
    include_resolved = str(request.args.get("includeResolved") or "").strip()
    return _rest_handle(
        "FAIL_CANDIDATES_LIST",
        {"stageName": stage, "includeResolved": include_resolved in {"1", "true", "TRUE", "yes", "YES"}},
    )


@rest_api.post("/api/candidates/<candidate_id>/training/mark-complete")
def rest_training_mark_complete(candidate_id: str):
    body = request.get_json(silent=True) or {}
    return _rest_handle(
        "TRAINING_MARK_COMPLETE",
        {"candidateId": candidate_id, "requirementId": body.get("requirementId") or ""},
    )


@rest_api.post("/api/candidates/<candidate_id>/training/close")
def rest_training_close(candidate_id: str):
    body = request.get_json(silent=True) or {}
    return _rest_handle(
        "TRAINING_CLOSE",
        {"candidateId": candidate_id, "requirementId": body.get("requirementId") or ""},
    )


@rest_api.post("/api/candidates/<candidate_id>/probation/complete")
def rest_probation_complete(candidate_id: str):
    body = request.get_json(silent=True) or {}
    return _rest_handle(
        "PROBATION_COMPLETE",
        {"candidateId": candidate_id, "requirementId": body.get("requirementId") or ""},
    )


@rest_api.post("/api/jobs/auto-reschedule-no-show")
def rest_auto_reschedule_no_show():
    body = request.get_json(silent=True) or {}
    return _rest_handle("AUTO_RESCHEDULE_NO_SHOW", {"dryRun": bool(body.get("dryRun")), "limit": body.get("limit")}, allow_internal=True)


@rest_api.get("/api/admin/sla-config")
def rest_sla_config_get():
    return _rest_handle("SLA_CONFIG_GET", {})


@rest_api.post("/api/admin/sla-config")
def rest_sla_config_upsert():
    body = request.get_json(silent=True) or {}
    return _rest_handle("SLA_CONFIG_UPSERT", {"items": body.get("items") or []})


@rest_api.get("/api/metrics/step-metrics")
def rest_step_metrics_query():
    params = {
        "stepName": str(request.args.get("stepName") or "").strip(),
        "requirementId": str(request.args.get("requirementId") or "").strip(),
        "candidateId": str(request.args.get("candidateId") or "").strip(),
        "dateFrom": str(request.args.get("dateFrom") or "").strip(),
        "dateTo": str(request.args.get("dateTo") or "").strip(),
    }
    return _rest_handle("STEP_METRICS_QUERY", params)


@rest_api.get("/api/employees/<employee_id>/profile")
def rest_employee_profile_get(employee_id: str):
    return _rest_handle("EMPLOYEE_PROFILE_GET", {"employeeId": employee_id})


@rest_api.get("/api/employees/<employee_id>/docs")
def rest_employee_docs_list(employee_id: str):
    return _rest_handle("EMPLOYEE_DOCS_LIST", {"employeeId": employee_id})


@rest_api.post("/api/employees/<employee_id>/role-change")
def rest_employee_role_change(employee_id: str):
    body = request.get_json(silent=True) or {}
    return _rest_handle(
        "EMPLOYEE_ROLE_CHANGE",
        {
            "employeeId": employee_id,
            "newRole": body.get("newRole") or body.get("jobRole") or "",
            "effectiveAt": body.get("effectiveAt") or "",
            "remark": body.get("remark") or "",
        },
    )


@rest_api.post("/api/employees/check-duplicate")
def rest_employee_check_duplicate():
    body = request.get_json(silent=True) or {}
    return _rest_handle("EMPLOYEE_DUPLICATE_CHECK", {"aadhaar": body.get("aadhaar") or "", "dob": body.get("dob") or ""})


@rest_api.post("/api/exit/start-notice")
def rest_exit_start_notice():
    body = request.get_json(silent=True) or {}
    return _rest_handle("EXIT_START_NOTICE", {"employeeId": body.get("employeeId") or "", "noticeDays": body.get("noticeDays") or 0})


@rest_api.post("/api/exit/mark-absconded")
def rest_exit_mark_absconded():
    body = request.get_json(silent=True) or {}
    return _rest_handle(
        "EXIT_MARK_ABSCONDED",
        {"employeeId": body.get("employeeId") or "", "absentSince": body.get("absentSince") or "", "remark": body.get("remark") or ""},
    )


@rest_api.post("/api/exit/terminate-init")
def rest_exit_terminate_init():
    body = request.get_json(silent=True) or {}
    return _rest_handle(
        "EXIT_TERMINATE_INIT",
        {"employeeId": body.get("employeeId") or "", "lastWorkingDay": body.get("lastWorkingDay") or "", "remark": body.get("remark") or ""},
    )


@rest_api.post("/api/exit/settlement-clear")
def rest_exit_settlement_clear():
    body = request.get_json(silent=True) or {}
    return _rest_handle("EXIT_SETTLEMENT_CLEAR", {"exitId": body.get("exitId") or "", "settlementDocId": body.get("settlementDocId") or ""})


@rest_api.post("/api/exit/attach-termination-letter")
def rest_exit_attach_termination_letter():
    body = request.get_json(silent=True) or {}
    return _rest_handle(
        "EXIT_ATTACH_TERMINATION_LETTER",
        {"exitId": body.get("exitId") or "", "terminationLetterDocId": body.get("terminationLetterDocId") or ""},
    )


@rest_api.post("/api/exit/complete")
def rest_exit_complete():
    body = request.get_json(silent=True) or {}
    return _rest_handle("EXIT_COMPLETE", {"exitId": body.get("exitId") or ""})


@rest_api.get("/api/exit/tasks/<exit_id>")
def rest_exit_tasks_get(exit_id: str):
    return _rest_handle("EXIT_TASKS_GET", {"exitId": exit_id})


@rest_api.post("/api/exit/task-update")
def rest_exit_task_update():
    body = request.get_json(silent=True) or {}
    return _rest_handle(
        "EXIT_TASK_UPDATE",
        {
            "exitId": body.get("exitId") or "",
            "taskKey": body.get("taskKey") or "",
            "status": body.get("status") or "",
            "note": body.get("note") or "",
            "docId": body.get("docId") or "",
        },
    )

@rest_api.get("/api/exit/clearance/queue")
def rest_exit_clearance_queue():
    return _rest_handle("EXIT_CLEARANCE_QUEUE", {})


@rest_api.get("/api/exit/clearance/<exit_id>")
def rest_exit_clearance_get(exit_id: str):
    return _rest_handle("EXIT_CLEARANCE_GET", {"exitId": exit_id})


@rest_api.get("/api/training/modules")
def rest_training_modules_get():
    return _rest_handle("TRAINING_MODULES_GET", {})


@rest_api.post("/api/training/admin/save-questions")
def rest_training_admin_save_questions():
    body = request.get_json(silent=True) or {}
    return _rest_handle(
        "TRAINING_ADMIN_SAVE_QUESTIONS",
        {"moduleId": body.get("moduleId") or "", "settings": body.get("settings") or {}, "questions": body.get("questions") or []},
    )


@rest_api.get("/api/training/admin/questions/<module_id>")
def rest_training_admin_get_questions(module_id: str):
    return _rest_handle("TRAINING_ADMIN_GET_QUESTIONS", {"moduleId": module_id})


@rest_api.post("/api/training/start-test")
def rest_training_start_test():
    body = request.get_json(silent=True) or {}
    return _rest_handle("TRAINING_START_TEST", {"moduleId": body.get("moduleId") or "", "employeeId": body.get("employeeId") or ""})


@rest_api.post("/api/training/submit-test")
def rest_training_submit_test():
    body = request.get_json(silent=True) or {}
    return _rest_handle(
        "TRAINING_SUBMIT_TEST",
        {
            "moduleId": body.get("moduleId") or "",
            "employeeId": body.get("employeeId") or "",
            "attemptNo": body.get("attemptNo") or 0,
            "answers": body.get("answers") or {},
        },
    )


@rest_api.post("/api/docs/upload")
def rest_employee_doc_upload():
    from db import SessionLocal

    if SessionLocal is None:
        raise RuntimeError("DB not initialized")

    cfg2: Config = current_app.config["CFG"]
    token = _rest_token()

    db = None
    try:
        db = SessionLocal()
        auth_ctx = validate_session_token(db, token, action="EMPLOYEE_DOC_UPLOAD")
        if not auth_ctx.valid:
            return err("AUTH_INVALID", "Invalid or expired session", http_status=401)[0], 401

        role = role_or_public(auth_ctx)
        assert_permission(db, role, "EMPLOYEE_DOC_UPLOAD")

        employee_id = str(request.form.get("employeeId") or "").strip()
        doc_type = str(request.form.get("docType") or "").strip()
        visibility = str(request.form.get("visibility") or "INTERNAL").strip()

        up = request.files.get("file")
        if not employee_id:
            raise ApiError("BAD_REQUEST", "Missing employeeId", http_status=400)
        if not doc_type:
            raise ApiError("BAD_REQUEST", "Missing docType", http_status=400)
        if not up:
            raise ApiError("BAD_REQUEST", "Missing file", http_status=400)

        filename = str(getattr(up, "filename", "") or "").strip() or "doc"
        mime_type = str(getattr(up, "mimetype", "") or "").strip() or "application/octet-stream"
        blob = up.read() or b""

        try:
            max_mb = int(str(os.getenv("MAX_EMPLOYEE_DOC_UPLOAD_MB", "20") or "20"))
        except Exception:
            max_mb = 20
        if len(blob) > max_mb * 1024 * 1024:
            raise ApiError("BAD_REQUEST", f"Max upload size is {max_mb}MB", http_status=413)

        from actions.helpers import append_audit
        from services.employee_docs_service import create_employee_doc

        row = create_employee_doc(
            db,
            cfg=cfg2,
            employee_id=employee_id,
            doc_type=doc_type,
            file_bytes=blob,
            file_name=filename,
            mime_type=mime_type,
            uploaded_by=str(auth_ctx.userId or auth_ctx.email or ""),
            visibility=visibility,
        )

        append_audit(
            db,
            entityType="EMPLOYEE_DOC",
            entityId=str(row.id or ""),
            action="EMPLOYEE_DOC_UPLOAD",
            stageTag="EMPLOYEE_DOC_UPLOAD",
            actor=auth_ctx,
            at=str(row.uploaded_at or iso_utc_now()),
            meta={
                "employeeId": employee_id,
                "docType": str(row.doc_type or ""),
                "fileName": str(row.file_name or ""),
                "mimeType": str(row.mime_type or ""),
                "size": int(row.size or 0),
                "visibility": str(row.visibility or ""),
                "version": int(row.version or 1),
            },
        )

        db.commit()
        return (
            ok(
                {
                    "docId": str(row.id or ""),
                    "employeeId": employee_id,
                    "docType": str(row.doc_type or ""),
                    "fileName": str(row.file_name or ""),
                    "mimeType": str(row.mime_type or ""),
                    "size": int(row.size or 0),
                    "uploadedBy": str(row.uploaded_by or ""),
                    "uploadedAt": str(row.uploaded_at or ""),
                    "visibility": str(row.visibility or ""),
                    "version": int(row.version or 1),
                }
            )[0]
        )
    except ApiError as e:
        if db is not None:
            db.rollback()
        return err(e.code, e.message, http_status=e.http_status)[0], e.http_status
    finally:
        if db is not None:
            db.close()


@rest_api.get("/api/docs/download/<doc_id>")
def rest_employee_doc_download(doc_id: str):
    from db import SessionLocal
    from models import EmployeeDoc

    if SessionLocal is None:
        raise RuntimeError("DB not initialized")

    cfg2: Config = current_app.config["CFG"]
    token = _rest_token()

    db = None
    try:
        db = SessionLocal()
        auth_ctx = validate_session_token(db, token, action="EMPLOYEE_DOC_DOWNLOAD")
        if not auth_ctx.valid:
            return err("AUTH_INVALID", "Invalid or expired session", http_status=401)[0], 401

        role = role_or_public(auth_ctx)
        assert_permission(db, role, "EMPLOYEE_DOC_DOWNLOAD")

        doc = db.execute(select(EmployeeDoc).where(EmployeeDoc.id == str(doc_id or "").strip())).scalar_one_or_none()
        if not doc:
            return err("NOT_FOUND", "Document not found", http_status=404)[0], 404

        if role == "EMPLOYEE":
            if str(doc.employee_id or "").strip() != str(auth_ctx.userId or "").strip():
                return err("FORBIDDEN", "Document not accessible", http_status=403)[0], 403
            if str(doc.visibility or "").upper().strip() != "EMPLOYEE":
                return err("FORBIDDEN", "Document not accessible", http_status=403)[0], 403

        from actions.helpers import append_audit

        append_audit(
            db,
            entityType="EMPLOYEE_DOC",
            entityId=str(doc.id or ""),
            action="EMPLOYEE_DOC_DOWNLOAD",
            stageTag="EMPLOYEE_DOC_DOWNLOAD",
            actor=auth_ctx,
            at=iso_utc_now(),
            meta={"employeeId": str(doc.employee_id or ""), "docType": str(doc.doc_type or ""), "docId": str(doc.id or "")},
        )
        db.commit()

        storage_key = str(doc.storage_key or "").strip()
        if re.fullmatch(r"[0-9a-fA-F]{32}", storage_key):
            pattern = os.path.join(cfg2.UPLOAD_DIR, f"{storage_key}_*")
            matches = sorted(glob.glob(pattern))
            if not matches:
                return err("NOT_FOUND", "File not found", http_status=404)[0], 404
            path = matches[0]
            download_name = str(doc.file_name or "") or os.path.basename(path)
            mime = str(doc.mime_type or "").strip() or mimetypes.guess_type(download_name)[0] or "application/octet-stream"
            resp = send_file(path, mimetype=mime, as_attachment=False, download_name=download_name)
            resp.headers["X-Content-Type-Options"] = "nosniff"
            return resp

        # Best-effort for Drive fileIds (FILE_STORAGE_MODE=gas): enforce permission, then redirect.
        return redirect(f"https://drive.google.com/uc?export=download&id={storage_key}")
    except ApiError as e:
        if db is not None:
            db.rollback()
        return err(e.code, e.message, http_status=e.http_status)[0], e.http_status
    finally:
        if db is not None:
            db.close()


def _is_public_http_url(url: str) -> bool:
    try:
        from urllib.parse import urlparse

        p = urlparse(str(url or "").strip())
        if p.scheme not in {"http", "https"}:
            return False
        host = (p.hostname or "").strip().lower()
        if not host:
            return False
        if host in {"localhost"}:
            return False
        if host.startswith(("127.", "0.", "169.254.")):
            return False
        if host.startswith("10.") or host.startswith("192.168."):
            return False
        if host.startswith("172."):
            try:
                part = int(host.split(".", 2)[1])
                if 16 <= part <= 31:
                    return False
            except Exception:
                pass
        return True
    except Exception:
        return False


@rest_api.get("/api/training/video/stream/<module_id>")
def rest_training_video_stream(module_id: str):
    from db import SessionLocal
    from models import TrainingMaster

    if SessionLocal is None:
        raise RuntimeError("DB not initialized")

    cfg2: Config = current_app.config["CFG"]
    token = _rest_token()

    db = None
    try:
        db = SessionLocal()
        auth_ctx = validate_session_token(db, token, action="TRAINING_VIDEO_STREAM")
        if not auth_ctx.valid:
            return err("AUTH_INVALID", "Invalid or expired session", http_status=401)[0], 401

        role = role_or_public(auth_ctx)
        assert_permission(db, role, "TRAINING_VIDEO_STREAM")

        row = db.execute(select(TrainingMaster).where(TrainingMaster.training_id == str(module_id or "").strip())).scalar_one_or_none()
        if not row:
            return err("NOT_FOUND", "Training module not found", http_status=404)[0], 404

        # Pick video by index (supports multi-video)
        try:
            idx = int(str(request.args.get("index") or "0").strip())
        except Exception:
            idx = 0
        idx = max(0, min(20, idx))

        videos = []
        raw_videos = str(getattr(row, "videoLinksJson", "") or "").strip()
        if raw_videos:
            try:
                videos = json.loads(raw_videos) or []
            except Exception:
                videos = []
        if not isinstance(videos, list):
            videos = []
        videos = [str(x or "").strip() for x in videos if str(x or "").strip()]
        if not videos and str(getattr(row, "video_link", "") or "").strip():
            videos = [str(getattr(row, "video_link", "") or "").strip()]

        if not videos:
            return err("NOT_FOUND", "Video not configured", http_status=404)[0], 404
        if idx >= len(videos):
            idx = 0
        video_ref = videos[idx]

        # Audit (best-effort)
        try:
            from actions.helpers import append_audit

            append_audit(
                db,
                entityType="TRAINING_MODULE",
                entityId=str(module_id or ""),
                action="TRAINING_VIDEO_STREAM",
                stageTag="TRAINING_VIDEO_STREAM",
                actor=auth_ctx,
                at=iso_utc_now(),
                meta={"moduleId": str(module_id or ""), "index": idx},
            )
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass

        # Local uploads: treat as file id.
        if re.fullmatch(r"[0-9a-fA-F]{32}", video_ref):
            pattern = os.path.join(cfg2.UPLOAD_DIR, f"{video_ref}_*")
            matches = sorted(glob.glob(pattern))
            if not matches:
                return err("NOT_FOUND", "Video file not found", http_status=404)[0], 404
            path = matches[0]
            mime = mimetypes.guess_type(path)[0] or "application/octet-stream"
            resp = send_file(path, mimetype=mime, as_attachment=False)
            resp.headers["X-Content-Type-Options"] = "nosniff"
            return resp

        if not _is_public_http_url(video_ref):
            return err("BAD_REQUEST", "Invalid video URL", http_status=400)[0], 400

        headers = {}
        rng = request.headers.get("Range")
        if rng:
            headers["Range"] = rng
        upstream = requests.get(video_ref, headers=headers, stream=True, timeout=30)

        # Pass through key headers for streaming/seek.
        resp_headers = {}
        for k in ("Content-Type", "Content-Length", "Accept-Ranges", "Content-Range"):
            if k in upstream.headers:
                resp_headers[k] = upstream.headers[k]

        return Response(
            stream_with_context(upstream.iter_content(chunk_size=1024 * 256)),
            status=upstream.status_code,
            headers=resp_headers,
        )
    except ApiError as e:
        if db is not None:
            db.rollback()
        return err(e.code, e.message, http_status=e.http_status)[0], e.http_status
    except Exception as e:
        if db is not None:
            db.rollback()
        logging.getLogger("api").exception("TRAINING_VIDEO_STREAM failed: %s", e)
        return err("INTERNAL", "Video stream failed", http_status=500)[0], 500
    finally:
        if db is not None:
            db.close()


def _configure_logging(level: str):
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def _seed_roles_and_permissions(db):
    now = iso_utc_now()
    actor = "SYSTEM_INIT"

    # Roles seed
    existing_roles = {r.roleCode.upper() for r in db.query(Role).all()}  # type: ignore[attr-defined]
    needed = ["ADMIN", "EA", "HR", "OWNER", "EMPLOYEE", "ACCOUNTS", "MIS", "DEO"]
    for rc in needed:
        if rc in existing_roles:
            continue
        db.add(
            Role(
                roleCode=rc,
                roleName=rc,
                status="ACTIVE",
                createdAt=now,
                createdBy=actor,
                updatedAt=now,
                updatedBy=actor,
            )
        )

    # Permissions seed (idempotent; only inserts missing keys to avoid overriding custom RBAC).
    existing_perm = {
        (str(p.permType or "").upper().strip(), str(p.permKey or "").upper().strip()): p
        for p in db.query(Permission).all()  # type: ignore[attr-defined]
    }

    ui_rows = [
        ("UI", "PORTAL_ADMIN", "ADMIN", True),
        ("UI", "PORTAL_REQUIREMENTS", "EA,ADMIN", True),
        ("UI", "PORTAL_HR_REVIEW", "HR,ADMIN", True),
        ("UI", "PORTAL_HR_PRECALL", "HR,ADMIN", True),
        ("UI", "PORTAL_HR_PREINTERVIEW", "HR,ADMIN", True),
        ("UI", "PORTAL_HR_INPERSON", "HR,ADMIN", True),
        ("UI", "PORTAL_HR_FINAL", "HR,ADMIN", True),
        ("UI", "PORTAL_HR_FINAL_HOLD", "HR,ADMIN", True),
        ("UI", "PORTAL_HR_JOINING", "HR,ADMIN", True),
        ("UI", "PORTAL_HR_PROBATION", "HR,EA,ADMIN", True),
        ("UI", "PORTAL_ATS", "ADMIN,HR,EA,OWNER", True),
        ("UI", "PORTAL_ATS_PIPELINE", "ADMIN,HR,EA,OWNER", True),
        ("UI", "PORTAL_ATS_CANDIDATES", "ADMIN,HR,EA,OWNER", True),
        ("UI", "PORTAL_ATS_SETTINGS", "ADMIN", True),
        ("UI", "PORTAL_OWNER", "OWNER,ADMIN", True),
        ("UI", "PORTAL_EA_TECH", "EA,ADMIN", True),
        ("UI", "PORTAL_REJECTION_LOG", "EA,HR,ADMIN", True),
        ("UI", "PORTAL_ANALYTICS", "HR,ADMIN", True),
        ("UI", "PORTAL_EMPLOYEE_PROFILE", "EA,HR,OWNER,ADMIN", True),
        ("UI", "PORTAL_EXIT_CLEARANCE", "HR,ADMIN,MIS,ACCOUNTS", True),
        ("UI", "PORTAL_FAIL_CANDIDATES", "HR,ADMIN", True),
        ("UI", "PORTAL_TESTS", "HR,EA,ADMIN,ACCOUNTS,MIS,DEO", True),
        ("UI", "PORTAL_ADMIN_SLA", "ADMIN", True),
        ("UI", "BTN_SHORTLIST_OWNER_SEND", "HR,ADMIN", True),
        ("UI", "BTN_OWNER_APPROVE_WALKIN", "OWNER,ADMIN", True),
        ("UI", "SECTION_EXCEL_MARKS", "ADMIN", True),
    ]

    for perm_type, perm_key, roles_csv, enabled in ui_rows:
        k = (perm_type.upper(), perm_key.upper())
        if k in existing_perm:
            continue
        db.add(
            Permission(
                permType=perm_type,
                permKey=perm_key,
                rolesCsv=roles_csv,
                enabled=bool(enabled),
                updatedAt=now,
                updatedBy=actor,
            )
        )

    # ACTION permissions seed from static mapping (idempotent).
    from auth import STATIC_RBAC_PERMISSIONS

    for action, roles in STATIC_RBAC_PERMISSIONS.items():
        key = action.upper()
        k2 = ("ACTION", key)
        if k2 in existing_perm:
            continue
        db.add(
            Permission(
                permType="ACTION",
                permKey=key,
                rolesCsv=",".join(roles),
                enabled=True,
                updatedAt=now,
                updatedBy=actor,
            )
        )


def _seed_test_master(db):
    now = iso_utc_now()
    actor = "SYSTEM_INIT"

    existing = {str(r.testKey or "").upper().strip() for r in db.query(TestMaster).all()}  # type: ignore[attr-defined]

    defaults = [
        {
            "testKey": "EXCEL",
            "label": "Excel",
            "fillRoles": ["MIS", "DEO", "ADMIN"],
            "reviewRoles": ["HR", "ADMIN"],
            "ordering": 10,
        },
        {
            "testKey": "TALLY",
            "label": "Tally",
            "fillRoles": ["ACCOUNTS", "ADMIN"],
            "reviewRoles": ["HR", "ADMIN"],
            "ordering": 20,
        },
        {
            "testKey": "VOICE",
            "label": "Voice",
            "fillRoles": ["EA", "ADMIN"],
            "reviewRoles": ["HR", "ADMIN"],
            "ordering": 30,
        },
        {
            "testKey": "MEMORY",
            "label": "Memory",
            "fillRoles": ["EA", "ADMIN"],
            "reviewRoles": ["HR", "ADMIN"],
            "ordering": 40,
        },
    ]

    for row in defaults:
        k = str(row.get("testKey") or "").upper().strip()
        if not k or k in existing:
            continue
        db.add(
            TestMaster(
                testKey=k,
                label=str(row.get("label") or k),
                fillRolesJson=json.dumps(row.get("fillRoles") or []),
                reviewRolesJson=json.dumps(row.get("reviewRoles") or []),
                active=True,
                ordering=int(row.get("ordering") or 0),
                createdAt=now,
                createdBy=actor,
                updatedAt=now,
                updatedBy=actor,
            )
        )


def _seed_sla_config(db):
    now = iso_utc_now()
    actor = "SYSTEM_INIT"

    existing = {str(r.stepName or "").upper().strip() for r in db.query(SLAConfig).all()}  # type: ignore[attr-defined]
    steps = [
        "HR_REVIEW",
        "JOB_POSTING",
        "ADD_CANDIDATE",
        "SHORTLISTING",
        "OWNER_APPROVAL",
        "WALKIN_SCHEDULE",
        "PRECALL",
        "PRE_INTERVIEW",
        "ONLINE_TEST",
        "IN_PERSON",
        "TECHNICAL",
        "FINAL_INTERVIEW",
        "JOINING",
        "DOCS",
        "TRAINING",
        "PROBATION",
    ]

    for s in steps:
        if s in existing:
            continue
        db.add(SLAConfig(stepName=s, plannedMinutes=0, enabled=True, updatedAt=now, updatedBy=actor))


def _seed_ats_stages(db):
    now = iso_utc_now()
    actor = "SYSTEM_INIT"

    existing = {str(r.stageKey or "").upper().strip() for r in db.query(AtsStage).all()}  # type: ignore[attr-defined]

    defaults = [
        {"stageKey": "NEW", "stageName": "New", "orderNo": 10, "color": "gray"},
        {"stageKey": "HOLD", "stageName": "Hold", "orderNo": 20, "color": "orange"},
        {"stageKey": "OWNER", "stageName": "Owner", "orderNo": 30, "color": "blue"},
        {"stageKey": "WALKIN_PENDING", "stageName": "Walk-in Pending", "orderNo": 40, "color": "blue"},
        {"stageKey": "PRECALL", "stageName": "Pre-call", "orderNo": 50, "color": "blue"},
        {"stageKey": "PRE_INTERVIEW", "stageName": "Pre-interview", "orderNo": 60, "color": "blue"},
        {"stageKey": "IN_PERSON", "stageName": "In-person", "orderNo": 70, "color": "blue"},
        {"stageKey": "TECHNICAL", "stageName": "Technical", "orderNo": 80, "color": "blue"},
        {"stageKey": "FINAL_INTERVIEW", "stageName": "Final Interview", "orderNo": 90, "color": "blue"},
        {"stageKey": "FINAL_HOLD", "stageName": "Final Hold", "orderNo": 100, "color": "orange"},
        {"stageKey": "JOINING", "stageName": "Joining", "orderNo": 110, "color": "green"},
        {"stageKey": "PROBATION", "stageName": "Probation", "orderNo": 120, "color": "green"},
    ]

    for it in defaults:
        k = str(it.get("stageKey") or "").upper().strip()
        if not k or k in existing:
            continue
        db.add(
            AtsStage(
                stageId=f"ATSSTG-{new_uuid()}",
                stageKey=k,
                stageName=str(it.get("stageName") or k),
                orderNo=int(it.get("orderNo") or 0),
                color=str(it.get("color") or ""),
                isActive=True,
                rolesCsv="ADMIN,HR,EA,OWNER",
                createdAt=now,
                createdBy=actor,
                updatedAt=now,
                updatedBy=actor,
            )
        )


def create_app() -> Flask:
    load_dotenv()
    cfg = Config()
    cfg.validate()
    _configure_logging(cfg.LOG_LEVEL)

    engine = init_engine(cfg.DATABASE_URL)
    if SessionLocal is None:
        raise RuntimeError("DB not initialized")

    # Optional sharding scaffold (off by default). Configure DB_URL_0..DB_URL_N to enable.
    try:
        from db import init_shard_engines

        if isinstance(getattr(cfg, "DB_URLS", None), list) and len(cfg.DB_URLS) > 1:
            init_shard_engines(cfg.DB_URLS)
    except Exception:
        pass

    from models import Base  # imported after engine init

    Base.metadata.create_all(bind=engine)

    # Lightweight schema evolution (adds new columns/indexes + backfills PII hashes/masks).
    from schema import ensure_schema

    ensure_schema(engine)

    app = Flask(__name__)
    app.config["CFG"] = cfg

    CORS(app, origins=cfg.ALLOWED_ORIGINS, supports_credentials=False)
    app.register_blueprint(rest_api)

    # Register public apply API (isolated from HRMS auth)
    from public_apply.routes import public_apply_bp
    app.register_blueprint(public_apply_bp)

    # Register HR public apply API (Authenticated via User Token for CV downloads)
    from public_apply.hr_routes import hr_apply_bp
    app.register_blueprint(hr_apply_bp)

    # Create public apply tables
    from public_apply.models import PublicApply, PublicApplyRateLimit, PublicApplyAuditLog
    PublicApply.metadata.create_all(bind=engine)

    limiter = SimpleRateLimiter()

    # Seed roles/permissions at startup (idempotent).
    db0 = SessionLocal()
    try:
        _seed_roles_and_permissions(db0)
        _seed_test_master(db0)
        _seed_sla_config(db0)
        _seed_ats_stages(db0)
        db0.commit()
    finally:
        db0.close()

    @app.before_request
    def _before():
        g.request_id = os.urandom(8).hex()
        g.start_ts = now_monotonic()

    @app.after_request
    def _after(resp):
        try:
            resp.headers["X-Request-ID"] = str(getattr(g, "request_id", "") or "")
        except Exception:
            pass
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @app.get("/health")
    def health():
        from cache_layer import cache_stats
        from db import get_pool_stats

        pool = get_pool_stats()
        cache = cache_stats()

        return ok({
            "status": "ok",
            "db_pool": pool,
            "cache": cache,
        })[0]

    @app.get("/")
    def index():
        return ok(
            {
                "status": "ok",
                "message": "HRMS backend is running. Use /health for a quick check and POST /api for actions.",
                "endpoints": {"health": "/health", "api": "/api"},
                "note": "In a browser, open http://127.0.0.1:5000/health (do not type 'GET /health' in the URL).",
            }
        )[0]

    @app.get("/files/<file_id>")
    def files_get(file_id: str):
        cfg2: Config = app.config["CFG"]
        fid = str(file_id or "").strip()
        if not re.fullmatch(r"[0-9a-fA-F]{32}", fid):
            return err("BAD_REQUEST", "Invalid file id", http_status=400)[0], 400

        token_q = str(request.args.get("token") or "").strip()
        token_h = str(request.headers.get("Authorization") or "").strip()
        token = token_q
        if token_h.lower().startswith("bearer "):
            token = token_h[7:].strip()

        if not token:
            return err("AUTH_INVALID", "Missing token", http_status=401)[0], 401

        db = SessionLocal()
        try:
            try:
                auth_ctx = validate_session_token(db, token, action="FILES_GET")
            except ApiError as e:
                return err(e.code, e.message, http_status=e.http_status)[0], e.http_status
            if not auth_ctx.valid:
                return err("AUTH_INVALID", "Invalid or expired session", http_status=401)[0], 401

            role = role_or_public(auth_ctx)
            if role == "PUBLIC":
                return err("AUTH_INVALID", "Login required", http_status=401)[0], 401

            # EMPLOYEE role can only access its own candidate/employee files.
            if role == "EMPLOYEE":
                try:
                    from sqlalchemy import select

                    from models import Candidate, Employee

                    emp = db.execute(select(Employee).where(Employee.employeeId == str(auth_ctx.userId or ""))).scalar_one_or_none()
                    if not emp:
                        return err("FORBIDDEN", "Employee not found", http_status=403)[0], 403

                    allowed = set()
                    if str(emp.cvFileId or "").strip():
                        allowed.add(str(emp.cvFileId).strip())

                    cand_id = str(emp.candidateId or "").strip()
                    if cand_id:
                        cand = db.execute(select(Candidate).where(Candidate.candidateId == cand_id)).scalar_one_or_none()
                        if cand and str(cand.cvFileId or "").strip():
                            allowed.add(str(cand.cvFileId).strip())
                        try:
                            docs = json.loads(str(getattr(cand, "docsJson", "") or "[]")) if cand else []
                            if isinstance(docs, list):
                                for d in docs:
                                    if isinstance(d, dict) and str(d.get("fileId") or "").strip():
                                        allowed.add(str(d.get("fileId")).strip())
                        except Exception:
                            pass

                    if fid not in allowed:
                        return err("FORBIDDEN", "File not accessible", http_status=403)[0], 403
                except Exception:
                    return err("FORBIDDEN", "File not accessible", http_status=403)[0], 403

            pattern = os.path.join(cfg2.UPLOAD_DIR, f"{fid}_*")
            matches = sorted(glob.glob(pattern))
            if not matches:
                return err("NOT_FOUND", "File not found", http_status=404)[0], 404

            path = matches[0]
            name = os.path.basename(path)
            download_name = name[len(fid) + 1 :] if name.startswith(fid + "_") else name
            mime, _enc = mimetypes.guess_type(download_name)
            mime = mime or "application/octet-stream"

            resp = send_file(path, mimetype=mime, as_attachment=False, download_name=download_name)
            resp.headers["X-Content-Type-Options"] = "nosniff"
            return resp
        finally:
            try:
                db.close()
            except Exception:
                pass

    @app.errorhandler(404)
    def not_found(_e):
        path = request.path
        return (
            err(
                "NOT_FOUND",
                f"Unknown endpoint: {path}. Use GET /health in browser, and POST /api for actions (don’t type 'GET'/'POST' in the URL).",
                http_status=404,
            )
        )

    @app.errorhandler(405)
    def method_not_allowed(_e):
        return err("BAD_REQUEST", "Method not allowed. Use POST /api for actions.", http_status=405)

    @app.post("/api")
    def api_route():
        cfg2: Config = app.config["CFG"]
        raw = request.get_data(as_text=True)
        db = None
        auth_ctx = None
        action_u = ""
        token = None
        data: Any = {}

        try:
            body = parse_json_body(raw)
            action_u = str(body.get("action") or "").upper().strip()
            token = body.get("token")
            
            # Fallback: check headers if token not in body
            if not token:
                authz = str(request.headers.get("Authorization") or "").strip()
                if authz.lower().startswith("bearer "):
                    token = authz.split(" ", 1)[1].strip()
                if not token:
                    token = str(request.headers.get("X-Session-Token") or "").strip()
            
            data = body.get("data") or {}

            if not action_u:
                raise ApiError("BAD_REQUEST", "Missing action")

            ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
            login_actions = {"LOGIN_EXCHANGE", "EMPLOYEE_LOGIN"}
            if action_u in login_actions:
                limiter.check(f"{ip}:LOGIN", cfg2.RATE_LIMIT_LOGIN)
            else:
                # Use a generous global limit + a per-action limit to avoid blocking normal SPA usage.
                limiter.check(f"{ip}:GLOBAL", cfg2.RATE_LIMIT_GLOBAL)
                limiter.check(f"{ip}:API:{action_u}", cfg2.RATE_LIMIT_DEFAULT)

            db = SessionLocal()

            if action_u != "LOGIN_EXCHANGE" and not is_public_action(action_u):
                auth_ctx = validate_session_token(db, token, action=action_u)
                if not auth_ctx.valid:
                    raise ApiError("AUTH_INVALID", "Invalid or expired session")
            else:
                if token:
                    try:
                        maybe = validate_session_token(db, token, action=action_u)
                        auth_ctx = maybe if maybe.valid else None
                    except ApiError:
                        auth_ctx = None

            role = role_or_public(auth_ctx)
            assert_permission(db, role, action_u)

            out = dispatch(action_u, data, auth_ctx, db, cfg2)

            # Audit API_CALL
            try:
                db.add(
                    AuditLog(
                        logId=f"LOG-{os.urandom(16).hex()}",
                        entityType="API",
                        entityId=str(auth_ctx.userId or auth_ctx.email or "") if auth_ctx else "PUBLIC",
                        action=action_u,
                        fromState="",
                        toState="",
                        stageTag="API_CALL",
                        remark="",
                        actorUserId=str(auth_ctx.userId) if auth_ctx else "PUBLIC",
                        actorRole=str(auth_ctx.role) if auth_ctx else "PUBLIC",
                        actorEmail=str(getattr(auth_ctx, "email", "") or "") if auth_ctx else "",
                        at=iso_utc_now(),
                        correlationId=str(getattr(g, "request_id", "") or ""),
                        metaJson=json.dumps({"data": redact_for_audit(data)}),
                    )
                )
            except Exception:
                pass

            db.commit()

            latency_ms = int((now_monotonic() - g.start_ts) * 1000)
            logging.getLogger("api").info(
                "request_id=%s action=%s user=%s role=%s latency_ms=%s",
                g.request_id,
                action_u,
                (auth_ctx.userId if auth_ctx else "PUBLIC"),
                (auth_ctx.role if auth_ctx else "PUBLIC"),
                latency_ms,
            )

            return ok(out)[0]
        except ApiError as e:
            if db is not None:
                db.rollback()
            _write_error_audit(cfg2, action_u, auth_ctx, data, e)
            return err(e.code, e.message, http_status=e.http_status)[0], e.http_status
        except DBAPIError as e:
            if db is not None:
                db.rollback()

            request_id = str(getattr(g, "request_id", "") or "").strip()
            orig = getattr(e, "orig", None)
            orig_msg = str(orig) if orig else ""
            orig_msg = re.sub(r"\s+", " ", orig_msg).strip()
            if len(orig_msg) > 300:
                orig_msg = orig_msg[:300] + "..."

            if cfg2.IS_PRODUCTION:
                msg = f"Database error (requestId: {request_id})" if request_id else "Database error"
            else:
                detail = f": {orig_msg}" if orig_msg else ""
                msg = f"Database error{detail} (requestId: {request_id})" if request_id else f"Database error{detail}"

            api_err = ApiError("INTERNAL", msg, http_status=500)
            _write_error_audit(cfg2, action_u, auth_ctx, data, api_err)
            logging.getLogger("api").exception("request_id=%s action=%s", request_id, action_u)
            return err(api_err.code, api_err.message, http_status=api_err.http_status)[0], api_err.http_status
        except Exception as e:
            if db is not None:
                db.rollback()

            request_id = str(getattr(g, "request_id", "") or "").strip()
            if cfg2.IS_PRODUCTION:
                msg = f"Unexpected error (requestId: {request_id})" if request_id else "Unexpected error"
            else:
                debug_details = str(os.getenv("DEBUG_ERROR_DETAILS", "") or "").strip().lower() in {
                    "1",
                    "true",
                    "yes",
                    "y",
                    "on",
                }
                detail = type(e).__name__
                if debug_details:
                    raw_msg = re.sub(r"\s+", " ", str(e) or "").strip()
                    if raw_msg:
                        if len(raw_msg) > 300:
                            raw_msg = raw_msg[:300] + "..."
                        detail = f"{detail}: {raw_msg}"
                msg = (
                    f"Unexpected error: {detail} (requestId: {request_id})"
                    if request_id
                    else f"Unexpected error: {detail}"
                )

            api_err = ApiError("INTERNAL", msg, http_status=500)
            _write_error_audit(cfg2, action_u, auth_ctx, data, api_err)
            logging.getLogger("api").exception("request_id=%s action=%s", request_id, action_u)
            return err(api_err.code, api_err.message, http_status=api_err.http_status)[0], api_err.http_status
        finally:
            if db is not None:
                db.close()

    _maybe_start_internal_scheduler(cfg)
    return app


def _write_error_audit(cfg: Config, action: str, auth_ctx, data: Any, err_obj: ApiError):
    if SessionLocal is None:
        return
    try:
        db2 = SessionLocal()
        db2.add(
            AuditLog(
                logId=f"LOG-{os.urandom(16).hex()}",
                entityType="API",
                entityId=str(auth_ctx.userId or auth_ctx.email or "") if auth_ctx else "PUBLIC",
                action=str(action or "").upper() or "UNKNOWN",
                fromState="",
                toState="",
                stageTag="API_ERROR",
                remark=f"{err_obj.code}: {err_obj.message}",
                actorUserId=str(auth_ctx.userId) if auth_ctx else "PUBLIC",
                actorRole=str(auth_ctx.role) if auth_ctx else "PUBLIC",
                actorEmail=str(getattr(auth_ctx, "email", "") or "") if auth_ctx else "",
                at=iso_utc_now(),
                correlationId=str(getattr(g, "request_id", "") or ""),
                metaJson=json.dumps(
                    {
                        "data": redact_for_audit(data or {}),
                        "error": {"code": err_obj.code, "message": err_obj.message},
                    }
                ),
            )
        )
        db2.commit()
    except Exception:
        pass
    finally:
        try:
            db2.close()
        except Exception:
            pass


if __name__ == "__main__":
    app = create_app()
    cfg = app.config["CFG"]

    os.makedirs(cfg.UPLOAD_DIR, exist_ok=True)
    app.run(host=cfg.HOST, port=cfg.PORT)
