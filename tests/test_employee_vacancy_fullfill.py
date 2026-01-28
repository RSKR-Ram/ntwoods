from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from db import SessionLocal
from models import AssignedTraining, Candidate, CandidateTrainingState, Employee, ExitCase, JobPosting, Requirement, Session as DbSession, User
from passwords import hash_password
from pii import hash_email, hash_name, mask_email, mask_name, mask_phone
from utils import iso_utc_now, sha256_hex, to_iso_utc


def _api(client, payload: dict):
    return client.post("/api", data=json.dumps(payload), content_type="text/plain; charset=utf-8")


def _seed_user(app, *, user_id: str, email: str, role: str) -> None:
    cfg = app.config["CFG"]
    now = iso_utc_now()
    email_h = hash_email(email, cfg.PEPPER)
    name_h = hash_name("Test User", cfg.PEPPER)
    with SessionLocal() as db:
        db.add(
            User(
                userId=user_id,
                email=email_h,
                fullName=mask_name("Test User"),
                email_hash=email_h,
                name_hash=name_h,
                email_masked=mask_email(email),
                name_masked=mask_name("Test User"),
                email_enc="",
                name_enc="",
                role=role,
                status="ACTIVE",
                lastLoginAt="",
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.commit()


def _login(client, *, email: str) -> str:
    res = _api(client, {"action": "LOGIN_EXCHANGE", "token": None, "data": {"idToken": f"TEST:{email}"}})
    body = res.get_json()
    assert body["ok"] is True
    token = body["data"]["sessionToken"]
    assert token
    return token


def test_employee_training_list_shows_new_trainings_after_close(app_client):
    app, client = app_client
    now_dt = datetime.now(timezone.utc)
    closed_at = to_iso_utc(now_dt)
    before = to_iso_utc(now_dt - timedelta(minutes=1))
    after = to_iso_utc(now_dt + timedelta(minutes=1))
    emp_password = "StrongPassw0rd!"

    # Candidate + Employee (used by EMPLOYEE_LOGIN).
    with SessionLocal() as db:
        db.add(
            Candidate(
                candidateId="C-T1",
                requirementId="REQ-T1",
                candidateName="Alice",
                mobile="9999999999",
                jobRole="CRM",
                status="EMPLOYEE",
                joinedAt=before,
                createdAt=before,
                createdBy="TEST",
                updatedAt=before,
                updatedBy="TEST",
            )
        )
        db.add(
            Employee(
                employeeId="EMP-T1",
                employee_id="EMP-T1",
                candidateId="C-T1",
                requirementId="REQ-T1",
                employeeName="Alice",
                mobile="9999999999",
                jobRole="CRM",
                jobTitle="CRM Exec",
                source="",
                cvFileId="",
                cvFileName="",
                joinedAt=before,
                probationStartAt="",
                probationEndsAt="",
                password_hash=hash_password(emp_password),
                password_reset_required=False,
                password_changed_at=before,
                createdAt=before,
                createdBy="TEST",
                timelineJson="[]",
            )
        )
        db.add(
            CandidateTrainingState(
                candidateId="C-T1",
                requirementId="REQ-T1",
                markedCompleteAt=before,
                markedCompleteBy="TEST",
                closedAt=closed_at,
                closedBy="TEST",
                updatedAt=closed_at,
                updatedBy="TEST",
            )
        )

        # Old (probation) training: should be hidden for EMPLOYEE after close.
        db.add(
            AssignedTraining(
                assigned_id="AT-OLD",
                candidate_id="C-T1",
                training_id="TR-OLD",
                training_name="Probation Training",
                department="HR",
                description="",
                video_link="",
                videoLinksJson="[]",
                documentsJson="[]",
                status="COMPLETED",
                assigned_date=before,
                due_date=before,
                start_time=before,
                completion_time=before,
                assigned_by="HR",
            )
        )

        # New training assigned after close: should be visible for EMPLOYEE.
        db.add(
            AssignedTraining(
                assigned_id="AT-NEW",
                candidate_id="C-T1",
                training_id="TR-NEW",
                training_name="Tech Product Training",
                department="TECH",
                description="",
                video_link="",
                videoLinksJson="[]",
                documentsJson="[]",
                status="PENDING",
                assigned_date=after,
                due_date=after,
                start_time="",
                completion_time="",
                assigned_by="HR",
            )
        )
        db.commit()

    # Employee portal login.
    res = _api(client, {"action": "EMPLOYEE_LOGIN", "token": None, "data": {"employeeId": "EMP-T1", "password": emp_password}})
    body = res.get_json()
    assert body["ok"] is True
    emp_token = body["data"]["sessionToken"]

    res = _api(client, {"action": "TRAINING_LIST", "token": emp_token, "data": {}})
    body = res.get_json()
    assert body["ok"] is True
    ids = {str(x.get("assigned_id") or "") for x in (body["data"].get("items") or [])}
    assert "AT-NEW" in ids
    assert "AT-OLD" not in ids

    # Employee can start the new training (assigned after close).
    res = _api(
        client,
        {
            "action": "TRAINING_STATUS_UPDATE",
            "token": emp_token,
            "data": {"candidate_id": "C-T1", "assigned_id": "AT-NEW", "op": "START", "remarks": ""},
        },
    )
    body = res.get_json()
    assert body["ok"] is True
    assert str(body["data"].get("status") or "").upper() == "IN_PROGRESS"


def test_probation_complete_refreshes_employee_timeline(app_client):
    app, client = app_client
    _seed_user(app, user_id="USR-ADMIN", email="admin@example.com", role="ADMIN")
    token = _login(client, email="admin@example.com")

    now = iso_utc_now()
    ends = to_iso_utc(datetime.now(timezone.utc) + timedelta(days=90))

    with SessionLocal() as db:
        db.add(
            Requirement(
                requirementId="REQ-P1",
                jobRole="CRM",
                jobTitle="CRM Exec",
                status="APPROVED",
                requiredCount=1,
                joinedCount=1,
                latestRemark="",
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.add(
            JobPosting(
                requirementId="REQ-P1",
                status="COMPLETE",
                checklistStateJson="{}",
                screenshotUploadId="",
                completedAt=now,
                completedBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.add(
            Candidate(
                candidateId="C-P1",
                requirementId="REQ-P1",
                candidateName="Bob",
                mobile="8888888888",
                jobRole="CRM",
                status="PROBATION",
                joinedAt=now,
                probationStartAt=now,
                probationEndsAt=ends,
                employeeId="EMP-P1",
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.add(
            Employee(
                employeeId="EMP-P1",
                candidateId="C-P1",
                requirementId="REQ-P1",
                employeeName="Bob",
                mobile="8888888888",
                jobRole="CRM",
                jobTitle="CRM Exec",
                source="",
                cvFileId="",
                cvFileName="",
                joinedAt=now,
                probationStartAt=now,
                probationEndsAt=ends,
                createdAt=now,
                createdBy="TEST",
                timelineJson="[]",
            )
        )
        db.add(
            CandidateTrainingState(
                candidateId="C-P1",
                requirementId="REQ-P1",
                markedCompleteAt=now,
                markedCompleteBy="TEST",
                closedAt=now,
                closedBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.add(
            AssignedTraining(
                assigned_id="AT-P1",
                candidate_id="C-P1",
                training_id="TR-P1",
                training_name="Probation Training",
                department="HR",
                description="",
                video_link="",
                videoLinksJson="[]",
                documentsJson="[]",
                status="COMPLETED",
                assigned_date=now,
                due_date=now,
                start_time=now,
                completion_time=now,
                assigned_by="HR",
            )
        )
        db.commit()

    res = _api(client, {"action": "PROBATION_COMPLETE", "token": token, "data": {"requirementId": "REQ-P1", "candidateId": "C-P1"}})
    body = res.get_json()
    assert body["ok"] is True
    assert body["data"]["employeeId"] == "EMP-P1"

    res = _api(client, {"action": "EMPLOYEE_GET", "token": token, "data": {"employeeId": "EMP-P1"}})
    body = res.get_json()
    assert body["ok"] is True
    timeline = body["data"].get("timeline") or []
    assert any(str(x.get("action") or "").upper() == "PROBATION_COMPLETE" for x in timeline)


def test_vacancy_fullfill_list_excludes_joined_candidates(app_client):
    app, client = app_client
    _seed_user(app, user_id="USR-ADMIN", email="admin@example.com", role="ADMIN")
    token = _login(client, email="admin@example.com")

    now = iso_utc_now()
    with SessionLocal() as db:
        db.add(
            Requirement(
                requirementId="REQ-V1",
                jobRole="CRM",
                jobTitle="CRM Exec",
                status="CLOSED",
                requiredCount=1,
                joinedCount=1,
                latestRemark="Auto closed",
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.add(
            Candidate(
                candidateId="C-JOINED",
                requirementId="REQ-V1",
                candidateName="Joined",
                mobile="7777777777",
                jobRole="CRM",
                status="JOINED",
                joinedAt=now,
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.add(
            Candidate(
                candidateId="C-LEFT",
                requirementId="REQ-V1",
                candidateName="Leftover",
                mobile="6666666666",
                jobRole="CRM",
                status="REJECTED",
                joinedAt="",
                excelMarks=7,
                techReview="Good candidate",
                rejectedReasonCode="VACANCY_FILLED",
                rejectedAt=now,
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.commit()

    res = _api(client, {"action": "VACANCY_FULLFILL_LIST", "token": token, "data": {"requirementId": "REQ-V1"}})
    body = res.get_json()
    assert body["ok"] is True
    items = body["data"].get("items") or []
    assert len(items) == 1
    req = items[0]
    assert req["requirementId"] == "REQ-V1"
    cands = req.get("candidates") or []
    ids = {str(c.get("candidateId") or "") for c in cands}
    assert "C-LEFT" in ids
    assert "C-JOINED" not in ids


def test_employee_list_returns_items(app_client):
    app, client = app_client
    _seed_user(app, user_id="USR-ADMIN", email="admin@example.com", role="ADMIN")
    token = _login(client, email="admin@example.com")

    now = iso_utc_now()
    with SessionLocal() as db:
        db.add(
            Employee(
                employeeId="EMP-L1",
                candidateId="C-L1",
                requirementId="REQ-L1",
                employeeName="List Employee",
                mobile="",
                jobRole="CRM",
                jobTitle="CRM Exec",
                source="",
                cvFileId="",
                cvFileName="",
                joinedAt=now,
                probationStartAt="",
                probationEndsAt="",
                createdAt=now,
                createdBy="TEST",
                timelineJson="[]",
            )
        )
        db.commit()

    res = _api(client, {"action": "EMPLOYEE_LIST", "token": token, "data": {"q": "EMP-L1"}})
    body = res.get_json()
    assert body["ok"] is True
    items = body["data"].get("items") or []
    assert any(str(it.get("employeeId") or "") == "EMP-L1" for it in items)


def test_probation_reject_exits_employee_and_hides_from_directory(app_client):
    app, client = app_client
    _seed_user(app, user_id="USR-ADMIN", email="admin@example.com", role="ADMIN")
    token = _login(client, email="admin@example.com")

    now = iso_utc_now()
    with SessionLocal() as db:
        db.add(
            Requirement(
                requirementId="REQ-PR1",
                jobRole="CRM",
                jobTitle="CRM Exec",
                status="APPROVED",
                requiredCount=1,
                joinedCount=1,
                latestRemark="",
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.add(
            JobPosting(
                requirementId="REQ-PR1",
                status="COMPLETE",
                checklistStateJson="{}",
                screenshotUploadId="",
                completedAt=now,
                completedBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.add(
            Candidate(
                candidateId="C-PR1",
                requirementId="REQ-PR1",
                candidateName=mask_name("Probation Candidate"),
                mobile=mask_phone("9999999999"),
                jobRole="CRM",
                status="PROBATION",
                employeeId="EMP-PR1",
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.add(
            Employee(
                employeeId="EMP-PR1",
                employee_id="EMP-PR1",
                candidateId="C-PR1",
                requirementId="REQ-PR1",
                employeeName=mask_name("Probation Candidate"),
                mobile=mask_phone("9999999999"),
                jobRole="CRM",
                jobTitle="CRM Exec",
                source="",
                cvFileId="",
                cvFileName="",
                joinedAt=now,
                probationStartAt=now,
                probationEndsAt="",
                status="ACTIVE",
                is_active=True,
                auth_version=0,
                createdAt=now,
                createdBy="TEST",
                timelineJson="[]",
            )
        )
        db.add(
            DbSession(
                sessionId="SES-PR1",
                tokenHash=sha256_hex("ST-PR1"),
                tokenPrefix="ST-PR1"[:12],
                userId="EMP-PR1",
                email="",
                role="EMPLOYEE",
                userStatus="ACTIVE",
                authVersion=0,
                issuedAt=now,
                expiresAt=now,
                lastSeenAt=now,
                revokedAt="",
                revokedBy="",
            )
        )
        db.commit()

    res = _api(
        client,
        {
            "action": "PROBATION_DECIDE",
            "token": token,
            "data": {"requirementId": "REQ-PR1", "candidateId": "C-PR1", "decision": "REJECT", "remark": "Not suitable"},
        },
    )
    body = res.get_json()
    assert body["ok"] is True
    assert body["data"]["status"] == "REJECTED"

    with SessionLocal() as db:
        emp = db.execute(select(Employee).where(Employee.employeeId == "EMP-PR1")).scalar_one()
        assert str(emp.status or "").upper() in {"INACTIVE", "EXITED"}
        assert bool(emp.is_active) is False
        assert int(getattr(emp, "auth_version", 0) or 0) >= 1
        exit_case = (
            db.execute(select(ExitCase).where(ExitCase.employee_id == "EMP-PR1").order_by(ExitCase.created_at.desc()).limit(1))
            .scalars()
            .first()
        )
        assert exit_case is not None
        assert str(getattr(exit_case, "exit_type", "") or "").upper() == "TERMINATED"

        ses = db.execute(select(DbSession).where(DbSession.sessionId == "SES-PR1")).scalar_one()
        assert str(getattr(ses, "revokedAt", "") or "").strip()

    res = _api(client, {"action": "EMPLOYEE_LIST", "token": token, "data": {"q": "EMP-PR1"}})
    body = res.get_json()
    assert body["ok"] is True
    items = body["data"].get("items") or []
    assert not any(str(it.get("employeeId") or "") == "EMP-PR1" for it in items)

    # Explicit override: allow fetching exited employees when requested.
    res = _api(client, {"action": "EMPLOYEE_LIST", "token": token, "data": {"q": "EMP-PR1", "includeExited": True}})
    body = res.get_json()
    assert body["ok"] is True
    items = body["data"].get("items") or []
    assert any(str(it.get("employeeId") or "") == "EMP-PR1" for it in items)
