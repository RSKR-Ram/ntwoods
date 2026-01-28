from __future__ import annotations

import json

from sqlalchemy import select

from db import SessionLocal
from models import Candidate, CandidateTest, FailCandidate, JobPosting, Role, TestMaster, User
from pii import hash_email, hash_name, mask_email, mask_name
from utils import iso_utc_now


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


def test_candidate_test_submit_requires_assignment_for_admin(app_client):
    app, client = app_client

    _seed_user(app, user_id="USR-0001", email="admin@example.com", role="ADMIN")
    _seed_user(app, user_id="USR-0002", email="mis@example.com", role="MIS")

    now = iso_utc_now()
    with SessionLocal() as db:
        db.add(
            Candidate(
                candidateId="C1",
                requirementId="REQ1",
                candidateName="Alice",
                mobile="9999999999",
                jobRole="ACCOUNTS",
                status="TECH_EVALUATED",
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.add(
            CandidateTest(
                candidateId="C1",
                requirementId="REQ1",
                testKey="EXCEL",
                isRequired=True,
                status="PENDING",
                fillOwnerUserId="USR-0002",
                createdAt=now,
                updatedAt=now,
            )
        )
        db.commit()

    token = _login(client, email="admin@example.com")

    # Not assigned to admin -> forbidden (strict).
    res = _api(
        client,
        {
            "action": "CANDIDATE_TEST_SUBMIT",
            "token": token,
            "data": {"requirementId": "REQ1", "candidateId": "C1", "testKey": "EXCEL", "marks": 7, "remarks": ""},
        },
    )
    body = res.get_json()
    assert body["ok"] is False
    assert body["error"]["code"] == "FORBIDDEN"

    # Assign to admin and submit.
    res = _api(
        client,
        {
            "action": "CANDIDATE_TEST_ASSIGN",
            "token": token,
            "data": {"candidateId": "C1", "testKey": "EXCEL", "fillOwnerUserId": "USR-0001"},
        },
    )
    body = res.get_json()
    assert body["ok"] is True, body

    res = _api(
        client,
        {
            "action": "CANDIDATE_TEST_SUBMIT",
            "token": token,
            "data": {"requirementId": "REQ1", "candidateId": "C1", "testKey": "EXCEL", "marks": 7, "remarks": "ok"},
        },
    )
    body = res.get_json()
    assert body["ok"] is True
    assert body["data"]["fillOwnerUserId"] == "USR-0001"


def test_custom_assign_creates_role_user_and_permissions(app_client):
    app, client = app_client
    cfg = app.config["CFG"]

    _seed_user(app, user_id="USR-0001", email="admin@example.com", role="ADMIN")

    now = iso_utc_now()
    with SessionLocal() as db:
        # Add a custom testKey that allows a not-yet-existing role.
        db.add(
            TestMaster(
                testKey="CUSTOM",
                label="Custom",
                fillRolesJson=json.dumps(["NEWROLE", "ADMIN"]),
                reviewRolesJson=json.dumps(["HR", "ADMIN"]),
                active=True,
                ordering=999,
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.add(
            Candidate(
                candidateId="C2",
                requirementId="REQ1",
                candidateName="Bob",
                mobile="8888888888",
                jobRole="ACCOUNTS",
                status="TECH_EVALUATED",
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.add(
            CandidateTest(
                candidateId="C2",
                requirementId="REQ1",
                testKey="CUSTOM",
                isRequired=True,
                status="PENDING",
                fillOwnerUserId="",
                createdAt=now,
                updatedAt=now,
            )
        )
        db.commit()

    admin_token = _login(client, email="admin@example.com")

    res = _api(
        client,
        {
            "action": "CANDIDATE_TEST_ASSIGN",
            "token": admin_token,
            "data": {
                "candidateId": "C2",
                "testKey": "CUSTOM",
                "customAssign": True,
                "roleName": "NEWROLE",
                "userEmail": "newrole@example.com",
                "userFullName": "New Role User",
            },
        },
    )
    body = res.get_json()
    assert body["ok"] is True, body
    assignee_user_id = body["data"]["fillOwnerUserId"]
    assert assignee_user_id

    email_h = hash_email("newrole@example.com", cfg.PEPPER)
    with SessionLocal() as db:
        role_row = db.execute(select(Role).where(Role.roleCode == "NEWROLE")).scalar_one_or_none()
        assert role_row is not None
        u = db.execute(select(User).where(User.email_hash == email_h)).scalar_one_or_none()
        assert u is not None
        assert u.role == "NEWROLE"
        assert u.userId == assignee_user_id

    # New role can log in and read its permissions (required for dynamic roles).
    new_token = _login(client, email="newrole@example.com")

    res = _api(client, {"action": "MY_PERMISSIONS_GET", "token": new_token, "data": {}})
    body = res.get_json()
    assert body["ok"] is True
    assert "PORTAL_TESTS" in (body["data"].get("uiKeys") or [])
    assert "TESTS_QUEUE_LIST" in (body["data"].get("actionKeys") or [])
    assert "CANDIDATE_TEST_SUBMIT" in (body["data"].get("actionKeys") or [])

    # Assigned user can submit marks for the assigned test.
    res = _api(
        client,
        {
            "action": "CANDIDATE_TEST_SUBMIT",
            "token": new_token,
            "data": {"requirementId": "REQ1", "candidateId": "C2", "testKey": "CUSTOM", "marks": 8, "remarks": "ok"},
        },
    )
    body = res.get_json()
    assert body["ok"] is True
    assert body["data"]["fillOwnerUserId"] == assignee_user_id


def test_docs_complete_requires_all_8_docs(app_client):
    app, client = app_client
    _seed_user(app, user_id="USR-0001", email="admin@example.com", role="ADMIN")

    now = iso_utc_now()
    with SessionLocal() as db:
        db.add(JobPosting(requirementId="REQDOC", status="COMPLETE", checklistStateJson="{}", screenshotUploadId="", completedAt=now, completedBy="TEST", updatedAt=now, updatedBy="TEST"))
        db.add(
            Candidate(
                candidateId="CDOC",
                requirementId="REQDOC",
                candidateName="Carol",
                mobile="7777777777",
                jobRole="ACCOUNTS",
                status="JOINING",
                docsJson=json.dumps([{"docType": "AADHAR_CARD", "fileId": "x"}, {"docType": "PAN_CARD", "fileId": "y"}]),
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.commit()

    token = _login(client, email="admin@example.com")

    res = _api(client, {"action": "DOCS_COMPLETE", "token": token, "data": {"requirementId": "REQDOC", "candidateId": "CDOC"}})
    body = res.get_json()
    assert body["ok"] is False
    assert body["error"]["code"] == "BAD_REQUEST"
    assert "Missing required docs" in body["error"]["message"]

    all_docs = [
        {"docType": "AADHAR_CARD", "fileId": "1"},
        {"docType": "PAN_CARD", "fileId": "2"},
        {"docType": "BANK_PASSBOOK", "fileId": "3"},
        {"docType": "EDUCATION_CERTIFICATE", "fileId": "4"},
        {"docType": "PREV_COMPANY_DOCS", "fileId": "5"},
        {"docType": "SALARY_STATEMENT_6M", "fileId": "6"},
        {"docType": "ESI_FAMILY_AADHAR_PHOTOS", "fileId": "7"},
        {"docType": "PASSPORT_PHOTOS_4", "fileId": "8"},
    ]
    with SessionLocal() as db:
        c = db.execute(select(Candidate).where(Candidate.candidateId == "CDOC")).scalar_one()
        c.docsJson = json.dumps(all_docs)
        db.commit()

    res = _api(client, {"action": "DOCS_COMPLETE", "token": token, "data": {"requirementId": "REQDOC", "candidateId": "CDOC"}})
    body = res.get_json()
    assert body["ok"] is True
    assert body["data"]["docsCompleteAt"]


def test_final_interview_list_excludes_open_online_test_fail(app_client):
    app, client = app_client
    _seed_user(app, user_id="USR-0001", email="admin@example.com", role="ADMIN")

    now = iso_utc_now()
    with SessionLocal() as db:
        db.add(
            Candidate(
                candidateId="C_OK",
                requirementId="REQF",
                candidateName="Eligible",
                mobile="6666666666",
                jobRole="ACCOUNTS",
                status="TECH_EVALUATED",
                onlineTestResult="",
                inPersonMarks=6,
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.add(
            Candidate(
                candidateId="C_FAIL",
                requirementId="REQF",
                candidateName="Failed Online",
                mobile="5555555555",
                jobRole="ACCOUNTS",
                status="TECH_EVALUATED",
                onlineTestResult="",
                inPersonMarks=6,
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.add(
            FailCandidate(
                candidateId="C_FAIL",
                requirementId="REQF",
                stageName="ONLINE_TEST",
                reason="Fail",
                score=0,
                failedAt=now,
                actorUserId="SYSTEM",
                actorRole="SYSTEM",
                resolvedAt="",
                resolvedBy="",
                resolution="",
                metaJson="{}",
            )
        )
        db.commit()

    token = _login(client, email="admin@example.com")
    res = _api(client, {"action": "FINAL_INTERVIEW_LIST", "token": token, "data": {}})
    body = res.get_json()
    assert body["ok"] is True
    ids = {str(it.get("candidateId") or "") for it in (body["data"].get("items") or [])}
    assert "C_OK" in ids
    assert "C_FAIL" not in ids
