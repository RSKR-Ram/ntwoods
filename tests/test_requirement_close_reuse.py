from __future__ import annotations

import json
from datetime import datetime, timezone

from db import SessionLocal
from models import Candidate, JobPosting, Requirement
from utils import iso_utc_now


def _api(client, payload: dict):
    return client.post("/api", data=json.dumps(payload), content_type="text/plain; charset=utf-8")


def _seed_user(app, *, user_id: str, email: str, role: str) -> None:
    from models import User
    from pii import hash_email, hash_name, mask_email, mask_name
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


def test_requirement_close_marks_candidates(app_client):
    """Test that REQUIREMENT_CLOSE marks candidates as available for reuse."""
    app, client = app_client
    _seed_user(app, user_id="USR-ADMIN", email="admin@example.com", role="ADMIN")
    token = _login(client, email="admin@example.com")

    now = iso_utc_now()
    with SessionLocal() as db:
        db.add(
            Requirement(
                requirementId="REQ-CLOSE-1",
                jobRole="CRM",
                jobTitle="CRM Exec",
                status="APPROVED",
                requiredCount=2,
                joinedCount=0,
                latestRemark="",
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.add(
            Candidate(
                candidateId="C-CLOSE-1",
                requirementId="REQ-CLOSE-1",
                candidateName="Alice",
                mobile="9999999999",
                jobRole="CRM",
                status="SHORTLISTED",
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.add(
            Candidate(
                candidateId="C-CLOSE-2",
                requirementId="REQ-CLOSE-1",
                candidateName="Bob",
                mobile="8888888888",
                jobRole="CRM",
                status="WALKIN_SCHEDULED",
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.commit()

    # Close the requirement
    res = _api(client, {"action": "REQUIREMENT_CLOSE", "token": token, "data": {"requirementId": "REQ-CLOSE-1", "remark": "No longer needed"}})
    body = res.get_json()
    assert body["ok"] is True
    assert body["data"]["status"] == "CLOSED"
    assert body["data"]["candidatesMarked"] == 2

    # Verify candidates are marked for reuse
    with SessionLocal() as db:
        cand1 = db.execute(
            __import__("sqlalchemy").select(Candidate).where(Candidate.candidateId == "C-CLOSE-1")
        ).scalar_one_or_none()
        assert cand1.rejectedReasonCode == "REQUIREMENT_CLOSED"
        
        cand2 = db.execute(
            __import__("sqlalchemy").select(Candidate).where(Candidate.candidateId == "C-CLOSE-2")
        ).scalar_one_or_none()
        assert cand2.rejectedReasonCode == "REQUIREMENT_CLOSED"


def test_candidate_reuse_creates_new_candidate(app_client):
    """Test that CANDIDATE_REUSE creates a new candidate linked to the same CandidateMaster."""
    app, client = app_client
    _seed_user(app, user_id="USR-ADMIN", email="admin@example.com", role="ADMIN")
    token = _login(client, email="admin@example.com")

    now = iso_utc_now()
    with SessionLocal() as db:
        # Source closed requirement
        db.add(
            Requirement(
                requirementId="REQ-SOURCE-1",
                jobRole="CRM",
                jobTitle="CRM Exec",
                status="CLOSED",
                requiredCount=1,
                joinedCount=1,
                latestRemark="",
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        # Target approved requirement
        db.add(
            Requirement(
                requirementId="REQ-TARGET-1",
                jobRole="CRM",
                jobTitle="CRM Exec",
                status="APPROVED",
                requiredCount=1,
                joinedCount=0,
                latestRemark="",
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.add(
            JobPosting(
                requirementId="REQ-TARGET-1",
                status="COMPLETE",
                checklistStateJson="{}",
                screenshotUploadId="",
                completedAt=now,
                completedBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        # Candidate from closed requirement
        db.add(
            Candidate(
                candidateId="C-REUSE-1",
                candidateMasterId="CM-1",
                requirementId="REQ-SOURCE-1",
                candidateName="Charlie",
                mobile="7777777777",
                name_hash="hash1",
                mobile_hash="hash2",
                jobRole="CRM",
                status="REJECTED",
                rejectedReasonCode="REQUIREMENT_CLOSED",
                cvFileId="FILE-123",
                cvFileName="charlie_cv.pdf",
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.commit()

    # Reuse the candidate
    res = _api(client, {
        "action": "CANDIDATE_REUSE",
        "token": token,
        "data": {"sourceCandidateId": "C-REUSE-1", "targetRequirementId": "REQ-TARGET-1"}
    })
    body = res.get_json()
    assert body["ok"] is True
    assert body["data"]["requirementId"] == "REQ-TARGET-1"
    new_candidate_id = body["data"]["candidateId"]
    assert new_candidate_id != "C-REUSE-1"  # New ID created

    # Verify new candidate exists with same CandidateMaster
    with SessionLocal() as db:
        new_cand = db.execute(
            __import__("sqlalchemy").select(Candidate).where(Candidate.candidateId == new_candidate_id)
        ).scalar_one_or_none()
        assert new_cand is not None
        assert new_cand.candidateMasterId == "CM-1"
        assert new_cand.requirementId == "REQ-TARGET-1"
        assert new_cand.cvFileId == "FILE-123"  # CV preserved
        assert "REUSED:" in new_cand.source


def test_candidate_get_detail_returns_full_profile(app_client):
    """Test that CANDIDATE_GET_DETAIL returns complete candidate profile."""
    app, client = app_client
    _seed_user(app, user_id="USR-ADMIN", email="admin@example.com", role="ADMIN")
    token = _login(client, email="admin@example.com")

    now = iso_utc_now()
    with SessionLocal() as db:
        db.add(
            Requirement(
                requirementId="REQ-DETAIL-1",
                jobRole="CRM",
                jobTitle="CRM Exec",
                status="APPROVED",
                requiredCount=1,
                joinedCount=0,
                latestRemark="",
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.add(
            Candidate(
                candidateId="C-DETAIL-1",
                requirementId="REQ-DETAIL-1",
                candidateName="David",
                mobile="6666666666",
                jobRole="CRM",
                status="SHORTLISTED",
                cvFileId="FILE-456",
                cvFileName="david_cv.pdf",
                preInterviewMarks="8/10",
                onlineTestScore=85,
                onlineTestResult="PASS",
                techResult="PASS",
                techReview="Good technical skills",
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.commit()

    res = _api(client, {"action": "CANDIDATE_GET_DETAIL", "token": token, "data": {"candidateId": "C-DETAIL-1"}})
    body = res.get_json()
    assert body["ok"] is True
    data = body["data"]
    assert data["candidateId"] == "C-DETAIL-1"
    assert data["cvFileId"] == "FILE-456"
    assert data["cvFileName"] == "david_cv.pdf"
    assert data["preInterviewMarks"] == "8/10"
    assert data["onlineTestScore"] == 85
    assert data["techResult"] == "PASS"
    assert data["requirement"]["requirementId"] == "REQ-DETAIL-1"
    assert "timeline" in data
