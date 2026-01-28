from __future__ import annotations

import json

from sqlalchemy import select

from db import SessionLocal
from models import AtsStage, AuditLog, Candidate, CandidateActivity, User
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
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    token = body["data"]["sessionToken"]
    assert token
    return token


def test_candidate_stage_set_writes_stage_audit_and_activity(app_client):
    app, client = app_client
    _seed_user(app, user_id="USR-HR", email="hr@example.com", role="HR")
    token = _login(client, email="hr@example.com")
    now = iso_utc_now()

    with SessionLocal() as db:
        db.add(
            Candidate(
                candidateId="C-ATS-1",
                requirementId="REQ-ATS-1",
                candidateName="Alice",
                mobile="9999999999",
                jobRole="CRM",
                status="NEW",
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.commit()

    res = _api(
        client,
        {
            "action": "CANDIDATE_STAGE_SET",
            "token": token,
            "data": {"candidateId": "C-ATS-1", "requirementId": "REQ-ATS-1", "stageKey": "PRECALL", "remark": "Move to precall"},
        },
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    assert body["data"]["ok"] is True
    assert body["data"]["stageKey"] == "PRECALL"
    assert body["data"]["stageUpdatedAt"]

    with SessionLocal() as db:
        cand = db.execute(select(Candidate).where(Candidate.candidateId == "C-ATS-1")).scalar_one()
        assert str(cand.candidateStage or "") == "PRECALL"
        assert str(cand.stageUpdatedAt or "")

        audit = db.execute(
            select(AuditLog)
            .where(AuditLog.entityType == "CANDIDATE")
            .where(AuditLog.entityId == "C-ATS-1")
            .where(AuditLog.action == "CANDIDATE_STAGE_SET")
        ).scalar_one_or_none()
        assert audit is not None
        assert audit.fromState == "NEW"
        assert audit.toState == "PRECALL"
        assert audit.stageTag == "ATS_STAGE_SET"

        act = db.execute(
            select(CandidateActivity)
            .where(CandidateActivity.candidateId == "C-ATS-1")
            .where(CandidateActivity.type == "SYSTEM")
            .order_by(CandidateActivity.at.desc())
        ).scalar_one_or_none()
        assert act is not None
        payload = json.loads(str(act.payloadJson or "{}") or "{}")
        assert payload.get("from") == "NEW"
        assert payload.get("to") == "PRECALL"
        assert payload.get("remark") == "Move to precall"


def test_ats_stage_upsert_forbidden_for_non_admin(app_client):
    app, client = app_client
    _seed_user(app, user_id="USR-HR", email="hr@example.com", role="HR")
    token = _login(client, email="hr@example.com")

    res = _api(
        client,
        {
            "action": "ATS_STAGE_UPSERT",
            "token": token,
            "data": {
                "stageKey": "CUSTOM_TEST",
                "stageName": "Custom",
                "orderNo": 999,
                "color": "purple",
                "isActive": True,
                "rolesCsv": "ADMIN",
            },
        },
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is False
    assert body["error"]["code"] == "FORBIDDEN"

    with SessionLocal() as db:
        row = db.execute(select(AtsStage).where(AtsStage.stageKey == "CUSTOM_TEST")).scalar_one_or_none()
        assert row is None

