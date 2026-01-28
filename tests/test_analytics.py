from __future__ import annotations

import json

from db import SessionLocal
from models import Candidate, Requirement, User
from pii import hash_email, hash_name, mask_email, mask_name
from utils import iso_utc_now


def _api(client, payload: dict):
    return client.post("/api", data=json.dumps(payload), content_type="text/plain; charset=utf-8")


def _seed_admin(app) -> None:
    cfg = app.config["CFG"]
    now = iso_utc_now()

    email = "admin@example.com"
    full_name = "Admin User"

    email_h = hash_email(email, cfg.PEPPER)
    name_h = hash_name(full_name, cfg.PEPPER)

    with SessionLocal() as db:
        db.add(
            User(
                userId="USR-0001",
                email=email_h,
                fullName=mask_name(full_name),
                email_hash=email_h,
                name_hash=name_h,
                email_masked=mask_email(email),
                name_masked=mask_name(full_name),
                email_enc="",
                name_enc="",
                role="ADMIN",
                status="ACTIVE",
                lastLoginAt="",
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.commit()


def _seed_analytics_fixtures() -> None:
    now = iso_utc_now()
    with SessionLocal() as db:
        db.add_all(
            [
                Requirement(
                    requirementId="REQ-0001",
                    jobRole="Software",
                    jobTitle="Software Engineer",
                    status="APPROVED",
                    createdAt=now,
                    createdBy="TEST",
                    updatedAt=now,
                    updatedBy="TEST",
                ),
                Requirement(
                    requirementId="REQ-0002",
                    jobRole="Sales",
                    jobTitle="Sales Executive",
                    status="APPROVED",
                    createdAt=now,
                    createdBy="TEST",
                    updatedAt=now,
                    updatedBy="TEST",
                ),
                Requirement(
                    requirementId="REQ-0003",
                    jobRole="HR",
                    jobTitle="HR Executive",
                    status="CLOSED",
                    createdAt=now,
                    createdBy="TEST",
                    updatedAt=now,
                    updatedBy="TEST",
                ),
            ]
        )

        db.add_all(
            [
                Candidate(
                    candidateId="CAND-0001",
                    requirementId="REQ-0001",
                    candidateName="Candidate 1",
                    mobile="9999999999",
                    source="JOB_PORTAL",
                    status="NEW",
                    createdAt=now,
                    createdBy="TEST",
                    updatedAt=now,
                    updatedBy="TEST",
                ),
                Candidate(
                    candidateId="CAND-0002",
                    requirementId="REQ-0001",
                    candidateName="Candidate 2",
                    mobile="9999999998",
                    source="REFERRAL",
                    status="OWNER",
                    createdAt=now,
                    createdBy="TEST",
                    updatedAt=now,
                    updatedBy="TEST",
                ),
                Candidate(
                    candidateId="CAND-0003",
                    requirementId="REQ-0002",
                    candidateName="Candidate 3",
                    mobile="9999999997",
                    source="WALK_IN",
                    status="WALKIN_SCHEDULED",
                    createdAt=now,
                    createdBy="TEST",
                    updatedAt=now,
                    updatedBy="TEST",
                ),
                Candidate(
                    candidateId="CAND-0004",
                    requirementId="REQ-0002",
                    candidateName="Candidate 4",
                    mobile="9999999996",
                    source="JOB_PORTAL",
                    status="JOINED",
                    joinedAt=now,
                    createdAt=now,
                    createdBy="TEST",
                    updatedAt=now,
                    updatedBy="TEST",
                ),
                Candidate(
                    candidateId="CAND-0005",
                    requirementId="REQ-0003",
                    candidateName="Candidate 5",
                    mobile="9999999995",
                    source="AGENCY",
                    status="REJECTED",
                    createdAt=now,
                    createdBy="TEST",
                    updatedAt=now,
                    updatedBy="TEST",
                ),
            ]
        )
        db.commit()


def test_analytics_endpoints_return_ok(app_client):
    app, client = app_client
    _seed_admin(app)
    _seed_analytics_fixtures()

    res = _api(client, {"action": "LOGIN_EXCHANGE", "token": None, "data": {"idToken": "TEST:admin@example.com"}})
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    token = body["data"]["sessionToken"]

    res = _api(client, {"action": "DASHBOARD_METRICS", "token": token, "data": {}})
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    assert body["data"]["totalCandidates"] == 5
    assert body["data"]["activeRequirements"] == 2
    assert body["data"]["pendingApprovals"] == 1
    assert body["data"]["thisMonthHires"] == 1

    res = _api(client, {"action": "CANDIDATE_PIPELINE_STATS", "token": token, "data": {}})
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    stages = body["data"]["stages"]
    assert isinstance(stages, list)
    assert any(s.get("stage") == "SHORTLISTING" for s in stages)
    assert any(s.get("stage") == "HIRED" for s in stages)

    res = _api(client, {"action": "SOURCE_DISTRIBUTION", "token": token, "data": {}})
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    sources = body["data"]["sources"]
    assert isinstance(sources, list)
    assert any(s.get("source") == "JOB_PORTAL" and int(s.get("count") or 0) == 2 for s in sources)

    res = _api(client, {"action": "HIRING_TRENDS", "token": token, "data": {"period": "monthly"}})
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    trends = body["data"]["trends"]
    assert isinstance(trends, list)
    assert sum(int(t.get("count") or 0) for t in trends) == 1

    res = _api(client, {"action": "SLA_COMPLIANCE_METRICS", "token": token, "data": {}})
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    assert isinstance(body["data"]["metrics"], list)

    res = _api(client, {"action": "RECENT_ACTIVITY", "token": token, "data": {"limit": 10}})
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    assert isinstance(body["data"]["activities"], list)
