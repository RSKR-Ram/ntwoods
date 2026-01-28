from __future__ import annotations

import io
import json

from sqlalchemy import select

from db import SessionLocal
from models import Employee, ExitCase, User
from pii import hash_email, hash_name, mask_email, mask_name
from utils import iso_utc_now


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
                userId="USR-ADMIN",
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


def _api(client, payload: dict):
    return client.post("/api", data=json.dumps(payload), content_type="text/plain; charset=utf-8")


def _login_admin(client) -> str:
    res = _api(client, {"action": "LOGIN_EXCHANGE", "token": None, "data": {"idToken": "TEST:admin@example.com"}})
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    return body["data"]["sessionToken"]


def _upload_doc(client, *, token: str, employee_id: str, doc_type: str) -> str:
    res = client.post(
        "/api/docs/upload",
        data={
            "employeeId": employee_id,
            "docType": doc_type,
            "visibility": "INTERNAL",
            "file": (io.BytesIO(b"test-bytes"), "doc.txt"),
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    return body["data"]["docId"]


def test_self_exit_notice_and_settlement_rules(app_client):
    app, client = app_client

    _seed_admin(app)
    token = _login_admin(client)

    employee_id = "EMP-0001"
    now = iso_utc_now()
    with SessionLocal() as db:
        db.add(Employee(employeeId=employee_id, employeeName="Employee", jobRole="CRM", joinedAt=now, createdAt=now, createdBy="TEST"))
        db.commit()

    res = client.post(
        "/api/exit/start-notice",
        json={"employeeId": employee_id, "noticeDays": 1},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    exit_id = body["data"]["exitCase"]["exitId"]

    # Cannot complete before notice end.
    res = client.post("/api/exit/complete", json={"exitId": exit_id}, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is False
    assert body["error"]["code"] == "BAD_REQUEST"
    assert "notice" in body["error"]["message"].lower()

    # Simulate notice period completed.
    with SessionLocal() as db:
        row = db.execute(select(ExitCase).where(ExitCase.id == exit_id)).scalar_one()
        row.notice_end = "2000-01-01T00:00:00.000Z"
        db.commit()

    # Still cannot complete without settlement clear + doc.
    res = client.post("/api/exit/complete", json={"exitId": exit_id}, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is False
    assert body["error"]["code"] == "BAD_REQUEST"
    assert "settlement" in body["error"]["message"].lower()

    settlement_doc_id = _upload_doc(client, token=token, employee_id=employee_id, doc_type="SETTLEMENT")

    res = client.post(
        "/api/exit/settlement-clear",
        json={"exitId": exit_id, "settlementDocId": settlement_doc_id},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True

    res = client.post("/api/exit/complete", json={"exitId": exit_id}, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    assert body["data"]["exitCase"]["state"] == "EXITED"

    with SessionLocal() as db:
        emp = db.execute(select(Employee).where(Employee.employeeId == employee_id)).scalar_one()
        assert emp.status == "EXITED"
        assert str(emp.exitAt or "").strip()


def test_terminated_exit_requires_letter(app_client):
    app, client = app_client

    _seed_admin(app)
    token = _login_admin(client)

    employee_id = "EMP-0002"
    now = iso_utc_now()
    with SessionLocal() as db:
        db.add(Employee(employeeId=employee_id, employeeName="Employee", jobRole="CRM", joinedAt=now, createdAt=now, createdBy="TEST"))
        db.commit()

    res = client.post(
        "/api/exit/terminate-init",
        json={"employeeId": employee_id, "lastWorkingDay": "2025-01-01", "remark": "policy breach"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    exit_id = body["data"]["exitCase"]["exitId"]

    settlement_doc_id = _upload_doc(client, token=token, employee_id=employee_id, doc_type="SETTLEMENT")
    res = client.post(
        "/api/exit/settlement-clear",
        json={"exitId": exit_id, "settlementDocId": settlement_doc_id},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    assert res.get_json()["ok"] is True

    # Cannot complete without termination letter.
    res = client.post("/api/exit/complete", json={"exitId": exit_id}, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is False
    assert body["error"]["code"] == "BAD_REQUEST"
    assert "termination" in body["error"]["message"].lower()

    letter_doc_id = _upload_doc(client, token=token, employee_id=employee_id, doc_type="TERMINATION_LETTER")
    res = client.post(
        "/api/exit/attach-termination-letter",
        json={"exitId": exit_id, "terminationLetterDocId": letter_doc_id},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    assert res.get_json()["ok"] is True

    res = client.post("/api/exit/complete", json={"exitId": exit_id}, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    assert body["data"]["exitCase"]["state"] == "EXITED"

