from __future__ import annotations

import io
import json

from db import SessionLocal
from models import Employee, User
from pii import hash_email, hash_name, mask_email, mask_name
from utils import iso_utc_now


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


def _api(client, payload: dict):
    return client.post("/api", data=json.dumps(payload), content_type="text/plain; charset=utf-8")


def _login(client, *, email: str) -> str:
    res = _api(client, {"action": "LOGIN_EXCHANGE", "token": None, "data": {"idToken": f"TEST:{email}"}})
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    return body["data"]["sessionToken"]


def _upload_doc(client, *, token: str, employee_id: str, doc_type: str, visibility: str) -> str:
    res = client.post(
        "/api/docs/upload",
        data={
            "employeeId": employee_id,
            "docType": doc_type,
            "visibility": visibility,
            "file": (io.BytesIO(b"hello"), "doc.txt"),
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    return body["data"]["docId"]


def test_employee_docs_visibility_and_permissions(app_client):
    app, client = app_client

    employee_id = "EMP-0001"

    _seed_user(app, user_id="USR-ADMIN", email="admin@example.com", role="ADMIN")
    _seed_user(app, user_id=employee_id, email="employee@example.com", role="EMPLOYEE")

    admin_token = _login(client, email="admin@example.com")
    employee_token = _login(client, email="employee@example.com")

    now = iso_utc_now()
    with SessionLocal() as db:
        db.add(Employee(employeeId=employee_id, employeeName="Employee", jobRole="CRM", joinedAt=now, createdAt=now, createdBy="TEST"))
        db.commit()

    # EMPLOYEE cannot upload docs (RBAC).
    res = client.post(
        "/api/docs/upload",
        data={"employeeId": employee_id, "docType": "ID", "file": (io.BytesIO(b"x"), "id.txt")},
        headers={"Authorization": f"Bearer {employee_token}"},
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is False
    assert body["error"]["code"] == "FORBIDDEN"

    # Upload INTERNAL doc as ADMIN; EMPLOYEE must not access it.
    internal_doc_id = _upload_doc(client, token=admin_token, employee_id=employee_id, doc_type="ID", visibility="INTERNAL")
    res = client.get(f"/api/docs/download/{internal_doc_id}", headers={"Authorization": f"Bearer {employee_token}"})
    assert res.status_code == 403
    body = res.get_json()
    assert body["ok"] is False
    assert body["error"]["code"] == "FORBIDDEN"

    # Upload EMPLOYEE-visible doc as ADMIN; EMPLOYEE can download it.
    employee_doc_id = _upload_doc(client, token=admin_token, employee_id=employee_id, doc_type="PAYSLIP", visibility="EMPLOYEE")
    res = client.get(f"/api/docs/download/{employee_doc_id}", headers={"Authorization": f"Bearer {employee_token}"})
    assert res.status_code == 200
    assert res.data

