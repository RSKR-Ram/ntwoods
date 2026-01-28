from __future__ import annotations

import json

from db import SessionLocal
from models import Employee, User
from pii import hash_email, hash_name, mask_email, mask_name
from services.identity_hash import aadhaar_dob_hash, aadhaar_last4
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


def test_employee_duplicate_check(app_client):
    app, client = app_client
    cfg = app.config["CFG"]

    _seed_admin(app)

    res = _api(client, {"action": "LOGIN_EXCHANGE", "token": None, "data": {"idToken": "TEST:admin@example.com"}})
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    token = body["data"]["sessionToken"]

    aadhaar = "123456789012"
    dob = "1990-01-01"
    h = aadhaar_dob_hash(aadhaar=aadhaar, dob=dob, salt=cfg.SERVER_SALT)

    now = iso_utc_now()
    with SessionLocal() as db:
        db.add(
            Employee(
                employeeId="EMP-0001",
                employeeName="Employee",
                jobRole="CRM",
                joinedAt=now,
                createdAt=now,
                createdBy="TEST",
                aadhaar_last4=aadhaar_last4(aadhaar),
                aadhaar_dob_hash=h,
            )
        )
        db.commit()

    res = client.post(
        "/api/employees/check-duplicate",
        json={"aadhaar": aadhaar, "dob": dob},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    assert body["data"]["duplicate"] is True
    assert body["data"]["matches"][0]["employeeId"] == "EMP-0001"

