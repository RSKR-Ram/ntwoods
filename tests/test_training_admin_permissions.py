from __future__ import annotations

import json

from db import SessionLocal
from models import User
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


def test_training_admin_endpoints_denied_for_employee(app_client):
    app, client = app_client

    _seed_user(app, user_id="USR-EMP", email="employee@example.com", role="EMPLOYEE")
    token = _login(client, email="employee@example.com")

    res = client.post(
        "/api/training/admin/save-questions",
        json={"moduleId": "MOD-1", "settings": {}, "questions": []},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is False
    assert body["error"]["code"] == "FORBIDDEN"

