from __future__ import annotations

import json

from db import SessionLocal
from models import User
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


def _api(client, payload: dict):
    return client.post("/api", data=json.dumps(payload), content_type="text/plain; charset=utf-8")


def test_login_exchange_and_get_me(app_client):
    app, client = app_client
    _seed_admin(app)

    res = _api(client, {"action": "LOGIN_EXCHANGE", "token": None, "data": {"idToken": "TEST:admin@example.com"}})
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    token = body["data"]["sessionToken"]
    assert token

    res = _api(client, {"action": "GET_ME", "token": token, "data": {}})
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    assert body["data"]["me"]["role"] == "ADMIN"
    assert body["data"]["me"]["email"] == "admin@example.com"


def test_unknown_action_returns_error(app_client):
    app, client = app_client
    _seed_admin(app)

    res = _api(client, {"action": "LOGIN_EXCHANGE", "token": None, "data": {"idToken": "TEST:admin@example.com"}})
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    token = body["data"]["sessionToken"]

    res = _api(client, {"action": "NOT_A_REAL_ACTION", "token": token, "data": {}})
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is False
    assert body["error"]["code"] == "BAD_REQUEST"
