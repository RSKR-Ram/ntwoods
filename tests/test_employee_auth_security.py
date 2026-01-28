from __future__ import annotations

import json

from sqlalchemy import select

from db import SessionLocal
from models import Candidate, Employee
from passwords import hash_password
from utils import iso_utc_now


def _api(client, payload: dict):
    return client.post("/api", data=json.dumps(payload), content_type="text/plain; charset=utf-8")


def _seed_employee(
    *, employee_id: str, candidate_id: str, requirement_id: str, password: str, password_reset_required: bool = False
) -> None:
    now = iso_utc_now()
    with SessionLocal() as db:
        db.add(
            Candidate(
                candidateId=candidate_id,
                requirementId=requirement_id,
                candidateName="Alice",
                mobile="9999999999",
                jobRole="CRM",
                status="EMPLOYEE",
                joinedAt=now,
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.add(
            Employee(
                employeeId=employee_id,
                employee_id=employee_id,
                candidateId=candidate_id,
                requirementId=requirement_id,
                employeeName="Alice",
                mobile="9999999999",
                jobRole="CRM",
                jobTitle="CRM Exec",
                joinedAt=now,
                status="ACTIVE",
                is_active=True,
                password_hash=hash_password(password),
                password_reset_required=bool(password_reset_required),
                password_changed_at=now,
                createdAt=now,
                createdBy="TEST",
                timelineJson="[]",
            )
        )
        db.commit()


def test_exited_employee_cannot_login_or_use_old_token(app_client):
    _app, client = app_client

    emp_id = "EMP-SEC-1"
    emp_password = "StrongPassw0rd!"
    _seed_employee(employee_id=emp_id, candidate_id="C-SEC-1", requirement_id="REQ-SEC-1", password=emp_password)

    res = _api(client, {"action": "EMPLOYEE_LOGIN", "token": None, "data": {"employeeId": emp_id, "password": emp_password}})
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    token = body["data"]["sessionToken"]

    res = _api(client, {"action": "GET_ME", "token": token, "data": {}})
    assert res.status_code == 200
    assert res.get_json()["ok"] is True

    # Simulate HR marking EXITED directly in the DB (token must stop working).
    now = iso_utc_now()
    with SessionLocal() as db:
        emp = db.execute(select(Employee).where(Employee.employeeId == emp_id)).scalar_one()
        emp.status = "EXITED"
        emp.is_active = False
        emp.exitAt = now
        emp.exit_date = now
        db.commit()

    res = _api(client, {"action": "GET_ME", "token": token, "data": {}})
    assert res.status_code == 403
    body = res.get_json()
    assert body["ok"] is False
    assert body["error"]["code"] == "FORBIDDEN"


def test_password_reset_required_blocks_actions_until_change(app_client):
    _app, client = app_client

    emp_id = "EMP-SEC-2"
    temp_password = "TempPassw0rd!"
    new_password = "N3wStrongPass!!"
    _seed_employee(
        employee_id=emp_id,
        candidate_id="C-SEC-2",
        requirement_id="REQ-SEC-2",
        password=temp_password,
        password_reset_required=True,
    )

    res = _api(client, {"action": "EMPLOYEE_LOGIN", "token": None, "data": {"employeeId": emp_id, "password": temp_password}})
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    token = body["data"]["sessionToken"]
    assert body["data"]["me"]["passwordResetRequired"] is True

    # Any protected action other than GET_ME / SESSION_VALIDATE / EMPLOYEE_CHANGE_PASSWORD must be blocked.
    res = _api(client, {"action": "MY_PERMISSIONS_GET", "token": token, "data": {}})
    assert res.status_code == 403
    body = res.get_json()
    assert body["ok"] is False
    assert body["error"]["code"] == "FORBIDDEN"

    res = _api(
        client,
        {
            "action": "EMPLOYEE_CHANGE_PASSWORD",
            "token": token,
            "data": {"currentPassword": temp_password, "newPassword": new_password},
        },
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True

    # Login again with the new password.
    res = _api(client, {"action": "EMPLOYEE_LOGIN", "token": None, "data": {"employeeId": emp_id, "password": new_password}})
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    assert body["data"]["me"]["passwordResetRequired"] is False
