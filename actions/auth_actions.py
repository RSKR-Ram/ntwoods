from __future__ import annotations

from sqlalchemy import func, select

from actions.helpers import append_audit
from auth import issue_session_token, revoke_user_sessions, verify_google_id_token
from models import Candidate, Employee, User
from utils import ApiError, AuthContext, iso_utc_now, normalize_role
from passwords import hash_password, verify_password
from pii import decrypt_pii, encrypt_pii, hash_email, looks_like_sha256_hex


def _find_user_by_email(db, cfg, email_or_hash: str):
    s = str(email_or_hash or "").strip()
    if not s:
        return None

    email_h = s.lower() if looks_like_sha256_hex(s) else hash_email(s, cfg.PEPPER)
    if email_h:
        found = db.execute(select(User).where(User.email_hash == email_h)).scalars().first()
        if found:
            return found
        found = db.execute(select(User).where(User.email == email_h)).scalars().first()
        if found:
            return found

    # Backward compatibility: pre-migration rows may still store plaintext emails.
    email_lc = str(s).lower().strip()
    if email_lc and "@" in email_lc:
        return db.execute(select(User).where(func.lower(User.email) == email_lc)).scalars().first()
    return None


def _update_user_last_login(db, cfg, email_or_hash: str):
    u = _find_user_by_email(db, cfg, email_or_hash)
    if not u:
        return
    u.lastLoginAt = iso_utc_now()


def _find_employee_by_employee_id(db, employee_id: str):
    emp_id = str(employee_id or "").strip()
    if not emp_id:
        return None
    return db.execute(select(Employee).where(Employee.employeeId == emp_id)).scalar_one_or_none()


def login_exchange(data, auth: AuthContext | None, db, cfg):
    id_token = (data or {}).get("idToken")
    google_user = verify_google_id_token(
        id_token,
        google_client_id=cfg.GOOGLE_CLIENT_ID,
        allow_test_tokens=bool(cfg.AUTH_ALLOW_TEST_TOKENS),
    )

    plain_email = str(google_user.get("email") or "").strip().lower()
    plain_name = str(google_user.get("fullName") or "").strip()

    user = _find_user_by_email(db, cfg, plain_email)
    if not user:
        raise ApiError("AUTH_INVALID", "User not found in Users")

    if str(user.status or "").upper() != "ACTIVE":
        raise ApiError("AUTH_INVALID", "User is disabled")

    # Best-effort: store encrypted-at-rest full values on login so UI can show normal values
    # without storing plaintext in DB.
    if str(getattr(cfg, "PII_ENC_KEY", "") or "").strip():
        if plain_email and "@" in plain_email:
            enc = encrypt_pii(plain_email, key=cfg.PII_ENC_KEY, aad=f"user:{user.userId}:email")
            if enc:
                user.email_enc = enc
        if plain_name and "*" not in plain_name:
            enc = encrypt_pii(plain_name, key=cfg.PII_ENC_KEY, aad=f"user:{user.userId}:name")
            if enc:
                user.name_enc = enc

    _update_user_last_login(db, cfg, user.email_hash or user.email)

    # If a Google SSO user has role=EMPLOYEE and maps to an Employee record, enforce Employee lifecycle rules too.
    session_status = str(user.status or "").upper().strip()
    session_auth_version = 0
    if normalize_role(user.role) == "EMPLOYEE":
        emp = _find_employee_by_employee_id(db, str(user.userId or ""))
        if emp:
            emp_status = str(getattr(emp, "status", "") or "").upper().strip()
            emp_active = bool(getattr(emp, "is_active", True))
            if emp_status != "ACTIVE" or not emp_active:
                raise ApiError("FORBIDDEN", "Employee account is not ACTIVE", http_status=403)
            session_status = emp_status
            session_auth_version = int(getattr(emp, "auth_version", 0) or 0)

    ses = issue_session_token(
        db,
        user_id=user.userId,
        email=(user.email_hash or user.email),
        role=user.role,
        user_status=session_status,
        auth_version=session_auth_version,
        session_ttl_minutes=cfg.SESSION_TTL_MINUTES,
    )

    append_audit(
        db,
        entityType="AUTH",
        entityId=str(user.userId),
        action="LOGIN_EXCHANGE",
        stageTag="AUTH_LOGIN",
        remark="",
        actor=AuthContext(valid=True, userId=user.userId, email=user.email, role=normalize_role(user.role) or "", expiresAt=ses["expiresAt"]),
        meta={"email_hash": user.email_hash or user.email},
    )

    return {
        "sessionToken": ses["sessionToken"],
        "expiresAt": ses["expiresAt"],
        "me": {
            "userId": user.userId,
            "email": plain_email or "",
            "fullName": plain_name or "",
            "role": normalize_role(user.role),
        },
    }


def employee_login(data, auth: AuthContext | None, db, cfg):
    employee_id = str((data or {}).get("employeeId") or "").strip()
    password = str((data or {}).get("password") or "")
    if not employee_id:
        raise ApiError("BAD_REQUEST", "Missing employeeId")
    if not password:
        raise ApiError("BAD_REQUEST", "Missing password", http_status=400)
    if len(password) > 256:
        raise ApiError("BAD_REQUEST", "Password is too long", http_status=400)

    emp = _find_employee_by_employee_id(db, employee_id)
    if not emp:
        raise ApiError("AUTH_INVALID", "Invalid employeeId")
    if not str(emp.candidateId or "").strip():
        raise ApiError("AUTH_INVALID", "Employee not linked to candidate")

    stored_hash = str(getattr(emp, "password_hash", "") or "").strip()
    if not stored_hash:
        raise ApiError("FORBIDDEN", "Employee password not set. Contact HR.", http_status=403)
    if not verify_password(password, stored_hash):
        raise ApiError("AUTH_INVALID", "Invalid credentials")

    emp_status = str(getattr(emp, "status", "") or "").upper().strip()
    emp_active = bool(getattr(emp, "is_active", True))
    if emp_status != "ACTIVE" or not emp_active:
        raise ApiError("FORBIDDEN", "Employee account is not ACTIVE", http_status=403)

    cand = db.execute(select(Candidate).where(Candidate.candidateId == str(emp.candidateId or ""))).scalar_one_or_none()
    if not cand:
        raise ApiError("AUTH_INVALID", "Employee candidate missing")

    cand_status = str(getattr(cand, "status", "") or "").upper().strip()
    if cand_status not in {"PROBATION", "EMPLOYEE"}:
        raise ApiError("AUTH_INVALID", "Employee access not allowed for current candidate status")

    full_name = ""
    if str(getattr(cfg, "PII_ENC_KEY", "") or "").strip():
        full_name = decrypt_pii(getattr(cand, "name_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{cand.candidateId}:name")

    user_id = emp.employeeId
    ses = issue_session_token(
        db,
        user_id=user_id,
        email="",
        role="EMPLOYEE",
        user_status=emp_status,
        auth_version=int(getattr(emp, "auth_version", 0) or 0),
        session_ttl_minutes=cfg.SESSION_TTL_MINUTES,
    )

    try:
        append_audit(
            db,
            entityType="AUTH",
            entityId=str(user_id),
            action="EMPLOYEE_LOGIN",
            stageTag="AUTH_LOGIN",
            remark="",
            actor=AuthContext(valid=True, userId=user_id, email="", role="EMPLOYEE", expiresAt=ses["expiresAt"]),
            meta={"employeeId": emp.employeeId, "candidateId": emp.candidateId},
        )
    except Exception:
        pass

    return {
        "sessionToken": ses["sessionToken"],
        "expiresAt": ses["expiresAt"],
        "me": {
            "userId": emp.employeeId,
            "email": "",
            "fullName": full_name or emp.employeeId,
            "role": "EMPLOYEE",
            "employeeId": emp.employeeId,
            "candidateId": emp.candidateId,
            "jobRole": emp.jobRole or "",
            "jobTitle": emp.jobTitle or "",
            "status": emp_status,
            "passwordResetRequired": bool(getattr(emp, "password_reset_required", False)),
        },
    }


def employee_change_password(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")
    if normalize_role(auth.role) != "EMPLOYEE":
        raise ApiError("FORBIDDEN", "Only EMPLOYEE can change employee password", http_status=403)

    current_password = str((data or {}).get("currentPassword") or "")
    new_password = str((data or {}).get("newPassword") or "")
    if not current_password:
        raise ApiError("BAD_REQUEST", "Missing currentPassword", http_status=400)
    if not new_password:
        raise ApiError("BAD_REQUEST", "Missing newPassword", http_status=400)
    if len(current_password) > 256 or len(new_password) > 256:
        raise ApiError("BAD_REQUEST", "Password is too long", http_status=400)

    emp_id = str(auth.userId or "").strip()
    emp = db.execute(select(Employee).where(Employee.employeeId == emp_id).with_for_update(of=Employee)).scalar_one_or_none()
    if not emp:
        raise ApiError("NOT_FOUND", "Employee not found", http_status=404)

    emp_status = str(getattr(emp, "status", "") or "").upper().strip()
    emp_active = bool(getattr(emp, "is_active", True))
    if emp_status != "ACTIVE" or not emp_active:
        raise ApiError("FORBIDDEN", "Employee account is not ACTIVE", http_status=403)

    stored_hash = str(getattr(emp, "password_hash", "") or "").strip()
    if not stored_hash or not verify_password(current_password, stored_hash):
        raise ApiError("AUTH_INVALID", "Invalid credentials", http_status=401)

    new_hash = hash_password(new_password)
    now = iso_utc_now()

    before = {"passwordResetRequired": bool(getattr(emp, "password_reset_required", False)), "passwordChangedAt": str(getattr(emp, "password_changed_at", "") or "")}
    emp.password_hash = new_hash
    emp.password_reset_required = False
    emp.password_changed_at = now
    emp.auth_version = int(getattr(emp, "auth_version", 0) or 0) + 1

    revoked = revoke_user_sessions(db, user_id=emp.employeeId, role="EMPLOYEE", revoked_by=str(auth.userId or ""))

    append_audit(
        db,
        entityType="EMPLOYEE_AUTH",
        entityId=str(emp.employeeId or ""),
        action="EMPLOYEE_CHANGE_PASSWORD",
        stageTag="EMPLOYEE_CHANGE_PASSWORD",
        actor=auth,
        at=now,
        before=before,
        after={"passwordResetRequired": False, "passwordChangedAt": now},
        meta={"revokedSessions": int(revoked or 0)},
    )

    return {"ok": True, "passwordChangedAt": now, "requiresReLogin": True}


def employee_admin_set_password(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    employee_id = str((data or {}).get("employeeId") or "").strip()
    new_password = str((data or {}).get("newPassword") or "")
    require_reset = bool((data or {}).get("requireReset") if (data or {}).get("requireReset") is not None else True)
    if not employee_id:
        raise ApiError("BAD_REQUEST", "Missing employeeId", http_status=400)
    if not new_password:
        raise ApiError("BAD_REQUEST", "Missing newPassword", http_status=400)
    if len(new_password) > 256:
        raise ApiError("BAD_REQUEST", "Password is too long", http_status=400)

    emp = db.execute(select(Employee).where(Employee.employeeId == employee_id).with_for_update(of=Employee)).scalar_one_or_none()
    if not emp:
        raise ApiError("NOT_FOUND", "Employee not found", http_status=404)

    now = iso_utc_now()
    before = {"passwordResetRequired": bool(getattr(emp, "password_reset_required", False)), "passwordChangedAt": str(getattr(emp, "password_changed_at", "") or "")}
    emp.password_hash = hash_password(new_password)
    emp.password_reset_required = bool(require_reset)
    emp.password_changed_at = now
    emp.auth_version = int(getattr(emp, "auth_version", 0) or 0) + 1

    revoked = revoke_user_sessions(db, user_id=emp.employeeId, role="EMPLOYEE", revoked_by=str(auth.userId or auth.email or ""))

    append_audit(
        db,
        entityType="EMPLOYEE_AUTH",
        entityId=str(emp.employeeId or ""),
        action="EMPLOYEE_ADMIN_SET_PASSWORD",
        stageTag="EMPLOYEE_ADMIN_SET_PASSWORD",
        actor=auth,
        at=now,
        before=before,
        after={"passwordResetRequired": bool(require_reset), "passwordChangedAt": now},
        meta={"revokedSessions": int(revoked or 0)},
    )

    return {"ok": True, "employeeId": str(emp.employeeId or ""), "passwordResetRequired": bool(require_reset)}


def employee_rejoin(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    employee_id = str((data or {}).get("employeeId") or "").strip()
    temp_password = str((data or {}).get("tempPassword") or "")
    if not employee_id:
        raise ApiError("BAD_REQUEST", "Missing employeeId", http_status=400)
    if not temp_password:
        raise ApiError("BAD_REQUEST", "Missing tempPassword", http_status=400)
    if len(temp_password) > 256:
        raise ApiError("BAD_REQUEST", "Password is too long", http_status=400)

    emp = db.execute(select(Employee).where(Employee.employeeId == employee_id).with_for_update(of=Employee)).scalar_one_or_none()
    if not emp:
        raise ApiError("NOT_FOUND", "Employee not found", http_status=404)

    now = iso_utc_now()
    before = {
        "status": str(getattr(emp, "status", "") or ""),
        "isActive": bool(getattr(emp, "is_active", True)),
        "rejoinDate": str(getattr(emp, "rejoin_date", "") or ""),
    }

    emp.status = "ACTIVE"
    emp.is_active = True
    emp.rejoin_date = now
    emp.password_hash = hash_password(temp_password)
    emp.password_reset_required = True
    emp.password_changed_at = now
    emp.auth_version = int(getattr(emp, "auth_version", 0) or 0) + 1

    revoked = revoke_user_sessions(db, user_id=emp.employeeId, role="EMPLOYEE", revoked_by=str(auth.userId or auth.email or ""))

    append_audit(
        db,
        entityType="EMPLOYEE",
        entityId=str(emp.employeeId or ""),
        action="EMPLOYEE_REJOIN",
        stageTag="EMPLOYEE_REJOIN",
        actor=auth,
        at=now,
        before=before,
        after={"status": "ACTIVE", "isActive": True, "rejoinDate": now},
        meta={"revokedSessions": int(revoked or 0)},
    )

    return {"ok": True, "employeeId": str(emp.employeeId or ""), "status": "ACTIVE", "rejoinDate": now, "passwordResetRequired": True}


def session_validate(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Invalid or expired session")
    return {
        "valid": True,
        "expiresAt": auth.expiresAt,
        # Don't echo internal identifiers (hashed email) back to the frontend; GET_ME returns masked profile fields.
        "me": {"userId": auth.userId, "email": "", "role": normalize_role(auth.role)},
    }


def get_me(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Invalid or expired session")

    if normalize_role(auth.role) == "EMPLOYEE":
        emp_id = str(auth.userId or "").strip()
        emp = _find_employee_by_employee_id(db, emp_id)
        if not emp:
            raise ApiError("AUTH_INVALID", "Employee missing")
        emp_status = str(getattr(emp, "status", "") or "").upper().strip()
        full_name = ""
        if str(getattr(cfg, "PII_ENC_KEY", "") or "").strip():
            cand = db.execute(select(Candidate).where(Candidate.candidateId == str(emp.candidateId or ""))).scalar_one_or_none()
            if cand:
                full_name = decrypt_pii(getattr(cand, "name_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{cand.candidateId}:name")
        return {
            "me": {
                "userId": emp.employeeId,
                "email": "",
                "fullName": full_name or emp.employeeId,
                "role": "EMPLOYEE",
                "employeeId": emp.employeeId,
                "candidateId": emp.candidateId or "",
                "jobRole": emp.jobRole or "",
                "jobTitle": emp.jobTitle or "",
                "status": emp_status,
                "passwordResetRequired": bool(getattr(emp, "password_reset_required", False)),
            }
        }

    user = _find_user_by_email(db, cfg, auth.email)
    if not user:
        raise ApiError("AUTH_INVALID", "User missing")
    if str(user.status or "").upper() != "ACTIVE":
        raise ApiError("AUTH_INVALID", "User is disabled")

    email_full = ""
    name_full = ""
    if str(getattr(cfg, "PII_ENC_KEY", "") or "").strip():
        email_full = decrypt_pii(getattr(user, "email_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"user:{user.userId}:email")
        name_full = decrypt_pii(getattr(user, "name_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"user:{user.userId}:name")

    return {
        "me": {
            "userId": user.userId,
            "email": email_full or (user.email_masked or ""),
            "fullName": name_full or (user.name_masked or user.userId),
            "role": normalize_role(user.role),
        }
    }
