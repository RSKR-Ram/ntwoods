from __future__ import annotations

import json
import re
from typing import Any

# Action handlers for TestMaster/CandidateTests (dynamic, config-driven).

from sqlalchemy import func, select

from actions.candidate_repo import find_candidate
from actions.helpers import append_audit
from cache_layer import cache_invalidate_prefix
from models import Candidate, CandidateTest, Permission, Requirement, Role, Setting, TestMaster, User
from pii import decrypt_pii
from sla import compute_sla
from utils import ApiError, AuthContext, iso_utc_now, normalize_role, parse_roles_csv, safe_json_string


TEST_STATUSES = {"NOT_SELECTED", "PENDING", "SUBMITTED", "REVIEW_PENDING", "APPROVED", "REJECTED"}
TEST_DEFAULT_FILL_OWNER_KEY = "TEST_DEFAULT_FILL_OWNER_BY_TESTKEY"


def _norm_test_key(test_key: str) -> str:
    return str(test_key or "").upper().strip()


def _parse_json_list(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(x or "").upper().strip() for x in raw if str(x or "").strip()]
    s = str(raw or "").strip()
    if not s:
        return []
    try:
        v = json.loads(s)
    except Exception:
        return []
    if not isinstance(v, list):
        return []
    return [str(x or "").upper().strip() for x in v if str(x or "").strip()]


def _read_test_master(db, *, active_only: bool) -> dict[str, dict[str, Any]]:
    rows = db.execute(select(TestMaster)).scalars().all()
    mp: dict[str, dict[str, Any]] = {}
    for r in rows:
        k = _norm_test_key(r.testKey)
        if not k:
            continue
        if active_only and not bool(r.active):
            continue
        mp[k] = {
            "testKey": k,
            "label": r.label or k,
            "fillRoles": _parse_json_list(r.fillRolesJson),
            "reviewRoles": _parse_json_list(r.reviewRolesJson),
            "active": bool(r.active),
            "ordering": int(r.ordering or 0),
        }
    return mp


def _read_test_default_fill_owners(db) -> dict[str, str]:
    row = db.execute(select(Setting).where(Setting.key == TEST_DEFAULT_FILL_OWNER_KEY)).scalar_one_or_none()
    raw = str(getattr(row, "value", "") or "").strip() if row else ""
    if not raw:
        return {}
    try:
        obj = json.loads(raw) if raw.strip().startswith(("{", "[")) else {}
    except Exception:
        return {}
    if not isinstance(obj, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in obj.items():
        kk = _norm_test_key(str(k or ""))
        uid = str(v or "").strip()
        if kk and uid:
            out[kk] = uid
    return out


def _default_fill_owner_for_test(
    *,
    test_key: str,
    conf: dict[str, Any] | None,
    defaults: dict[str, str],
    users_by_id: dict[str, User],
) -> str:
    k = _norm_test_key(test_key)
    if not k:
        return ""
    uid = str(defaults.get(k) or "").strip()
    if not uid:
        return ""
    u = users_by_id.get(uid)
    if not u:
        return ""
    if str(getattr(u, "status", "") or "").upper() != "ACTIVE":
        return ""
    fill_roles = {normalize_role(x) for x in (conf or {}).get("fillRoles") or []}
    if fill_roles and normalize_role(getattr(u, "role", "") or "") not in fill_roles:
        return ""
    return str(getattr(u, "userId", "") or "")


def test_master_get(data, auth: AuthContext | None, db, cfg):
    active_only = True
    if isinstance(data, dict) and "activeOnly" in data:
        active_only = bool(data.get("activeOnly"))
    mp = _read_test_master(db, active_only=active_only)
    items = list(mp.values())
    items.sort(key=lambda x: (int(x.get("ordering") or 0), str(x.get("label") or "")))
    return {"items": items}


def _normalize_roles_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        parts = [normalize_role(p) for p in value.split(",")]
        return [p for p in parts if p]
    if isinstance(value, list):
        parts = [normalize_role(p) for p in value]
        return [p for p in parts if p]
    return []


def test_master_upsert(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")
    if normalize_role(auth.role) != "ADMIN":
        raise ApiError("FORBIDDEN", "Admin only", http_status=403)

    items = None
    if isinstance(data, dict):
        items = data.get("items")
    if not isinstance(items, list) or not items:
        raise ApiError("BAD_REQUEST", "Missing items")

    now = iso_utc_now()
    actor_id = str(auth.userId or auth.email or "")

    existing = {str(r.testKey or "").upper().strip(): r for r in db.execute(select(TestMaster)).scalars().all()}
    updated = 0

    for it in items:
        it = it or {}
        test_key = _norm_test_key(str(it.get("testKey") or ""))
        if not test_key:
            continue

        label = str(it.get("label") or test_key).strip() or test_key
        active = bool(it.get("active", True))
        try:
            ordering = int(it.get("ordering") or 0)
        except Exception:
            ordering = 0

        fill_roles = _normalize_roles_list(it.get("fillRoles"))
        review_roles = _normalize_roles_list(it.get("reviewRoles"))
        fill_roles = sorted(set(fill_roles))
        review_roles = sorted(set(review_roles))

        row = existing.get(test_key)
        if not row:
            row = TestMaster(
                testKey=test_key,
                label=label,
                fillRolesJson=json.dumps(fill_roles),
                reviewRolesJson=json.dumps(review_roles),
                active=active,
                ordering=ordering,
                createdAt=now,
                createdBy=actor_id,
                updatedAt=now,
                updatedBy=actor_id,
            )
            db.add(row)
            existing[test_key] = row
        else:
            row.label = label
            row.fillRolesJson = json.dumps(fill_roles)
            row.reviewRolesJson = json.dumps(review_roles)
            row.active = active
            row.ordering = ordering
            row.updatedAt = now
            row.updatedBy = actor_id

        updated += 1

    append_audit(
        db,
        entityType="TEST_MASTER",
        entityId="GLOBAL",
        action="TEST_MASTER_UPSERT",
        stageTag="ADMIN_TEST_MASTER_UPSERT",
        actor=auth,
        meta={"updated": updated},
        at=now,
    )

    return test_master_get({"activeOnly": False}, auth, db, cfg) | {"updated": updated}


def _serialize_candidate_test(db, ct: CandidateTest, tm: dict[str, Any] | None) -> dict[str, Any]:
    try:
        marks = json.loads(ct.marksJson) if str(ct.marksJson or "").strip().startswith(("{", "[")) else ct.marksJson
    except Exception:
        marks = ct.marksJson or ""
    out = {
        "id": ct.id,
        "candidateId": ct.candidateId or "",
        "requirementId": ct.requirementId or "",
        "testKey": ct.testKey or "",
        "label": (tm or {}).get("label") if isinstance(tm, dict) else "",
        "isRequired": bool(ct.isRequired),
        "status": ct.status or "",
        "marks": marks,
        "marksNumber": ct.marksNumber,
        "fillOwnerUserId": getattr(ct, "fillOwnerUserId", "") or "",
        "filledBy": ct.filledBy or "",
        "filledAt": ct.filledAt or "",
        "reviewedBy": ct.reviewedBy or "",
        "reviewedAt": ct.reviewedAt or "",
        "remarks": ct.remarks or "",
        "updatedAt": ct.updatedAt or "",
    }
    if isinstance(tm, dict):
        out["fillRoles"] = tm.get("fillRoles") or []
        out["reviewRoles"] = tm.get("reviewRoles") or []
    return out


def candidate_tests_get(data, auth: AuthContext | None, db, cfg):
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    req_id = str(cand.requirementId or "")

    tm = _read_test_master(db, active_only=False)
    rows = (
        db.execute(select(CandidateTest).where(CandidateTest.candidateId == candidate_id).order_by(CandidateTest.id.asc()))
        .scalars()
        .all()
    )
    items = [_serialize_candidate_test(db, r, tm.get(_norm_test_key(r.testKey))) for r in rows]
    required = [x for x in items if bool(x.get("isRequired"))]
    required.sort(key=lambda x: (int((tm.get(_norm_test_key(x.get("testKey") or "")) or {}).get("ordering") or 0), str(x.get("label") or "")))
    return {"candidateId": candidate_id, "requirementId": req_id, "items": items, "requiredTests": required}


def _backfill_candidate_test_from_legacy(cand: Candidate, test_key: str) -> dict[str, Any]:
    k = _norm_test_key(test_key)
    if k == "TALLY":
        return {"marksNumber": cand.tallyMarks, "remarks": cand.techReview or ""}
    if k == "VOICE":
        return {"marksNumber": cand.voiceMarks, "remarks": cand.techReview or ""}
    if k == "EXCEL":
        return {"marksNumber": cand.excelMarks, "remarks": cand.excelReview or ""}
    return {}


def candidate_required_tests_set(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    test_keys = (data or {}).get("testKeys") or []

    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not isinstance(test_keys, list):
        raise ApiError("BAD_REQUEST", "testKeys must be a list")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    req_id = str(cand.requirementId or "")

    tm = _read_test_master(db, active_only=True)
    defaults = _read_test_default_fill_owners(db)
    users_by_id = {u.userId: u for u in db.execute(select(User)).scalars().all()} if defaults else {}
    normalized: list[str] = []
    for x in test_keys:
        k = _norm_test_key(str(x or ""))
        if not k:
            continue
        if k not in tm:
            raise ApiError("BAD_REQUEST", f"Unknown or inactive testKey: {k}")
        if k not in normalized:
            normalized.append(k)

    now = iso_utc_now()
    actor_id = str(auth.userId or auth.email or "")

    existing_rows = (
        db.execute(select(CandidateTest).where(CandidateTest.candidateId == candidate_id)).scalars().all()
    )
    by_key = {str(r.testKey or "").upper().strip(): r for r in existing_rows}
    prev_required = sorted([k for k, r in by_key.items() if bool(getattr(r, "isRequired", False))])

    # Mark selected as required.
    for k in normalized:
        row = by_key.get(k)
        if not row:
            legacy = _backfill_candidate_test_from_legacy(cand, k)
            marks_num = legacy.get("marksNumber")
            remarks = str(legacy.get("remarks") or "")
            has_marks = marks_num is not None and str(marks_num).strip() != ""

            row = CandidateTest(
                candidateId=candidate_id,
                requirementId=req_id,
                testKey=k,
                isRequired=True,
                status="APPROVED" if has_marks else "PENDING",
                marksJson=safe_json_string(marks_num, "") if has_marks else "",
                marksNumber=int(marks_num) if has_marks else None,
                fillOwnerUserId=_default_fill_owner_for_test(test_key=k, conf=tm.get(k), defaults=defaults, users_by_id=users_by_id),
                filledBy="MIGRATION" if has_marks else "",
                filledAt=str(getattr(cand, "techEvaluatedAt", "") or getattr(cand, "updatedAt", "") or now) if has_marks else "",
                reviewedBy="MIGRATION" if has_marks else "",
                reviewedAt=str(getattr(cand, "techEvaluatedAt", "") or getattr(cand, "updatedAt", "") or now) if has_marks else "",
                remarks=remarks if has_marks else "",
                createdAt=now,
                updatedAt=now,
            )
            db.add(row)
            by_key[k] = row
        else:
            row.isRequired = True
            if str(row.status or "").upper().strip() in {"", "NOT_SELECTED"}:
                row.status = "PENDING"
            if not str(getattr(row, "fillOwnerUserId", "") or "").strip():
                row.fillOwnerUserId = _default_fill_owner_for_test(test_key=k, conf=tm.get(k), defaults=defaults, users_by_id=users_by_id)
            row.updatedAt = now

    # Mark unselected as not required.
    for k, row in by_key.items():
        if k in normalized:
            continue
        if not bool(getattr(row, "isRequired", False)):
            continue
        row.isRequired = False
        # If never filled, keep status aligned with selection state.
        if not str(row.filledAt or "").strip() and str(row.status or "").upper().strip() in {"PENDING", "SUBMITTED", "REVIEW_PENDING"}:
            row.status = "NOT_SELECTED"
        row.updatedAt = now

    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="CANDIDATE_REQUIRED_TESTS_SET",
        fromState=str(cand.status or ""),
        toState=str(cand.status or ""),
        stageTag="Required Tests",
        remark=",".join(normalized),
        actor=auth,
        at=now,
        meta={"requirementId": req_id, "from": prev_required, "to": normalized},
    )

    return candidate_tests_get({"candidateId": candidate_id, "requirementId": req_id}, auth, db, cfg)


def _assert_role_in_list(role: str, allowed: list[str], *, err_msg: str):
    r = normalize_role(role)
    allowed_u = {normalize_role(x) for x in allowed}
    allowed_u = {x for x in allowed_u if x}
    if not r or r not in allowed_u:
        raise ApiError("FORBIDDEN", err_msg)


def candidate_test_submit(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    test_key = _norm_test_key(str((data or {}).get("testKey") or ""))
    marks = (data or {}).get("marks")
    remarks = str((data or {}).get("remarks") or "").strip()

    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not test_key:
        raise ApiError("BAD_REQUEST", "Missing testKey")
    if marks is None or marks == "":
        raise ApiError("BAD_REQUEST", "Missing marks")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    req_id = str(cand.requirementId or "")

    tm = _read_test_master(db, active_only=True)
    conf = tm.get(test_key)

    _assert_role_in_list(auth.role, conf.get("fillRoles") or [], err_msg="Not allowed to fill this test")

    row = (
        db.execute(select(CandidateTest).where(CandidateTest.candidateId == candidate_id).where(CandidateTest.testKey == test_key))
        .scalars()
        .first()
    )
    if not row or not bool(row.isRequired):
        raise ApiError("BAD_REQUEST", "Test not selected by HR")

    assigned = str(getattr(row, "fillOwnerUserId", "") or "").strip()
    if not assigned or assigned != str(auth.userId or "").strip():
        raise ApiError("FORBIDDEN", "Test not assigned to you", http_status=403)

    now = iso_utc_now()
    actor_id = str(auth.userId or auth.email or "")

    # Normalize marks storage.
    marks_json = ""
    marks_num = None
    if isinstance(marks, (dict, list)):
        marks_json = json.dumps(marks)
    else:
        # numeric/string
        try:
            marks_num = int(float(marks))
        except Exception:
            marks_num = None
        marks_json = safe_json_string(marks, str(marks or ""))

    row.marksJson = marks_json
    row.marksNumber = marks_num
    row.filledBy = actor_id
    row.filledAt = now
    row.reviewedBy = ""
    row.reviewedAt = ""
    row.remarks = remarks

    review_roles = conf.get("reviewRoles") or []
    if review_roles:
        row.status = "REVIEW_PENDING"
    else:
        row.status = "SUBMITTED"
    row.updatedAt = now

    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="CANDIDATE_TEST_SUBMIT",
        fromState=str(cand.status or ""),
        toState=str(cand.status or ""),
        stageTag=f"{test_key} Submit",
        remark=remarks,
        actor=auth,
        at=now,
        meta={"requirementId": req_id, "testKey": test_key},
    )

    return _serialize_candidate_test(db, row, conf)


def candidate_test_review(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    test_key = _norm_test_key(str((data or {}).get("testKey") or ""))
    decision = str((data or {}).get("decision") or "").upper().strip()
    remarks = str((data or {}).get("remarks") or "").strip()

    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not test_key:
        raise ApiError("BAD_REQUEST", "Missing testKey")
    if decision not in {"APPROVE", "REJECT"}:
        raise ApiError("BAD_REQUEST", "Invalid decision")
    if decision == "REJECT" and not remarks:
        raise ApiError("BAD_REQUEST", "Remarks required")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    req_id = str(cand.requirementId or "")

    tm = _read_test_master(db, active_only=True)
    conf = tm.get(test_key)
    if not conf:
        raise ApiError("BAD_REQUEST", f"Unknown or inactive testKey: {test_key}")

    _assert_role_in_list(auth.role, conf.get("reviewRoles") or [], err_msg="Not allowed to review this test")

    row = (
        db.execute(select(CandidateTest).where(CandidateTest.candidateId == candidate_id).where(CandidateTest.testKey == test_key))
        .scalars()
        .first()
    )
    if not row:
        raise ApiError("NOT_FOUND", "Candidate test not found")

    now = iso_utc_now()
    actor_id = str(auth.userId or auth.email or "")

    row.reviewedBy = actor_id
    row.reviewedAt = now
    row.remarks = remarks or (row.remarks or "")
    row.status = "APPROVED" if decision == "APPROVE" else "REJECTED"
    row.updatedAt = now

    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="CANDIDATE_TEST_REVIEW",
        fromState=str(cand.status or ""),
        toState=str(cand.status or ""),
        stageTag=f"{test_key} {row.status}",
        remark=remarks,
        actor=auth,
        at=now,
        meta={"requirementId": req_id, "testKey": test_key, "decision": decision},
    )

    return _serialize_candidate_test(db, row, conf)


def candidate_test_assign(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")
    if normalize_role(auth.role) != "ADMIN":
        raise ApiError("FORBIDDEN", "Admin only", http_status=403)

    candidate_id = str((data or {}).get("candidateId") or "").strip()
    test_key = _norm_test_key(str((data or {}).get("testKey") or ""))
    owner_user_id = str(
        (data or {}).get("fillOwnerUserId")
        or (data or {}).get("ownerUserId")
        or (data or {}).get("assigneeUserId")
        or ""
    ).strip()
    custom_assign = bool((data or {}).get("customAssign") is True)
    custom_role_name = str((data or {}).get("roleName") or (data or {}).get("customRoleName") or "").strip()
    custom_role_code = normalize_role((data or {}).get("roleCode") or (data or {}).get("customRoleCode") or "") or ""
    custom_user_email = str((data or {}).get("userEmail") or (data or {}).get("customUserEmail") or "").strip()
    custom_user_full_name = str((data or {}).get("userFullName") or (data or {}).get("fullName") or "").strip()

    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not test_key:
        raise ApiError("BAD_REQUEST", "Missing testKey")

    tm = _read_test_master(db, active_only=True)
    conf = tm.get(test_key)
    if not conf:
        raise ApiError("BAD_REQUEST", f"Unknown or inactive testKey: {test_key}")

    row = (
        db.execute(select(CandidateTest).where(CandidateTest.candidateId == candidate_id).where(CandidateTest.testKey == test_key))
        .scalars()
        .first()
    )
    if not row:
        raise ApiError("NOT_FOUND", "Candidate test not found")

    def _role_code_from_name(name: str) -> str:
        raw = str(name or "").strip()
        if not raw:
            return ""
        # Convert "Role Name" to a safe roleCode (A-Z0-9_).
        code = raw.upper().strip()
        code = re.sub(r"[^A-Z0-9_]+", "_", code)
        code = re.sub(r"_+", "_", code).strip("_")
        return code

    def _ensure_role_in_permission(*, perm_type: str, perm_key: str, role_code: str, now: str, by: str) -> bool:
        pt = str(perm_type or "").upper().strip()
        pk = str(perm_key or "").upper().strip()
        rc = normalize_role(role_code) or ""
        if not pt or not pk or not rc:
            return False

        p = (
            db.execute(select(Permission).where(Permission.permType == pt).where(Permission.permKey == pk))
            .scalars()
            .first()
        )
        if not p:
            # Be careful: creating an ACTION permission row makes dynamic RBAC authoritative (overrides static mapping).
            # If the row is missing, seed it with the static roles + the new role to avoid locking out existing users.
            roles_csv = rc
            if pt == "ACTION":
                try:
                    from auth import STATIC_RBAC_PERMISSIONS

                    base_roles = STATIC_RBAC_PERMISSIONS.get(pk) or []
                    roles_csv = ",".join(sorted({normalize_role(x) for x in ([rc, *base_roles]) if normalize_role(x)}))
                except Exception:
                    roles_csv = rc
            elif pt == "UI" and pk == "PORTAL_TESTS":
                roles_csv = ",".join(sorted({normalize_role(x) for x in ["ADMIN", "HR", "EA", "ACCOUNTS", "MIS", "DEO", rc] if normalize_role(x)}))
            db.add(
                Permission(
                    permType=pt,
                    permKey=pk,
                    rolesCsv=roles_csv,
                    enabled=True,
                    updatedAt=now,
                    updatedBy=by,
                )
            )
            return True

        roles = parse_roles_csv(p.rolesCsv or "")
        if rc not in roles:
            roles.append(rc)
        roles_csv = ",".join(sorted({normalize_role(x) for x in roles if normalize_role(x)}))

        changed = False
        if str(p.rolesCsv or "").strip() != roles_csv:
            p.rolesCsv = roles_csv
            changed = True
        if not bool(p.enabled):
            p.enabled = True
            changed = True
        if changed:
            p.updatedAt = now
            p.updatedBy = by
        return changed

    if owner_user_id:
        u = db.execute(select(User).where(User.userId == owner_user_id)).scalar_one_or_none()
        if not u:
            raise ApiError("BAD_REQUEST", "Assignee not found")
        if str(getattr(u, "status", "") or "").upper() != "ACTIVE":
            raise ApiError("BAD_REQUEST", "Assignee is disabled")
        if conf:
            _assert_role_in_list(
                getattr(u, "role", "") or "",
                conf.get("fillRoles") or [],
                err_msg="Assignee role is not allowed to fill this test",
            )
    elif custom_assign or (custom_user_email and (custom_role_code or custom_role_name)):
        if not conf:
            raise ApiError("BAD_REQUEST", f"Unknown or inactive testKey: {test_key}")
        if not custom_user_email:
            raise ApiError("BAD_REQUEST", "Missing userEmail")
        if not custom_role_code:
            custom_role_code = _role_code_from_name(custom_role_name)
        if not custom_role_code:
            raise ApiError("BAD_REQUEST", "Missing roleName")
        if not re.match(r"^[A-Z0-9_]{2,30}$", custom_role_code):
            raise ApiError("BAD_REQUEST", "Invalid roleName/roleCode")

        # Ensure role exists (auto-create if missing).
        now = iso_utc_now()
        by = str(auth.userId or auth.email or "")
        role_row = db.execute(select(Role).where(Role.roleCode == custom_role_code)).scalar_one_or_none()
        created_role = False
        if not role_row:
            db.add(
                Role(
                    roleCode=custom_role_code,
                    roleName=custom_role_name or custom_role_code,
                    status="ACTIVE",
                    createdAt=now,
                    createdBy=by,
                    updatedAt=now,
                    updatedBy=by,
                )
            )
            created_role = True
            # SessionLocal has autoflush=False; ensure the new role is visible to downstream queries.
            db.flush()
        elif str(getattr(role_row, "status", "") or "").upper() != "ACTIVE":
            raise ApiError("BAD_REQUEST", "Role is inactive")

        # Role must be allowed for this test's fillRoles (keeps role-based logic intact).
        _assert_role_in_list(custom_role_code, conf.get("fillRoles") or [], err_msg="Role is not allowed to fill this test")

        # Ensure user exists (auto-create if missing).
        email = str(custom_user_email or "").strip().lower()
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            raise ApiError("BAD_REQUEST", "Invalid userEmail")

        from pii import hash_email

        email_h = hash_email(email, cfg.PEPPER)
        u = db.execute(select(User).where(User.email_hash == email_h)).scalar_one_or_none()
        if not u:
            # Backward compatibility: legacy rows may still store plaintext emails.
            u = db.execute(select(User).where(func.lower(User.email) == email)).scalar_one_or_none()

        created_user = False
        if u:
            if str(getattr(u, "status", "") or "").upper() != "ACTIVE":
                raise ApiError("BAD_REQUEST", "Assignee is disabled")
            if normalize_role(getattr(u, "role", "") or "") != custom_role_code:
                raise ApiError("CONFLICT", f"User already exists with role {normalize_role(getattr(u, 'role', '') or '')}")
        else:
            from actions.admin import users_upsert

            created = users_upsert({"email": email, "fullName": custom_user_full_name, "role": custom_role_code, "active": True}, auth, db, cfg)
            created_user = True
            # SessionLocal has autoflush=False; ensure the new user is visible to downstream queries.
            db.flush()
            owner_user_id = str((created or {}).get("userId") or "").strip()
            if owner_user_id:
                u = db.execute(select(User).where(User.userId == owner_user_id)).scalar_one_or_none()
            else:
                u = None
        if not u:
            raise ApiError("INTERNAL_ERROR", "Failed to create assignee")

        owner_user_id = str(getattr(u, "userId", "") or "").strip()
        if not owner_user_id:
            raise ApiError("INTERNAL_ERROR", "Invalid assignee userId")

        # Ensure the role can open the Tests portal and submit assigned marks.
        changed_perm = False
        changed_perm |= _ensure_role_in_permission(perm_type="UI", perm_key="PORTAL_TESTS", role_code=custom_role_code, now=now, by=by)
        changed_perm |= _ensure_role_in_permission(perm_type="ACTION", perm_key="TESTS_QUEUE_LIST", role_code=custom_role_code, now=now, by=by)
        changed_perm |= _ensure_role_in_permission(perm_type="ACTION", perm_key="CANDIDATE_TEST_SUBMIT", role_code=custom_role_code, now=now, by=by)
        if created_role or created_user or changed_perm:
            cache_invalidate_prefix("RBAC:")

    now = iso_utc_now()
    prev = str(getattr(row, "fillOwnerUserId", "") or "")
    row.fillOwnerUserId = owner_user_id
    row.updatedAt = now

    append_audit(
        db,
        entityType="CANDIDATE_TEST",
        entityId=f"{candidate_id}:{test_key}",
        action="CANDIDATE_TEST_ASSIGN",
        fromState=prev,
        toState=owner_user_id,
        stageTag="Test Assignment",
        remark="",
        actor=auth,
        at=now,
        meta={"candidateId": candidate_id, "testKey": test_key, "fillOwnerUserId": owner_user_id},
    )

    return {"candidateId": candidate_id, "testKey": test_key, "fillOwnerUserId": owner_user_id}


def tests_queue_list(data, auth: AuthContext | None, db, cfg):
    mode = str((data or {}).get("mode") or "FILL").upper().strip()
    if mode not in {"FILL", "REVIEW"}:
        raise ApiError("BAD_REQUEST", "Invalid mode")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    role_u = normalize_role(auth.role)
    tm = _read_test_master(db, active_only=True)
    can_pii = bool(getattr(cfg, "PII_ENC_KEY", "").strip()) and str(getattr(auth, "role", "") or "").upper() in set(getattr(cfg, "PII_VIEW_ROLES", []) or [])
    defaults = _read_test_default_fill_owners(db) if mode == "FILL" and role_u == "ADMIN" else {}
    users_by_id = {u.userId: u for u in db.execute(select(User)).scalars().all()} if defaults else {}

    q = select(CandidateTest).where(CandidateTest.isRequired == True)  # noqa: E712
    if mode == "FILL" and role_u != "ADMIN":
        q = q.where(CandidateTest.fillOwnerUserId == str(auth.userId or ""))
    rows = db.execute(q).scalars().all()
    items: list[dict[str, Any]] = []

    cand_map: dict[str, Candidate] = {c.candidateId: c for c in db.execute(select(Candidate)).scalars().all()}
    req_map: dict[str, Requirement] = {r.requirementId: r for r in db.execute(select(Requirement)).scalars().all()}

    for r in rows:
        test_key = _norm_test_key(r.testKey)
        conf = tm.get(test_key)
        if not conf:
            continue
        fill_roles = {normalize_role(x) for x in conf.get("fillRoles") or []}
        review_roles = {normalize_role(x) for x in conf.get("reviewRoles") or []}

        st = str(r.status or "").upper().strip()
        if mode == "FILL":
            if role_u != "ADMIN" and role_u not in fill_roles:
                continue
            if st not in {"PENDING", "REJECTED"}:
                continue
        else:
            if role_u != "ADMIN" and role_u not in review_roles:
                continue
            if st != "REVIEW_PENDING":
                continue

        cand = cand_map.get(r.candidateId)
        if not cand or str(cand.status or "").upper() == "REJECTED":
            continue
        req = req_map.get(str(cand.requirementId or ""))

        # Admin convenience: auto-fill default assignee for unassigned required tests.
        if mode == "FILL" and role_u == "ADMIN" and defaults and not str(getattr(r, "fillOwnerUserId", "") or "").strip():
            owner_user_id = _default_fill_owner_for_test(test_key=test_key, conf=conf, defaults=defaults, users_by_id=users_by_id)
            if owner_user_id:
                now = iso_utc_now()
                prev = str(getattr(r, "fillOwnerUserId", "") or "")
                r.fillOwnerUserId = owner_user_id
                r.updatedAt = now
                append_audit(
                    db,
                    entityType="CANDIDATE_TEST",
                    entityId=f"{cand.candidateId}:{test_key}",
                    action="CANDIDATE_TEST_ASSIGN",
                    fromState=prev,
                    toState=owner_user_id,
                    stageTag="Test Assignment (Auto)",
                    remark="",
                    actor=auth,
                    at=now,
                    meta={"candidateId": cand.candidateId, "testKey": test_key, "fillOwnerUserId": owner_user_id, "auto": True},
                )

        item = {
                "candidateId": cand.candidateId,
                "requirementId": cand.requirementId,
                "candidateName": cand.candidateName or "",
                "mobile": cand.mobile or "",
                "jobRole": cand.jobRole or "",
                "jobTitle": (req.jobTitle if req else "") or "",
                "cvFileId": cand.cvFileId or "",
                "cvFileName": cand.cvFileName or "",
                "sla": compute_sla(
                    db,
                    step_name="TECHNICAL",
                    start_ts=str(getattr(cand, "techSelectedAt", "") or getattr(r, "createdAt", "") or getattr(r, "updatedAt", "") or ""),
                    app_timezone=cfg.APP_TIMEZONE,
                ),
                "test": _serialize_candidate_test(db, r, conf),
            }

        if can_pii:
            name_full = decrypt_pii(getattr(cand, "name_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{cand.candidateId}:name")
            mobile_full = decrypt_pii(getattr(cand, "mobile_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{cand.candidateId}:mobile")
            if name_full:
                item["candidateNameFull"] = name_full
            if mobile_full:
                item["mobileFull"] = mobile_full

        items.append(item)

    items.sort(key=lambda x: (str(x.get("test", {}).get("testKey") or ""), str(x.get("candidateName") or "")))
    return {"items": items, "total": len(items), "mode": mode}


def required_tests_approved(db, *, candidate_id: str) -> bool:
    rows = (
        db.execute(select(CandidateTest).where(CandidateTest.candidateId == candidate_id).where(CandidateTest.isRequired == True))  # noqa: E712
        .scalars()
        .all()
    )
    if not rows:
        return True
    for r in rows:
        if str(r.status or "").upper().strip() != "APPROVED":
            return False
    return True
