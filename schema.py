from __future__ import annotations

import glob
import json
import logging
import os
import re

from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from models import (
    AssignedTraining,
    AuditLog,
    Candidate,
    CandidateIdentity,
    CandidateMaster,
    CandidateTest,
    Employee,
    EmployeeDoc,
    JobPosting,
    JobTemplate,
    Permission,
    Requirement,
    Role,
    RoleHistory,
    SLAConfig,
    Setting,
    Session as DbSession,
    TrainingAttempt,
    TrainingMaster,
    TrainingModule,
    TrainingQuestion,
    TrainingSetting,
    User,
)
from pii import encrypt_pii, get_pii_enc_key, looks_like_sha256_hex, maybe_hash_from_stored, normalize_phone, require_pepper
from utils import iso_utc_now


_log = logging.getLogger("schema")
_SAFE_EXT_RE = re.compile(r"^\.[A-Za-z0-9]{1,8}$")


def _safe_ext(filename: str) -> str:
    _base, ext = os.path.splitext(str(filename or "").strip())
    if ext and _SAFE_EXT_RE.fullmatch(ext):
        return ext.lower()
    return ""


def _parse_name_mobile_from_cv_filename(filename: str) -> tuple[str, str]:
    """
    Best-effort parse of (candidateName, mobile) from a filename like:
      Name_Mobile_Source.pdf
      First_Last_Mobile_Source.pdf
    """

    raw = os.path.basename(str(filename or "").strip())
    if not raw:
        return "", ""
    base, _ext = os.path.splitext(raw)
    parts = [p.strip() for p in base.split("_") if p.strip()]
    if len(parts) < 2:
        return "", ""

    mobile_idx = None
    for i in range(1, len(parts)):
        digits = re.sub(r"\D+", "", parts[i])
        if len(digits) >= 8:
            mobile_idx = i
            break
    if mobile_idx is None:
        return "", ""

    name = " ".join(parts[:mobile_idx]).strip()
    mobile = parts[mobile_idx].strip()
    return name, mobile


def _quoted(name: str) -> str:
    return f"\"{str(name).replace('\"', '\"\"')}\""


def _ensure_column(engine, *, table: str, column: str, ddl_type: str, default_sql: str = "''") -> None:
    insp = inspect(engine)
    cols = {c.get("name") for c in insp.get_columns(table)}
    if column in cols:
        return
    ddl = f"ALTER TABLE {_quoted(table)} ADD COLUMN {_quoted(column)} {ddl_type} DEFAULT {default_sql}"
    with engine.begin() as conn:
        conn.execute(text(ddl))


def _ensure_index(engine, *, name: str, table: str, column: str) -> None:
    ddl = f"CREATE INDEX IF NOT EXISTS {_quoted(name)} ON {_quoted(table)}({_quoted(column)})"
    with engine.begin() as conn:
        conn.execute(text(ddl))


def _ensure_ddl(engine, ddl: str) -> None:
    with engine.begin() as conn:
        conn.execute(text(ddl))


def ensure_schema(engine) -> None:
    """
    Lightweight, idempotent schema evolution (no Alembic).

    Adds new columns and backfills deterministic hashes/masked values for PII fields.
    """
    pepper = require_pepper()

    # Users
    _ensure_column(engine, table="users", column="email_hash", ddl_type="TEXT")
    _ensure_column(engine, table="users", column="name_hash", ddl_type="TEXT")
    _ensure_column(engine, table="users", column="email_masked", ddl_type="TEXT")
    _ensure_column(engine, table="users", column="name_masked", ddl_type="TEXT")
    _ensure_column(engine, table="users", column="email_enc", ddl_type="TEXT")
    _ensure_column(engine, table="users", column="name_enc", ddl_type="TEXT")

    _ensure_index(engine, name="ix_users_email_hash", table="users", column="email_hash")
    _ensure_index(engine, name="ix_users_name_hash", table="users", column="name_hash")

    # Candidates
    _ensure_column(engine, table="candidates", column="name_hash", ddl_type="TEXT")
    _ensure_column(engine, table="candidates", column="mobile_hash", ddl_type="TEXT")
    _ensure_column(engine, table="candidates", column="name_masked", ddl_type="TEXT")
    _ensure_column(engine, table="candidates", column="mobile_masked", ddl_type="TEXT")
    _ensure_column(engine, table="candidates", column="name_enc", ddl_type="TEXT")
    _ensure_column(engine, table="candidates", column="mobile_enc", ddl_type="TEXT")
    _ensure_column(engine, table="candidates", column="candidateMasterId", ddl_type="TEXT")
    _ensure_column(engine, table="candidates", column="candidateStage", ddl_type="TEXT")
    _ensure_column(engine, table="candidates", column="stageUpdatedAt", ddl_type="TEXT")

    _ensure_index(engine, name="ix_candidates_name_hash", table="candidates", column="name_hash")
    _ensure_index(engine, name="ix_candidates_mobile_hash", table="candidates", column="mobile_hash")
    _ensure_index(engine, name="ix_candidates_candidateMasterId", table="candidates", column="candidateMasterId")
    # Pipeline list performance (filters + ordering).
    _ensure_index(engine, name="ix_candidates_status", table="candidates", column="status")
    _ensure_index(engine, name="ix_candidates_requirementId", table="candidates", column="requirementId")
    _ensure_index(engine, name="ix_candidates_jobRole", table="candidates", column="jobRole")
    _ensure_index(engine, name="ix_candidates_preCallAt", table="candidates", column="preCallAt")
    _ensure_index(engine, name="ix_candidates_walkinAt", table="candidates", column="walkinAt")
    _ensure_index(engine, name="ix_candidates_updatedAt", table="candidates", column="updatedAt")
    _ensure_index(engine, name="ix_candidates_candidateStage", table="candidates", column="candidateStage")
    _ensure_index(engine, name="ix_candidates_stageUpdatedAt", table="candidates", column="stageUpdatedAt")

    # Prevent duplicate applications of the same candidate master to the same requirement
    # (compatible with existing data: only enforces once candidateMasterId is populated).
    _ensure_ddl(
        engine,
        ddl=(
            f"CREATE UNIQUE INDEX IF NOT EXISTS {_quoted('uq_candidates_requirement_candidateMasterId')} "
            f"ON {_quoted('candidates')}({_quoted('requirementId')}, {_quoted('candidateMasterId')}) "
            f"WHERE {_quoted('candidateMasterId')} <> ''"
        ),
    )

    # CandidateTests (tenant isolation)
    _ensure_column(engine, table="candidate_tests", column="fillOwnerUserId", ddl_type="TEXT")
    _ensure_index(engine, name="ix_candidate_tests_fillOwnerUserId", table="candidate_tests", column="fillOwnerUserId")

    # Trainings: multi-video support
    _ensure_column(engine, table="trainings_master", column="videoLinksJson", ddl_type="TEXT")
    _ensure_column(engine, table="assigned_trainings", column="videoLinksJson", ddl_type="TEXT")
    _ensure_column(engine, table="assigned_trainings", column="video_progress", ddl_type="TEXT")

    # Employees: exit + role history + uniqueness
    _ensure_column(engine, table="employees", column="employee_id", ddl_type="TEXT")
    _ensure_column(engine, table="employees", column="status", ddl_type="TEXT", default_sql="'ACTIVE'")
    _ensure_column(engine, table="employees", column="exitAt", ddl_type="TEXT")
    _ensure_column(engine, table="employees", column="exit_date", ddl_type="TEXT")
    _ensure_column(engine, table="employees", column="rejoin_date", ddl_type="TEXT")
    _ensure_column(engine, table="employees", column="is_active", ddl_type="BOOLEAN", default_sql="TRUE")
    _ensure_column(engine, table="employees", column="auth_version", ddl_type="INTEGER", default_sql="0")
    _ensure_column(engine, table="employees", column="password_hash", ddl_type="TEXT")
    _ensure_column(engine, table="employees", column="password_reset_required", ddl_type="BOOLEAN", default_sql="TRUE")
    _ensure_column(engine, table="employees", column="password_changed_at", ddl_type="TEXT")
    _ensure_column(engine, table="employees", column="currentRole", ddl_type="TEXT")
    _ensure_column(engine, table="employees", column="aadhaar_last4", ddl_type="TEXT")
    _ensure_column(engine, table="employees", column="aadhaar_dob_hash", ddl_type="TEXT")

    _ensure_index(engine, name="ix_employees_employee_id", table="employees", column="employee_id")
    _ensure_index(engine, name="ix_employees_status", table="employees", column="status")
    _ensure_index(engine, name="ix_employees_exitAt", table="employees", column="exitAt")
    _ensure_index(engine, name="ix_employees_exit_date", table="employees", column="exit_date")
    _ensure_index(engine, name="ix_employees_rejoin_date", table="employees", column="rejoin_date")
    _ensure_index(engine, name="ix_employees_is_active", table="employees", column="is_active")
    _ensure_index(engine, name="ix_employees_password_reset_required", table="employees", column="password_reset_required")
    _ensure_index(engine, name="ix_employees_currentRole", table="employees", column="currentRole")
    _ensure_index(engine, name="ix_employees_aadhaar_dob_hash", table="employees", column="aadhaar_dob_hash")

    _ensure_ddl(
        engine,
        ddl=(
            f"CREATE UNIQUE INDEX IF NOT EXISTS {_quoted('uq_employees_employee_id')} "
            f"ON {_quoted('employees')}({_quoted('employee_id')}) "
            f"WHERE {_quoted('employee_id')} <> ''"
        ),
    )

    _ensure_ddl(
        engine,
        ddl=(
            f"CREATE UNIQUE INDEX IF NOT EXISTS {_quoted('uq_employees_aadhaar_dob_hash')} "
            f"ON {_quoted('employees')}({_quoted('aadhaar_dob_hash')}) "
            f"WHERE {_quoted('aadhaar_dob_hash')} <> ''"
        ),
    )

    # Candidates: capture uniqueness at joining time (copied to Employee later).
    _ensure_column(engine, table="candidates", column="aadhaar_last4", ddl_type="TEXT")
    _ensure_column(engine, table="candidates", column="aadhaar_dob_hash", ddl_type="TEXT")
    _ensure_index(engine, name="ix_candidates_aadhaar_dob_hash", table="candidates", column="aadhaar_dob_hash")

    # Audit log: correlation + diffs (append-only)
    _ensure_column(engine, table="audit_log", column="actorEmail", ddl_type="TEXT")
    _ensure_column(engine, table="audit_log", column="correlationId", ddl_type="TEXT")
    _ensure_column(engine, table="audit_log", column="beforeJson", ddl_type="TEXT")
    _ensure_column(engine, table="audit_log", column="afterJson", ddl_type="TEXT")
    _ensure_index(engine, name="ix_audit_log_correlationId", table="audit_log", column="correlationId")

    # Sessions: bind tokens to subject status + auth version (revocation).
    _ensure_column(engine, table="sessions", column="userStatus", ddl_type="TEXT")
    _ensure_column(engine, table="sessions", column="authVersion", ddl_type="INTEGER", default_sql="0")
    _ensure_index(engine, name="ix_sessions_userStatus", table="sessions", column="userStatus")

    _backfill_pii(engine, pepper=pepper)
    _backfill_candidate_master_links(engine, pepper=pepper)
    _backfill_actor_refs(engine, pepper=pepper)
    _backfill_test_owners(engine)
    _backfill_training_videos(engine)
    _backfill_employee_current_role(engine)
    _backfill_employee_lifecycle_and_auth(engine)
    _backfill_training_modules(engine)


def _backfill_employee_lifecycle_and_auth(engine) -> None:
    """
    Ensure employee lifecycle + auth fields are consistent for legacy rows.

    - employees.employee_id mirrors employees.employeeId (unique identifier)
    - employees.exit_date mirrors employees.exitAt
    - employees.is_active derived from status (ACTIVE => True else False)
    - employees.auth_version defaults to 0
    """

    insp = inspect(engine)
    existing_tables = set(insp.get_table_names())
    if "employees" not in existing_tables:
        return

    cols = {c.get("name") for c in insp.get_columns("employees")}
    required = {"employeeId", "employee_id", "status", "exitAt", "exit_date", "is_active", "auth_version"}
    if not required.issubset(cols):
        return

    with Session(engine) as db:
        try:
            # Mirror employeeId -> employee_id for legacy rows.
            db.execute(
                text(
                    f"UPDATE {_quoted('employees')} "
                    f"SET {_quoted('employee_id')} = {_quoted('employeeId')} "
                    f"WHERE ({_quoted('employee_id')} IS NULL OR {_quoted('employee_id')} = '') "
                    f"AND {_quoted('employeeId')} <> ''"
                )
            )

            # Mirror exitAt -> exit_date for legacy rows.
            db.execute(
                text(
                    f"UPDATE {_quoted('employees')} "
                    f"SET {_quoted('exit_date')} = {_quoted('exitAt')} "
                    f"WHERE ({_quoted('exit_date')} IS NULL OR {_quoted('exit_date')} = '') "
                    f"AND {_quoted('exitAt')} <> ''"
                )
            )

            # is_active derived from status (ACTIVE => True else False).
            db.execute(
                text(
                    f"UPDATE {_quoted('employees')} "
                    f"SET {_quoted('is_active')} = CASE WHEN UPPER({_quoted('status')}) = 'ACTIVE' THEN TRUE ELSE FALSE END "
                    f"WHERE {_quoted('is_active')} IS NULL OR "
                    f"(UPPER({_quoted('status')}) = 'ACTIVE' AND {_quoted('is_active')} <> TRUE) OR "
                    f"(UPPER({_quoted('status')}) <> 'ACTIVE' AND {_quoted('is_active')} <> FALSE)"
                )
            )

            # Default auth_version when NULL.
            db.execute(
                text(
                    f"UPDATE {_quoted('employees')} "
                    f"SET {_quoted('auth_version')} = 0 "
                    f"WHERE {_quoted('auth_version')} IS NULL"
                )
            )

            db.commit()
        except Exception:
            db.rollback()


def _backfill_candidate_master_links(engine, *, pepper: str) -> None:
    """
    Backfill `candidates.candidateMasterId` using deterministic phone hashes.

    - Creates one `candidate_master` per unique `candidates.mobile_hash`
    - Creates one active `candidate_identity` row per master for PHONE_HASH
    - Links existing `candidates` rows to the master (no deletes / no data loss)
    """

    insp = inspect(engine)
    existing_tables = set(insp.get_table_names())
    if "candidates" not in existing_tables or "candidate_master" not in existing_tables or "candidate_identity" not in existing_tables:
        return

    with Session(engine) as db:
        rows = (
            db.query(Candidate)  # type: ignore[attr-defined]
            .filter(Candidate.candidateMasterId == "")
            .filter(Candidate.mobile_hash != "")
            .all()
        )
        if not rows:
            return

        updated = 0
        created_masters = 0

        for c in rows:
            mobile_hash = str(getattr(c, "mobile_hash", "") or "").strip().lower()
            if not mobile_hash:
                continue

            ident = (
                db.query(CandidateIdentity)  # type: ignore[attr-defined]
                .filter(CandidateIdentity.identityType == "PHONE_HASH")
                .filter(CandidateIdentity.normalizedValue == mobile_hash)
                .filter(CandidateIdentity.active == True)  # noqa: E712
                .first()
            )
            if ident and str(getattr(ident, "candidateMasterId", "") or "").strip():
                c.candidateMasterId = str(getattr(ident, "candidateMasterId", "") or "").strip()
                updated += 1
                continue

            cm_id = "CAN-" + os.urandom(12).hex().upper()
            now = iso_utc_now()

            db.add(
                CandidateMaster(
                    candidateMasterId=cm_id,
                    status="ACTIVE",
                    name_hash=str(getattr(c, "name_hash", "") or ""),
                    mobile_hash=mobile_hash,
                    name_masked=str(getattr(c, "name_masked", "") or getattr(c, "candidateName", "") or ""),
                    mobile_masked=str(getattr(c, "mobile_masked", "") or getattr(c, "mobile", "") or ""),
                    name_enc=str(getattr(c, "name_enc", "") or ""),
                    mobile_enc=str(getattr(c, "mobile_enc", "") or ""),
                    createdAt=str(getattr(c, "createdAt", "") or now),
                    createdBy=str(getattr(c, "createdBy", "") or "SYSTEM_MIGRATION"),
                    updatedAt=str(getattr(c, "updatedAt", "") or now),
                    updatedBy=str(getattr(c, "updatedBy", "") or "SYSTEM_MIGRATION"),
                )
            )
            db.add(
                CandidateIdentity(
                    candidateMasterId=cm_id,
                    identityType="PHONE_HASH",
                    normalizedValue=mobile_hash,
                    active=True,
                    createdAt=now,
                    createdBy="SYSTEM_MIGRATION",
                )
            )

            c.candidateMasterId = cm_id
            updated += 1
            created_masters += 1

        if updated:
            db.commit()
            _log.info("Candidate master backfill complete linked=%s createdMasters=%s", updated, created_masters)


def _backfill_pii(engine, *, pepper: str) -> None:
    enc_key = get_pii_enc_key()
    upload_dir = os.getenv("UPLOAD_DIR", "./uploads").strip() or "./uploads"
    file_storage_mode = os.getenv("FILE_STORAGE_MODE", "local").strip().lower()
    with Session(engine) as db:
        users = db.query(User).all()  # type: ignore[attr-defined]
        user_updates = 0
        for u in users:
            email_hash_existing = str(getattr(u, "email_hash", "") or "").strip()
            email_mask_existing = str(getattr(u, "email_masked", "") or "").strip()

            stored_email = str(getattr(u, "email", "") or "").strip()
            email_enc_existing = str(getattr(u, "email_enc", "") or "").strip()
            if email_hash_existing:
                email_hash = email_hash_existing.lower()
                email_masked = email_mask_existing
            else:
                email_hash, email_masked = maybe_hash_from_stored(stored_email, kind="email", pepper=pepper)
                if not email_masked:
                    email_masked = email_mask_existing

            name_hash_existing = str(getattr(u, "name_hash", "") or "").strip()
            name_mask_existing = str(getattr(u, "name_masked", "") or "").strip()
            stored_name = str(getattr(u, "fullName", "") or "").strip()
            name_enc_existing = str(getattr(u, "name_enc", "") or "").strip()
            if name_hash_existing:
                name_hash = name_hash_existing.lower()
                name_masked = name_mask_existing or stored_name
            else:
                name_hash, name_masked = maybe_hash_from_stored(stored_name, kind="name", pepper=pepper)
                if not name_masked:
                    name_masked = name_mask_existing or stored_name

            changed = False
            if enc_key and not email_enc_existing and stored_email and "@" in stored_email and not looks_like_sha256_hex(stored_email):
                enc = encrypt_pii(stored_email, key=enc_key, aad=f"user:{getattr(u, 'userId', '')}:email")
                if enc and str(getattr(u, "email_enc", "") or "") != enc:
                    u.email_enc = enc
                    changed = True
            if enc_key and not name_enc_existing and stored_name and "*" not in stored_name and not looks_like_sha256_hex(stored_name):
                enc = encrypt_pii(stored_name, key=enc_key, aad=f"user:{getattr(u, 'userId', '')}:name")
                if enc and str(getattr(u, "name_enc", "") or "") != enc:
                    u.name_enc = enc
                    changed = True

            if email_hash and str(getattr(u, "email_hash", "") or "") != email_hash:
                u.email_hash = email_hash
                changed = True
            # Keep legacy `email` column hashed to avoid storing plaintext.
            if email_hash and str(getattr(u, "email", "") or "") != email_hash:
                u.email = email_hash
                changed = True
            if email_masked and str(getattr(u, "email_masked", "") or "") != email_masked:
                u.email_masked = email_masked
                changed = True

            if name_hash and str(getattr(u, "name_hash", "") or "") != name_hash:
                u.name_hash = name_hash
                changed = True
            if name_masked and str(getattr(u, "name_masked", "") or "") != name_masked:
                u.name_masked = name_masked
                changed = True
            # Keep legacy `fullName` column masked to avoid storing plaintext.
            if name_masked and str(getattr(u, "fullName", "") or "") != name_masked:
                u.fullName = name_masked
                changed = True

            if changed:
                user_updates += 1

        candidates = db.query(Candidate).all()  # type: ignore[attr-defined]
        cand_updates = 0
        for c in candidates:
            name_hash_existing = str(getattr(c, "name_hash", "") or "").strip()
            name_mask_existing = str(getattr(c, "name_masked", "") or "").strip()
            stored_name = str(getattr(c, "candidateName", "") or "").strip()
            name_enc_existing = str(getattr(c, "name_enc", "") or "").strip()
            cv_filename_existing = str(getattr(c, "cvFileName", "") or "").strip()
            if name_hash_existing:
                name_hash = name_hash_existing.lower()
                name_masked = name_mask_existing or stored_name
            else:
                name_hash, name_masked = maybe_hash_from_stored(stored_name, kind="name", pepper=pepper)
                if not name_masked:
                    name_masked = name_mask_existing or stored_name

            mob_hash_existing = str(getattr(c, "mobile_hash", "") or "").strip()
            mob_mask_existing = str(getattr(c, "mobile_masked", "") or "").strip()
            stored_mobile = str(getattr(c, "mobile", "") or "").strip()
            mobile_enc_existing = str(getattr(c, "mobile_enc", "") or "").strip()
            if mob_hash_existing:
                mobile_hash = mob_hash_existing.lower()
                mobile_masked = mob_mask_existing
            else:
                mobile_hash, mobile_masked = maybe_hash_from_stored(stored_mobile, kind="phone", pepper=pepper)
                if not mobile_masked:
                    mobile_masked = mob_mask_existing

            changed = False

            # Recovery + scrubbing: older rows stored plaintext PII in CV filenames
            # (e.g., Name_Mobile_Source.pdf). Extract full PII into encrypted columns
            # and scrub DB+filesystem filenames to remove plaintext.
            if cv_filename_existing and enc_key:
                cv_name, cv_mobile = _parse_name_mobile_from_cv_filename(cv_filename_existing)

                cv_mobile_norm = normalize_phone(cv_mobile) if cv_mobile else ""
                cv_mob_hash, _cv_mob_mask = maybe_hash_from_stored(cv_mobile_norm or cv_mobile, kind="phone", pepper=pepper)

                allow_mobile = bool(cv_mobile_norm) and (
                    not mob_hash_existing or (cv_mob_hash and mob_hash_existing.lower() == cv_mob_hash.lower())
                )
                # If mobile matches (or no mobile hash exists yet), trust CV filename name for display.
                allow_name = bool(cv_name) and allow_mobile

                if allow_mobile and not mobile_enc_existing:
                    enc = encrypt_pii(cv_mobile_norm, key=enc_key, aad=f"candidate:{getattr(c, 'candidateId', '')}:mobile")
                    if enc and str(getattr(c, "mobile_enc", "") or "") != enc:
                        c.mobile_enc = enc
                        changed = True

                if allow_name and not name_enc_existing:
                    enc = encrypt_pii(cv_name, key=enc_key, aad=f"candidate:{getattr(c, 'candidateId', '')}:name")
                    if enc and str(getattr(c, "name_enc", "") or "") != enc:
                        c.name_enc = enc
                        changed = True

                # Scrub CV filename and local upload file name (idempotent).
                if "_" in cv_filename_existing and any(ch.isdigit() for ch in cv_filename_existing):
                    cid = str(getattr(c, "candidateId", "") or "").strip()
                    if cid:
                        ext = _safe_ext(cv_filename_existing)
                        new_cv_name = f"CV_{cid}{ext}"
                        if str(getattr(c, "cvFileName", "") or "") != new_cv_name:
                            c.cvFileName = new_cv_name
                            changed = True

                        if file_storage_mode != "gas":
                            fid = str(getattr(c, "cvFileId", "") or "").strip()
                            if fid:
                                try:
                                    pattern = os.path.join(upload_dir, f"{fid}_*")
                                    matches = sorted(glob.glob(pattern))
                                    if matches:
                                        src = matches[0]
                                        dst = os.path.join(upload_dir, f"{fid}_{new_cv_name}")
                                        if src != dst and not os.path.exists(dst):
                                            os.rename(src, dst)
                                except Exception:
                                    pass

            if enc_key and not name_enc_existing and stored_name and "*" not in stored_name and not looks_like_sha256_hex(stored_name):
                enc = encrypt_pii(stored_name, key=enc_key, aad=f"candidate:{getattr(c, 'candidateId', '')}:name")
                if enc and str(getattr(c, "name_enc", "") or "") != enc:
                    c.name_enc = enc
                    changed = True
            if (
                enc_key
                and not mobile_enc_existing
                and stored_mobile
                and "*" not in stored_mobile
                and "x" not in stored_mobile.lower()
                and not looks_like_sha256_hex(stored_mobile)
            ):
                enc = encrypt_pii(stored_mobile, key=enc_key, aad=f"candidate:{getattr(c, 'candidateId', '')}:mobile")
                if enc and str(getattr(c, "mobile_enc", "") or "") != enc:
                    c.mobile_enc = enc
                    changed = True

            if name_hash and str(getattr(c, "name_hash", "") or "") != name_hash:
                c.name_hash = name_hash
                changed = True
            if name_masked and str(getattr(c, "name_masked", "") or "") != name_masked:
                c.name_masked = name_masked
                changed = True
            # Keep legacy `candidateName` column masked to avoid storing plaintext.
            if name_masked and str(getattr(c, "candidateName", "") or "") != name_masked:
                c.candidateName = name_masked
                changed = True

            if mobile_hash and str(getattr(c, "mobile_hash", "") or "") != mobile_hash:
                c.mobile_hash = mobile_hash
                changed = True
            if mobile_masked and str(getattr(c, "mobile_masked", "") or "") != mobile_masked:
                c.mobile_masked = mobile_masked
                changed = True
            # Keep legacy `mobile` column masked to avoid storing plaintext.
            if mobile_masked and str(getattr(c, "mobile", "") or "") != mobile_masked:
                c.mobile = mobile_masked
                changed = True

            if changed:
                cand_updates += 1

        ses_updates = 0
        sessions = db.query(DbSession).all()  # type: ignore[attr-defined]
        for s in sessions:
            raw = str(getattr(s, "email", "") or "").strip()
            if "@" not in raw:
                continue
            h, _m = maybe_hash_from_stored(raw, kind="email", pepper=pepper)
            if h and raw != h:
                s.email = h
                ses_updates += 1

        if user_updates or cand_updates or ses_updates:
            db.commit()
            _log.info("PII backfill complete users=%s candidates=%s sessions=%s", user_updates, cand_updates, ses_updates)


def _backfill_actor_refs(engine, *, pepper: str) -> None:
    """
    Convert legacy audit-ish actor columns (e.g. createdBy/updatedBy) that may contain
    plaintext emails or email-hashes into stable, UI-friendly userIds.

    This avoids showing long SHA256 hex digests on the frontend while still keeping
    deterministic references for older rows.
    """

    def _convert_actor_ref(value: str, email_hash_to_user_id: dict[str, str]) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""

        # Already a human-friendly identifier (USR-xxxx / EMP-xxxx / SYSTEM / etc.)
        if "@" not in raw and not looks_like_sha256_hex(raw):
            return raw

        if looks_like_sha256_hex(raw):
            h = raw.lower()
            return email_hash_to_user_id.get(h, h)

        h, _m = maybe_hash_from_stored(raw, kind="email", pepper=pepper)
        if not h:
            return ""
        return email_hash_to_user_id.get(h.lower(), h.lower())

    insp = inspect(engine)
    existing_tables = set(insp.get_table_names())

    with Session(engine) as db:
        email_hash_to_user_id: dict[str, str] = {}
        if "users" in existing_tables:
            for u in db.query(User).all():  # type: ignore[attr-defined]
                user_id = str(getattr(u, "userId", "") or "").strip()
                if not user_id:
                    continue
                email_h = str(getattr(u, "email_hash", "") or getattr(u, "email", "") or "").strip().lower()
                if looks_like_sha256_hex(email_h):
                    email_hash_to_user_id[email_h] = user_id
                elif "@" in email_h:
                    h, _m = maybe_hash_from_stored(email_h, kind="email", pepper=pepper)
                    if h:
                        email_hash_to_user_id[h.lower()] = user_id

        targets: list[tuple[str, object, tuple[str, ...]]] = [
            ("users", User, ("createdBy", "updatedBy")),
            ("roles", Role, ("createdBy", "updatedBy")),
            ("permissions", Permission, ("updatedBy",)),
            ("settings", Setting, ("updatedBy",)),
            ("job_templates", JobTemplate, ("createdBy", "updatedBy")),
            ("requirements", Requirement, ("createdBy", "updatedBy")),
            ("job_posting", JobPosting, ("completedBy", "updatedBy")),
            ("candidates", Candidate, ("createdBy", "updatedBy")),
            ("employees", Employee, ("createdBy",)),
            ("sla_config", SLAConfig, ("updatedBy",)),
            ("trainings_master", TrainingMaster, ("created_by",)),
            ("assigned_trainings", AssignedTraining, ("assigned_by",)),
        ]

        updated = 0
        for table_name, model, fields in targets:
            if table_name not in existing_tables:
                continue
            for row in db.query(model).all():  # type: ignore[attr-defined]
                for field in fields:
                    old = str(getattr(row, field, "") or "").strip()
                    new = _convert_actor_ref(old, email_hash_to_user_id)
                    if new == old:
                        continue
                    setattr(row, field, new)
                    updated += 1

        if updated:
            db.commit()
            _log.info("Actor ref backfill complete updated=%s", updated)


def _backfill_test_owners(engine) -> None:
    with Session(engine) as db:
        rows = (
            db.query(CandidateTest)  # type: ignore[attr-defined]
            .filter(CandidateTest.fillOwnerUserId == "")
            .filter(CandidateTest.filledBy != "")
            .all()
        )
        if not rows:
            return
        for r in rows:
            r.fillOwnerUserId = str(getattr(r, "filledBy", "") or "").strip()
        db.commit()


def _backfill_employee_current_role(engine) -> None:
    """
    Backfill employees.currentRole from employees.jobRole (for existing records).
    """

    insp = inspect(engine)
    existing_tables = set(insp.get_table_names())
    if "employees" not in existing_tables:
        return

    with Session(engine) as db:
        rows = db.query(Employee).filter(Employee.currentRole == "").all()  # type: ignore[attr-defined]
        if not rows:
            return
        for e in rows:
            e.currentRole = str(getattr(e, "jobRole", "") or "")
        db.commit()


def _backfill_training_modules(engine) -> None:
    """
    Keep training_modules in sync with trainings_master (best-effort, idempotent).
    """

    insp = inspect(engine)
    existing_tables = set(insp.get_table_names())
    if "trainings_master" not in existing_tables or "training_modules" not in existing_tables:
        return

    with Session(engine) as db:
        existing = {str(r.moduleId or "").strip() for r in db.query(TrainingModule).all()}  # type: ignore[attr-defined]
        masters = db.query(TrainingMaster).all()  # type: ignore[attr-defined]
        if not masters:
            return

        now = iso_utc_now()
        created = 0

        for t in masters:
            mid = str(getattr(t, "training_id", "") or "").strip()
            if not mid or mid in existing:
                continue

            title = str(getattr(t, "name", "") or "").strip() or mid
            video_ref = str(getattr(t, "video_link", "") or "").strip()
            raw_videos = str(getattr(t, "videoLinksJson", "") or "").strip()
            if raw_videos:
                try:
                    arr = json.loads(raw_videos)
                except Exception:
                    arr = None
                if isinstance(arr, list):
                    first = next((str(x or "").strip() for x in arr if str(x or "").strip()), "")
                    if first:
                        video_ref = first

            db.add(
                TrainingModule(
                    moduleId=mid,
                    title=title,
                    video_provider="URL",
                    video_ref=video_ref,
                    active=True,
                    createdAt=now,
                    createdBy="SYSTEM_SCHEMA",
                    updatedAt=now,
                    updatedBy="SYSTEM_SCHEMA",
                )
            )
            existing.add(mid)
            created += 1

        if created:
            db.commit()


def _backfill_training_videos(engine) -> None:
    with Session(engine) as db:
        updated = 0

        masters = (
            db.query(TrainingMaster)  # type: ignore[attr-defined]
            .filter(TrainingMaster.videoLinksJson == "")
            .filter(TrainingMaster.video_link != "")
            .all()
        )
        for t in masters:
            t.videoLinksJson = f"[{json.dumps(str(getattr(t, 'video_link', '') or '').strip())}]"
            updated += 1

        assigned = (
            db.query(AssignedTraining)  # type: ignore[attr-defined]
            .filter(AssignedTraining.videoLinksJson == "")
            .filter(AssignedTraining.video_link != "")
            .all()
        )
        for t in assigned:
            t.videoLinksJson = f"[{json.dumps(str(getattr(t, 'video_link', '') or '').strip())}]"
            updated += 1

        if updated:
            db.commit()
