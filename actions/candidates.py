from __future__ import annotations

import json
import os
from datetime import datetime

from sqlalchemy import select

from actions.candidate_repo import (
    find_candidate,
    get_or_create_candidate_master_by_phone_hash,
    has_duplicate_candidate_in_requirement,
    normalize_mobile,
    reject_candidate_with_meta,
    update_candidate,
    update_candidate_master_phone_hash,
)
from actions.helpers import append_audit, append_hold_log, append_rejection_log, next_prefixed_id
from actions.jobposting import assert_job_posting_complete
from actions.lifecycle_service import transition_candidate_status
from models import Candidate, RejectionLog, Requirement
from utils import ApiError, AuthContext, decode_base64_to_bytes, iso_utc_now, parse_datetime_maybe, sanitize_filename, to_iso_utc
from services.gas_uploader import gas_upload_file
from pii import decrypt_pii, encrypt_pii, hash_name, hash_phone, mask_name, mask_phone


def _get_requirement_job_role(db, requirement_id: str) -> str:
    req = db.execute(select(Requirement).where(Requirement.requirementId == requirement_id)).scalar_one_or_none()
    if not req:
        raise ApiError("NOT_FOUND", "Requirement not found")
    return str(req.jobRole or "")


def file_upload_cv(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    filename = str((data or {}).get("filename") or "").strip() or "cv"
    mime_type = str((data or {}).get("mimeType") or "").strip() or "application/octet-stream"
    base64 = str((data or {}).get("base64") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not base64:
        raise ApiError("BAD_REQUEST", "Missing base64")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    # Never store or log the original filename (it often contains candidate PII).
    safe_name = sanitize_filename(filename)
    _base, ext = os.path.splitext(safe_name)
    ext = str(ext or "").lower()
    if not ext or len(ext) > 10 or not ext.startswith(".") or not ext[1:].isalnum():
        ext = ""

    out_name = f"CV_{requirement_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{os.urandom(4).hex()}{ext}"

    file_id = ""
    if str(cfg.FILE_STORAGE_MODE or "").lower() == "gas":
        up = gas_upload_file(
            cfg=cfg,
            file_base64=base64,
            file_name=out_name,
            mime_type=mime_type,
            extra={"requirementId": requirement_id, "sourceAction": "FILE_UPLOAD_CV", "uploadedBy": auth.userId},
        )
        file_id = str(up.get("fileId") or "").strip()
    else:
        bytes_ = decode_base64_to_bytes(base64)
        file_id = os.urandom(16).hex()
        os.makedirs(cfg.UPLOAD_DIR, exist_ok=True)
        out_path = os.path.join(cfg.UPLOAD_DIR, f"{file_id}_{out_name}")
        with open(out_path, "wb") as f:
            f.write(bytes_)

    now = iso_utc_now()
    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=requirement_id,
        action="FILE_UPLOAD_CV",
        fromState="",
        toState="",
        stageTag="FILE_UPLOAD_CV",
        remark=out_name,
        actor=auth,
        at=now,
        meta={"fileId": file_id, "mimeType": mime_type},
    )

    return {"fileId": file_id, "fileName": out_name}


def candidate_add(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_name = str((data or {}).get("candidateName") or "").strip()
    mobile = str((data or {}).get("mobile") or "").strip()
    source = str((data or {}).get("source") or "").strip()
    cv_file_id = str((data or {}).get("cvFileId") or "").strip()
    cv_file_name = str((data or {}).get("cvFileName") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_name:
        raise ApiError("BAD_REQUEST", "Missing candidateName")
    if not mobile:
        raise ApiError("BAD_REQUEST", "Missing mobile")
    if not cv_file_id:
        raise ApiError("BAD_REQUEST", "Missing cvFileId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    job_role = _get_requirement_job_role(db, requirement_id)

    norm_mobile = normalize_mobile(mobile)
    if not norm_mobile:
        raise ApiError("BAD_REQUEST", "Invalid mobile")

    name_hash = hash_name(candidate_name, cfg.PEPPER)
    mobile_hash = hash_phone(norm_mobile, cfg.PEPPER)

    # Global candidate identity anchor (prevents duplicate identities across requirements).
    master = get_or_create_candidate_master_by_phone_hash(
        db,
        phone_hash=mobile_hash,
        name_hash=name_hash,
        name_masked=mask_name(candidate_name),
        mobile_masked=mask_phone(norm_mobile),
        name_enc="",
        mobile_enc="",
        auth=auth,
    )

    # Prevent duplicate applications of the same identity within the same requirement.
    dup = (
        db.execute(
            select(Candidate.candidateId)
            .where(Candidate.requirementId == requirement_id)
            .where(Candidate.candidateMasterId == str(master.candidateMasterId or "").strip())
        )
        .scalars()
        .first()
    )
    if dup:
        raise ApiError("CONFLICT", "Candidate already exists in this requirement (same identity)")

    existing_ids = [x for x in db.execute(select(Candidate.candidateId)).scalars().all()]
    candidate_id = next_prefixed_id(db, counter_key="CND", prefix="CND-", pad=5, existing_ids=existing_ids)

    now = iso_utc_now()
    name_masked = mask_name(candidate_name)
    mobile_masked = mask_phone(norm_mobile)
    name_enc = ""
    mobile_enc = ""
    if str(getattr(cfg, "PII_ENC_KEY", "") or "").strip():
        name_enc = encrypt_pii(candidate_name, key=cfg.PII_ENC_KEY, aad=f"candidate:{candidate_id}:name")
        mobile_enc = encrypt_pii(norm_mobile, key=cfg.PII_ENC_KEY, aad=f"candidate:{candidate_id}:mobile")
    db.add(
        Candidate(
            candidateId=candidate_id,
            candidateMasterId=str(master.candidateMasterId or "").strip(),
            requirementId=requirement_id,
            candidateName=name_masked,
            jobRole=job_role,
            mobile=mobile_masked,
            name_hash=name_hash,
            mobile_hash=mobile_hash,
            name_masked=name_masked,
            mobile_masked=mobile_masked,
            name_enc=name_enc,
            mobile_enc=mobile_enc,
            source=source,
            cvFileId=cv_file_id,
            cvFileName=cv_file_name,
            status="NEW",
            notPickCount=0,
            createdAt=now,
            createdBy=auth.userId,
            updatedAt=now,
            updatedBy=auth.userId,
        )
    )

    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="CANDIDATE_ADD",
        fromState="",
        toState="NEW",
        stageTag="CANDIDATE_ADD",
        remark="",
        actor=auth,
        at=now,
        meta={"requirementId": requirement_id, "candidateMasterId": str(master.candidateMasterId or "").strip()},
    )

    return {"candidateId": candidate_id}


def candidate_pii_set(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    candidate_name = str((data or {}).get("candidateName") or "").strip()
    mobile = str((data or {}).get("mobile") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not candidate_name:
        raise ApiError("BAD_REQUEST", "Missing candidateName")
    if not mobile:
        raise ApiError("BAD_REQUEST", "Missing mobile")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)

    norm_mobile = normalize_mobile(mobile)
    if not norm_mobile:
        raise ApiError("BAD_REQUEST", "Invalid mobile")

    name_hash = hash_name(candidate_name, cfg.PEPPER)
    mobile_hash = hash_phone(norm_mobile, cfg.PEPPER)

    dup = (
        db.execute(
            select(Candidate.candidateId)
            .where(Candidate.requirementId == requirement_id)
            .where(Candidate.mobile_hash == mobile_hash)
            .where(Candidate.candidateId != candidate_id)
        )
        .scalars()
        .first()
    )
    if dup:
        raise ApiError("CONFLICT", "Candidate already exists (same mobile) in this requirement")

    name_masked = mask_name(candidate_name)
    mobile_masked = mask_phone(norm_mobile)

    name_enc = ""
    mobile_enc = ""
    if str(getattr(cfg, "PII_ENC_KEY", "") or "").strip():
        name_enc = encrypt_pii(candidate_name, key=cfg.PII_ENC_KEY, aad=f"candidate:{candidate_id}:name")
        mobile_enc = encrypt_pii(norm_mobile, key=cfg.PII_ENC_KEY, aad=f"candidate:{candidate_id}:mobile")

    # Ensure the candidate is linked to exactly one global identity anchor.
    cm_id = str(getattr(cand, "candidateMasterId", "") or "").strip()
    if not cm_id:
        master = get_or_create_candidate_master_by_phone_hash(
            db,
            phone_hash=mobile_hash,
            name_hash=name_hash,
            name_masked=name_masked,
            mobile_masked=mobile_masked,
            name_enc="",
            mobile_enc="",
            auth=auth,
        )
        cm_id = str(master.candidateMasterId or "").strip()
    else:
        update_candidate_master_phone_hash(
            db,
            candidate_master_id=cm_id,
            next_phone_hash=mobile_hash,
            next_name_hash=name_hash,
            next_name_masked=name_masked,
            next_mobile_masked=mobile_masked,
            next_name_enc="",
            next_mobile_enc="",
            auth=auth,
        )

    cand.name_hash = name_hash
    cand.mobile_hash = mobile_hash
    cand.name_masked = name_masked
    cand.mobile_masked = mobile_masked
    cand.candidateName = name_masked
    cand.mobile = mobile_masked
    if name_enc:
        cand.name_enc = name_enc
    if mobile_enc:
        cand.mobile_enc = mobile_enc
    cand.candidateMasterId = cm_id
    cand.updatedAt = iso_utc_now()
    cand.updatedBy = auth.userId

    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="CANDIDATE_PII_SET",
        fromState=str(cand.status or ""),
        toState=str(cand.status or ""),
        stageTag="CANDIDATE_PII_SET",
        remark="",
        actor=auth,
        at=iso_utc_now(),
        meta={"requirementId": requirement_id},
    )

    return {"ok": True, "candidateId": candidate_id, "requirementId": requirement_id}


def candidate_bulk_add(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    items = (data or {}).get("items") or []

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not isinstance(items, list):
        raise ApiError("BAD_REQUEST", "items must be an array")
    if len(items) > 50:
        raise ApiError("BAD_REQUEST", "Max 50 files")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    job_role = _get_requirement_job_role(db, requirement_id)

    existing = db.execute(select(Candidate).where(Candidate.requirementId == requirement_id)).scalars().all()
    existing_phone_hashes = set()
    for c in existing:
        mh = str(getattr(c, "mobile_hash", "") or "").strip().lower()
        if mh:
            existing_phone_hashes.add(mh)

    now = iso_utc_now()
    created = []
    errors = []

    existing_ids = [x for x in db.execute(select(Candidate.candidateId)).scalars().all()]
    ids_pool = list(existing_ids)

    for i, it in enumerate(items):
        it = it or {}
        candidate_name = str(it.get("candidateName") or "").strip()
        mobile = str(it.get("mobile") or "").strip()
        source = str(it.get("source") or "").strip()
        cv_file_id = str(it.get("cvFileId") or "").strip()
        cv_file_name = str(it.get("cvFileName") or "").strip()

        if not candidate_name or not mobile or not cv_file_id:
            errors.append({"index": i, "message": "Missing candidateName/mobile/cvFileId"})
            continue

        norm_mobile = normalize_mobile(mobile)
        if not norm_mobile:
            errors.append({"index": i, "message": "Invalid mobile"})
            continue

        name_hash = hash_name(candidate_name, cfg.PEPPER)
        mobile_hash = hash_phone(norm_mobile, cfg.PEPPER)
        if str(mobile_hash or "").strip().lower() in existing_phone_hashes:
            errors.append({"index": i, "message": "Duplicate candidate (same mobile) in requirement"})
            continue
        existing_phone_hashes.add(str(mobile_hash or "").strip().lower())

        master = get_or_create_candidate_master_by_phone_hash(
            db,
            phone_hash=mobile_hash,
            name_hash=name_hash,
            name_masked=mask_name(candidate_name),
            mobile_masked=mask_phone(norm_mobile),
            name_enc="",
            mobile_enc="",
            auth=auth,
        )

        candidate_id = next_prefixed_id(db, counter_key="CND", prefix="CND-", pad=5, existing_ids=ids_pool)
        ids_pool.append(candidate_id)

        name_masked = mask_name(candidate_name)
        mobile_masked = mask_phone(norm_mobile)
        name_enc = ""
        mobile_enc = ""
        if str(getattr(cfg, "PII_ENC_KEY", "") or "").strip():
            name_enc = encrypt_pii(candidate_name, key=cfg.PII_ENC_KEY, aad=f"candidate:{candidate_id}:name")
            mobile_enc = encrypt_pii(norm_mobile, key=cfg.PII_ENC_KEY, aad=f"candidate:{candidate_id}:mobile")
        db.add(
            Candidate(
                candidateId=candidate_id,
                candidateMasterId=str(master.candidateMasterId or "").strip(),
                requirementId=requirement_id,
                candidateName=name_masked,
                jobRole=job_role,
                mobile=mobile_masked,
                name_hash=name_hash,
                mobile_hash=mobile_hash,
                name_masked=name_masked,
                mobile_masked=mobile_masked,
                name_enc=name_enc,
                mobile_enc=mobile_enc,
                source=source,
                cvFileId=cv_file_id,
                cvFileName=cv_file_name,
                status="NEW",
                notPickCount=0,
                createdAt=now,
                createdBy=auth.userId,
                updatedAt=now,
                updatedBy=auth.userId,
            )
        )

        append_audit(
            db,
            entityType="CANDIDATE",
            entityId=candidate_id,
            action="CANDIDATE_ADD",
            fromState="",
            toState="NEW",
            stageTag="CANDIDATE_ADD",
            remark="BULK",
            actor=auth,
            at=now,
            meta={"requirementId": requirement_id, "candidateMasterId": str(master.candidateMasterId or "").strip()},
        )

        created.append({"candidateId": candidate_id})

    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=requirement_id,
        action="CANDIDATE_BULK_ADD",
        fromState="",
        toState="",
        stageTag="CANDIDATE_BULK_ADD",
        remark="",
        actor=auth,
        at=now,
        meta={"created": len(created), "errors": len(errors)},
    )

    return {"created": created, "errors": errors}


def shortlist_decide(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    decision = str((data or {}).get("decision") or "").upper().strip()
    remark = str((data or {}).get("remark") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not decision:
        raise ApiError("BAD_REQUEST", "Missing decision")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()

    if current_status in {"OWNER", "OWNER_HOLD"}:
        raise ApiError("BAD_REQUEST", "Candidate is locked in Owner tab")

    if decision == "REJECT":
        if not remark:
            raise ApiError("BAD_REQUEST", "Remark required")
        return reject_candidate_with_meta(
            db,
            candidate_id=candidate_id,
            requirement_id=requirement_id,
            stage_tag="Shortlisting",
            remark=remark,
            reason_code="SHORTLIST_REJECT",
            auth=auth,
            audit_action="SHORTLIST_DECIDE",
        )

    if decision == "HOLD":
        if not remark:
            raise ApiError("BAD_REQUEST", "Remark required")
        append_hold_log(
            db,
            candidateId=candidate_id,
            requirementId=requirement_id,
            action="HOLD",
            stageTag="Shortlisting Hold",
            remark=remark,
            actor=auth,
            holdUntil="",
        )
        transition_candidate_status(
            db,
            candidate_id=candidate_id,
            requirement_id=requirement_id,
            to_status="HOLD",
            action="SHORTLIST_DECIDE",
            stage_tag="Shortlisting Hold",
            auth=auth,
            remark=remark,
            patch={"holdUntil": ""},
        )
        return {"ok": True, "status": "HOLD"}

    if decision == "HR_APPROVE_WALKIN":
        transition_candidate_status(
            db,
            candidate_id=candidate_id,
            requirement_id=requirement_id,
            to_status="WALKIN_PENDING",
            action="HR_APPROVE_WALKIN",
            stage_tag="HR_APPROVE_WALKIN",
            auth=auth,
            remark="",
            patch={
                "holdUntil": "",
                "walkinAt": "",
                "walkinNotes": "",
                "notPickCount": 0,
                "preCallAt": "",
            },
            require_from={"NEW"},
        )
        return {"ok": True, "status": "WALKIN_PENDING"}

    if decision == "OWNER_SEND":
        transition_candidate_status(
            db,
            candidate_id=candidate_id,
            requirement_id=requirement_id,
            to_status="OWNER",
            action="OWNER_SEND",
            stage_tag="SHORTLIST_OWNER_SEND",
            auth=auth,
            remark="",
            patch={"holdUntil": ""},
        )
        return {"ok": True, "status": "OWNER"}

    raise ApiError("BAD_REQUEST", "Invalid decision")


def shortlist_hold_revert(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    remark = str((data or {}).get("remark") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    if str(cand.status or "").upper() != "HOLD":
        raise ApiError("BAD_REQUEST", "Candidate not in HOLD")

    append_hold_log(
        db,
        candidateId=candidate_id,
        requirementId=requirement_id,
        action="REVERT",
        stageTag="Shortlisting Hold",
        remark=remark or "Revert",
        actor=auth,
        holdUntil="",
    )
    transition_candidate_status(
        db,
        candidate_id=candidate_id,
        requirement_id=requirement_id,
        to_status="NEW",
        action="SHORTLIST_HOLD_REVERT",
        stage_tag="Shortlisting Hold Revert",
        auth=auth,
        remark=remark or "Revert",
        patch={"holdUntil": ""},
        require_from={"HOLD"},
    )
    return {"ok": True, "status": "NEW"}


def hold_revert(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    remark = str((data or {}).get("remark") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    role = str(auth.role or "").upper()
    if role not in {"OWNER", "EA", "ADMIN"}:
        raise ApiError("FORBIDDEN", "Not allowed")

    assert_job_posting_complete(db, requirement_id)

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    if str(cand.status or "").upper() != "OWNER_HOLD":
        raise ApiError("BAD_REQUEST", "Candidate not in OWNER_HOLD")

    append_hold_log(
        db,
        candidateId=candidate_id,
        requirementId=requirement_id,
        action="REVERT",
        stageTag="Owner Hold",
        remark=remark or "Revert",
        actor=auth,
        holdUntil="",
    )
    transition_candidate_status(
        db,
        candidate_id=candidate_id,
        requirement_id=requirement_id,
        to_status="OWNER",
        action="HOLD_REVERT",
        stage_tag="Owner Hold Revert",
        auth=auth,
        remark=remark or "Revert",
        patch={"holdUntil": ""},
        require_from={"OWNER_HOLD"},
    )
    return {"ok": True, "status": "OWNER"}


def owner_candidates_list(data, auth: AuthContext | None, db, cfg):
    count_only = bool((data or {}).get("countOnly"))

    req_map = {}
    if not count_only:
        reqs = db.execute(select(Requirement.requirementId, Requirement.jobTitle, Requirement.jobRole)).all()
        req_map = {rid: {"jobTitle": jt or "", "jobRole": jr or ""} for rid, jt, jr in reqs}

    rows = (
        db.execute(select(Candidate).where(Candidate.status.in_(["OWNER", "OWNER_HOLD", "FINAL_OWNER_PENDING"])))
        .scalars()
        .all()
    )
    if not rows:
        return {"items": [], "total": 0} if count_only else {"items": [], "total": 0}

    approvals_count = 0
    final_count = 0
    items = []
    can_pii = bool(getattr(cfg, "PII_ENC_KEY", "").strip()) and bool(auth and auth.valid) and str(getattr(auth, "role", "") or "").upper() in set(getattr(cfg, "PII_VIEW_ROLES", []) or [])

    for c in rows:
        status = str(c.status or "").upper()
        if status in {"OWNER", "OWNER_HOLD"}:
            approvals_count += 1
        if status == "FINAL_OWNER_PENDING":
            final_count += 1
        if count_only:
            continue

        rm = req_map.get(c.requirementId, {})
        selected_tests = []
        raw = str(c.techSelectedTestsJson or "").strip()
        if raw:
            try:
                selected_tests = json.loads(raw)
            except Exception:
                selected_tests = []

        item = {
                "candidateId": c.candidateId,
                "requirementId": c.requirementId,
                "candidateName": c.candidateName,
                "jobRole": c.jobRole,
                "jobTitle": rm.get("jobTitle", ""),
                "mobile": c.mobile,
                "source": c.source,
                "cvFileId": c.cvFileId,
                "cvFileName": c.cvFileName,
                "status": c.status,
                "holdUntil": c.holdUntil or "",
                "onlineTestScore": c.onlineTestScore if c.onlineTestScore is not None else "",
                "onlineTestResult": c.onlineTestResult or "",
                "testDecisionsJson": c.testDecisionsJson or "",
                "candidate_test_failed_but_manually_continued": c.candidate_test_failed_but_manually_continued or False,
                "preInterviewMarks": c.preInterviewMarks or "",
                "inPersonMarks": c.inPersonMarks or "",
                "techSelectedTests": selected_tests,
                "tallyMarks": c.tallyMarks or "",
                "voiceMarks": c.voiceMarks or "",
                "techReview": c.techReview or "",
                "excelMarks": c.excelMarks or "",
                "excelReview": c.excelReview or "",
                "techResult": c.techResult or "",
                "techEvaluatedAt": c.techEvaluatedAt or "",
                "finalHoldAt": c.finalHoldAt or "",
                "finalHoldRemark": c.finalHoldRemark or "",
                "createdAt": c.createdAt or "",
                "createdBy": c.createdBy or "",
                "updatedAt": c.updatedAt or "",
                "updatedBy": c.updatedBy or "",
            }

        if can_pii:
            name_full = decrypt_pii(getattr(c, "name_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{c.candidateId}:name")
            mobile_full = decrypt_pii(getattr(c, "mobile_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{c.candidateId}:mobile")
            if name_full:
                item["candidateNameFull"] = name_full
            if mobile_full:
                item["mobileFull"] = mobile_full

        items.append(item)

    items.sort(key=lambda x: str(x.get("updatedAt") or ""), reverse=True)

    if count_only:
        return {"items": [], "total": approvals_count + final_count, "counts": {"approvals": approvals_count, "final": final_count}}

    return {"items": items, "total": len(items)}


def owner_final_decide(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    decision = str((data or {}).get("decision") or "").upper().strip()
    remark = str((data or {}).get("remark") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not decision:
        raise ApiError("BAD_REQUEST", "Missing decision")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status != "FINAL_OWNER_PENDING":
        raise ApiError("BAD_REQUEST", "Candidate not pending Owner final")

    now = iso_utc_now()

    if decision == "SELECT":
        transition_candidate_status(
            db,
            candidate_id=candidate_id,
            requirement_id=requirement_id,
            to_status="SELECTED",
            action="OWNER_FINAL_DECIDE",
            stage_tag="Final Select",
            auth=auth,
            remark=remark or "",
            require_from={"FINAL_OWNER_PENDING"},
        )
        return {"ok": True, "status": "SELECTED"}

    if decision == "REJECT":
        if not remark:
            raise ApiError("BAD_REQUEST", "Remark required")
        rej = reject_candidate_with_meta(
            db,
            candidate_id=candidate_id,
            requirement_id=requirement_id,
            stage_tag="Final Owner Reject",
            remark=remark,
            reason_code="FINAL_OWNER_REJECT",
            auth=auth,
            audit_action="OWNER_FINAL_DECIDE",
        )
        return rej

    if decision == "HOLD":
        append_hold_log(
            db,
            candidateId=candidate_id,
            requirementId=requirement_id,
            action="HOLD",
            stageTag="Final Hold",
            remark=remark or "Hold",
            actor=auth,
            holdUntil="",
        )
        transition_candidate_status(
            db,
            candidate_id=candidate_id,
            requirement_id=requirement_id,
            to_status="FINAL_HOLD",
            action="OWNER_FINAL_DECIDE",
            stage_tag="Final Hold",
            auth=auth,
            remark=remark or "",
            patch={"finalHoldAt": "", "finalHoldRemark": remark or ""},
            require_from={"FINAL_OWNER_PENDING"},
        )
        return {"ok": True, "status": "FINAL_HOLD"}

    raise ApiError("BAD_REQUEST", "Invalid decision")


def rejection_log_list(data, auth: AuthContext | None, db, cfg):
    reqs = db.execute(select(Requirement.requirementId, Requirement.jobTitle, Requirement.jobRole)).all()
    req_map = {rid: {"jobTitle": jt or "", "jobRole": jr or ""} for rid, jt, jr in reqs}

    logs = db.execute(select(RejectionLog)).scalars().all()
    logs_by_key: dict[str, list[dict]] = {}
    for l in logs:
        cid = str(l.candidateId or "").strip()
        rid = str(l.requirementId or "").strip()
        if not cid or not rid:
            continue
        k = f"{cid}|{rid}"
        logs_by_key.setdefault(k, []).append(
            {
                "logId": l.logId or "",
                "at": l.at or "",
                "stageTag": l.stageTag or "",
                "remark": l.remark or "",
                "actorRole": l.actorRole or "",
                "actorUserId": l.actorUserId or "",
                "rejectionType": l.rejectionType or "",
                "autoRejectCode": l.autoRejectCode or "",
            }
        )
    for k in logs_by_key:
        logs_by_key[k].sort(key=lambda x: str(x.get("at") or ""), reverse=True)

    cands = db.execute(select(Candidate).where(Candidate.status == "REJECTED")).scalars().all()
    items = []
    can_pii = bool(getattr(cfg, "PII_ENC_KEY", "").strip()) and bool(auth and auth.valid) and str(getattr(auth, "role", "") or "").upper() in set(getattr(cfg, "PII_VIEW_ROLES", []) or [])
    for c in cands:
        cid = str(c.candidateId or "").strip()
        rid = str(c.requirementId or "").strip()
        if not cid or not rid:
            continue
        rm = req_map.get(rid, {})
        job_role = str(c.jobRole or rm.get("jobRole", "")).strip()

        key2 = f"{cid}|{rid}"
        logs2 = logs_by_key.get(key2, [])
        latest = logs2[0] if logs2 else None

        item = {
                "candidateId": cid,
                "requirementId": rid,
                "candidateName": c.candidateName or "",
                "mobile": c.mobile or "",
                "source": c.source or "",
                "jobRole": job_role,
                "jobTitle": rm.get("jobTitle", ""),
                "status": c.status or "",
                "rejectedFromStatus": c.rejectedFromStatus or "",
                "rejectedReasonCode": c.rejectedReasonCode or "",
                "rejectedAt": c.rejectedAt or "",
                "updatedAt": c.updatedAt or "",
                "updatedBy": c.updatedBy or "",
                "rejectedStageTag": (latest or {}).get("stageTag", "") if latest else "",
                "rejectedRemark": (latest or {}).get("remark", "") if latest else "",
                "rejectedActorRole": (latest or {}).get("actorRole", "") if latest else "",
                "rejectedActorUserId": (latest or {}).get("actorUserId", "") if latest else "",
                "rejectionType": (latest or {}).get("rejectionType", "") if latest else "",
                "autoRejectCode": (latest or {}).get("autoRejectCode", "") if latest else "",
                "logs": logs2,
            }

        if can_pii:
            name_full = decrypt_pii(getattr(c, "name_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{cid}:name")
            mobile_full = decrypt_pii(getattr(c, "mobile_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{cid}:mobile")
            if name_full:
                item["candidateNameFull"] = name_full
            if mobile_full:
                item["mobileFull"] = mobile_full

        items.append(item)

    items.sort(key=lambda x: str(x.get("rejectedAt") or ""), reverse=True)
    return {"items": items, "total": len(items)}


def reject_revert(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    remark = str((data or {}).get("remark") or "").strip()
    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    status = str(cand.status or "").upper()
    if status != "REJECTED":
        raise ApiError("BAD_REQUEST", "Candidate not rejected")

    prev = str(cand.rejectedFromStatus or "").upper()
    reason = str(cand.rejectedReasonCode or "").upper()
    if not prev:
        raise ApiError("BAD_REQUEST", "Cannot revert (missing previous status)")

    role = str(auth.role or "").upper()
    allow = False
    if reason in {"ONLINE_TEST_FAIL", "ONLINE_TEST_FAIL_MANUAL"}:
        allow = role in {"ADMIN", "OWNER", "EA"}
    elif reason in {"TECH_FAIL", "TECH_FAIL_MANUAL"}:
        allow = role in {"ADMIN", "OWNER", "EA", "HR"}
    elif reason in {"INPERSON_LOW", "INPERSON_FAIL_MANUAL"}:
        allow = role in {"ADMIN", "OWNER", "EA"}
    else:
        allow = role == "ADMIN"

    if not allow:
        raise ApiError("FORBIDDEN", "Not allowed to revert this rejection")

    transition_candidate_status(
        db,
        candidate_id=candidate_id,
        requirement_id=requirement_id,
        to_status=prev,
        action="REJECT_REVERT",
        stage_tag="Reject Revert",
        auth=auth,
        remark=remark,
        patch={"rejectedFromStatus": "", "rejectedReasonCode": "", "rejectedAt": ""},
        require_from={"REJECTED"},
        meta={"reason": reason},
    )
    return {"ok": True, "status": prev}


def owner_decide(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    decision = str((data or {}).get("decision") or "").upper().strip()
    remark = str((data or {}).get("remark") or "").strip()
    hold_until_iso = str((data or {}).get("holdUntil") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not decision:
        raise ApiError("BAD_REQUEST", "Missing decision")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status not in {"OWNER", "OWNER_HOLD"}:
        raise ApiError("BAD_REQUEST", "Candidate not in Owner tab")

    if decision == "REJECT":
        if not remark:
            raise ApiError("BAD_REQUEST", "Remark required")
        rej = reject_candidate_with_meta(
            db,
            candidate_id=candidate_id,
            requirement_id=requirement_id,
            stage_tag="Owner Rejected before Walk-in",
            remark=remark,
            reason_code="OWNER_REJECT",
            auth=auth,
            audit_action="OWNER_DECIDE",
        )
        # Preserve legacy behavior (clear holdUntil).
        update_candidate(db, cand=cand, patch={"holdUntil": ""}, auth=auth)
        return rej

    if decision == "HOLD":
        if not hold_until_iso:
            raise ApiError("BAD_REQUEST", "Missing holdUntil")
        dt = parse_datetime_maybe(hold_until_iso, app_timezone=cfg.APP_TIMEZONE)
        if not dt:
            raise ApiError("BAD_REQUEST", "Invalid holdUntil")
        hold_until = to_iso_utc(dt)

        append_hold_log(
            db,
            candidateId=candidate_id,
            requirementId=requirement_id,
            action="HOLD",
            stageTag="Owner Hold",
            remark=remark or "Hold",
            actor=auth,
            holdUntil=hold_until,
        )
        transition_candidate_status(
            db,
            candidate_id=candidate_id,
            requirement_id=requirement_id,
            to_status="OWNER_HOLD",
            action="OWNER_DECIDE",
            stage_tag="Owner Hold",
            auth=auth,
            remark=remark or "Hold",
            patch={"holdUntil": hold_until},
            require_from={"OWNER", "OWNER_HOLD"},
        )
        return {"ok": True, "status": "OWNER_HOLD", "holdUntil": hold_until}

    if decision == "APPROVE_WALKIN":
        update_candidate(
            db,
            cand=cand,
            patch={
                "status": "WALKIN_PENDING",
                "holdUntil": "",
                "walkinAt": "",
                "walkinNotes": "",
                "notPickCount": 0,
                "preCallAt": "",
            },
            auth=auth,
        )
        append_audit(
            db,
            entityType="CANDIDATE",
            entityId=candidate_id,
            action="APPROVE_WALKIN",
            fromState=current_status,
            toState="WALKIN_PENDING",
            stageTag="OWNER_APPROVE_WALKIN",
            remark="",
            actor=auth,
            at=iso_utc_now(),
            meta={"requirementId": requirement_id},
        )
        return {"ok": True, "status": "WALKIN_PENDING"}

    raise ApiError("BAD_REQUEST", "Invalid decision")
