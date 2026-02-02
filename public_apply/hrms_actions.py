"""
HRMS Actions for Public Apply Integration.

These actions are called from the Flask action dispatcher for:
- Listing applications from the Apply Inbox
- Getting application details
- Approving applications (triggers candidate creation)
- Rejecting applications
- Getting audit logs

All actions require HR or ADMIN role via RBAC.
"""
from __future__ import annotations

import json
from typing import Any

from sqlalchemy import func, or_, select

from public_apply.models import PublicApply, PublicApplyAuditLog
from public_apply.security import iso_utc_now, log_audit, sha256_hash
import uuid
from datetime import datetime, timezone


def _parse_date_filter(value: str, *, end_of_day: bool) -> str:
    """
    Accepts:
      - YYYY-MM-DD
      - ISO timestamp (with/without Z)
    Returns ISO-UTC string suitable for lexicographic comparisons against stored ISO strings.
    """

    raw = str(value or "").strip()
    if not raw:
        return ""

    # Date-only input.
    if len(raw) == 10 and raw[4] == "-" and raw[7] == "-":
        try:
            yyyy = int(raw[0:4])
            mm = int(raw[5:7])
            dd = int(raw[8:10])
            if end_of_day:
                dt = datetime(yyyy, mm, dd, 23, 59, 59, 999000, tzinfo=timezone.utc)
            else:
                dt = datetime(yyyy, mm, dd, 0, 0, 0, 0, tzinfo=timezone.utc)
            return dt.isoformat().replace("+00:00", "Z")
        except Exception:
            return ""

    # ISO-ish input.
    try:
        s = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    except Exception:
        return ""


def list_job_tiles(db) -> dict:
    """
    List unique job_public_codes with pending application counts.
    
    Returns:
        {
            items: [{job_public_code, position_title, pending_count, last_applied}],
            total_pending: int
        }
    """
    results = db.execute(
        select(
            PublicApply.job_public_code,
            PublicApply.position_title,
            func.count(PublicApply.id).label("pending_count"),
            func.max(PublicApply.applied_at).label("last_applied")
        )
        .where(PublicApply.status == "PENDING")
        .group_by(PublicApply.job_public_code, PublicApply.position_title)
        .order_by(func.count(PublicApply.id).desc())
    ).all()

    items = []
    for r in results:
        items.append({
            "jobPublicCode": r.job_public_code or "GENERAL",
            "positionTitle": r.position_title or "General Application",
            "pendingCount": r.pending_count,
            "lastApplied": r.last_applied or "",
        })

    total = sum(i["pendingCount"] for i in items)

    return {"items": items, "totalPending": total}


def list_pending_applications(
    db,
    limit: int = 100,
    offset: int = 0,
    job_filter: str = "",
    status_filter: str = "PENDING",
    q: str = "",
    applied_from: str = "",
    applied_to: str = "",
    position_filter: str = "",
    source_filter: str = "",
    has_cv: bool | None = None,
    exp_min: float | None = None,
    exp_max: float | None = None,
) -> dict:
    """
    List applications with optional filters.
    
    Args:
        db: Database session
        limit: Max results (default 100)
        offset: Pagination offset
        job_filter: Filter by job_public_code
        status_filter: Filter by status (default PENDING)
    
    Returns:
        {items: [...], total: int}
    """
    query = select(PublicApply)
    
    if status_filter and status_filter.upper() != "ALL":
        query = query.where(PublicApply.status == status_filter.upper())
    
    if job_filter:
        query = query.where(PublicApply.job_public_code == job_filter)

    if position_filter:
        query = query.where(PublicApply.position_title == position_filter)

    if source_filter:
        query = query.where(PublicApply.source == source_filter)

    if has_cv is True:
        query = query.where(PublicApply.cv_storage_key != "")
    elif has_cv is False:
        query = query.where(or_(PublicApply.cv_storage_key == "", PublicApply.cv_storage_key.is_(None)))

    if exp_min is not None:
        try:
            query = query.where(PublicApply.experience_years >= float(exp_min))
        except Exception:
            pass
    if exp_max is not None:
        try:
            query = query.where(PublicApply.experience_years <= float(exp_max))
        except Exception:
            pass

    # Applied-at range (stored as ISO string).
    af = _parse_date_filter(applied_from, end_of_day=False)
    at = _parse_date_filter(applied_to, end_of_day=True)
    if af:
        query = query.where(PublicApply.applied_at >= af)
    if at:
        query = query.where(PublicApply.applied_at <= at)

    qraw = str(q or "").strip()
    if qraw:
        like = f"%{qraw}%"
        query = query.where(
            or_(
                PublicApply.name_enc.ilike(like),
                PublicApply.email_enc.ilike(like),
                PublicApply.mobile_enc.ilike(like),
                PublicApply.position_title.ilike(like),
                PublicApply.current_location.ilike(like),
                PublicApply.job_public_code.ilike(like),
                PublicApply.source.ilike(like),
            )
        )

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = db.execute(count_query).scalar() or 0

    # Get paginated results
    query = query.order_by(PublicApply.applied_at.desc()).limit(limit).offset(offset)
    results = db.execute(query).scalars().all()

    items = []
    for app in results:
        items.append({
            "applyId": app.id,
            "status": app.status,
            # Apply Inbox is an HR-only internal UI; return normal values for display.
            # (Fallbacks: frontend still has *Masked fields for safer rendering when needed.)
            "name": app.name_enc,
            "email": app.email_enc,
            "mobile": app.mobile_enc,
            "nameMasked": app.name_masked,
            "emailMasked": app.email_masked,
            "mobileMasked": app.mobile_masked,
            "jobPublicCode": app.job_public_code,
            "positionTitle": app.position_title,
            "experienceYears": app.experience_years,
            "currentLocation": app.current_location,
            "cvFileId": app.cv_storage_key,
            "appliedAt": app.applied_at,
            "source": app.source,
        })

    return {"items": items, "total": total}


def get_application_details(db, apply_id: str) -> dict:
    """
    Get full application details for HR review.
    
    Returns decrypted PII for authorized users.
    """
    app = db.execute(
        select(PublicApply).where(PublicApply.id == apply_id)
    ).scalar_one_or_none()

    if not app:
        raise ValueError("Application not found")

    return {
        "applyId": app.id,
        "status": app.status,
        "name": app.name_enc,
        "email": app.email_enc,
        "mobile": app.mobile_enc,
        "jobPublicCode": app.job_public_code,
        "positionTitle": app.position_title,
        "experienceYears": app.experience_years,
        "currentLocation": app.current_location,
        "cvFileId": app.cv_storage_key,
        "cvOriginalName": app.cv_original_name,
        "cvMimeType": app.cv_mime_type,
        "remarks": app.remarks,
        "appliedAt": app.applied_at,
        "source": app.source,
        "candidateId": app.candidate_id,
        "selectedRequirementId": app.selected_requirement_id,
        "approvedAt": app.approved_at,
        "approvedBy": app.approved_by,
        "rejectedAt": app.rejected_at,
        "rejectedBy": app.rejected_by,
        "rejectionRemark": app.rejection_remark,
    }


def approve_application(db, apply_id: str, requirement_id: str, user_id: str) -> dict:
    """
    Approve an application and create/link candidate in HRMS.
    
    Flow:
    1. Validate application is PENDING
    2. Check for existing candidate (dedupe by email/mobile)
    3. Create or update candidate
    4. Add candidate to requirement's SHORTLISTING stage
    5. Mark application APPROVED
    
    Returns:
        {candidateId: str, isNew: bool, isExisting: bool}
    """
    from models import Candidate, CandidateMaster, CandidateIdentity
    
    app = db.execute(
        select(PublicApply).where(PublicApply.id == apply_id)
    ).scalar_one_or_none()

    if not app:
        raise ValueError("Application not found")
    
    if app.status != "PENDING":
        raise ValueError(f"Application already {app.status}")

    if not requirement_id:
        raise ValueError("Requirement ID is required")

    now = iso_utc_now()
    year = datetime.now(timezone.utc).year

    # Dedupe via CandidateIdentity (Master lookup)
    master_id = None
    match_by = ""

    # Check Email Identity
    if app.email_hash:
        ident = db.execute(
            select(CandidateIdentity).where(
                CandidateIdentity.identityType == "EMAIL_HASH",
                CandidateIdentity.normalizedValue == app.email_hash,
                CandidateIdentity.active == True
            )
        ).scalar_one_or_none()
        if ident:
            master_id = ident.candidateMasterId
            match_by = "email"

    # Check Mobile Identity if not found
    if not master_id and app.mobile_hash:
        ident = db.execute(
            select(CandidateIdentity).where(
                CandidateIdentity.identityType == "PHONE_HASH",
                CandidateIdentity.normalizedValue == app.mobile_hash,
                CandidateIdentity.active == True
            )
        ).scalar_one_or_none()
        if ident:
            master_id = ident.candidateMasterId
            match_by = "mobile"

    # Generate new Candidate ID (always create new application instance)
    c_uid = uuid.uuid4().hex[:8].upper()
    candidate_id = f"C-{year}-{c_uid}"

    is_new_person = False

    if master_id:
        # EXISTING PERSON: Link new Candidate to existing Master
        is_new_person = False
    else:
        # NEW PERSON: Create Master + Identities
        is_new_person = True
        master_id = f"CM-{year}-{c_uid}"
        
        # Create Master
        master = CandidateMaster(
            candidateMasterId=master_id,
            status="ACTIVE",
            name_masked=app.name_masked,
            mobile_masked=app.mobile_masked,
            name_enc=app.name_enc,
            mobile_enc=app.mobile_enc,
            name_hash=sha256_hash(app.name_enc),
            mobile_hash=app.mobile_hash,
            # Source not in CandidateMaster
            createdAt=now,
            createdBy=user_id,
            updatedAt=now,
            updatedBy=user_id,
        )
        db.add(master)

        # Create Identities
        if app.email_hash:
            db.add(CandidateIdentity(
                candidateMasterId=master_id,
                identityType="EMAIL_HASH",
                normalizedValue=app.email_hash,
                active=True,
                createdAt=now,
                createdBy=user_id
            ))
        
        if app.mobile_hash:
            db.add(CandidateIdentity(
                candidateMasterId=master_id,
                identityType="PHONE_HASH",
                normalizedValue=app.mobile_hash,
                active=True,
                createdAt=now,
                createdBy=user_id
            ))

    # Create Candidate (Application Instance)
    # Note: Linked to master_id (new or existing)
    candidate = Candidate(
        candidateId=candidate_id,
        candidateMasterId=master_id,
        requirementId=requirement_id,
        # Store the "normal" values for HR workflows (stage UIs commonly read these fields).
        # Full PII is also stored in *_enc for future encryption-at-rest improvements.
        candidateName=app.name_enc,
        mobile=app.mobile_enc,
        name_masked=app.name_masked,
        mobile_masked=app.mobile_masked,
        name_enc=app.name_enc,
        mobile_enc=app.mobile_enc,
        name_hash=sha256_hash(app.name_enc),
        mobile_hash=app.mobile_hash,
        source=app.source,
        status="NEW",
        candidateStage="SHORTLISTING",
        cvFileId=app.cv_storage_key,
        cvFileName=app.cv_original_name,
        createdAt=now,
        createdBy=user_id,
        updatedAt=now,
        updatedBy=user_id,
    )
    db.add(candidate)
    
    is_new = is_new_person # Return value compatibility

    # Update application
    app.status = "APPROVED"
    app.candidate_id = candidate_id
    app.selected_requirement_id = requirement_id
    app.approved_at = now
    app.approved_by = user_id
    app.updated_at = now

    log_audit(db, "APPROVE", "SUCCESS", apply_id=apply_id,
              details={
                  "candidate_id": candidate_id,
                  "requirement_id": requirement_id,
                  "is_new": is_new,
                  "match_by": match_by,
              })
    
    db.commit()

    return {
        "candidateId": candidate_id,
        "isNew": is_new,
        "isExisting": not is_new,
        "matchBy": match_by,
    }


def reject_application(db, apply_id: str, remark: str, user_id: str) -> dict:
    """
    Reject an application with mandatory remark.
    """
    app = db.execute(
        select(PublicApply).where(PublicApply.id == apply_id)
    ).scalar_one_or_none()

    if not app:
        raise ValueError("Application not found")

    if app.status != "PENDING":
        raise ValueError(f"Application already {app.status}")

    if not remark or not str(remark).strip():
        raise ValueError("Remark is required")

    now = iso_utc_now()

    app.status = "REJECTED"
    app.rejected_at = now
    app.rejected_by = user_id
    app.rejection_remark = remark.strip()[:1000]
    app.updated_at = now

    log_audit(db, "REJECT", "SUCCESS", apply_id=apply_id,
              details={"remark": remark[:100]})
    
    db.commit()

    return {"success": True}


def get_apply_audit_log(db, apply_id: str, limit: int = 50) -> dict:
    """
    Get audit log for an application.
    """
    logs = db.execute(
        select(PublicApplyAuditLog)
        .where(PublicApplyAuditLog.apply_id == apply_id)
        .order_by(PublicApplyAuditLog.timestamp.desc())
        .limit(limit)
    ).scalars().all()

    items = []
    for log in logs:
        items.append({
            "timestamp": log.timestamp,
            "action": log.action,
            "result": log.result,
            "ipAddress": log.ip_address,
            "details": json.loads(log.details) if log.details else {},
        })

    return {"items": items}


def list_open_requirements(db) -> list[dict]:
    """
    Get list of open requirements for HR to select when approving.
    
    Returns requirements with status APPROVED and vacancy > 0.
    """
    from models import Requirement
    
    results = db.execute(
        select(Requirement)
        .where(Requirement.status == "APPROVED")
        .order_by(Requirement.createdAt.desc())
        .limit(100)
    ).scalars().all()

    items = []
    for req in results:
        items.append({
            "requirementId": req.requirementId,
            "jobTitle": req.jobTitle or req.templateId or "",
            "department": getattr(req, "department", "") or "",
            "vacancy": getattr(req, "vacancy", 1) or 1,
            "status": req.status,
        })

    return items
