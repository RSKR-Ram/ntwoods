"""
Internal API Routes for Apply System (HRMS Use Only).

These endpoints are protected by:
- IP allowlist (INTERNAL_ALLOWED_IPS)
- HMAC signature verification

Endpoints:
- GET  /internal/applications       - List applications with filters
- GET  /internal/applications/{id}  - Get application details
- POST /internal/applications/{id}/approve - Approve and create candidate
- POST /internal/applications/{id}/reject  - Reject with remark
- GET  /internal/cv/{file_id}       - Download CV file
- GET  /internal/jobs               - Job tiles with counts
"""
from __future__ import annotations

import json
import os
from functools import wraps

from flask import Blueprint, Response, jsonify, request, send_file
from sqlalchemy import func, select

from db import get_db
from public_apply.models import PublicApply, PublicApplyAuditLog
from public_apply.security import (
    get_hmac_secret,
    is_ip_allowed,
    iso_utc_now,
    log_audit,
    verify_hmac_signature,
)
from storage import get_file_from_storage


internal_apply_bp = Blueprint("internal_apply", __name__, url_prefix="/internal")


# ============================================================================
# Security Decorators
# ============================================================================

def require_internal_auth(f):
    """
    Decorator to require internal API authentication.
    
    Checks:
    1. IP allowlist
    2. HMAC signature (X-Signature header)
    3. Timestamp freshness (X-Timestamp header)
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr

        # Check IP allowlist
        if not is_ip_allowed(ip):
            return jsonify({"success": False, "error": "Forbidden"}), 403

        # Check HMAC signature
        signature = request.headers.get("X-Signature", "").strip()
        timestamp_str = request.headers.get("X-Timestamp", "").strip()
        
        secret = get_hmac_secret()
        if secret:
            try:
                timestamp = int(timestamp_str)
            except (ValueError, TypeError):
                return jsonify({"success": False, "error": "Invalid timestamp"}), 401

            # Get request body as dict
            try:
                payload = request.get_json(force=True) or {}
            except Exception:
                payload = {}

            # For GET requests, use query params
            if request.method == "GET":
                payload = dict(request.args)

            ok, err = verify_hmac_signature(payload, signature, timestamp, secret)
            if not ok:
                return jsonify({"success": False, "error": err}), 401

        return f(*args, **kwargs)
    return decorated


# ============================================================================
# GET /internal/jobs - Job tiles with pending counts
# ============================================================================

@internal_apply_bp.route("/jobs", methods=["GET"])
@require_internal_auth
def list_jobs():
    """
    List unique job_public_codes with pending counts.
    
    Returns:
    {
        "success": true,
        "items": [
            {
                "job_public_code": "ACC-001",
                "position_title": "Senior Accountant",
                "pending_count": 5,
                "last_applied": "2026-01-30T12:00:00Z"
            }
        ]
    }
    """
    db = get_db()

    # Query unique jobs with pending counts
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
            "job_public_code": r.job_public_code or "GENERAL",
            "position_title": r.position_title or "",
            "pending_count": r.pending_count,
            "last_applied": r.last_applied or "",
        })

    # Add "All" tile
    total_count = sum(i["pending_count"] for i in items)

    return jsonify({
        "success": True,
        "items": items,
        "total_pending": total_count,
    })


# ============================================================================
# GET /internal/applications - List applications with filters
# ============================================================================

@internal_apply_bp.route("/applications", methods=["GET"])
@require_internal_auth
def list_applications():
    """
    List applications with optional filters.
    
    Query params:
    - status: PENDING (default), APPROVED, REJECTED, ALL
    - job: job_public_code filter
    - limit: max 100
    - offset: pagination
    
    Returns:
    {
        "success": true,
        "items": [...],
        "total": 100
    }
    """
    db = get_db()

    status = request.args.get("status", "PENDING").upper().strip()
    job = request.args.get("job", "").strip()
    limit = min(int(request.args.get("limit", 100) or 100), 100)
    offset = int(request.args.get("offset", 0) or 0)

    query = select(PublicApply)
    
    if status and status != "ALL":
        query = query.where(PublicApply.status == status)
    
    if job:
        query = query.where(PublicApply.job_public_code == job)

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = db.execute(count_query).scalar() or 0

    # Get paginated results
    query = query.order_by(PublicApply.applied_at.desc()).limit(limit).offset(offset)
    results = db.execute(query).scalars().all()

    items = []
    for app in results:
        items.append({
            "id": app.id,
            "status": app.status,
            "name": app.name_enc, # Unmasked for HR
            "name_masked": app.name_masked,
            "email_masked": app.email_masked,
            "mobile_masked": app.mobile_masked,
            "job_public_code": app.job_public_code,
            "position_title": app.position_title,
            "experience_years": app.experience_years,
            "current_location": app.current_location,
            "cv_file_id": app.cv_storage_key,
            "applied_at": app.applied_at,
            "source": app.source,
        })

    return jsonify({
        "success": True,
        "items": items,
        "total": total,
    })


# ============================================================================
# GET /internal/applications/{id} - Get application details
# ============================================================================

@internal_apply_bp.route("/applications/<apply_id>", methods=["GET"])
@require_internal_auth
def get_application(apply_id: str):
    """
    Get full application details (for HR review).
    
    Returns decrypted PII fields for authorized HRMS users.
    """
    db = get_db()

    app = db.execute(
        select(PublicApply).where(PublicApply.id == apply_id)
    ).scalar_one_or_none()

    if not app:
        return jsonify({"success": False, "error": "Application not found"}), 404

    return jsonify({
        "success": True,
        "application": {
            "id": app.id,
            "status": app.status,
            "name": app.name_enc,  # Decrypted for HRMS
            "email": app.email_enc,
            "mobile": app.mobile_enc,
            "job_public_code": app.job_public_code,
            "position_title": app.position_title,
            "experience_years": app.experience_years,
            "current_location": app.current_location,
            "cv_file_id": app.cv_storage_key,
            "cv_original_name": app.cv_original_name,
            "cv_mime_type": app.cv_mime_type,
            "remarks": app.remarks,
            "applied_at": app.applied_at,
            "source": app.source,
            "candidate_id": app.candidate_id,
            "selected_requirement_id": app.selected_requirement_id,
            "approved_at": app.approved_at,
            "approved_by": app.approved_by,
            "rejected_at": app.rejected_at,
            "rejected_by": app.rejected_by,
            "rejection_remark": app.rejection_remark,
        }
    })


# ============================================================================
# POST /internal/applications/{id}/approve - Approve and create candidate
# ============================================================================

@internal_apply_bp.route("/applications/<apply_id>/approve", methods=["POST"])
@require_internal_auth
def approve_application(apply_id: str):
    """
    Approve an application and trigger HRMS candidate creation.
    
    Request JSON:
    {
        "requirement_id": "REQ-2026-001",  # Required: HRMS requirement to add candidate to
        "hr_user": "user@company.com"      # Required: approving user
    }
    
    Flow:
    1. Mark application APPROVED
    2. Call HRMS internal API to upsert candidate
    3. Call HRMS to add candidate to requirement's SHORTLISTING stage
    4. Return candidate_id
    """
    db = get_db()

    try:
        data = request.get_json(force=True) or {}
    except Exception:
        return jsonify({"success": False, "error": "Invalid request body"}), 400

    requirement_id = str(data.get("requirement_id", "") or "").strip()
    hr_user = str(data.get("hr_user", "") or "").strip()

    if not requirement_id:
        return jsonify({"success": False, "error": "requirement_id is required"}), 400
    if not hr_user:
        return jsonify({"success": False, "error": "hr_user is required"}), 400

    # Get application
    app = db.execute(
        select(PublicApply).where(PublicApply.id == apply_id)
    ).scalar_one_or_none()

    if not app:
        return jsonify({"success": False, "error": "Application not found"}), 404

    if app.status != "PENDING":
        return jsonify({"success": False, "error": f"Application already {app.status}"}), 400

    now = iso_utc_now()

    # Call HRMS to upsert candidate (via hrms_client)
    try:
        from public_apply.hrms_client import add_to_shortlisting, upsert_candidate

        # Upsert candidate (dedupe by email/mobile)
        candidate_result = upsert_candidate({
            "name": app.name_enc,
            "email": app.email_enc,
            "mobile": app.mobile_enc,
            "email_hash": app.email_hash,
            "mobile_hash": app.mobile_hash,
            "cv_file_id": app.cv_storage_key,
            "cv_file_name": app.cv_original_name,
            "source": app.source,
            "experience_years": app.experience_years,
            "current_location": app.current_location,
        })
        
        candidate_id = candidate_result.get("candidate_id")
        is_new = candidate_result.get("is_new", True)

        # Add to requirement's SHORTLISTING stage
        add_to_shortlisting(requirement_id, candidate_id)

    except Exception as e:
        log_audit(db, "APPROVE", "FAILED", apply_id=apply_id,
                  details={"error": str(e), "requirement_id": requirement_id})
        db.commit()
        return jsonify({"success": False, "error": f"HRMS integration failed: {str(e)}"}), 500

    # Update application
    app.status = "APPROVED"
    app.candidate_id = candidate_id
    app.selected_requirement_id = requirement_id
    app.approved_at = now
    app.approved_by = hr_user
    app.updated_at = now

    log_audit(db, "APPROVE", "SUCCESS", apply_id=apply_id,
              details={
                  "candidate_id": candidate_id,
                  "requirement_id": requirement_id,
                  "is_new_candidate": is_new,
              })
    
    db.commit()

    return jsonify({
        "success": True,
        "candidate_id": candidate_id,
        "is_new_candidate": is_new,
    })


# ============================================================================
# POST /internal/applications/{id}/reject - Reject with remark
# ============================================================================

@internal_apply_bp.route("/applications/<apply_id>/reject", methods=["POST"])
@require_internal_auth
def reject_application(apply_id: str):
    """
    Reject an application with mandatory remark.
    
    Request JSON:
    {
        "remark": "Not qualified for position",  # Required
        "hr_user": "user@company.com"            # Required
    }
    """
    db = get_db()

    try:
        data = request.get_json(force=True) or {}
    except Exception:
        return jsonify({"success": False, "error": "Invalid request body"}), 400

    remark = str(data.get("remark", "") or "").strip()
    hr_user = str(data.get("hr_user", "") or "").strip()

    if not remark:
        return jsonify({"success": False, "error": "Remark is required"}), 400
    if not hr_user:
        return jsonify({"success": False, "error": "hr_user is required"}), 400

    # Get application
    app = db.execute(
        select(PublicApply).where(PublicApply.id == apply_id)
    ).scalar_one_or_none()

    if not app:
        return jsonify({"success": False, "error": "Application not found"}), 404

    if app.status != "PENDING":
        return jsonify({"success": False, "error": f"Application already {app.status}"}), 400

    now = iso_utc_now()

    # Update application
    app.status = "REJECTED"
    app.rejected_at = now
    app.rejected_by = hr_user
    app.rejection_remark = remark
    app.updated_at = now

    log_audit(db, "REJECT", "SUCCESS", apply_id=apply_id,
              details={"remark": remark[:100]})  # Truncate for log
    
    db.commit()

    return jsonify({"success": True})


# ============================================================================
# GET /internal/cv/{file_id} - Download CV file
# ============================================================================

@internal_apply_bp.route("/cv/<file_id>", methods=["GET"])
@require_internal_auth
def download_cv(file_id: str):
    """
    Download CV file for HRMS review.
    
    Returns the file as binary stream.
    """
    if not file_id or ".." in file_id or "/" in file_id:
        return jsonify({"success": False, "error": "Invalid file ID"}), 400

    try:
        # Get file from storage
        file_data, content_type = get_file_from_storage(file_id)
        
        # Determine filename for download
        original_name = file_id.split("_")[-1] if "_" in file_id else file_id
        
        return Response(
            file_data,
            mimetype=content_type or "application/octet-stream",
            headers={
                "Content-Disposition": f"inline; filename=\"{original_name}\"",
                "Cache-Control": "private, max-age=3600",
            }
        )
    except FileNotFoundError:
        return jsonify({"success": False, "error": "File not found"}), 404
    except Exception as e:
        return jsonify({"success": False, "error": "Download failed"}), 500


# ============================================================================
# GET /internal/audit/{apply_id} - Audit log for application
# ============================================================================

@internal_apply_bp.route("/audit/<apply_id>", methods=["GET"])
@require_internal_auth
def get_audit_log(apply_id: str):
    """
    Get audit log for an application.
    """
    db = get_db()

    logs = db.execute(
        select(PublicApplyAuditLog)
        .where(PublicApplyAuditLog.apply_id == apply_id)
        .order_by(PublicApplyAuditLog.timestamp.desc())
        .limit(50)
    ).scalars().all()

    items = []
    for log in logs:
        items.append({
            "timestamp": log.timestamp,
            "action": log.action,
            "result": log.result,
            "ip_address": log.ip_address,
            "details": json.loads(log.details) if log.details else {},
        })

    return jsonify({
        "success": True,
        "items": items,
    })
