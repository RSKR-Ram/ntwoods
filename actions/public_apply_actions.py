"""
Public Apply Action Handlers for HRMS.

These handlers are registered in the action dispatcher and called from
the HRMS frontend for the Apply Inbox feature.

All actions require HR or ADMIN role via RBAC.
"""
from __future__ import annotations

from typing import Any

from utils import ApiError, AuthContext

from public_apply.hrms_actions import (
    approve_application,
    get_application_details,
    get_apply_audit_log,
    list_job_tiles,
    list_open_requirements,
    list_pending_applications,
    reject_application,
)


def public_apply_job_tiles(data: dict[str, Any], auth: AuthContext | None, db, cfg) -> dict:
    """
    List job tiles with pending application counts.
    
    Returns: {items: [...], totalPending: int}
    """
    return list_job_tiles(db)


def public_apply_list(data: dict[str, Any], auth: AuthContext | None, db, cfg) -> dict:
    """
    List applications with filters.
    
    Data: {limit?, offset?, jobFilter?, statusFilter?}
    Returns: {items: [...], total: int}
    """
    limit = int(data.get("limit", 100) or 100)
    offset = int(data.get("offset", 0) or 0)
    job_filter = str(data.get("jobFilter", "") or "").strip()
    status_filter = str(data.get("statusFilter", "PENDING") or "PENDING").strip()

    q = str(data.get("q", "") or "").strip()
    applied_from = str(data.get("appliedFrom", "") or "").strip()
    applied_to = str(data.get("appliedTo", "") or "").strip()
    position_filter = str(data.get("position", "") or "").strip()
    source_filter = str(data.get("source", "") or "").strip()

    has_cv_raw = data.get("hasCv", None)
    has_cv = None
    if has_cv_raw is True or str(has_cv_raw).strip().lower() in {"1", "true", "yes", "y", "on"}:
        has_cv = True
    elif has_cv_raw is False or str(has_cv_raw).strip().lower() in {"0", "false", "no", "n", "off"}:
        has_cv = False

    exp_min_raw = data.get("expMin", None)
    exp_max_raw = data.get("expMax", None)
    exp_min = None
    exp_max = None
    try:
        if exp_min_raw is not None and str(exp_min_raw).strip() != "":
            exp_min = float(exp_min_raw)
    except Exception:
        exp_min = None
    try:
        if exp_max_raw is not None and str(exp_max_raw).strip() != "":
            exp_max = float(exp_max_raw)
    except Exception:
        exp_max = None
    
    return list_pending_applications(
        db,
        limit=limit,
        offset=offset,
        job_filter=job_filter,
        status_filter=status_filter,
        q=q,
        applied_from=applied_from,
        applied_to=applied_to,
        position_filter=position_filter,
        source_filter=source_filter,
        has_cv=has_cv,
        exp_min=exp_min,
        exp_max=exp_max,
    )


def public_apply_get(data: dict[str, Any], auth: AuthContext | None, db, cfg) -> dict:
    """
    Get application details.
    
    Data: {applyId: str}
    Returns: {applyId, status, name, email, ...}
    """
    apply_id = str(data.get("applyId", "") or "").strip()
    if not apply_id:
        raise ApiError("BAD_REQUEST", "applyId is required")
    
    return get_application_details(db, apply_id)


def public_apply_approve(data: dict[str, Any], auth: AuthContext | None, db, cfg) -> dict:
    """
    Approve an application.
    
    Data: {applyId: str, requirementId: str}
    Returns: {candidateId, isNew, isExisting}
    """
    apply_id = str(data.get("applyId", "") or "").strip()
    requirement_id = str(data.get("requirementId", "") or "").strip()
    
    if not apply_id:
        raise ApiError("BAD_REQUEST", "applyId is required")
    if not requirement_id:
        raise ApiError("BAD_REQUEST", "requirementId is required")
    
    user_id = auth.userId if auth else "SYSTEM"
    
    try:
        return approve_application(db, apply_id, requirement_id, user_id)
    except ValueError as e:
        raise ApiError("BAD_REQUEST", str(e))


def public_apply_reject(data: dict[str, Any], auth: AuthContext | None, db, cfg) -> dict:
    """
    Reject an application.
    
    Data: {applyId: str, remark: str}
    Returns: {success: bool}
    """
    apply_id = str(data.get("applyId", "") or "").strip()
    remark = str(data.get("remark", "") or "").strip()
    
    if not apply_id:
        raise ApiError("BAD_REQUEST", "applyId is required")
    if not remark:
        raise ApiError("BAD_REQUEST", "remark is required")
    
    user_id = auth.userId if auth else "SYSTEM"
    
    try:
        return reject_application(db, apply_id, remark, user_id)
    except ValueError as e:
        raise ApiError("BAD_REQUEST", str(e))


def public_apply_audit_log(data: dict[str, Any], auth: AuthContext | None, db, cfg) -> dict:
    """
    Get audit log for an application.
    
    Data: {applyId: str}
    Returns: {items: [...]}
    """
    apply_id = str(data.get("applyId", "") or "").strip()
    if not apply_id:
        raise ApiError("BAD_REQUEST", "applyId is required")
    
    return get_apply_audit_log(db, apply_id)


def public_apply_requirements(data: dict[str, Any], auth: AuthContext | None, db, cfg) -> dict:
    """
    List open requirements for HR to select when approving.
    
    Returns: {items: [...]}
    """
    items = list_open_requirements(db)
    return {"items": items}
