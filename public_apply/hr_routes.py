"""
HR Routes for Public Apply System (Authenticated via User Token).

These endpoints are for the React Frontend usage by HR users.
"""
from __future__ import annotations

from flask import Blueprint, Response, request, jsonify
from sqlalchemy import select

from db import SessionLocal
from auth import validate_session_token, assert_permission
from storage import get_file_from_storage

hr_apply_bp = Blueprint("hr_apply", __name__, url_prefix="/api/hr/apply")


@hr_apply_bp.route("/cv/<file_id>", methods=["GET"])
def download_cv_hr(file_id: str):
    """
    Download CV using session token (cookie/query param).
    Used by frontend window.open().
    """
    token = request.args.get("token", "").strip()
    if not token:
        return "Missing token", 401

    if SessionLocal is None:
        return "DB not initialized", 500

    db = SessionLocal()
    try:
        # 1. Verify Session
        auth_ctx = validate_session_token(db, token)
        if not auth_ctx.valid:
            return "Invalid or expired session", 401
        
        # 2. Check Permission
        try:
            assert_permission(db, auth_ctx.role, "PUBLIC_APPLY_GET")
        except Exception:
            return "Forbidden: insufficient permissions", 403

        # 3. Validate File ID
        if not file_id or ".." in file_id or "/" in file_id:
            return "Invalid file ID", 400

        # 4. Download File
        try:
            # Get file from storage
            file_data, content_type = get_file_from_storage(file_id)
            
            # Determine filename
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
            return "File not found", 404
        except Exception as e:
            return f"Download failed: {str(e)}", 500
    finally:
        db.close()
