"""
Public Apply API Routes (Option-2: No OTP).

Public endpoints:
- POST /v1/apply/init      - Create/update application with Turnstile + rate limiting
- POST /v1/apply/upload-cv - Upload CV file to private storage

Security:
- Cloudflare Turnstile CAPTCHA (server-verified)
- Rate limiting: IP (5/hour) + Email (1/24h)
- Honeypot + timing trap for bot detection
- CORS only allows configured origins
"""
from __future__ import annotations

import os
import uuid

from flask import Blueprint, jsonify, request

from db import SessionLocal
from public_apply.models import PublicApply
from public_apply.security import (
    HONEYPOT_FIELD,
    check_apply_rate_limits,
    find_existing_application,
    generate_cv_storage_key,
    hmac_hash,
    iso_utc_now,
    log_audit,
    mask_email,
    mask_mobile,
    sha256_hash,
    unix_timestamp_ms,
    validate_bot_traps,
    validate_cv_file,
    verify_turnstile,
)

# Storage service
from storage import upload_file_to_storage


public_apply_bp = Blueprint("public_apply", __name__, url_prefix="/api/v1/apply")


# ============================================================================
# Helpers
# ============================================================================

def json_success(data: dict | None = None, status: int = 200):
    resp = {"success": True}
    if data:
        resp.update(data)
    return jsonify(resp), status


def json_error(msg: str, status: int = 400):
    return jsonify({"success": False, "error": msg}), status


def get_client_ip() -> str:
    """Get client IP from X-Forwarded-For or remote_addr."""
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or ""


def get_pepper() -> str:
    """Get pepper for hashing."""
    return os.getenv("PEPPER", "dev-pepper")


def validate_email(email: str) -> tuple[bool, str]:
    """Validate email format."""
    e = str(email or "").strip().lower()
    if not e:
        return False, "Email is required"
    if "@" not in e or len(e) < 5 or len(e) > 100:
        return False, "Invalid email format"
    return True, e


def validate_name(name: str) -> tuple[bool, str]:
    """Validate candidate name."""
    n = str(name or "").strip()
    if not n:
        return False, "Name is required"
    if len(n) < 2:
        return False, "Name too short"
    if len(n) > 100:
        return False, "Name too long"
    return True, n


def validate_mobile(mobile: str) -> tuple[bool, str]:
    """Validate mobile (optional)."""
    m = str(mobile or "").strip().replace(" ", "").replace("-", "")
    if not m:
        return True, ""  # Optional
    if len(m) != 10 or not m.isdigit():
        return False, "Invalid mobile number"
    return True, m


def generate_apply_id() -> str:
    """Generate unique application ID: PA-2026-XXXXX"""
    from datetime import datetime, timezone
    year = datetime.now(timezone.utc).year
    uid = uuid.uuid4().hex[:8].upper()
    return f"PA-{year}-{uid}"


# ============================================================================
# POST /v1/apply/init
# ============================================================================

@public_apply_bp.route("/init", methods=["POST"])
def apply_init():
    """
    Initialize or update an application.
    
    Request JSON:
    {
        "turnstile_token": "...",     # Cloudflare Turnstile token
        "name": "John Doe",           # Required
        "email": "john@example.com",  # Required (for rate limiting)
        "mobile": "9876543210",       # Optional
        "job_public_code": "ACC-001", # Job/position code
        "position_title": "Senior Accountant",  # Position name
        "_hp_check": "",              # Honeypot (must be empty)
        "_timestamp": 1234567890123   # Form load timestamp (ms)
    }
    
    Returns:
    {
        "success": true,
        "apply_id": "PA-2026-XXXXXXXX",
        "email_masked": "jo***@example.com",
        "is_update": false
    }
    """
    ip = get_client_ip()
    user_agent = request.headers.get("User-Agent", "")[:500]
    
    try:
        data = request.get_json(force=True) or {}
    except Exception:
        return json_error("Invalid request body")

    db = SessionLocal()

    # 1. Verify Turnstile CAPTCHA
    turnstile_token = str(data.get("turnstile_token", "") or "").strip()
    ok, err = verify_turnstile(turnstile_token, ip)
    if not ok:
        log_audit(db, "CAPTCHA_FAIL", "BLOCKED", ip_address=ip, 
                  details={"error": err}, user_agent=user_agent)
        db.commit()
        return json_error("Please complete the CAPTCHA")

    # 2. Validate honeypot + timing (bot detection)
    honeypot_value = str(data.get(HONEYPOT_FIELD, "") or "")
    form_timestamp = data.get("_timestamp", "")
    ok, err = validate_bot_traps(honeypot_value, form_timestamp)
    if not ok:
        # Log but return generic error
        log_audit(db, "BOT_DETECTED", "BLOCKED", ip_address=ip,
                  details={"reason": err}, user_agent=user_agent)
        db.commit()
        return json_error("Submission failed. Please try again.")

    # 3. Validate inputs
    ok, name = validate_name(data.get("name"))
    if not ok:
        return json_error(name)

    ok, email = validate_email(data.get("email"))
    if not ok:
        return json_error(email)

    ok, mobile = validate_mobile(data.get("mobile"))
    if not ok:
        return json_error(mobile)

    job_public_code = str(data.get("job_public_code", "") or "").strip()[:100]
    position_title = str(data.get("position_title", "") or "").strip()[:200]
    
    # Legacy field support
    job_role = str(data.get("job_role", "") or "").strip()[:100]
    if not position_title and job_role:
        position_title = job_role

    # 4. Hash for rate limiting and dedupe
    pepper = get_pepper()
    email_hash = hmac_hash(email.lower(), pepper) if email else ""
    mobile_hash = hmac_hash(mobile, pepper) if mobile else ""

    # 5. Check rate limits
    ok, err = check_apply_rate_limits(db, ip, email_hash)
    if not ok:
        log_audit(db, "RATE_LIMIT", "BLOCKED", ip_address=ip,
                  email_masked=mask_email(email), details={"error": err}, user_agent=user_agent)
        db.commit()
        return json_error(err, 429)

    # 6. Check for existing application (dedupe)
    existing_id = find_existing_application(db, email_hash, job_public_code)
    now = iso_utc_now()
    
    if existing_id:
        # Update existing application
        from sqlalchemy import select
        app = db.execute(select(PublicApply).where(PublicApply.id == existing_id)).scalar_one()
        
        # Update mutable fields
        app.name_enc = name  # In production: encrypt
        app.name_masked = name[:2] + "***" if len(name) > 2 else name
        app.mobile_hash = mobile_hash
        app.mobile_enc = mobile
        app.mobile_masked = mask_mobile(mobile)
        app.position_title = position_title
        app.job_role = job_role
        app.applied_at = now
        app.updated_at = now
        app.applied_ip = ip
        app.applied_user_agent = user_agent
        app.turnstile_verified = True
        app.honeypot_passed = True
        
        apply_id = existing_id
        is_update = True
    else:
        # Create new application
        apply_id = generate_apply_id()
        
        app = PublicApply(
            id=apply_id,
            status="PENDING",
            name_enc=name,
            name_masked=name[:2] + "***" if len(name) > 2 else name,
            email_hash=email_hash,
            email_enc=email,
            email_masked=mask_email(email),
            mobile_hash=mobile_hash,
            mobile_enc=mobile,
            mobile_masked=mask_mobile(mobile),
            job_public_code=job_public_code,
            position_title=position_title,
            job_role=job_role,
            source="PUBLIC_APPLY",
            applied_ip=ip,
            applied_user_agent=user_agent,
            turnstile_verified=True,
            honeypot_passed=True,
            applied_at=now,
            updated_at=now,
        )
        db.add(app)
        is_update = False

    log_audit(db, "SUBMIT", "SUCCESS", apply_id=apply_id, ip_address=ip,
              email_masked=mask_email(email),
              details={"is_update": is_update, "job": job_public_code},
              user_agent=user_agent)
    
    db.commit()

    return json_success({
        "apply_id": apply_id,
        "email_masked": mask_email(email),
        "is_update": is_update,
    })


# ============================================================================
# POST /v1/apply/upload-cv
# ============================================================================

@public_apply_bp.route("/upload-cv", methods=["POST"])
def apply_upload_cv():
    """
    Upload CV for an existing application.
    
    Request: multipart/form-data
    - apply_id: Application ID
    - cv: File (PDF, DOC, DOCX, max 2MB)
    
    Optional form fields:
    - experience: years of experience
    - location: current location
    
    Returns:
    {
        "success": true,
        "file_id": "cv_PA-2026-XXX_20260130_xxxx"
    }
    """
    ip = get_client_ip()
    user_agent = request.headers.get("User-Agent", "")[:500]

    apply_id = request.form.get("apply_id", "").strip()
    if not apply_id:
        return json_error("Application ID required")

    db = SessionLocal()

    # Find application
    from sqlalchemy import select
    app = db.execute(
        select(PublicApply).where(PublicApply.id == apply_id, PublicApply.status == "PENDING")
    ).scalar_one_or_none()
    
    if not app:
        return json_error("Application not found or already processed")

    # Validate CV file
    if "cv" not in request.files:
        return json_error("CV file required")
    
    cv_file = request.files["cv"]
    if not cv_file or not cv_file.filename:
        return json_error("CV file required")

    # Get file info
    cv_file.seek(0, 2)  # Seek to end
    file_size = cv_file.tell()
    cv_file.seek(0)  # Seek back to start

    ok, err = validate_cv_file(cv_file.filename, cv_file.content_type, file_size)
    if not ok:
        return json_error(err)

    # Generate secure storage key
    storage_key = generate_cv_storage_key(apply_id)
    
    # Get file extension
    original_ext = os.path.splitext(cv_file.filename.lower())[1]
    storage_key_with_ext = storage_key + original_ext

    # Upload to storage
    try:
        file_data = cv_file.read()
        upload_file_to_storage(storage_key_with_ext, file_data, cv_file.content_type)
    except Exception as e:
        log_audit(db, "CV_UPLOAD", "FAILED", apply_id=apply_id, ip_address=ip,
                  details={"error": str(e)}, user_agent=user_agent)
        db.commit()
        return json_error("Failed to upload file. Please try again.")

    # Update application
    app.cv_storage_key = storage_key_with_ext
    app.cv_original_name = cv_file.filename
    app.cv_mime_type = cv_file.content_type or "application/octet-stream"
    app.cv_size = file_size
    app.updated_at = iso_utc_now()

    # Optional fields
    experience = request.form.get("experience", "").strip()
    if experience:
        try:
            app.experience_years = int(experience)
        except ValueError:
            pass

    location = request.form.get("location", "").strip()[:100]
    if location:
        app.current_location = location

    log_audit(db, "CV_UPLOAD", "SUCCESS", apply_id=apply_id, ip_address=ip,
              details={"size": file_size, "type": cv_file.content_type},
              user_agent=user_agent)
    
    db.commit()

    return json_success({
        "file_id": storage_key_with_ext,
        "message": "Application submitted successfully"
    })


# ============================================================================
# CORS Preflight (if needed)
# ============================================================================

def _get_allowed_origins() -> list[str]:
    """Get allowed origins from env or default for development."""
    allowed = os.getenv("ALLOWED_ORIGINS", "").strip()
    if allowed:
        return [o.strip() for o in allowed.split(",") if o.strip()]
    # Default for development
    return ["https://ntwoods-com.github.io", "http://localhost:5173", "http://127.0.0.1:5173"]


def _is_origin_allowed(origin: str) -> bool:
    """Check if origin is in allowed list."""
    if not origin:
        return False
    # In dev mode, allow all if ALLOWED_ORIGINS not set and FLASK_ENV is development
    if os.getenv("FLASK_ENV") == "development" and not os.getenv("ALLOWED_ORIGINS"):
        return True
    return origin in _get_allowed_origins()


@public_apply_bp.after_request
def add_cors_headers(response):
    """Add CORS headers for public endpoints."""
    origin = request.headers.get("Origin", "")
    
    if _is_origin_allowed(origin):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        response.headers["Access-Control-Max-Age"] = "86400"
    
    return response


@public_apply_bp.route("/init", methods=["OPTIONS"])
@public_apply_bp.route("/upload-cv", methods=["OPTIONS"])
def cors_preflight():
    """Handle CORS preflight requests."""
    # The after_request handler will add CORS headers
    return "", 204

