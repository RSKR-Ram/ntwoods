"""
Public Apply Security Utilities (Option-2: No OTP).

Handles:
- Cloudflare Turnstile CAPTCHA verification
- Rate limiting (IP + email based)
- Honeypot + timing trap for bot detection
- CV file validation and secure naming
- Audit logging
- HMAC signature for internal API auth
"""
from __future__ import annotations

import hashlib
import hmac as hmac_module
import json
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import requests
from sqlalchemy import select
from sqlalchemy.orm import Session

from public_apply.models import PublicApplyAuditLog, PublicApplyRateLimit


# ============================================================================
# Environment Helpers
# ============================================================================

def _env_str(name: str, default: str = "") -> str:
    return str(os.getenv(name, default) or default).strip()


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    raw = str(os.getenv(name, "") or "").strip().lower()
    return raw in {"1", "true", "yes", "on"} if raw else default


def _env_list(name: str, default: list[str] | None = None) -> list[str]:
    """Parse comma-separated list from env."""
    raw = str(os.getenv(name, "") or "").strip()
    if not raw:
        return default or []
    return [x.strip() for x in raw.split(",") if x.strip()]


# ============================================================================
# Time Utilities
# ============================================================================

def iso_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_iso(s: str) -> datetime | None:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def unix_timestamp_ms() -> int:
    """Current timestamp in milliseconds."""
    return int(time.time() * 1000)


# ============================================================================
# Hashing Utilities
# ============================================================================

def sha256_hash(value: str) -> str:
    """SHA256 hash for lookups (deterministic)."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hmac_hash(value: str, pepper: str) -> str:
    """HMAC-SHA256 for secure hashing with pepper."""
    return hmac_module.new(pepper.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def mask_mobile(mobile: str) -> str:
    """Mask mobile: 9876543210 -> 98****3210"""
    m = str(mobile or "").strip()
    if len(m) < 6:
        return "****"
    return m[:2] + "****" + m[-4:]


def mask_email(email: str) -> str:
    """Mask email: test@example.com -> te***@example.com"""
    e = str(email or "").strip()
    if "@" not in e:
        return "****"
    local, domain = e.rsplit("@", 1)
    if len(local) <= 2:
        return local[0] + "***@" + domain
    return local[:2] + "***@" + domain


# ============================================================================
# Cloudflare Turnstile CAPTCHA
# ============================================================================

def verify_turnstile(token: str, ip: str) -> tuple[bool, str]:
    """
    Verify Cloudflare Turnstile CAPTCHA token.
    
    Returns: (success, error_message)
    """
    secret_key = _env_str("TURNSTILE_SECRET_KEY")
    if not secret_key:
        # Skip in development if not configured
        if _env_str("APP_ENV", "development").lower() in {"development", "dev", "test"}:
            return True, ""
        return False, "CAPTCHA not configured"

    try:
        resp = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={
                "secret": secret_key,
                "response": token,
                "remoteip": ip,
            },
            timeout=10,
        )
        result = resp.json()
        if result.get("success"):
            return True, ""
        return False, "CAPTCHA verification failed"
    except Exception as e:
        return False, f"CAPTCHA service error: {str(e)}"


# ============================================================================
# Honeypot + Timing Validation (Bot Detection)
# ============================================================================

# Honeypot field name - hidden field that should be empty
HONEYPOT_FIELD = "_hp_check"

# Minimum time (ms) a human would take to fill the form
MIN_FORM_TIME_MS = 2000  # 2 seconds


def validate_honeypot(honeypot_value: str) -> tuple[bool, str]:
    """
    Validate honeypot field is empty.
    
    Bots often fill all fields; humans leave hidden fields empty.
    Returns: (success, error_message)
    """
    if honeypot_value and str(honeypot_value).strip():
        # Honeypot filled = likely bot
        return False, "HONEYPOT_FILLED"
    return True, ""


def validate_timing(form_timestamp: str | int) -> tuple[bool, str]:
    """
    Validate form was not submitted too quickly.
    
    Bots submit instantly; humans take time to fill forms.
    Returns: (success, error_message)
    """
    try:
        ts = int(form_timestamp)
    except (ValueError, TypeError):
        # No timestamp = skip timing check (backward compat)
        return True, ""
    
    now = unix_timestamp_ms()
    elapsed = now - ts
    
    if elapsed < MIN_FORM_TIME_MS:
        # Submitted too fast = likely bot
        return False, "TIMING_TOO_FAST"
    
    # Also reject if timestamp is in the future or too old (> 1 hour)
    if elapsed < 0:
        return False, "TIMING_INVALID"
    if elapsed > 3600000:  # 1 hour
        return False, "TIMING_EXPIRED"
    
    return True, ""


def validate_bot_traps(honeypot_value: str, form_timestamp: str | int) -> tuple[bool, str]:
    """
    Combined honeypot + timing validation.
    
    Returns: (success, error_for_logging)
    Note: Never expose "bot detected" to client; return generic error.
    """
    ok, err = validate_honeypot(honeypot_value)
    if not ok:
        return False, err
    
    ok, err = validate_timing(form_timestamp)
    if not ok:
        return False, err
    
    return True, ""


# ============================================================================
# Rate Limiting
# ============================================================================

def _get_window_id(window_hours: int) -> str:
    """Generate window ID for rate limiting."""
    now = datetime.now(timezone.utc)
    if window_hours >= 24:
        return now.strftime("%Y-%m-%d")
    return now.strftime("%Y-%m-%d-%H")


def check_rate_limit(
    db: Session,
    key_type: str,
    key_value: str,
    max_count: int,
    window_hours: int,
) -> tuple[bool, str]:
    """
    Check and increment rate limit.
    
    Returns: (allowed, error_message)
    """
    key_hash = sha256_hash(key_value)
    window_id = _get_window_id(window_hours)

    record = db.execute(
        select(PublicApplyRateLimit).where(
            PublicApplyRateLimit.key_type == key_type,
            PublicApplyRateLimit.key_hash == key_hash,
            PublicApplyRateLimit.window_id == window_id,
        )
    ).scalar_one_or_none()

    now = iso_utc_now()

    if record:
        if record.count >= max_count:
            return False, f"Rate limit exceeded. Try again later."
        record.count += 1
        record.last_at = now
    else:
        db.add(PublicApplyRateLimit(
            key_type=key_type,
            key_hash=key_hash,
            window_id=window_id,
            count=1,
            first_at=now,
            last_at=now,
        ))

    return True, ""


def check_apply_rate_limits(db: Session, ip: str, email_hash: str) -> tuple[bool, str]:
    """
    Check all rate limits for apply action.
    
    Returns: (allowed, error_message)
    """
    # IP limit: 5 per hour
    ip_max = _env_int("PUBLIC_APPLY_RATE_IP_MAX", 5)
    ip_window = _env_int("PUBLIC_APPLY_RATE_IP_WINDOW_HOURS", 1)
    ok, err = check_rate_limit(db, "IP", ip, ip_max, ip_window)
    if not ok:
        return False, err

    # Email limit: 1 per 24 hours
    email_max = _env_int("PUBLIC_APPLY_RATE_EMAIL_MAX", 1)
    email_window = _env_int("PUBLIC_APPLY_RATE_EMAIL_WINDOW_HOURS", 24)
    ok, err = check_rate_limit(db, "EMAIL", email_hash, email_max, email_window)
    if not ok:
        return False, "You have already applied recently. Please try again later."

    return True, ""


# ============================================================================
# CV File Validation
# ============================================================================

ALLOWED_CV_EXTENSIONS = {".pdf", ".doc", ".docx"}
ALLOWED_CV_MIME_TYPES = {
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}
MAX_CV_SIZE_BYTES = 2 * 1024 * 1024  # 2 MB


def validate_cv_file(filename: str, content_type: str, size: int) -> tuple[bool, str]:
    """
    Validate CV file before upload.
    
    Returns: (valid, error_message)
    """
    # Check extension
    ext = os.path.splitext(filename.lower())[1] if filename else ""
    if ext not in ALLOWED_CV_EXTENSIONS:
        return False, f"Invalid file type. Allowed: PDF, DOC, DOCX"

    # Check MIME type
    if content_type and content_type.lower() not in ALLOWED_CV_MIME_TYPES:
        return False, f"Invalid file type. Allowed: PDF, DOC, DOCX"

    # Check size
    max_mb = MAX_CV_SIZE_BYTES // (1024 * 1024)
    if size > MAX_CV_SIZE_BYTES:
        return False, f"File too large. Maximum size: {max_mb}MB"

    return True, ""


def generate_cv_storage_key(apply_id: str, timestamp: str = "") -> str:
    """
    Generate secure CV filename (no original filename exposed).
    
    Format: cv_APPLYID_TIMESTAMP_RANDOM.ext
    """
    ts = timestamp or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    random_suffix = os.urandom(4).hex()
    return f"cv_{apply_id}_{ts}_{random_suffix}"


# ============================================================================
# Audit Logging
# ============================================================================

def log_audit(
    db: Session,
    action: str,
    result: str,
    apply_id: str = "",
    ip_address: str = "",
    email_masked: str = "",
    details: dict[str, Any] | None = None,
    user_agent: str = "",
) -> None:
    """Log security audit event."""
    db.add(PublicApplyAuditLog(
        timestamp=iso_utc_now(),
        action=action,
        result=result,
        apply_id=apply_id,
        ip_address=ip_address,
        mobile_masked=email_masked,  # Reusing column for email
        details=json.dumps(details or {}),
        user_agent=user_agent[:500] if user_agent else "",
    ))


# ============================================================================
# HMAC Signature for Internal APIs
# ============================================================================

def generate_hmac_signature(payload: dict, secret: str, timestamp: int) -> str:
    """
    Generate HMAC-SHA256 signature for internal API authentication.
    
    Signature = HMAC(secret, timestamp + sorted_json_payload)
    """
    sorted_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    message = f"{timestamp}:{sorted_payload}"
    return hmac_module.new(
        secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def verify_hmac_signature(
    payload: dict,
    signature: str,
    timestamp: int,
    secret: str,
    max_age_seconds: int = 300
) -> tuple[bool, str]:
    """
    Verify HMAC signature from internal API request.
    
    Returns: (valid, error_message)
    """
    if not secret:
        return False, "HMAC secret not configured"
    
    # Check timestamp is recent
    now = int(time.time())
    if abs(now - timestamp) > max_age_seconds:
        return False, "Request timestamp expired"
    
    expected = generate_hmac_signature(payload, secret, timestamp)
    if not hmac_module.compare_digest(expected, signature):
        return False, "Invalid signature"
    
    return True, ""


def get_hmac_secret() -> str:
    """Get HMAC secret for internal API auth."""
    return _env_str("APPLY_API_HMAC_SECRET", "")


# ============================================================================
# IP Allowlist for Internal APIs
# ============================================================================

def is_ip_allowed(ip: str) -> bool:
    """
    Check if IP is in allowlist for internal API access.
    
    Supports CIDR notation (e.g., 10.0.0.0/8).
    """
    import ipaddress
    
    allowed_ips = _env_list("INTERNAL_ALLOWED_IPS")
    if not allowed_ips:
        # In development, allow all if not configured
        if _env_str("APP_ENV", "development").lower() in {"development", "dev", "test"}:
            return True
        return False
    
    try:
        client_ip = ipaddress.ip_address(ip)
    except ValueError:
        return False
    
    for allowed in allowed_ips:
        try:
            if "/" in allowed:
                network = ipaddress.ip_network(allowed, strict=False)
                if client_ip in network:
                    return True
            else:
                if client_ip == ipaddress.ip_address(allowed):
                    return True
        except ValueError:
            continue
    
    return False


# ============================================================================
# Duplicate Detection
# ============================================================================

def find_existing_application(db: Session, email_hash: str, job_public_code: str) -> str | None:
    """
    Find existing PENDING application for same email + job.
    
    Returns: apply_id if found, None otherwise
    """
    from public_apply.models import PublicApply
    
    if not email_hash or not job_public_code:
        return None
    
    existing = db.execute(
        select(PublicApply).where(
            PublicApply.email_hash == email_hash,
            PublicApply.job_public_code == job_public_code,
            PublicApply.status == "PENDING"
        )
    ).scalar_one_or_none()
    
    if existing:
        return str(existing.id)
    return None
