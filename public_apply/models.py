"""
Public Apply Database Models.

These tables are isolated from core HRMS and handle public candidate applications
with security measures (rate limiting, honeypot, audit logs).

Option-2 Security: No OTP, uses Turnstile + rate limiting + honeypot.
"""
from __future__ import annotations

from sqlalchemy import Boolean, Column, Index, Integer, String, Text, UniqueConstraint

from db import Base


class PublicApply(Base):
    """
    Pending applications from public apply form awaiting HR review.
    
    Status flow: PENDING -> APPROVED/REJECTED
    On APPROVED: Creates Candidate record in SHORTLISTING stage
    
    Dedupe: (email_hash + job_public_code) - same person + same job = update, not create
    """
    __tablename__ = "public_applies"
    __table_args__ = (
        # Index for dedupe lookup
        Index("ix_public_apply_email_job", "email_hash", "job_public_code"),
        # Index for job tiles query
        Index("ix_public_apply_status_job", "status", "job_public_code"),
    )

    id = Column(String, primary_key=True)  # PA-2026-xxxxx
    status = Column(String, nullable=False, default="PENDING", index=True)  # PENDING|APPROVED|REJECTED

    # PII fields (encrypted at rest, hashed for lookup)
    name_enc = Column(Text, nullable=False, default="")
    name_masked = Column(Text, nullable=False, default="")
    mobile_hash = Column(String, nullable=False, default="", index=True)
    mobile_enc = Column(Text, nullable=False, default="")
    mobile_masked = Column(Text, nullable=False, default="")
    email_hash = Column(String, nullable=False, default="", index=True)
    email_enc = Column(Text, nullable=False, default="")
    email_masked = Column(Text, nullable=False, default="")

    # CV storage (secure filename, not public)
    cv_storage_key = Column(String, nullable=False, default="")
    cv_original_name = Column(Text, nullable=False, default="")  # Original for display only
    cv_mime_type = Column(String, nullable=False, default="")
    cv_size = Column(Integer, nullable=False, default=0)

    # Job/Position context (NEW)
    job_public_code = Column(String(100), nullable=False, default="", index=True)  # e.g. "ACC-2026-001"
    position_title = Column(String(200), nullable=False, default="")  # e.g. "Senior Accountant"
    
    # Legacy fields (kept for backward compat)
    job_role = Column(Text, nullable=False, default="")  # Deprecated: use position_title
    requirement_id = Column(String, nullable=False, default="", index=True)  # Default HRMS requirement if known
    
    # Application context
    source = Column(Text, nullable=False, default="PUBLIC_APPLY")
    experience_years = Column(Integer, nullable=True)
    current_location = Column(Text, nullable=False, default="")
    remarks = Column(Text, nullable=False, default="")

    # Security audit
    applied_ip = Column(String, nullable=False, default="")
    applied_user_agent = Column(Text, nullable=False, default="")
    turnstile_verified = Column(Boolean, nullable=False, default=False)
    honeypot_passed = Column(Boolean, nullable=False, default=True)  # NEW: bot detection

    # Timestamps
    applied_at = Column(Text, nullable=False, default="", index=True)
    updated_at = Column(Text, nullable=False, default="")

    # HR action
    candidate_id = Column(String, nullable=False, default="", index=True)  # Set on approval
    selected_requirement_id = Column(String(50), nullable=False, default="")  # NEW: HR-selected requirement
    
    approved_at = Column(Text, nullable=False, default="")
    approved_by = Column(String, nullable=False, default="")
    
    rejected_at = Column(Text, nullable=False, default="")
    rejected_by = Column(String, nullable=False, default="")
    rejection_remark = Column(Text, nullable=False, default="")  # Mandatory on rejection
    
    hr_remark = Column(Text, nullable=False, default="")  # NEW: General HR notes


class PublicApplyRateLimit(Base):
    """
    Rate limit tracking for IPs and emails.
    
    Limits:
    - IP: 5 applications per hour
    - Email: 1 application per 24 hours
    """
    __tablename__ = "public_apply_rate_limit"
    __table_args__ = (UniqueConstraint("key_type", "key_hash", "window_id", name="uq_public_apply_rate_key_window"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    key_type = Column(String, nullable=False, default="", index=True)  # IP|EMAIL
    key_hash = Column(String, nullable=False, default="", index=True)  # Hashed IP or email
    window_id = Column(String, nullable=False, default="", index=True)  # YYYY-MM-DD-HH or YYYY-MM-DD
    count = Column(Integer, nullable=False, default=0)
    first_at = Column(Text, nullable=False, default="")
    last_at = Column(Text, nullable=False, default="")


class PublicApplyAuditLog(Base):
    """
    Security audit log for all public apply actions.
    
    Logs: CAPTCHA, rate limit, honeypot, submit, approve, reject
    """
    __tablename__ = "public_apply_audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Text, nullable=False, default="", index=True)
    action = Column(String, nullable=False, default="", index=True)  # CAPTCHA_FAIL|BOT_DETECTED|RATE_LIMIT|SUBMIT|APPROVE|REJECT
    result = Column(String, nullable=False, default="", index=True)  # SUCCESS|BLOCKED|FAILED
    
    apply_id = Column(String, nullable=False, default="", index=True)
    ip_address = Column(String, nullable=False, default="")
    mobile_masked = Column(String, nullable=False, default="")  # Also stores email_masked
    
    details = Column(Text, nullable=False, default="")  # JSON with additional context
    user_agent = Column(Text, nullable=False, default="")


# Note: PublicApplyOTP table removed - Option-2 security doesn't use OTP
