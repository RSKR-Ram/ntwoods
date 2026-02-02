from __future__ import annotations

from sqlalchemy import Boolean, Column, Integer, String, Text, UniqueConstraint

from db import Base


class IdCounter(Base):
    __tablename__ = "id_counters"

    key = Column(String, primary_key=True)
    nextValue = Column(Integer, nullable=False, default=1)


class User(Base):
    __tablename__ = "users"

    userId = Column(String, primary_key=True)
    email = Column(String, nullable=False, unique=True, index=True)
    fullName = Column(Text, nullable=False, default="")
    # Deterministic pseudonymization (HMAC-SHA256 with PEPPER).
    email_hash = Column(String, nullable=False, default="", index=True)
    name_hash = Column(String, nullable=False, default="", index=True)
    # Display-safe masked values (never full PII).
    email_masked = Column(Text, nullable=False, default="")
    name_masked = Column(Text, nullable=False, default="")
    # Encrypted-at-rest full values (AES-256-GCM; optional).
    email_enc = Column(Text, nullable=False, default="")
    name_enc = Column(Text, nullable=False, default="")
    role = Column(String, nullable=False, index=True)
    status = Column(String, nullable=False, default="ACTIVE", index=True)
    lastLoginAt = Column(Text, nullable=False, default="")
    createdAt = Column(Text, nullable=False, default="")
    createdBy = Column(String, nullable=False, default="")
    updatedAt = Column(Text, nullable=False, default="")
    updatedBy = Column(String, nullable=False, default="")


class Role(Base):
    __tablename__ = "roles"

    roleCode = Column(String, primary_key=True)
    roleName = Column(String, nullable=False, default="")
    status = Column(String, nullable=False, default="ACTIVE")
    createdAt = Column(Text, nullable=False, default="")
    createdBy = Column(String, nullable=False, default="")
    updatedAt = Column(Text, nullable=False, default="")
    updatedBy = Column(String, nullable=False, default="")


class Permission(Base):
    __tablename__ = "permissions"
    __table_args__ = (UniqueConstraint("permType", "permKey", name="uq_permissions_type_key"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    permType = Column(String, nullable=False)
    permKey = Column(String, nullable=False)
    rolesCsv = Column(Text, nullable=False, default="")
    enabled = Column(Boolean, nullable=False, default=True)
    updatedAt = Column(Text, nullable=False, default="")
    updatedBy = Column(String, nullable=False, default="")


class Setting(Base):
    __tablename__ = "settings"

    key = Column(String, primary_key=True)
    value = Column(Text, nullable=False, default="")
    type = Column(String, nullable=False, default="")
    scope = Column(String, nullable=False, default="")
    updatedAt = Column(Text, nullable=False, default="")
    updatedBy = Column(String, nullable=False, default="")


class JobTemplate(Base):
    __tablename__ = "job_templates"

    templateId = Column(String, primary_key=True)
    jobRole = Column(Text, nullable=False, default="")
    jobTitle = Column(Text, nullable=False, default="")
    jd = Column(Text, nullable=False, default="")
    responsibilities = Column(Text, nullable=False, default="")
    skills = Column(Text, nullable=False, default="")
    shift = Column(Text, nullable=False, default="")
    payScale = Column(Text, nullable=False, default="")
    perks = Column(Text, nullable=False, default="")
    notes = Column(Text, nullable=False, default="")
    status = Column(String, nullable=False, default="ACTIVE")
    createdAt = Column(Text, nullable=False, default="")
    createdBy = Column(String, nullable=False, default="")
    updatedAt = Column(Text, nullable=False, default="")
    updatedBy = Column(String, nullable=False, default="")


class Requirement(Base):
    __tablename__ = "requirements"

    requirementId = Column(String, primary_key=True)
    templateId = Column(String, nullable=False, default="")
    jobRole = Column(Text, nullable=False, default="")
    jobTitle = Column(Text, nullable=False, default="")
    jd = Column(Text, nullable=False, default="")
    responsibilities = Column(Text, nullable=False, default="")
    skills = Column(Text, nullable=False, default="")
    shift = Column(Text, nullable=False, default="")
    payScale = Column(Text, nullable=False, default="")
    perks = Column(Text, nullable=False, default="")
    notes = Column(Text, nullable=False, default="")
    raisedFor = Column(Text, nullable=False, default="")
    concernedPerson = Column(Text, nullable=False, default="")
    requiredCount = Column(Integer, nullable=False, default=1)
    joinedCount = Column(Integer, nullable=False, default=0)
    status = Column(String, nullable=False, default="DRAFT", index=True)
    latestRemark = Column(Text, nullable=False, default="")
    createdAt = Column(Text, nullable=False, default="")
    createdBy = Column(String, nullable=False, default="")
    updatedAt = Column(Text, nullable=False, default="")
    updatedBy = Column(String, nullable=False, default="")


class RequirementHistory(Base):
    __tablename__ = "requirement_history"

    historyId = Column(String, primary_key=True)
    requirementId = Column(String, nullable=False, index=True)
    fromStatus = Column(String, nullable=False, default="")
    toStatus = Column(String, nullable=False, default="")
    stageTag = Column(String, nullable=False, default="")
    remark = Column(Text, nullable=False, default="")
    actorUserId = Column(String, nullable=False, default="")
    actorRole = Column(String, nullable=False, default="")
    at = Column(Text, nullable=False, default="")
    metaJson = Column(Text, nullable=False, default="")


class JobPosting(Base):
    __tablename__ = "job_posting"

    requirementId = Column(String, primary_key=True)
    status = Column(String, nullable=False, default="")
    checklistStateJson = Column(Text, nullable=False, default="")
    screenshotUploadId = Column(String, nullable=False, default="")
    completedAt = Column(Text, nullable=False, default="")
    completedBy = Column(String, nullable=False, default="")
    updatedAt = Column(Text, nullable=False, default="")
    updatedBy = Column(String, nullable=False, default="")


class CandidateMaster(Base):
    """
    Canonical, lifelong candidate/person record (no vacancy coupling).

    NOTE: The existing `candidates` table is currently used as an application record
    (candidate-per-requirement). This table provides a non-duplicating identity anchor.
    """

    __tablename__ = "candidate_master"

    candidateMasterId = Column(String, primary_key=True)
    status = Column(String, nullable=False, default="ACTIVE", index=True)

    # Deterministic pseudonymization (HMAC-SHA256 with PEPPER).
    name_hash = Column(String, nullable=False, default="", index=True)
    mobile_hash = Column(String, nullable=False, default="", index=True)

    # Display-safe masked values (never full PII).
    name_masked = Column(Text, nullable=False, default="")
    mobile_masked = Column(Text, nullable=False, default="")

    # Encrypted-at-rest full values (AES-256-GCM; optional).
    name_enc = Column(Text, nullable=False, default="")
    mobile_enc = Column(Text, nullable=False, default="")

    createdAt = Column(Text, nullable=False, default="")
    createdBy = Column(String, nullable=False, default="")
    updatedAt = Column(Text, nullable=False, default="")
    updatedBy = Column(String, nullable=False, default="")


class CandidateIdentity(Base):
    """
    Candidate identity map.

    For PII safety, `normalizedValue` stores a deterministic hash (HMAC-SHA256 hex),
    not the raw identifier.
    """

    __tablename__ = "candidate_identity"
    __table_args__ = (
        UniqueConstraint("identityType", "normalizedValue", "active", name="uq_candidate_identity_type_value_active"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    candidateMasterId = Column(String, nullable=False, index=True)
    identityType = Column(String, nullable=False, default="", index=True)  # e.g. PHONE_HASH, EMAIL_HASH
    normalizedValue = Column(String, nullable=False, default="", index=True)
    active = Column(Boolean, nullable=False, default=True, index=True)
    createdAt = Column(Text, nullable=False, default="")
    createdBy = Column(String, nullable=False, default="")


class Candidate(Base):
    __tablename__ = "candidates"

    candidateId = Column(String, primary_key=True)
    candidateMasterId = Column(String, nullable=False, default="", index=True)
    requirementId = Column(String, nullable=False, index=True)
    candidateName = Column(Text, nullable=False, default="")
    jobRole = Column(Text, nullable=False, default="")
    mobile = Column(String, nullable=False, default="")
    # Deterministic pseudonymization (HMAC-SHA256 with PEPPER).
    name_hash = Column(String, nullable=False, default="", index=True)
    mobile_hash = Column(String, nullable=False, default="", index=True)
    # Display-safe masked values (never full PII).
    name_masked = Column(Text, nullable=False, default="")
    mobile_masked = Column(Text, nullable=False, default="")
    # Encrypted-at-rest full values (AES-256-GCM; optional).
    name_enc = Column(Text, nullable=False, default="")
    mobile_enc = Column(Text, nullable=False, default="")
    source = Column(Text, nullable=False, default="")
    cvFileId = Column(String, nullable=False, default="")
    cvFileName = Column(Text, nullable=False, default="")
    status = Column(String, nullable=False, default="", index=True)
    # ATS stage tracking (additive; does not replace `status`).
    candidateStage = Column(Text, nullable=False, default="", index=True)
    stageUpdatedAt = Column(Text, nullable=False, default="", index=True)
    holdUntil = Column(Text, nullable=False, default="")
    walkinAt = Column(Text, nullable=False, default="")
    walkinNotes = Column(Text, nullable=False, default="")
    notPickCount = Column(Integer, nullable=False, default=0)
    preCallAt = Column(Text, nullable=False, default="")
    preInterviewStatus = Column(Text, nullable=False, default="")
    preInterviewMarks = Column(Text, nullable=False, default="")
    preInterviewMarksAt = Column(Text, nullable=False, default="")
    testToken = Column(String, nullable=False, default="", index=True)
    testTokenExpiresAt = Column(Text, nullable=False, default="")
    onlineTestScore = Column(Integer, nullable=True)
    onlineTestResult = Column(Text, nullable=False, default="")
    onlineTestSubmittedAt = Column(Text, nullable=False, default="")
    testDecisionsJson = Column(Text, nullable=False, default="")
    candidate_test_failed_but_manually_continued = Column(Boolean, nullable=False, default=False)
    inPersonMarks = Column(Integer, nullable=True)
    inPersonMarksAt = Column(Text, nullable=False, default="")
    techSelectedTestsJson = Column(Text, nullable=False, default="")
    techSelectedAt = Column(Text, nullable=False, default="")
    tallyMarks = Column(Integer, nullable=True)
    voiceMarks = Column(Integer, nullable=True)
    techReview = Column(Text, nullable=False, default="")
    excelMarks = Column(Integer, nullable=True)
    excelReview = Column(Text, nullable=False, default="")
    techResult = Column(Text, nullable=False, default="")
    techEvaluatedAt = Column(Text, nullable=False, default="")
    finalHoldAt = Column(Text, nullable=False, default="")
    finalHoldRemark = Column(Text, nullable=False, default="")
    joiningAt = Column(Text, nullable=False, default="")
    docsJson = Column(Text, nullable=False, default="")
    docsCompleteAt = Column(Text, nullable=False, default="")
    joinedAt = Column(Text, nullable=False, default="")
    probationStartAt = Column(Text, nullable=False, default="")
    probationEndsAt = Column(Text, nullable=False, default="")
    employeeId = Column(String, nullable=False, default="", index=True)
    # Employee uniqueness (never store full Aadhaar).
    aadhaar_last4 = Column(String, nullable=False, default="", index=True)
    aadhaar_dob_hash = Column(String, nullable=False, default="", index=True)
    rejectedFromStatus = Column(Text, nullable=False, default="")
    rejectedReasonCode = Column(Text, nullable=False, default="")
    rejectedAt = Column(Text, nullable=False, default="")
    createdAt = Column(Text, nullable=False, default="")
    createdBy = Column(String, nullable=False, default="")
    updatedAt = Column(Text, nullable=False, default="")
    updatedBy = Column(String, nullable=False, default="")


class AtsStage(Base):
    __tablename__ = "ats_stages"
    __table_args__ = (UniqueConstraint("stageKey", name="uq_ats_stages_stageKey"),)

    stageId = Column(String, primary_key=True)
    stageKey = Column(String, nullable=False, default="", index=True)  # e.g. NEW, PRECALL, TECH, JOINING
    stageName = Column(Text, nullable=False, default="")
    orderNo = Column(Integer, nullable=False, default=0, index=True)
    color = Column(String, nullable=False, default="")
    isActive = Column(Boolean, nullable=False, default=True, index=True)
    rolesCsv = Column(Text, nullable=False, default="")  # visibility/move roles
    createdAt = Column(Text, nullable=False, default="")
    createdBy = Column(String, nullable=False, default="")
    updatedAt = Column(Text, nullable=False, default="")
    updatedBy = Column(String, nullable=False, default="")


class CandidateNote(Base):
    __tablename__ = "candidate_notes"

    noteId = Column(String, primary_key=True)
    candidateId = Column(String, nullable=False, default="", index=True)
    requirementId = Column(String, nullable=False, default="", index=True)
    noteText = Column(Text, nullable=False, default="")
    visibility = Column(String, nullable=False, default="INTERNAL", index=True)
    createdAt = Column(Text, nullable=False, default="", index=True)
    createdBy = Column(String, nullable=False, default="", index=True)


class CandidateTag(Base):
    __tablename__ = "candidate_tags"
    __table_args__ = (UniqueConstraint("tagName", name="uq_candidate_tags_tagName"),)

    tagId = Column(String, primary_key=True)
    tagName = Column(String, nullable=False, default="", index=True)
    createdAt = Column(Text, nullable=False, default="", index=True)
    createdBy = Column(String, nullable=False, default="", index=True)


class CandidateTagMap(Base):
    __tablename__ = "candidate_tag_map"
    __table_args__ = (UniqueConstraint("candidateId", "tagId", name="uq_candidate_tag_map_candidate_tag"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    candidateId = Column(String, nullable=False, default="", index=True)
    tagId = Column(String, nullable=False, default="", index=True)
    createdAt = Column(Text, nullable=False, default="", index=True)
    createdBy = Column(String, nullable=False, default="", index=True)


class CandidateActivity(Base):
    __tablename__ = "candidate_activity"

    activityId = Column(String, primary_key=True)
    candidateId = Column(String, nullable=False, default="", index=True)
    requirementId = Column(String, nullable=False, default="", index=True)
    type = Column(String, nullable=False, default="", index=True)  # CALL|WHATSAPP|EMAIL|INTERVIEW|NOTE|SYSTEM
    payloadJson = Column(Text, nullable=False, default="")
    at = Column(Text, nullable=False, default="", index=True)
    actorUserId = Column(String, nullable=False, default="", index=True)
    actorRole = Column(String, nullable=False, default="", index=True)


class TestDecisionLog(Base):
    __tablename__ = "logs_test_decision"

    logId = Column(String, primary_key=True)
    candidateId = Column(String, nullable=False, index=True)
    requirementId = Column(String, nullable=False, index=True)
    testType = Column(String, nullable=False, default="")
    marks = Column(Text, nullable=False, default="")
    passFail = Column(String, nullable=False, default="")
    hrDecision = Column(String, nullable=False, default="")
    remark = Column(Text, nullable=False, default="")
    overrideFlag = Column(Boolean, nullable=False, default=False)
    actorUserId = Column(String, nullable=False, default="")
    actorRole = Column(String, nullable=False, default="")
    at = Column(Text, nullable=False, default="")
    metaJson = Column(Text, nullable=False, default="")


class Session(Base):
    __tablename__ = "sessions"

    sessionId = Column(String, primary_key=True)
    tokenHash = Column(String, nullable=False, unique=True, index=True)
    tokenPrefix = Column(String, nullable=False, default="", index=True)
    userId = Column(String, nullable=False, default="")
    email = Column(String, nullable=False, default="")
    role = Column(String, nullable=False, default="", index=True)
    userStatus = Column(String, nullable=False, default="", index=True)
    authVersion = Column(Integer, nullable=False, default=0)
    issuedAt = Column(Text, nullable=False, default="")
    expiresAt = Column(Text, nullable=False, default="")
    lastSeenAt = Column(Text, nullable=False, default="")
    revokedAt = Column(Text, nullable=False, default="")
    revokedBy = Column(String, nullable=False, default="")


class AuditLog(Base):
    __tablename__ = "audit_log"

    logId = Column(String, primary_key=True)
    entityType = Column(String, nullable=False, default="", index=True)
    entityId = Column(String, nullable=False, default="", index=True)
    action = Column(String, nullable=False, default="", index=True)
    fromState = Column(String, nullable=False, default="")
    toState = Column(String, nullable=False, default="")
    stageTag = Column(String, nullable=False, default="", index=True)
    remark = Column(Text, nullable=False, default="")
    actorUserId = Column(String, nullable=False, default="", index=True)
    actorRole = Column(String, nullable=False, default="", index=True)
    actorEmail = Column(Text, nullable=False, default="")
    at = Column(Text, nullable=False, default="", index=True)
    correlationId = Column(String, nullable=False, default="", index=True)
    beforeJson = Column(Text, nullable=False, default="")
    afterJson = Column(Text, nullable=False, default="")
    metaJson = Column(Text, nullable=False, default="")


class RejectionLog(Base):
    __tablename__ = "logs_rejection"

    logId = Column(String, primary_key=True)
    candidateId = Column(String, nullable=False, index=True)
    requirementId = Column(String, nullable=False, index=True)
    rejectionType = Column(String, nullable=False, default="")
    autoRejectCode = Column(String, nullable=False, default="")
    stageTag = Column(String, nullable=False, default="", index=True)
    remark = Column(Text, nullable=False, default="")
    actorUserId = Column(String, nullable=False, default="")
    actorRole = Column(String, nullable=False, default="")
    at = Column(Text, nullable=False, default="", index=True)


class OnlineTest(Base):
    __tablename__ = "online_tests"

    testId = Column(String, primary_key=True)
    token = Column(String, nullable=False, unique=True, index=True)
    candidateId = Column(String, nullable=False, index=True)
    requirementId = Column(String, nullable=False, index=True)
    issuedAt = Column(Text, nullable=False, default="")
    expiresAt = Column(Text, nullable=False, default="")
    status = Column(String, nullable=False, default="")
    fullName = Column(Text, nullable=False, default="")
    applyingFor = Column(Text, nullable=False, default="")
    source = Column(Text, nullable=False, default="")
    questionsJson = Column(Text, nullable=False, default="")
    answersJson = Column(Text, nullable=False, default="")
    score = Column(Integer, nullable=True)
    result = Column(String, nullable=False, default="")
    submittedAt = Column(Text, nullable=False, default="")
    updatedAt = Column(Text, nullable=False, default="")


class HoldLog(Base):
    __tablename__ = "logs_hold"

    logId = Column(String, primary_key=True)
    candidateId = Column(String, nullable=False, index=True)
    requirementId = Column(String, nullable=False, index=True)
    action = Column(String, nullable=False, default="")
    holdUntil = Column(Text, nullable=False, default="")
    stageTag = Column(String, nullable=False, default="", index=True)
    remark = Column(Text, nullable=False, default="")
    actorUserId = Column(String, nullable=False, default="")
    actorRole = Column(String, nullable=False, default="")
    at = Column(Text, nullable=False, default="", index=True)


class JoinLog(Base):
    __tablename__ = "logs_join"

    logId = Column(String, primary_key=True)
    candidateId = Column(String, nullable=False, index=True)
    requirementId = Column(String, nullable=False, index=True)
    action = Column(String, nullable=False, default="")
    stageTag = Column(String, nullable=False, default="", index=True)
    remark = Column(Text, nullable=False, default="")
    actorUserId = Column(String, nullable=False, default="")
    actorRole = Column(String, nullable=False, default="")
    at = Column(Text, nullable=False, default="", index=True)


class Employee(Base):
    __tablename__ = "employees"

    employeeId = Column(String, primary_key=True)
    # Canonical, unique employee identifier (DB requirement). Kept in sync with employeeId.
    employee_id = Column(String, nullable=False, default="", index=True)
    candidateId = Column(String, nullable=False, default="", index=True)
    requirementId = Column(String, nullable=False, default="", index=True)
    employeeName = Column(Text, nullable=False, default="")
    mobile = Column(String, nullable=False, default="")
    jobRole = Column(Text, nullable=False, default="")
    jobTitle = Column(Text, nullable=False, default="")
    source = Column(Text, nullable=False, default="")
    cvFileId = Column(String, nullable=False, default="")
    cvFileName = Column(Text, nullable=False, default="")
    joinedAt = Column(Text, nullable=False, default="")
    probationStartAt = Column(Text, nullable=False, default="")
    probationEndsAt = Column(Text, nullable=False, default="")
    status = Column(String, nullable=False, default="ACTIVE", index=True)
    exitAt = Column(Text, nullable=False, default="", index=True)
    # Employment lifecycle (DB requirement).
    exit_date = Column(Text, nullable=False, default="", index=True)
    rejoin_date = Column(Text, nullable=False, default="", index=True)
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    # Auth hard-revocation version: bump to invalidate all existing sessions/tokens.
    auth_version = Column(Integer, nullable=False, default=0)
    # Employee portal credentials (never store plaintext).
    password_hash = Column(Text, nullable=False, default="")
    password_reset_required = Column(Boolean, nullable=False, default=True, index=True)
    password_changed_at = Column(Text, nullable=False, default="")
    currentRole = Column(Text, nullable=False, default="", index=True)
    # Employee uniqueness (never store full Aadhaar).
    aadhaar_last4 = Column(String, nullable=False, default="", index=True)
    aadhaar_dob_hash = Column(String, nullable=False, default="", index=True)
    createdAt = Column(Text, nullable=False, default="")
    createdBy = Column(String, nullable=False, default="")
    timelineJson = Column(Text, nullable=False, default="")


class EmployeeDoc(Base):
    __tablename__ = "employee_docs"
    __table_args__ = (UniqueConstraint("employee_id", "doc_type", "version", name="uq_employee_docs_emp_type_ver"),)

    id = Column(String, primary_key=True)  # DOC-YYYY-xxxxx
    employee_id = Column(String, nullable=False, index=True)
    doc_type = Column(String, nullable=False, default="", index=True)
    storage_key = Column(String, nullable=False, default="", index=True)
    file_name = Column(Text, nullable=False, default="")
    mime_type = Column(String, nullable=False, default="")
    size = Column(Integer, nullable=False, default=0)
    uploaded_by = Column(String, nullable=False, default="", index=True)
    uploaded_at = Column(Text, nullable=False, default="", index=True)
    visibility = Column(String, nullable=False, default="INTERNAL", index=True)
    version = Column(Integer, nullable=False, default=1)


class RoleHistory(Base):
    __tablename__ = "role_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    employee_id = Column(String, nullable=False, index=True)
    role = Column(String, nullable=False, default="", index=True)
    start_at = Column(Text, nullable=False, default="", index=True)
    end_at = Column(Text, nullable=False, default="", index=True)
    changed_by = Column(String, nullable=False, default="", index=True)
    remark = Column(Text, nullable=False, default="")


class ExitCase(Base):
    __tablename__ = "exit_cases"

    id = Column(String, primary_key=True)  # EXIT-YYYY-xxxxx
    employee_id = Column(String, nullable=False, index=True)
    exit_type = Column(String, nullable=False, default="", index=True)  # SELF/ABSCONDED/TERMINATED
    state = Column(String, nullable=False, default="", index=True)
    notice_start = Column(Text, nullable=False, default="")
    notice_days = Column(Integer, nullable=False, default=0)
    notice_end = Column(Text, nullable=False, default="", index=True)
    last_working_day = Column(Text, nullable=False, default="", index=True)
    absent_since = Column(Text, nullable=False, default="", index=True)
    settlement_cleared = Column(Boolean, nullable=False, default=False, index=True)
    settlement_doc_id = Column(String, nullable=False, default="")
    termination_letter_doc_id = Column(String, nullable=False, default="")
    exit_completed_at = Column(Text, nullable=False, default="", index=True)
    created_at = Column(Text, nullable=False, default="", index=True)
    created_by = Column(String, nullable=False, default="", index=True)
    updated_at = Column(Text, nullable=False, default="", index=True)
    updated_by = Column(String, nullable=False, default="", index=True)


class ExitTask(Base):
    """
    Enterprise exit clearance checklist items.

    This enables multi-department clearance (HR/IT/Finance/Admin) before an employee
    can be marked as EXITED.
    """

    __tablename__ = "exit_tasks"
    __table_args__ = (UniqueConstraint("exit_id", "task_key", name="uq_exit_tasks_exit_taskkey"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    exit_id = Column(String, nullable=False, default="", index=True)
    task_key = Column(String, nullable=False, default="", index=True)
    label = Column(Text, nullable=False, default="")
    department = Column(String, nullable=False, default="", index=True)  # HR/IT/FINANCE/ADMIN/...
    required = Column(Boolean, nullable=False, default=True, index=True)

    status = Column(String, nullable=False, default="PENDING", index=True)  # PENDING/DONE/NA/BLOCKED
    assigned_role = Column(String, nullable=False, default="", index=True)  # e.g. MIS/ACCOUNTS/HR
    assigned_to = Column(String, nullable=False, default="", index=True)  # userId (optional)

    doc_id = Column(String, nullable=False, default="")  # optional EmployeeDoc reference
    note = Column(Text, nullable=False, default="")
    completed_by = Column(String, nullable=False, default="", index=True)
    completed_at = Column(Text, nullable=False, default="", index=True)

    created_at = Column(Text, nullable=False, default="", index=True)
    created_by = Column(String, nullable=False, default="", index=True)
    updated_at = Column(Text, nullable=False, default="", index=True)
    updated_by = Column(String, nullable=False, default="", index=True)


class TrainingModule(Base):
    __tablename__ = "training_modules"

    moduleId = Column(String, primary_key=True)
    title = Column(Text, nullable=False, default="")
    video_provider = Column(String, nullable=False, default="")
    video_ref = Column(Text, nullable=False, default="")
    active = Column(Boolean, nullable=False, default=True, index=True)
    createdAt = Column(Text, nullable=False, default="")
    createdBy = Column(String, nullable=False, default="")
    updatedAt = Column(Text, nullable=False, default="")
    updatedBy = Column(String, nullable=False, default="")


class TrainingSetting(Base):
    __tablename__ = "training_settings"

    moduleId = Column(String, primary_key=True)
    passMarks = Column(Integer, nullable=False, default=0)
    timeLimitMin = Column(Integer, nullable=False, default=0)
    maxAttempts = Column(Integer, nullable=False, default=0)
    randomize = Column(Boolean, nullable=False, default=False)
    updatedAt = Column(Text, nullable=False, default="")
    updatedBy = Column(String, nullable=False, default="")


class TrainingQuestion(Base):
    __tablename__ = "training_questions"
    __table_args__ = (UniqueConstraint("moduleId", "qId", name="uq_training_questions_module_qid"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    moduleId = Column(String, nullable=False, index=True)
    qId = Column(String, nullable=False, default="")
    question = Column(Text, nullable=False, default="")
    optionsJSON = Column(Text, nullable=False, default="[]")
    correctOption = Column(String, nullable=False, default="")
    marks = Column(Integer, nullable=False, default=0)
    active = Column(Boolean, nullable=False, default=True, index=True)
    updatedAt = Column(Text, nullable=False, default="", index=True)
    updatedBy = Column(String, nullable=False, default="")


class TrainingAttempt(Base):
    __tablename__ = "training_attempts"
    __table_args__ = (UniqueConstraint("employeeId", "moduleId", "attemptNo", name="uq_training_attempts_emp_mod_attempt"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    employeeId = Column(String, nullable=False, default="", index=True)
    moduleId = Column(String, nullable=False, default="", index=True)
    attemptNo = Column(Integer, nullable=False, default=1)
    score = Column(Integer, nullable=False, default=0)
    passFail = Column(String, nullable=False, default="", index=True)
    submittedAt = Column(Text, nullable=False, default="", index=True)
    metaJson = Column(Text, nullable=False, default="")


class TrainingMaster(Base):
    __tablename__ = "trainings_master"

    training_id = Column(String, primary_key=True)
    name = Column(Text, nullable=False, default="")
    department = Column(Text, nullable=False, default="")
    description = Column(Text, nullable=False, default="")
    video_link = Column(Text, nullable=False, default="")
    videoLinksJson = Column(Text, nullable=False, default="")
    documentsJson = Column(Text, nullable=False, default="")
    created_by = Column(String, nullable=False, default="")
    created_on = Column(Text, nullable=False, default="")


class AssignedTraining(Base):
    __tablename__ = "assigned_trainings"

    assigned_id = Column(String, primary_key=True)
    candidate_id = Column(String, nullable=False, default="", index=True)
    training_id = Column(String, nullable=False, default="", index=True)
    training_name = Column(Text, nullable=False, default="")
    department = Column(Text, nullable=False, default="")
    description = Column(Text, nullable=False, default="")
    video_link = Column(Text, nullable=False, default="")
    videoLinksJson = Column(Text, nullable=False, default="")
    documentsJson = Column(Text, nullable=False, default="")
    status = Column(String, nullable=False, default="", index=True)
    assigned_date = Column(Text, nullable=False, default="")
    due_date = Column(Text, nullable=False, default="")
    start_time = Column(Text, nullable=False, default="")
    completion_time = Column(Text, nullable=False, default="")
    assigned_by = Column(String, nullable=False, default="")
    video_progress = Column(Text, nullable=False, default="")  # JSON: {videoIdx: {max_time, duration, completed}}


class TrainingLog(Base):
    __tablename__ = "training_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Text, nullable=False, default="", index=True)
    candidate_id = Column(String, nullable=False, default="", index=True)
    training_id = Column(String, nullable=False, default="", index=True)
    assigned_id = Column(String, nullable=False, default="", index=True)
    action = Column(String, nullable=False, default="", index=True)
    performed_by = Column(String, nullable=False, default="")
    remarks = Column(Text, nullable=False, default="")
    metaJson = Column(Text, nullable=False, default="")


class TestMaster(Base):
    __tablename__ = "test_master"

    testKey = Column(String, primary_key=True)
    label = Column(Text, nullable=False, default="")
    fillRolesJson = Column(Text, nullable=False, default="[]")
    reviewRolesJson = Column(Text, nullable=False, default="[]")
    active = Column(Boolean, nullable=False, default=True, index=True)
    ordering = Column(Integer, nullable=False, default=0)
    createdAt = Column(Text, nullable=False, default="")
    createdBy = Column(String, nullable=False, default="")
    updatedAt = Column(Text, nullable=False, default="")
    updatedBy = Column(String, nullable=False, default="")


class CandidateTest(Base):
    __tablename__ = "candidate_tests"
    __table_args__ = (UniqueConstraint("candidateId", "testKey", name="uq_candidate_tests_candidate_test"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    candidateId = Column(String, nullable=False, default="", index=True)
    requirementId = Column(String, nullable=False, default="", index=True)
    testKey = Column(String, nullable=False, default="", index=True)
    isRequired = Column(Boolean, nullable=False, default=False, index=True)
    status = Column(String, nullable=False, default="NOT_SELECTED", index=True)
    marksJson = Column(Text, nullable=False, default="")
    marksNumber = Column(Integer, nullable=True)
    # Multi-tenant isolation: assignee for filling the test (userId).
    fillOwnerUserId = Column(String, nullable=False, default="", index=True)
    filledBy = Column(String, nullable=False, default="")
    filledAt = Column(Text, nullable=False, default="")
    reviewedBy = Column(String, nullable=False, default="")
    reviewedAt = Column(Text, nullable=False, default="")
    remarks = Column(Text, nullable=False, default="")
    createdAt = Column(Text, nullable=False, default="")
    updatedAt = Column(Text, nullable=False, default="", index=True)


class FailCandidate(Base):
    __tablename__ = "fail_candidates"

    id = Column(Integer, primary_key=True, autoincrement=True)
    candidateId = Column(String, nullable=False, default="", index=True)
    requirementId = Column(String, nullable=False, default="", index=True)
    stageName = Column(String, nullable=False, default="", index=True)
    reason = Column(Text, nullable=False, default="")
    score = Column(Integer, nullable=True)
    failedAt = Column(Text, nullable=False, default="", index=True)
    actorUserId = Column(String, nullable=False, default="")
    actorRole = Column(String, nullable=False, default="")
    resolvedAt = Column(Text, nullable=False, default="", index=True)
    resolvedBy = Column(String, nullable=False, default="")
    resolution = Column(String, nullable=False, default="", index=True)
    metaJson = Column(Text, nullable=False, default="")


class SLAConfig(Base):
    __tablename__ = "sla_config"

    stepName = Column(String, primary_key=True)
    plannedMinutes = Column(Integer, nullable=False, default=0)
    enabled = Column(Boolean, nullable=False, default=True)
    updatedAt = Column(Text, nullable=False, default="")
    updatedBy = Column(String, nullable=False, default="")


class StepMetric(Base):
    __tablename__ = "step_metrics"

    id = Column(Integer, primary_key=True, autoincrement=True)
    requirementId = Column(String, nullable=False, default="", index=True)
    candidateId = Column(String, nullable=False, default="", index=True)
    stepName = Column(String, nullable=False, default="", index=True)
    plannedMinutes = Column(Integer, nullable=False, default=0)
    startTs = Column(Text, nullable=False, default="")
    endTs = Column(Text, nullable=False, default="")
    actualMinutes = Column(Integer, nullable=True)
    breached = Column(Boolean, nullable=False, default=False)
    actorUserId = Column(String, nullable=False, default="")
    actorRole = Column(String, nullable=False, default="")
    createdAt = Column(Text, nullable=False, default="", index=True)


class CandidateTrainingState(Base):
    __tablename__ = "candidate_training_state"

    candidateId = Column(String, primary_key=True)
    requirementId = Column(String, nullable=False, default="", index=True)
    markedCompleteAt = Column(Text, nullable=False, default="")
    markedCompleteBy = Column(String, nullable=False, default="")
    closedAt = Column(Text, nullable=False, default="", index=True)
    closedBy = Column(String, nullable=False, default="")
    updatedAt = Column(Text, nullable=False, default="")
    updatedBy = Column(String, nullable=False, default="")


class ProbationLog(Base):
    __tablename__ = "probation_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    candidateId = Column(String, nullable=False, default="", index=True)
    employeeId = Column(String, nullable=False, default="", index=True)
    requirementId = Column(String, nullable=False, default="", index=True)
    profileSnapshotJson = Column(Text, nullable=False, default="")
    trainingsSnapshotJson = Column(Text, nullable=False, default="")
    probationStartAt = Column(Text, nullable=False, default="")
    probationEndsAt = Column(Text, nullable=False, default="")
    decision = Column(String, nullable=False, default="")
    decidedAt = Column(Text, nullable=False, default="")
    actorUserId = Column(String, nullable=False, default="")
    actorRole = Column(String, nullable=False, default="")
    createdAt = Column(Text, nullable=False, default="", index=True)


class PortalRegistry(Base):
    __tablename__ = "portal_registry"
    __table_args__ = (UniqueConstraint("portalKey", name="uq_portal_registry_key"),)

    portalId = Column(String, primary_key=True)
    portalKey = Column(String, nullable=False, default="", index=True)  # stable identifier (e.g. EMP_ATTENDANCE)
    title = Column(Text, nullable=False, default="")
    description = Column(Text, nullable=False, default="")
    url = Column(Text, nullable=False, default="")
    openMode = Column(String, nullable=False, default="NEW_TAB")  # NEW_TAB | SAME_TAB | IFRAME
    icon = Column(String, nullable=False, default="")

    # Access rules (DB-driven; no frontend hardcoding)
    rolesCsv = Column(Text, nullable=False, default="")
    employeesCsv = Column(Text, nullable=False, default="")

    enabled = Column(Boolean, nullable=False, default=True, index=True)
    orderNo = Column(Integer, nullable=False, default=0, index=True)

    createdAt = Column(Text, nullable=False, default="")
    createdBy = Column(String, nullable=False, default="")
    updatedAt = Column(Text, nullable=False, default="")
    updatedBy = Column(String, nullable=False, default="")
