from __future__ import annotations

import json
import os
import re
from typing import Any, Optional

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from actions.helpers import append_audit, append_rejection_log, append_requirement_history
from models import Candidate, CandidateIdentity, CandidateMaster, FailCandidate, Requirement, TestDecisionLog
from utils import ApiError, AuthContext, iso_utc_now
from pii import normalize_name, normalize_phone


_SYSTEM_AUTH = AuthContext(valid=True, userId="SYSTEM", email="SYSTEM", role="SYSTEM", expiresAt="")
_SLOT_CONSUMING_STATUSES = {"JOINED", "PROBATION", "EMPLOYEE"}


def _release_requirement_slot_on_exit(db, *, requirement_id: str, now: str, actor: AuthContext, reason: str) -> None:
    req = (
        db.execute(select(Requirement).where(Requirement.requirementId == requirement_id).with_for_update(of=Requirement))
        .scalars()
        .first()
    )
    if not req:
        raise ApiError("NOT_FOUND", "Requirement not found")

    required_count = int(req.requiredCount or 0)
    joined_count = int(req.joinedCount or 0)
    if joined_count < 0:
        joined_count = 0

    if joined_count == 0:
        return

    next_joined = max(0, joined_count - 1)
    req.joinedCount = next_joined
    req.updatedAt = now
    req.updatedBy = str(actor.userId or actor.email or "")

    append_requirement_history(
        db,
        requirementId=requirement_id,
        fromStatus="",
        toStatus="",
        stageTag="JOINED_COUNT_DEC",
        remark=reason or "",
        actor=actor,
        meta={"joinedCount": next_joined, "requiredCount": required_count, "reason": reason or ""},
    )
    append_audit(
        db,
        entityType="REQUIREMENT",
        entityId=requirement_id,
        action="JOINED_COUNT_DEC",
        fromState="",
        toState="",
        stageTag="JOINED_COUNT_DEC",
        remark=reason or "",
        actor=actor,
        at=now,
        meta={"joinedCount": next_joined, "requiredCount": required_count, "reason": reason or ""},
    )

    status = str(req.status or "").upper().strip()
    if status == "CLOSED" and required_count > 0 and next_joined < required_count:
        req.status = "APPROVED"
        req.latestRemark = f"Reopened (slot freed): {reason or 'EXIT'}"
        req.updatedAt = now
        req.updatedBy = str(actor.userId or actor.email or "")

        append_requirement_history(
            db,
            requirementId=requirement_id,
            fromStatus="CLOSED",
            toStatus="APPROVED",
            stageTag="REQUIREMENT_REOPEN",
            remark=req.latestRemark or "",
            actor=actor,
            meta={"joinedCount": next_joined, "requiredCount": required_count, "reason": reason or ""},
        )
        append_audit(
            db,
            entityType="REQUIREMENT",
            entityId=requirement_id,
            action="REQUIREMENT_REOPEN",
            fromState="CLOSED",
            toState="APPROVED",
            stageTag="REQUIREMENT_REOPEN",
            remark=req.latestRemark or "",
            actor=actor,
            at=now,
            meta={"joinedCount": next_joined, "requiredCount": required_count, "reason": reason or ""},
        )


def normalize_mobile(mobile: Any) -> str:
    return normalize_phone(str(mobile or ""))


def normalize_candidate_name(name: Any) -> str:
    return normalize_name(str(name or ""))


def has_duplicate_candidate_in_requirement(db, *, requirement_id: str, name_hash: str, mobile_hash: str) -> bool:
    nh = str(name_hash or "").strip().lower()
    mh = str(mobile_hash or "").strip().lower()
    if not requirement_id or not nh or not mh:
        return False
    row = (
        db.execute(
            select(Candidate.candidateId)
            .where(Candidate.requirementId == requirement_id)
            .where(Candidate.name_hash == nh)
            .where(Candidate.mobile_hash == mh)
        )
        .scalars()
        .first()
    )
    return bool(row)


def _new_candidate_master_id() -> str:
    return "CAN-" + os.urandom(12).hex().upper()


def get_or_create_candidate_master_by_phone_hash(
    db,
    *,
    phone_hash: str,
    name_hash: str,
    name_masked: str,
    mobile_masked: str,
    name_enc: str,
    mobile_enc: str,
    auth: AuthContext,
) -> CandidateMaster:
    """
    Global, non-duplicating identity anchor for a person.

    Identity uses PHONE_HASH (HMAC-SHA256 hex) so we can dedupe without storing raw phone numbers.
    Uses a nested transaction so concurrent creates don't abort the outer request transaction.
    """

    ph = str(phone_hash or "").strip().lower()
    if not ph:
        raise ApiError("BAD_REQUEST", "Invalid phone hash")

    ident = (
        db.execute(
            select(CandidateIdentity)
            .where(CandidateIdentity.identityType == "PHONE_HASH")
            .where(CandidateIdentity.normalizedValue == ph)
            .where(CandidateIdentity.active == True)  # noqa: E712
        )
        .scalars()
        .first()
    )
    if ident:
        cm_id = str(getattr(ident, "candidateMasterId", "") or "").strip()
        if cm_id:
            master = db.execute(select(CandidateMaster).where(CandidateMaster.candidateMasterId == cm_id)).scalars().first()
            if master:
                return master

    now = iso_utc_now()
    cm_id = _new_candidate_master_id()
    master = CandidateMaster(
        candidateMasterId=cm_id,
        status="ACTIVE",
        name_hash=str(name_hash or ""),
        mobile_hash=ph,
        name_masked=str(name_masked or ""),
        mobile_masked=str(mobile_masked or ""),
        name_enc=str(name_enc or ""),
        mobile_enc=str(mobile_enc or ""),
        createdAt=now,
        createdBy=str(auth.userId or auth.email or ""),
        updatedAt=now,
        updatedBy=str(auth.userId or auth.email or ""),
    )
    identity = CandidateIdentity(
        candidateMasterId=cm_id,
        identityType="PHONE_HASH",
        normalizedValue=ph,
        active=True,
        createdAt=now,
        createdBy=str(auth.userId or auth.email or ""),
    )

    try:
        with db.begin_nested():
            db.add(master)
            db.add(identity)
            db.flush([master, identity])
        return master
    except IntegrityError:
        # Someone else won the race; load the existing identity+master.
        db.expire_all()
        ident2 = (
            db.execute(
                select(CandidateIdentity)
                .where(CandidateIdentity.identityType == "PHONE_HASH")
                .where(CandidateIdentity.normalizedValue == ph)
                .where(CandidateIdentity.active == True)  # noqa: E712
            )
            .scalars()
            .first()
        )
        if not ident2:
            raise ApiError("CONFLICT", "Candidate identity already exists")
        cm_id2 = str(getattr(ident2, "candidateMasterId", "") or "").strip()
        if not cm_id2:
            raise ApiError("INTERNAL", "Corrupt candidate identity row")
        master2 = db.execute(select(CandidateMaster).where(CandidateMaster.candidateMasterId == cm_id2)).scalars().first()
        if not master2:
            raise ApiError("INTERNAL", "Candidate master missing for existing identity")
        return master2


def update_candidate_master_phone_hash(
    db,
    *,
    candidate_master_id: str,
    next_phone_hash: str,
    next_name_hash: str,
    next_name_masked: str,
    next_mobile_masked: str,
    next_name_enc: str,
    next_mobile_enc: str,
    auth: AuthContext,
) -> CandidateMaster:
    cm_id = str(candidate_master_id or "").strip()
    if not cm_id:
        raise ApiError("BAD_REQUEST", "Missing candidateMasterId")

    ph = str(next_phone_hash or "").strip().lower()
    if not ph:
        raise ApiError("BAD_REQUEST", "Invalid phone hash")

    now = iso_utc_now()

    master = (
        db.execute(select(CandidateMaster).where(CandidateMaster.candidateMasterId == cm_id).with_for_update(of=CandidateMaster))
        .scalars()
        .first()
    )
    if not master:
        raise ApiError("NOT_FOUND", "Candidate master not found")

    ident = (
        db.execute(
            select(CandidateIdentity)
            .where(CandidateIdentity.candidateMasterId == cm_id)
            .where(CandidateIdentity.identityType == "PHONE_HASH")
            .where(CandidateIdentity.active == True)  # noqa: E712
            .with_for_update(of=CandidateIdentity)
        )
        .scalars()
        .first()
    )
    if not ident:
        ident = CandidateIdentity(
            candidateMasterId=cm_id,
            identityType="PHONE_HASH",
            normalizedValue=ph,
            active=True,
            createdAt=now,
            createdBy=str(auth.userId or auth.email or ""),
        )
        db.add(ident)
    else:
        current_ph = str(getattr(ident, "normalizedValue", "") or "").strip().lower()
        if current_ph != ph:
            conflict = (
                db.execute(
                    select(CandidateIdentity)
                    .where(CandidateIdentity.identityType == "PHONE_HASH")
                    .where(CandidateIdentity.normalizedValue == ph)
                    .where(CandidateIdentity.active == True)  # noqa: E712
                )
                .scalars()
                .first()
            )
            if conflict and str(getattr(conflict, "candidateMasterId", "") or "").strip() != cm_id:
                raise ApiError("CONFLICT", "Mobile already linked to another candidate")
            ident.normalizedValue = ph

    master.name_hash = str(next_name_hash or "")
    master.mobile_hash = ph
    master.name_masked = str(next_name_masked or "")
    master.mobile_masked = str(next_mobile_masked or "")
    if str(next_name_enc or "").strip():
        master.name_enc = str(next_name_enc or "")
    if str(next_mobile_enc or "").strip():
        master.mobile_enc = str(next_mobile_enc or "")
    master.updatedAt = now
    master.updatedBy = str(auth.userId or auth.email or "")

    return master


def find_candidate(db, *, candidate_id: str, requirement_id: str = "") -> Candidate:
    cand = db.execute(select(Candidate).where(Candidate.candidateId == str(candidate_id))).scalar_one_or_none()
    if not cand:
        raise ApiError("NOT_FOUND", "Candidate not found")
    if requirement_id and str(cand.requirementId or "") != str(requirement_id):
        raise ApiError("BAD_REQUEST", "Candidate does not belong to requirement")
    return cand


def update_candidate(db, *, cand: Candidate, patch: dict[str, Any], auth: AuthContext):
    def set_str(key: str, value: Any):
        setattr(cand, key, str(value or ""))

    def set_iso(key: str, value: Any):
        setattr(cand, key, str(value or ""))

    def set_int_or_none(key: str, value: Any):
        if value == "" or value is None:
            setattr(cand, key, None)
            return
        try:
            setattr(cand, key, int(value))
        except Exception:
            setattr(cand, key, None)

    if "jobRole" in patch and patch["jobRole"] is not None:
        set_str("jobRole", patch["jobRole"])
    if "candidateMasterId" in patch and patch["candidateMasterId"] is not None:
        set_str("candidateMasterId", patch["candidateMasterId"])
    if "status" in patch and patch["status"] is not None:
        set_str("status", patch["status"])
    if "candidateStage" in patch and patch["candidateStage"] is not None:
        set_str("candidateStage", patch["candidateStage"])
    if "stageUpdatedAt" in patch and patch["stageUpdatedAt"] is not None:
        set_iso("stageUpdatedAt", patch["stageUpdatedAt"])
    if "holdUntil" in patch and patch["holdUntil"] is not None:
        set_iso("holdUntil", patch["holdUntil"])
    if "walkinAt" in patch and patch["walkinAt"] is not None:
        set_iso("walkinAt", patch["walkinAt"])
    if "walkinNotes" in patch and patch["walkinNotes"] is not None:
        set_str("walkinNotes", patch["walkinNotes"])
    if "notPickCount" in patch and patch["notPickCount"] is not None:
        try:
            cand.notPickCount = int(patch["notPickCount"] or 0)
        except Exception:
            cand.notPickCount = 0
    if "preCallAt" in patch and patch["preCallAt"] is not None:
        set_iso("preCallAt", patch["preCallAt"])
    if "preInterviewStatus" in patch and patch["preInterviewStatus"] is not None:
        set_str("preInterviewStatus", patch["preInterviewStatus"])
    if "preInterviewMarks" in patch and patch["preInterviewMarks"] is not None:
        cand.preInterviewMarks = "" if patch["preInterviewMarks"] == "" else patch["preInterviewMarks"]
    if "preInterviewMarksAt" in patch and patch["preInterviewMarksAt"] is not None:
        set_iso("preInterviewMarksAt", patch["preInterviewMarksAt"])
    if "testToken" in patch and patch["testToken"] is not None:
        set_str("testToken", patch["testToken"])
    if "testTokenExpiresAt" in patch and patch["testTokenExpiresAt"] is not None:
        set_iso("testTokenExpiresAt", patch["testTokenExpiresAt"])
    if "onlineTestScore" in patch and patch["onlineTestScore"] is not None:
        set_int_or_none("onlineTestScore", patch["onlineTestScore"])
    if "onlineTestResult" in patch and patch["onlineTestResult"] is not None:
        set_str("onlineTestResult", patch["onlineTestResult"])
    if "onlineTestSubmittedAt" in patch and patch["onlineTestSubmittedAt"] is not None:
        set_iso("onlineTestSubmittedAt", patch["onlineTestSubmittedAt"])
    if "testDecisionsJson" in patch and patch["testDecisionsJson"] is not None:
        set_str("testDecisionsJson", patch["testDecisionsJson"])
    if "candidate_test_failed_but_manually_continued" in patch and patch["candidate_test_failed_but_manually_continued"] is not None:
        cand.candidate_test_failed_but_manually_continued = bool(patch["candidate_test_failed_but_manually_continued"])
    if "inPersonMarks" in patch and patch["inPersonMarks"] is not None:
        set_int_or_none("inPersonMarks", patch["inPersonMarks"])
    if "inPersonMarksAt" in patch and patch["inPersonMarksAt"] is not None:
        set_iso("inPersonMarksAt", patch["inPersonMarksAt"])
    if "techSelectedTestsJson" in patch and patch["techSelectedTestsJson"] is not None:
        set_str("techSelectedTestsJson", patch["techSelectedTestsJson"])
    if "techSelectedAt" in patch and patch["techSelectedAt"] is not None:
        set_iso("techSelectedAt", patch["techSelectedAt"])
    if "tallyMarks" in patch and patch["tallyMarks"] is not None:
        set_int_or_none("tallyMarks", patch["tallyMarks"])
    if "voiceMarks" in patch and patch["voiceMarks"] is not None:
        set_int_or_none("voiceMarks", patch["voiceMarks"])
    if "techReview" in patch and patch["techReview"] is not None:
        set_str("techReview", patch["techReview"])
    if "excelMarks" in patch and patch["excelMarks"] is not None:
        set_int_or_none("excelMarks", patch["excelMarks"])
    if "excelReview" in patch and patch["excelReview"] is not None:
        set_str("excelReview", patch["excelReview"])
    if "techResult" in patch and patch["techResult"] is not None:
        set_str("techResult", patch["techResult"])
    if "techEvaluatedAt" in patch and patch["techEvaluatedAt"] is not None:
        set_iso("techEvaluatedAt", patch["techEvaluatedAt"])
    if "finalHoldAt" in patch and patch["finalHoldAt"] is not None:
        set_iso("finalHoldAt", patch["finalHoldAt"])
    if "finalHoldRemark" in patch and patch["finalHoldRemark"] is not None:
        set_str("finalHoldRemark", patch["finalHoldRemark"])
    if "joiningAt" in patch and patch["joiningAt"] is not None:
        set_iso("joiningAt", patch["joiningAt"])
    if "docsJson" in patch and patch["docsJson"] is not None:
        set_str("docsJson", patch["docsJson"])
    if "docsCompleteAt" in patch and patch["docsCompleteAt"] is not None:
        set_iso("docsCompleteAt", patch["docsCompleteAt"])
    if "joinedAt" in patch and patch["joinedAt"] is not None:
        set_iso("joinedAt", patch["joinedAt"])
    if "probationStartAt" in patch and patch["probationStartAt"] is not None:
        set_iso("probationStartAt", patch["probationStartAt"])
    if "probationEndsAt" in patch and patch["probationEndsAt"] is not None:
        set_iso("probationEndsAt", patch["probationEndsAt"])
    if "employeeId" in patch and patch["employeeId"] is not None:
        set_str("employeeId", patch["employeeId"])
    if "rejectedFromStatus" in patch and patch["rejectedFromStatus"] is not None:
        set_str("rejectedFromStatus", patch["rejectedFromStatus"])
    if "rejectedReasonCode" in patch and patch["rejectedReasonCode"] is not None:
        set_str("rejectedReasonCode", patch["rejectedReasonCode"])
    if "rejectedAt" in patch and patch["rejectedAt"] is not None:
        set_iso("rejectedAt", patch["rejectedAt"])

    cand.updatedAt = iso_utc_now()
    cand.updatedBy = auth.userId


def _parse_json_object(raw: Any, fallback: dict) -> dict:
    try:
        s = str(raw or "").strip()
        if not s:
            return fallback
        o = json.loads(s)
        if not isinstance(o, dict):
            return fallback
        return o
    except Exception:
        return fallback


def get_test_decisions(cand: Candidate) -> dict:
    return _parse_json_object(getattr(cand, "testDecisionsJson", "") or "", {})


def is_test_continued(cand: Candidate, test_type: str) -> bool:
    mp = get_test_decisions(cand)
    entry = mp.get(test_type) if isinstance(mp, dict) else None
    if not isinstance(entry, dict):
        return False
    return str(entry.get("decision") or "").upper() == "CONTINUE"


def upsert_test_decision(
    db,
    *,
    candidate_id: str,
    requirement_id: str,
    test_type: str,
    decision: str,
    remark: str,
    meta: dict,
    auth: AuthContext,
):
    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    existing = get_test_decisions(cand)
    now = iso_utc_now()

    existing[test_type] = {
        "decision": str(decision or "").upper(),
        "at": now,
        "userId": auth.userId,
        "role": auth.role,
        "remark": remark or "",
    }

    continued = str(decision or "").upper() == "CONTINUE"

    update_candidate(
        db,
        cand=cand,
        patch={
            "testDecisionsJson": json.dumps(existing),
            "candidate_test_failed_but_manually_continued": True if continued else bool(cand.candidate_test_failed_but_manually_continued),
        },
        auth=auth,
    )

    db.add(
        TestDecisionLog(
            logId="LOG-" + os.urandom(16).hex(),
            candidateId=candidate_id,
            requirementId=requirement_id,
            testType=str(test_type or ""),
            marks=json.dumps(meta.get("marks")) if meta.get("marks") is not None else "",
            passFail=str(meta.get("passFail") or ""),
            hrDecision=str(decision or "").upper(),
            remark=str(remark or ""),
            overrideFlag=True if continued else False,
            actorUserId=auth.userId,
            actorRole=auth.role,
            at=now,
            metaJson=json.dumps(meta or {}),
        )
    )

    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="TEST_FAIL_DECIDE",
        fromState=str(cand.status or ""),
        toState=str(cand.status or ""),
        stageTag=f"{str(test_type or 'TEST')} {str(decision or '')}",
        remark=str(remark or ""),
        actor=auth,
        at=now,
        meta={"requirementId": requirement_id, "testType": test_type, "decision": decision, "meta": meta or {}},
    )

    if str(test_type or "").upper().strip() == "ONLINE_TEST":
        row = (
            db.execute(
                select(FailCandidate)
                .where(FailCandidate.candidateId == candidate_id)
                .where(func.upper(FailCandidate.stageName) == "ONLINE_TEST")
                .where(FailCandidate.resolvedAt == "")
                .order_by(FailCandidate.failedAt.desc())
            )
            .scalars()
            .first()
        )
        if row:
            row.resolvedAt = now
            row.resolvedBy = str(auth.userId or auth.email or "")
            row.resolution = str(decision or "").upper().strip()

    return {"ok": True, "testType": test_type, "decision": str(decision or "").upper(), "at": now}


def reject_candidate_with_meta(
    db,
    *,
    candidate_id: str,
    requirement_id: str,
    stage_tag: str,
    remark: str,
    reason_code: str,
    auth: AuthContext | None,
    audit_action: str = "CANDIDATE_REJECT",
):
    cand = (
        db.execute(select(Candidate).where(Candidate.candidateId == str(candidate_id)).with_for_update(of=Candidate))
        .scalars()
        .first()
    )
    if not cand:
        raise ApiError("NOT_FOUND", "Candidate not found")
    if requirement_id and str(cand.requirementId or "") != str(requirement_id):
        raise ApiError("BAD_REQUEST", "Candidate does not belong to requirement")

    current_status = str(cand.status or "").upper()
    if current_status == "REJECTED":
        return {"ok": True, "status": "REJECTED", "alreadyRejected": True}

    now = iso_utc_now()
    actor = auth if auth else _SYSTEM_AUTH

    # If the candidate is exiting after consuming a vacancy slot, release capacity safely.
    if current_status in _SLOT_CONSUMING_STATUSES:
        _release_requirement_slot_on_exit(
            db,
            requirement_id=requirement_id,
            now=now,
            actor=actor,
            reason=f"{str(reason_code or 'REJECT').upper()}",
        )

    update_candidate(
        db,
        cand=cand,
        patch={
            "rejectedFromStatus": current_status,
            "rejectedReasonCode": str(reason_code or ""),
            "rejectedAt": now,
            "status": "REJECTED",
        },
        auth=actor,
    )

    append_rejection_log(
        db,
        candidateId=candidate_id,
        requirementId=requirement_id,
        stageTag=stage_tag,
        remark=remark,
        actor=auth,
        reasonCode=reason_code,
    )

    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action=str(audit_action or "CANDIDATE_REJECT").upper(),
        fromState=current_status,
        toState="REJECTED",
        stageTag=stage_tag,
        remark=remark or "",
        actor=actor,
        at=now,
        meta={"requirementId": requirement_id, "reasonCode": str(reason_code or "")},
    )

    return {
        "ok": True,
        "status": "REJECTED",
        "rejectedFromStatus": current_status,
        "rejectedReasonCode": str(reason_code or ""),
        "rejectedAt": now,
    }
