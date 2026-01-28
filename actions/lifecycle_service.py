from __future__ import annotations

from typing import Any, Iterable, Optional

from sqlalchemy import select

from actions.candidate_repo import update_candidate
from actions.helpers import append_audit, append_requirement_history
from models import Candidate, Requirement
from utils import ApiError, AuthContext, iso_utc_now


SLOT_CONSUMING_STATUSES = {"JOINED", "PROBATION", "EMPLOYEE"}


def lock_candidate(db, *, candidate_id: str, requirement_id: str = "") -> Candidate:
    cid = str(candidate_id or "").strip()
    if not cid:
        raise ApiError("BAD_REQUEST", "Missing candidateId")

    cand = (
        db.execute(select(Candidate).where(Candidate.candidateId == cid).with_for_update(of=Candidate))
        .scalars()
        .first()
    )
    if not cand:
        raise ApiError("NOT_FOUND", "Candidate not found")
    if requirement_id and str(cand.requirementId or "") != str(requirement_id):
        raise ApiError("BAD_REQUEST", "Candidate does not belong to requirement")
    return cand


def lock_requirement(db, *, requirement_id: str) -> Requirement:
    rid = str(requirement_id or "").strip()
    if not rid:
        raise ApiError("BAD_REQUEST", "Missing requirementId")

    req = (
        db.execute(select(Requirement).where(Requirement.requirementId == rid).with_for_update(of=Requirement))
        .scalars()
        .first()
    )
    if not req:
        raise ApiError("NOT_FOUND", "Requirement not found")
    return req


def _reserve_requirement_slot(db, *, requirement_id: str, auth: AuthContext, now: str) -> dict[str, Any]:
    req = lock_requirement(db, requirement_id=requirement_id)

    required_count = int(req.requiredCount or 0)
    joined_count = int(req.joinedCount or 0)
    if required_count <= 0:
        raise ApiError("BAD_REQUEST", "Invalid requiredCount")
    if joined_count < 0:
        joined_count = 0
    if joined_count >= required_count:
        raise ApiError("BAD_REQUEST", "Requirement already filled")

    next_joined = joined_count + 1
    req.joinedCount = next_joined
    req.updatedAt = now
    req.updatedBy = auth.userId

    append_requirement_history(
        db,
        requirementId=requirement_id,
        fromStatus="",
        toStatus="",
        stageTag="JOINED_COUNT_INC",
        remark="",
        actor=auth,
        meta={"joinedCount": next_joined, "requiredCount": required_count},
    )
    append_audit(
        db,
        entityType="REQUIREMENT",
        entityId=requirement_id,
        action="JOINED_COUNT_INC",
        fromState="",
        toState="",
        stageTag="JOINED_COUNT_INC",
        remark="",
        actor=auth,
        at=now,
        meta={"joinedCount": next_joined, "requiredCount": required_count},
    )

    status = str(req.status or "").upper()
    auto_closed = False
    if next_joined == required_count and status != "CLOSED":
        req.status = "CLOSED"
        req.latestRemark = "Auto closed (JoinedCount reached RequiredCount)"
        req.updatedAt = now
        req.updatedBy = auth.userId

        append_requirement_history(
            db,
            requirementId=requirement_id,
            fromStatus=status,
            toStatus="CLOSED",
            stageTag="REQUIREMENT_AUTO_CLOSE",
            remark="Auto closed",
            actor=auth,
            meta={"joinedCount": next_joined, "requiredCount": required_count},
        )
        append_audit(
            db,
            entityType="REQUIREMENT",
            entityId=requirement_id,
            action="REQUIREMENT_AUTO_CLOSE",
            fromState=status,
            toState="CLOSED",
            stageTag="REQUIREMENT_AUTO_CLOSE",
            remark="Auto closed",
            actor=auth,
            at=now,
            meta={"joinedCount": next_joined, "requiredCount": required_count},
        )
        status = "CLOSED"
        auto_closed = True

    return {
        "ok": True,
        "requirementId": requirement_id,
        "joinedCount": next_joined,
        "requiredCount": required_count,
        "status": status,
        "autoClosed": auto_closed,
    }


def _release_requirement_slot(db, *, requirement_id: str, auth: AuthContext, now: str, reason: str) -> dict[str, Any]:
    req = lock_requirement(db, requirement_id=requirement_id)

    required_count = int(req.requiredCount or 0)
    joined_count = int(req.joinedCount or 0)
    if required_count <= 0:
        required_count = 0
    if joined_count < 0:
        joined_count = 0

    if joined_count == 0:
        return {
            "ok": True,
            "requirementId": requirement_id,
            "joinedCount": 0,
            "requiredCount": required_count,
            "status": str(req.status or "").upper(),
            "reopened": False,
        }

    next_joined = max(0, joined_count - 1)
    req.joinedCount = next_joined
    req.updatedAt = now
    req.updatedBy = auth.userId

    append_requirement_history(
        db,
        requirementId=requirement_id,
        fromStatus="",
        toStatus="",
        stageTag="JOINED_COUNT_DEC",
        remark=reason or "",
        actor=auth,
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
        actor=auth,
        at=now,
        meta={"joinedCount": next_joined, "requiredCount": required_count, "reason": reason or ""},
    )

    status = str(req.status or "").upper()
    reopened = False
    if status == "CLOSED" and required_count > 0 and next_joined < required_count:
        req.status = "APPROVED"
        req.latestRemark = f"Reopened (slot freed): {reason or 'EXIT'}"
        req.updatedAt = now
        req.updatedBy = auth.userId

        append_requirement_history(
            db,
            requirementId=requirement_id,
            fromStatus="CLOSED",
            toStatus="APPROVED",
            stageTag="REQUIREMENT_REOPEN",
            remark=req.latestRemark or "",
            actor=auth,
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
            actor=auth,
            at=now,
            meta={"joinedCount": next_joined, "requiredCount": required_count, "reason": reason or ""},
        )
        status = "APPROVED"
        reopened = True

    return {
        "ok": True,
        "requirementId": requirement_id,
        "joinedCount": next_joined,
        "requiredCount": required_count,
        "status": status,
        "reopened": reopened,
    }


def transition_candidate_status(
    db,
    *,
    candidate_id: str,
    requirement_id: str,
    to_status: str,
    action: str,
    stage_tag: str,
    auth: AuthContext,
    remark: str = "",
    meta: Any = None,
    patch: Optional[dict[str, Any]] = None,
    require_from: Optional[Iterable[str]] = None,
) -> tuple[Candidate, Optional[dict[str, Any]]]:
    """
    Single-transaction, audited state transition with vacancy capacity enforcement.

    This function:
    - locks the Candidate row (SELECT .. FOR UPDATE) to prevent concurrent state races
    - if the transition crosses the "slot consuming" boundary, locks the Requirement row
      and updates joinedCount with strict capacity checks
    - updates the Candidate in-place
    - writes an AuditLog row for the transition

    IMPORTANT: Do not call `db.commit()` here; the API router owns the transaction boundary.
    """

    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    now = iso_utc_now()
    cand = lock_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)

    from_status = str(cand.status or "").upper().strip()
    to_u = str(to_status or "").upper().strip()
    if not to_u:
        raise ApiError("BAD_REQUEST", "Missing to_status")

    if require_from is not None:
        allowed = {str(x or "").upper().strip() for x in require_from}
        if from_status not in allowed:
            raise ApiError("BAD_REQUEST", "Candidate not in expected state")

    req_update: Optional[dict[str, Any]] = None
    from_slot = from_status in SLOT_CONSUMING_STATUSES
    to_slot = to_u in SLOT_CONSUMING_STATUSES

    if not from_slot and to_slot:
        req_update = _reserve_requirement_slot(db, requirement_id=requirement_id, auth=auth, now=now)
    elif from_slot and not to_slot:
        req_update = _release_requirement_slot(
            db,
            requirement_id=requirement_id,
            auth=auth,
            now=now,
            reason=f"{action}:{from_status}->{to_u}",
        )

    patch2 = dict(patch or {})
    patch2["status"] = to_u
    update_candidate(db, cand=cand, patch=patch2, auth=auth)

    meta2 = {"requirementId": requirement_id}
    if meta is not None:
        meta2["meta"] = meta
    if req_update:
        meta2["requirement"] = req_update

    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action=str(action or "").upper(),
        fromState=from_status,
        toState=to_u,
        stageTag=str(stage_tag or ""),
        remark=str(remark or ""),
        actor=auth,
        at=now,
        meta=meta2,
    )

    return cand, req_update

