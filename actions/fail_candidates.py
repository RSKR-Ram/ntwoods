from __future__ import annotations

from typing import Any

from sqlalchemy import select

from models import Candidate, FailCandidate, Requirement
from pii import decrypt_pii
from utils import ApiError, AuthContext


def fail_candidates_list(data, auth: AuthContext | None, db, cfg):
    stage = str((data or {}).get("stageName") or "").upper().strip()
    include_resolved = bool((data or {}).get("includeResolved"))

    q = select(FailCandidate)
    if stage:
        q = q.where(FailCandidate.stageName == stage)
    if not include_resolved:
        q = q.where(FailCandidate.resolvedAt == "")
    rows = db.execute(q.order_by(FailCandidate.failedAt.desc())).scalars().all()

    cand_map: dict[str, Candidate] = {c.candidateId: c for c in db.execute(select(Candidate)).scalars().all()}
    req_map: dict[str, Requirement] = {r.requirementId: r for r in db.execute(select(Requirement)).scalars().all()}

    items: list[dict[str, Any]] = []
    can_pii = bool(getattr(cfg, "PII_ENC_KEY", "").strip()) and bool(auth and auth.valid) and str(getattr(auth, "role", "") or "").upper() in set(getattr(cfg, "PII_VIEW_ROLES", []) or [])
    for r in rows:
        cand = cand_map.get(r.candidateId)
        if not cand:
            continue
        req = req_map.get(str(cand.requirementId or ""))
        item = {
                "id": r.id,
                "candidateId": r.candidateId or "",
                "requirementId": r.requirementId or "",
                "candidateName": cand.candidateName or "",
                "mobile": cand.mobile or "",
                "cvFileId": getattr(cand, "cvFileId", "") or "",
                "cvFileName": getattr(cand, "cvFileName", "") or "",
                "jobRole": cand.jobRole or "",
                "jobTitle": (req.jobTitle if req else "") or "",
                "stageName": r.stageName or "",
                "reason": r.reason or "",
                "score": r.score,
                "failedAt": r.failedAt or "",
                "actorUserId": r.actorUserId or "",
                "actorRole": r.actorRole or "",
                "resolvedAt": r.resolvedAt or "",
                "resolvedBy": r.resolvedBy or "",
                "resolution": r.resolution or "",
            }
        if can_pii:
            name_full = decrypt_pii(getattr(cand, "name_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{cand.candidateId}:name")
            mobile_full = decrypt_pii(getattr(cand, "mobile_enc", "") or "", key=cfg.PII_ENC_KEY, aad=f"candidate:{cand.candidateId}:mobile")
            if name_full:
                item["candidateNameFull"] = name_full
            if mobile_full:
                item["mobileFull"] = mobile_full

        items.append(item)

    return {"items": items, "total": len(items)}
