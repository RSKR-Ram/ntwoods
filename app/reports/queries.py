from __future__ import annotations

from datetime import datetime
from typing import Any


def summary_report(db, start_dt: datetime, end_dt: datetime) -> dict[str, Any]:
    req_pipe = [
        {"$match": {"createdAt": {"$gte": start_dt, "$lt": end_dt}}},
        {"$addFields": {"status": {"$ifNull": ["$status", "UNKNOWN"]}}},
        {"$group": {"_id": "$status", "count": {"$sum": 1}}},
        {"$project": {"_id": 0, "status": "$_id", "count": 1}},
        {"$sort": {"status": 1}},
    ]
    req_by_status = list(db.requirements.aggregate(req_pipe))

    cand_pipe = [
        {"$match": {"createdAt": {"$gte": start_dt, "$lt": end_dt}}},
        {"$addFields": {"stage": {"$ifNull": ["$stage", {"$ifNull": ["$status", "UNKNOWN"]}]}}},
        {"$group": {"_id": "$stage", "count": {"$sum": 1}}},
        {"$project": {"_id": 0, "stage": "$_id", "count": 1}},
        {"$sort": {"stage": 1}},
    ]
    cand_by_stage = list(db.candidates.aggregate(cand_pipe))

    return {
        "requirements": {
            "total": sum(int(x["count"]) for x in req_by_status),
            "byStatus": req_by_status,
        },
        "candidates": {
            "total": sum(int(x["count"]) for x in cand_by_stage),
            "byStage": cand_by_stage,
        },
    }


def funnel_report(
    db, start_dt: datetime, end_dt: datetime, *, department: str | None
) -> dict[str, Any]:
    pipe: list[dict[str, Any]] = [
        {"$match": {"createdAt": {"$gte": start_dt, "$lt": end_dt}}},
        {"$addFields": {"stage": {"$ifNull": ["$stage", {"$ifNull": ["$status", "UNKNOWN"]}]}}},
    ]

    if department:
        dep_norm = str(department).strip().lower()
        pipe += [
            {
                "$lookup": {
                    "from": "requirements",
                    "localField": "requirementId",
                    "foreignField": "requirementId",
                    "as": "req",
                }
            },
            {"$unwind": {"path": "$req", "preserveNullAndEmptyArrays": True}},
            {
                "$addFields": {
                    "reqDepartment": {
                        "$ifNull": ["$req.department", {"$ifNull": ["$req.raisedFor", ""]}]
                    },
                }
            },
            {"$addFields": {"reqDepartmentNorm": {"$toLower": "$reqDepartment"}}},
            {"$match": {"reqDepartmentNorm": dep_norm}},
        ]

    pipe += [
        {"$group": {"_id": "$stage", "count": {"$sum": 1}}},
        {"$project": {"_id": 0, "stage": "$_id", "count": 1}},
        {"$sort": {"stage": 1}},
    ]

    items = list(db.candidates.aggregate(pipe))
    return {"total": sum(int(x["count"]) for x in items), "items": items}
