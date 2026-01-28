"""
Advanced Analytics Actions for HRMS Dashboard

Provides pipeline statistics, hiring trends, SLA compliance metrics,
and other advanced analytics features.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, func, select

from models import AuditLog, Candidate, Requirement, SLAConfig, StepMetric
from utils import AuthContext, to_iso_utc


def candidate_pipeline_stats(data, auth: AuthContext | None, db, cfg) -> dict:
    """Get candidate counts across the pipeline.

    NOTE: In this codebase `Candidate.status` represents the pipeline stage
    (there is no separate "ACTIVE/INACTIVE" flag, and no `Candidate.stage` column).
    """
    rows = db.execute(
        select(func.upper(Candidate.status).label("status_u"), func.count(Candidate.candidateId).label("count"))
        .group_by(func.upper(Candidate.status))
        .order_by(func.upper(Candidate.status).asc())
    ).all()

    counts_by_status: dict[str, int] = {}
    total = 0
    for status_u, count in rows:
        key = str(status_u or "").upper().strip()
        c = int(count or 0)
        counts_by_status[key] = c
        total += c

    def sum_statuses(statuses: list[str]) -> int:
        return int(sum(int(counts_by_status.get(s, 0) or 0) for s in statuses))

    stages = [
        {"stage": "SHORTLISTING", "label": "Shortlisting", "count": sum_statuses(["NEW", "HOLD"])},
        {"stage": "OWNER_APPROVAL", "label": "Owner Approval", "count": sum_statuses(["OWNER", "OWNER_HOLD"])},
        {"stage": "WALKIN", "label": "Walk-in", "count": sum_statuses(["WALKIN_PENDING", "WALKIN_SCHEDULED"])},
        {"stage": "FINAL_DECISION", "label": "Final Decision", "count": sum_statuses(["FINAL_OWNER_PENDING", "FINAL_HOLD"])},
        {"stage": "JOINING", "label": "Joining", "count": sum_statuses(["SELECTED", "JOINING"])},
        {"stage": "HIRED", "label": "Hired", "count": sum_statuses(["JOINED", "PROBATION", "EMPLOYEE"])},
        {"stage": "REJECTED", "label": "Rejected", "count": sum_statuses(["REJECTED"])},
    ]

    known = sum(int(s["count"] or 0) for s in stages)
    other = total - known
    if other > 0:
        stages.append({"stage": "OTHER", "label": "Other", "count": int(other)})

    return {"stages": stages}


def dashboard_metrics(data, auth: AuthContext | None, db, cfg) -> dict:
    """Get summary metrics for dashboard."""
    now = datetime.now(timezone.utc)
    month_start = to_iso_utc(datetime(now.year, now.month, 1, tzinfo=timezone.utc))
    
    # Total candidates
    total_candidates = db.execute(
        select(func.count(Candidate.candidateId))
    ).scalar() or 0
    
    # Active requirements (approved + not closed)
    active_requirements = db.execute(
        select(func.count(Requirement.requirementId)).where(
            func.upper(Requirement.status) == "APPROVED"
        )
    ).scalar() or 0
    
    # Pending approvals (Owner approvals + final owner pending)
    pending_approvals = db.execute(
        select(func.count(Candidate.candidateId)).where(
            func.upper(Candidate.status).in_(["OWNER", "OWNER_HOLD", "FINAL_OWNER_PENDING"])
        )
    ).scalar() or 0
    
    # This month hires (candidates that actually joined in this month)
    this_month_hires = db.execute(
        select(func.count(Candidate.candidateId)).where(
            and_(
                Candidate.joinedAt != "",
                Candidate.joinedAt >= month_start,
            )
        )
    ).scalar() or 0
    
    return {
        "totalCandidates": int(total_candidates),
        "activeRequirements": int(active_requirements),
        "pendingApprovals": int(pending_approvals),
        "thisMonthHires": int(this_month_hires),
    }


def hiring_trends(data, auth: AuthContext | None, db, cfg) -> dict:
    """Get hiring trends over time."""
    period = str((data or {}).get("period") or "monthly").lower()
    if period not in {"daily", "weekly", "monthly"}:
        period = "monthly"
    date_from = str((data or {}).get("dateFrom") or "").strip()
    date_to = str((data or {}).get("dateTo") or "").strip()
    
    # Default to last 6 months
    now = datetime.now(timezone.utc)
    if not date_from:
        date_from = to_iso_utc(now - timedelta(days=180))
    if not date_to:
        date_to = to_iso_utc(now)

    # JoinedAt is the canonical "hire" moment in this codebase (set by MARK_JOIN).
    joined_rows = db.execute(
        select(Candidate.joinedAt).where(
            and_(
                Candidate.joinedAt != "",
                Candidate.joinedAt >= date_from,
                Candidate.joinedAt <= date_to,
            )
        )
    ).all()

    trend_data: dict[str, int] = {}
    for (joined_at,) in joined_rows:
        s = str(joined_at or "").strip()
        if not s:
            continue
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            continue

        if period == "daily":
            key = dt.strftime("%Y-%m-%d")
        elif period == "weekly":
            key = dt.strftime("%Y-W%U")
        else:
            key = dt.strftime("%Y-%m")

        trend_data[key] = int(trend_data.get(key, 0) or 0) + 1

    result = [{"period": k, "count": int(v)} for k, v in sorted(trend_data.items())]
    return {"trends": result, "period": period}


def source_distribution(data, auth: AuthContext | None, db, cfg) -> dict:
    """Get candidate source distribution."""
    date_from = str((data or {}).get("dateFrom") or "").strip()
    date_to = str((data or {}).get("dateTo") or "").strip()

    q = select(Candidate.source, func.count(Candidate.candidateId).label("count"))
    if date_from:
        q = q.where(Candidate.createdAt >= date_from)
    if date_to:
        q = q.where(Candidate.createdAt <= date_to)

    sources = db.execute(q.group_by(Candidate.source)).all()
    
    counts_by_source: dict[str, int] = {}
    for source, count in sources:
        key = str(source or "").strip().upper() or "OTHER"
        counts_by_source[key] = int(counts_by_source.get(key, 0) or 0) + int(count or 0)

    result = []
    color_map = {
        "JOB_PORTAL": "blue",
        "REFERRAL": "green",
        "WALK_IN": "orange",
        "CAMPUS": "purple",
        "AGENCY": "red",
    }
    
    for source_key in sorted(counts_by_source.keys()):
        count = counts_by_source.get(source_key, 0)
        result.append({
            "source": source_key,
            "label": source_key.replace("_", " ").title(),
            "count": int(count),
            "color": color_map.get(source_key, "gray"),
        })
    
    return {"sources": result}


def sla_compliance_metrics(data, auth: AuthContext | None, db, cfg) -> dict:
    """Get SLA compliance metrics by stage."""
    # Get SLA configs
    sla_configs = db.execute(select(SLAConfig).where(SLAConfig.enabled == True)).scalars().all()
    sla_map = {s.stepName: s.plannedMinutes for s in sla_configs}
    
    # Get step metrics
    stages = ["HR_REVIEW", "PRECALL", "PRE_INTERVIEW", "INPERSON_TECH", "FINAL_INTERVIEW", "JOINING"]
    
    result = []
    for stage in stages:
        planned_minutes = int(sla_map.get(stage, 60) or 0)
        if planned_minutes <= 0:
            planned_minutes = 60  # Default 60 mins
        
        # Get metrics for this stage
        metrics = (
            db.execute(
                select(StepMetric)
                .where(and_(StepMetric.stepName == stage, StepMetric.actualMinutes.isnot(None)))
                .order_by(StepMetric.createdAt.desc())
                .limit(100)
            )
            .scalars()
            .all()
        )
        
        if not metrics:
            result.append({
                "stage": stage,
                "label": stage.replace("_", " ").title(),
                "compliance": 100,
                "avgMinutes": 0,
                "totalCount": 0,
            })
            continue
        
        compliant_count = 0
        total_minutes = 0
        total_count = 0
        
        for m in metrics:
            if m.actualMinutes is None:
                continue
            total_count += 1
            actual = int(m.actualMinutes or 0)
            total_minutes += actual

            planned_eff = int(m.plannedMinutes or 0) if int(m.plannedMinutes or 0) > 0 else planned_minutes
            if planned_eff <= 0 or actual <= planned_eff:
                compliant_count += 1
        
        compliance = (compliant_count / total_count * 100) if total_count else 100
        avg_minutes = total_minutes / total_count if total_count else 0
        
        result.append({
            "stage": stage,
            "label": stage.replace("_", " ").title(),
            "compliance": round(compliance, 1),
            "avgMinutes": round(avg_minutes, 1),
            "plannedMinutes": planned_minutes,
            "totalCount": total_count,
        })
    
    return {"metrics": result}


def recent_activity(data, auth: AuthContext | None, db, cfg) -> dict:
    """Get recent activity from audit log."""
    try:
        limit = int((data or {}).get("limit") or 20)
    except Exception:
        limit = 20
    limit = max(1, min(100, limit))
    entity_type = str((data or {}).get("entityType") or "").strip() or None
    
    q = select(AuditLog).order_by(AuditLog.at.desc()).limit(limit)
    
    if entity_type:
        q = q.where(AuditLog.entityType == entity_type)
    
    logs = db.execute(q).scalars().all()
    
    activities = []
    for log in logs:
        activity_type = "UPDATE"
        if "CREATE" in log.action or "ADD" in log.action:
            activity_type = "CREATE"
        elif "DELETE" in log.action or "REMOVE" in log.action:
            activity_type = "DELETE"
        elif "REJECT" in log.action or "FAIL" in log.action:
            activity_type = "REJECTION"
        elif "APPROVE" in log.action:
            activity_type = "APPROVAL"
        elif "HIRE" in log.action or log.toState == "HIRED":
            activity_type = "HIRE"
        elif log.fromState and log.toState:
            activity_type = "STATUS_CHANGE"
        
        activities.append({
            "id": log.logId,
            "type": activity_type,
            "title": log.action.replace("_", " ").title(),
            "description": log.remark or f"{log.entityType}: {log.entityId}",
            "timestamp": log.at,
            "metadata": {
                "from": log.fromState or None,
                "to": log.toState or None,
                "actor": log.actorUserId or "System",
            },
        })
    
    return {"activities": activities}


def export_analytics_report(data, auth: AuthContext | None, db, cfg) -> dict:
    """Generate analytics report for export."""
    report_type = str((data or {}).get("reportType") or "pipeline").lower()
    format_type = str((data or {}).get("format") or "excel").lower()
    
    # For now, just return a placeholder
    # In production, this would generate actual files
    return {
        "status": "pending",
        "reportType": report_type,
        "format": format_type,
        "message": "Report generation queued. You will be notified when ready.",
    }
