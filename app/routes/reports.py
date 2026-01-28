from __future__ import annotations

from io import BytesIO

from flask import Blueprint, current_app, jsonify, request, send_file

from app.reports.excel import build_workbook_bytes
from app.reports.queries import funnel_report, summary_report
from app.utils.auth import require_roles
from app.utils.errors import ApiError
from app.utils.validators import parse_date_range

reports_bp = Blueprint("reports", __name__)


@reports_bp.get("/summary")
@require_roles(["ADMIN", "OWNER", "EA", "HR"])
def summary():
    start_dt, end_dt, from_s, to_s = parse_date_range(request.args)
    db = current_app.extensions["mongo_db"]
    data = summary_report(db, start_dt, end_dt)
    return jsonify({"success": True, "data": {"from": from_s, "to": to_s, **data}})


@reports_bp.get("/funnel")
@require_roles(["ADMIN", "OWNER", "EA", "HR"])
def funnel():
    start_dt, end_dt, from_s, to_s = parse_date_range(request.args)
    department = str(request.args.get("department") or "").strip() or None
    db = current_app.extensions["mongo_db"]
    data = funnel_report(db, start_dt, end_dt, department=department)
    return jsonify(
        {"success": True, "data": {"from": from_s, "to": to_s, "department": department, **data}}
    )


@reports_bp.get("/export.xlsx")
@require_roles(["ADMIN", "OWNER", "EA", "HR"])
def export_xlsx():
    start_dt, end_dt, from_s, to_s = parse_date_range(request.args)
    report_type = str(request.args.get("type") or "").strip().lower() or "summary"
    if report_type not in {"summary", "funnel"}:
        raise ApiError("BAD_REQUEST", "type must be funnel|summary", status=400)

    department = str(request.args.get("department") or "").strip() or None
    db = current_app.extensions["mongo_db"]

    if report_type == "summary":
        payload = {"summary": summary_report(db, start_dt, end_dt)}
    else:
        payload = {"funnel": funnel_report(db, start_dt, end_dt, department=department)}

    xlsx_bytes = build_workbook_bytes(
        report_type=report_type,
        from_s=from_s,
        to_s=to_s,
        timezone_display=current_app.config["CFG"].TIMEZONE_DISPLAY,
        data=payload,
    )

    filename = f"hrms_{report_type}_{from_s}_{to_s}.xlsx"
    return send_file(
        BytesIO(xlsx_bytes),
        as_attachment=True,
        download_name=filename,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
