from __future__ import annotations

import base64
import os
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select

from actions.helpers import next_prefixed_id
from models import Employee, EmployeeDoc
from services.gas_uploader import gas_upload_file
from utils import ApiError, iso_utc_now, sanitize_filename


def _new_doc_id(db) -> str:
    year = datetime.now(timezone.utc).strftime("%Y")
    prefix = f"DOC-{year}-"
    existing = [str(x or "") for x in db.execute(select(EmployeeDoc.id).where(EmployeeDoc.id.like(f"{prefix}%"))).scalars().all()]
    return next_prefixed_id(db, counter_key=f"DOC_{year}", prefix=prefix, pad=5, existing_ids=existing)


def _next_doc_version(db, *, employee_id: str, doc_type: str) -> int:
    v = (
        db.execute(
            select(func.max(EmployeeDoc.version))
            .where(EmployeeDoc.employee_id == employee_id)
            .where(EmployeeDoc.doc_type == doc_type)
        )
        .scalar_one_or_none()
    )
    try:
        return int(v or 0) + 1
    except Exception:
        return 1


def create_employee_doc(
    db,
    *,
    cfg: Any,
    employee_id: str,
    doc_type: str,
    file_bytes: bytes,
    file_name: str,
    mime_type: str,
    uploaded_by: str,
    visibility: str = "INTERNAL",
) -> EmployeeDoc:
    emp = db.execute(select(Employee).where(Employee.employeeId == employee_id)).scalar_one_or_none()
    if not emp:
        raise ApiError("NOT_FOUND", "Employee not found")

    doc_type_clean = str(doc_type or "").strip().upper()
    if not doc_type_clean:
        raise ApiError("BAD_REQUEST", "Missing docType")

    safe_name = sanitize_filename(file_name or "doc")
    mime = str(mime_type or "").strip() or "application/octet-stream"
    size = int(len(file_bytes or b""))
    if size <= 0:
        raise ApiError("BAD_REQUEST", "Empty file")

    vis = str(visibility or "INTERNAL").strip().upper()
    if vis not in {"INTERNAL", "EMPLOYEE"}:
        raise ApiError("BAD_REQUEST", "Invalid visibility")

    mode = str(getattr(cfg, "FILE_STORAGE_MODE", "") or "local").strip().lower()
    if mode != "gas":
        os.makedirs(str(getattr(cfg, "UPLOAD_DIR", "./uploads") or "./uploads"), exist_ok=True)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    stored_name = f"EMP_DOC_{employee_id}_{doc_type_clean}_{stamp}_{safe_name}"

    storage_key = ""
    if mode == "gas":
        b64 = base64.b64encode(file_bytes).decode("ascii")
        up = gas_upload_file(
            cfg=cfg,
            file_base64=b64,
            file_name=stored_name,
            mime_type=mime,
            extra={
                "employeeId": employee_id,
                "docType": doc_type_clean,
                "sourceAction": "EMPLOYEE_DOC_UPLOAD",
                "uploadedBy": uploaded_by,
            },
        )
        storage_key = str(up.get("fileId") or "").strip()
        if not storage_key:
            raise ApiError("INTERNAL", "Upload failed (missing fileId)")
    else:
        storage_key = os.urandom(16).hex()
        out_path = os.path.join(str(getattr(cfg, "UPLOAD_DIR", "./uploads") or "./uploads"), f"{storage_key}_{stored_name}")
        with open(out_path, "wb") as f:
            f.write(file_bytes)

    doc_id = _new_doc_id(db)
    version = _next_doc_version(db, employee_id=employee_id, doc_type=doc_type_clean)
    uploaded_at = iso_utc_now()

    row = EmployeeDoc(
        id=doc_id,
        employee_id=employee_id,
        doc_type=doc_type_clean,
        storage_key=storage_key,
        file_name=safe_name,
        mime_type=mime,
        size=size,
        uploaded_by=str(uploaded_by or ""),
        uploaded_at=uploaded_at,
        visibility=vis,
        version=version,
    )
    db.add(row)
    return row
