from __future__ import annotations

from sqlalchemy import select

from actions.helpers import append_audit, next_prefixed_id
from models import Employee, PortalRegistry
from utils import ApiError, AuthContext, iso_utc_now, normalize_role, parse_roles_csv


_ALLOWED_OPEN_MODES = {"NEW_TAB", "SAME_TAB", "IFRAME"}


def _normalize_open_mode(value: str) -> str:
    m = str(value or "").strip().upper() or "NEW_TAB"
    if m in {"NEW", "TAB", "NEW-TAB", "NEWTAB"}:
        m = "NEW_TAB"
    if m in {"SAME", "IN_APP", "INAPP"}:
        m = "SAME_TAB"
    if m in {"EMBED", "EMBEDDED"}:
        m = "IFRAME"
    if m not in _ALLOWED_OPEN_MODES:
        m = "NEW_TAB"
    return m


def _serialize_portal(p: PortalRegistry) -> dict:
    return {
        "portalId": str(getattr(p, "portalId", "") or ""),
        "portalKey": str(getattr(p, "portalKey", "") or ""),
        "title": str(getattr(p, "title", "") or ""),
        "description": str(getattr(p, "description", "") or ""),
        "url": str(getattr(p, "url", "") or ""),
        "openMode": _normalize_open_mode(str(getattr(p, "openMode", "") or "")),
        "icon": str(getattr(p, "icon", "") or ""),
        "rolesCsv": str(getattr(p, "rolesCsv", "") or ""),
        "employeesCsv": str(getattr(p, "employeesCsv", "") or ""),
        "enabled": bool(getattr(p, "enabled", True)),
        "orderNo": int(getattr(p, "orderNo", 0) or 0),
        "updatedAt": str(getattr(p, "updatedAt", "") or ""),
        "updatedBy": str(getattr(p, "updatedBy", "") or ""),
    }


def portals_for_me(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    role = normalize_role(auth.role) or ""
    if not role:
        raise ApiError("AUTH_INVALID", "Login required")

    # Employee-aware filtering.
    requested_employee_id = str((data or {}).get("employeeId") or "").strip()
    employee_id = ""

    if role == "EMPLOYEE":
        employee_id = str(auth.userId or "").strip()
    elif requested_employee_id and role == "ADMIN":
        # Admin can query portals for a given employeeId.
        employee_id = requested_employee_id

    # Resolve canonical employeeId when possible (helps when userId is an internal id).
    if employee_id:
        emp = db.execute(select(Employee).where(Employee.employeeId == employee_id)).scalar_one_or_none()
        if emp and str(getattr(emp, "employee_id", "") or "").strip():
            employee_id = str(getattr(emp, "employee_id", "") or "").strip()

    rows = (
        db.execute(select(PortalRegistry).where(PortalRegistry.enabled == True))  # noqa: E712
        .scalars()
        .all()
    )

    items = []
    for p in rows:
        roles = parse_roles_csv(str(getattr(p, "rolesCsv", "") or ""))
        if roles and role not in roles and "PUBLIC" not in roles:
            continue

        employees = [str(x or "").strip() for x in str(getattr(p, "employeesCsv", "") or "").split(",")]
        employees = [x for x in employees if x]
        if employees:
            if not employee_id or employee_id not in employees:
                continue

        items.append(_serialize_portal(p))

    items.sort(key=lambda x: (int(x.get("orderNo") or 0), str(x.get("title") or ""), str(x.get("portalKey") or "")))
    return {"items": items}


def portal_registry_list(data, auth: AuthContext | None, db, cfg):
    # Admin-only, used for registry management.
    rows = db.execute(select(PortalRegistry)).scalars().all()
    items = [_serialize_portal(p) for p in rows]
    items.sort(key=lambda x: (int(x.get("orderNo") or 0), str(x.get("title") or ""), str(x.get("portalKey") or "")))
    return {"items": items}


def portal_registry_upsert(data, auth: AuthContext | None, db, cfg):
    items = (data or {}).get("items")
    if not isinstance(items, list):
        raise ApiError("BAD_REQUEST", "items must be an array")
    if len(items) > 200:
        raise ApiError("BAD_REQUEST", "Max 200 items per batch")

    now = iso_utc_now()
    by = str(auth.userId or "") if auth else ""

    existing_by_id = {str(p.portalId or ""): p for p in db.execute(select(PortalRegistry)).scalars().all()}
    existing_by_key = {str(p.portalKey or "").upper().strip(): p for p in existing_by_id.values() if str(p.portalKey or "").strip()}

    upserted = 0
    created = 0

    for it in items:
        it = it or {}
        portal_id = str(it.get("portalId") or "").strip()
        portal_key = str(it.get("portalKey") or "").strip()
        title = str(it.get("title") or "").strip() or portal_key
        url = str(it.get("url") or "").strip()
        open_mode = _normalize_open_mode(str(it.get("openMode") or ""))
        icon = str(it.get("icon") or "").strip()
        description = str(it.get("description") or "").strip()
        roles_csv = str(it.get("rolesCsv") or "").strip()
        employees_csv = str(it.get("employeesCsv") or "").strip()
        enabled = bool(it.get("enabled") is True)

        try:
            order_no = int(it.get("orderNo") or 0)
        except Exception:
            order_no = 0

        if not portal_key:
            raise ApiError("BAD_REQUEST", "portalKey is required")
        if not url:
            raise ApiError("BAD_REQUEST", "url is required")

        key_u = portal_key.upper().strip()

        row = existing_by_id.get(portal_id) if portal_id else None
        if not row:
            row = existing_by_key.get(key_u)

        if not row:
            existing_ids = [x for x in existing_by_id.keys() if x]
            new_id = next_prefixed_id(db, counter_key="PRT", prefix="PRT-", pad=4, existing_ids=existing_ids)
            row = PortalRegistry(
                portalId=new_id,
                portalKey=portal_key,
                title=title,
                description=description,
                url=url,
                openMode=open_mode,
                icon=icon,
                rolesCsv=roles_csv,
                employeesCsv=employees_csv,
                enabled=enabled,
                orderNo=order_no,
                createdAt=now,
                createdBy=by,
                updatedAt=now,
                updatedBy=by,
            )
            db.add(row)
            existing_by_id[new_id] = row
            existing_by_key[key_u] = row
            created += 1
        else:
            row.portalKey = portal_key
            row.title = title
            row.description = description
            row.url = url
            row.openMode = open_mode
            row.icon = icon
            row.rolesCsv = roles_csv
            row.employeesCsv = employees_csv
            row.enabled = enabled
            row.orderNo = order_no
            row.updatedAt = now
            row.updatedBy = by

        upserted += 1

    append_audit(
        db,
        entityType="PORTAL_REGISTRY",
        entityId="BATCH",
        action="PORTAL_REGISTRY_UPSERT",
        stageTag="ADMIN_PORTAL_REGISTRY_UPSERT",
        actor=auth,
        meta={"upserted": upserted, "created": created},
        at=now,
    )

    return {"upserted": upserted, "created": created}
