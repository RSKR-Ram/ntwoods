from __future__ import annotations

import json
import logging
from typing import Any

import requests

from config import Config
from utils import ApiError, safe_json_string

log = logging.getLogger(__name__)


def _parse_json_maybe(text: str) -> Any:
    s = str(text or "").strip()
    if not s:
        return None
    try:
        return json.loads(s)
    except Exception:
        return None


def _extract_file_id(obj: Any) -> str:
    if isinstance(obj, dict):
        for key in ("fileId", "driveFileId", "id"):
            v = str(obj.get(key) or "").strip()
            if v:
                return v
        data = obj.get("data")
        if isinstance(data, dict):
            for key in ("fileId", "driveFileId", "id"):
                v = str(data.get(key) or "").strip()
                if v:
                    return v
    return ""


def gas_upload_file(
    *,
    cfg: Config,
    file_base64: str,
    file_name: str,
    mime_type: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    url = str(cfg.GAS_UPLOAD_URL or "").strip()
    if not url:
        raise ApiError("INTERNAL", "GAS_UPLOAD_URL is not configured (set FILE_STORAGE_MODE=local or provide GAS_UPLOAD_URL)")

    fmt = str(cfg.GAS_UPLOAD_REQUEST_FORMAT or "json").strip().lower()
    if fmt not in {"json", "form"}:
        raise ApiError("INTERNAL", f"Invalid GAS_UPLOAD_REQUEST_FORMAT: {fmt} (expected 'json' or 'form')")

    payload: dict[str, Any] = {
        "fileBase64": str(file_base64 or "").strip(),
        "fileName": str(file_name or "").strip(),
        "mimeType": str(mime_type or "").strip() or "application/octet-stream",
    }
    if cfg.GAS_UPLOAD_FOLDER_ID:
        payload["folderId"] = cfg.GAS_UPLOAD_FOLDER_ID
    # Shared secret for simple protection (Apps Script can reliably read body params;
    # some deployments cannot access custom HTTP headers).
    if cfg.GAS_UPLOAD_API_KEY:
        payload["apiKey"] = cfg.GAS_UPLOAD_API_KEY
    if extra:
        payload.update(extra)

    headers: dict[str, str] = {}
    if cfg.GAS_UPLOAD_API_KEY:
        headers["X-Api-Key"] = cfg.GAS_UPLOAD_API_KEY

    try:
        if fmt == "form":
            resp = requests.post(url, data=payload, headers=headers, timeout=cfg.GAS_UPLOAD_TIMEOUT_SECONDS)
        else:
            resp = requests.post(url, json=payload, headers=headers, timeout=cfg.GAS_UPLOAD_TIMEOUT_SECONDS)
    except Exception as e:
        raise ApiError("INTERNAL", f"Failed to call GAS uploader: {e}")

    raw_text = str(resp.text or "")
    parsed = None
    try:
        parsed = resp.json()
    except Exception:
        parsed = _parse_json_maybe(raw_text)

    if resp.status_code >= 400:
        snippet = raw_text.strip()[:500]
        raise ApiError("INTERNAL", f"GAS upload failed (HTTP {resp.status_code}): {snippet or 'no response body'}")

    if isinstance(parsed, dict) and parsed.get("ok") is False:
        err_obj = parsed.get("error") if isinstance(parsed.get("error"), dict) else {}
        msg = str((err_obj or {}).get("message") or "").strip() or "GAS upload failed"
        code = str((err_obj or {}).get("code") or "").strip() or "INTERNAL"
        raise ApiError(code, msg)

    file_id = _extract_file_id(parsed)
    if not file_id:
        snippet = raw_text.strip()[:500]
        log.warning("GAS uploader response missing fileId: %s", safe_json_string(parsed, fallback=snippet))
        raise ApiError("INTERNAL", "GAS upload succeeded but no fileId was returned")

    if isinstance(parsed, dict):
        out = dict(parsed)
        out["fileId"] = file_id
        return out

    return {"fileId": file_id, "raw": parsed}
