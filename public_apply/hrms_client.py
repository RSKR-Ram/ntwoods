"""
HRMS Internal API Client.

Makes HMAC-signed requests to HRMS internal endpoints:
- POST /internal/candidates/upsert
- POST /internal/requirements/{id}/candidates/add_or_move_to_shortlisting

Security: All requests are signed with HMAC-SHA256 and timestamp.
"""
from __future__ import annotations

import json
import os
import time
from typing import Any

import requests

from public_apply.security import generate_hmac_signature, get_hmac_secret


def _env_str(name: str, default: str = "") -> str:
    return str(os.getenv(name, default) or default).strip()


def get_hrms_base_url() -> str:
    """Get HRMS internal API base URL."""
    return _env_str("HRMS_INTERNAL_URL", "http://localhost:5000")


def _make_signed_request(
    method: str,
    endpoint: str,
    payload: dict[str, Any] | None = None,
    timeout: int = 30,
) -> dict:
    """
    Make an HMAC-signed request to HRMS internal API.
    
    Headers:
    - X-Timestamp: Unix timestamp
    - X-Signature: HMAC-SHA256 signature
    - Content-Type: application/json
    """
    base_url = get_hrms_base_url()
    url = f"{base_url}{endpoint}"
    
    timestamp = int(time.time())
    secret = get_hmac_secret()
    
    payload = payload or {}
    signature = generate_hmac_signature(payload, secret, timestamp) if secret else ""
    
    headers = {
        "Content-Type": "application/json",
        "X-Timestamp": str(timestamp),
        "X-Signature": signature,
    }
    
    try:
        if method.upper() == "GET":
            resp = requests.get(url, params=payload, headers=headers, timeout=timeout)
        else:
            resp = requests.post(url, json=payload, headers=headers, timeout=timeout)
        
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        raise RuntimeError(f"HRMS API request failed: {str(e)}")


def upsert_candidate(candidate_data: dict) -> dict:
    """
    Upsert candidate in HRMS (dedupe by email/mobile).
    
    Args:
        candidate_data: {
            name: str,
            email: str,
            mobile: str,
            email_hash: str,
            mobile_hash: str,
            cv_file_id: str,
            cv_file_name: str,
            source: str,
            experience_years: int,
            current_location: str,
        }
    
    Returns:
        {candidate_id: str, is_new: bool}
    """
    result = _make_signed_request(
        "POST",
        "/internal/candidates/upsert",
        candidate_data
    )
    
    if not result.get("success"):
        raise RuntimeError(result.get("error", "Candidate upsert failed"))
    
    return {
        "candidate_id": result.get("candidate_id"),
        "is_new": result.get("is_new", True),
    }


def add_to_shortlisting(requirement_id: str, candidate_id: str) -> dict:
    """
    Add candidate to requirement's SHORTLISTING stage.
    
    Args:
        requirement_id: HRMS requirement ID
        candidate_id: HRMS candidate ID
    
    Returns:
        {success: bool}
    """
    result = _make_signed_request(
        "POST",
        f"/internal/requirements/{requirement_id}/candidates/add_or_move_to_shortlisting",
        {"candidate_id": candidate_id}
    )
    
    if not result.get("success"):
        raise RuntimeError(result.get("error", "Add to shortlisting failed"))
    
    return {"success": True}


def get_open_requirements() -> list[dict]:
    """
    Get list of open requirements from HRMS.
    
    Returns:
        [{
            requirement_id: str,
            job_title: str,
            status: str,
            vacancy: int,
        }]
    """
    result = _make_signed_request(
        "GET",
        "/internal/requirements/open",
        {}
    )
    
    if not result.get("success"):
        raise RuntimeError(result.get("error", "Failed to get requirements"))
    
    return result.get("items", [])
