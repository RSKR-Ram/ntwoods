"""
Secure Training Video Module

Provides secure video access with:
- Token-based video URLs (signed, expiring)
- Heartbeat tracking for watch progress
- Completion verification
- YouTube embed security configuration
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select

from actions.helpers import append_audit
from models import AssignedTraining, Employee, TrainingMaster, TrainingLog
from utils import ApiError, AuthContext, iso_utc_now, normalize_role, safe_json_string


# Video token expiry in seconds
VIDEO_TOKEN_EXPIRY = 300  # 5 minutes


def _get_video_secret(cfg) -> str:
    """Get the secret key for signing video tokens."""
    secret = str(getattr(cfg, "VIDEO_TOKEN_SECRET", "") or "").strip()
    if not secret:
        # Fallback to session secret if no dedicated video secret
        secret = str(getattr(cfg, "SESSION_SECRET", "") or "").strip()
    if not secret:
        secret = "DEFAULT_VIDEO_SECRET_CHANGE_ME"
    return secret


def _sign_video_token(payload: dict, secret: str) -> str:
    """Create a signed video access token."""
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload_b64}.{signature}"


def _verify_video_token(token: str, secret: str) -> dict | None:
    """Verify and decode a signed video token. Returns None if invalid."""
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None
        payload_b64, signature = parts
        expected_sig = hmac.new(secret.encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_sig):
            return None
        payload_json = base64.urlsafe_b64decode(payload_b64.encode("utf-8")).decode("utf-8")
        payload = json.loads(payload_json)
        # Check expiry
        exp = payload.get("exp", 0)
        if time.time() > exp:
            return None
        return payload
    except Exception:
        return None


def training_video_get_token(data, auth: AuthContext | None, db, cfg):
    """
    Generate a secure, short-lived token for video access.
    
    Request:
        module_id: Training module ID
        video_index: Index of video (0-based)
        
    Response:
        token: Signed video access token
        expires_at: Expiry timestamp
        embed_config: YouTube embed configuration
    """
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")
    
    module_id = str((data or {}).get("module_id") or (data or {}).get("moduleId") or "").strip()
    video_index = int((data or {}).get("video_index") or (data or {}).get("videoIndex") or 0)
    passed_candidate_id = str((data or {}).get("candidate_id") or (data or {}).get("candidateId") or "").strip()
    
    if not module_id:
        raise ApiError("BAD_REQUEST", "Missing module_id")
    
    # Verify user has access to this training and determine candidate_id
    role = normalize_role(auth.role if auth else "")
    employee_id = str(auth.userId or "").strip()
    
    if role == "EMPLOYEE":
        emp = db.execute(select(Employee).where(Employee.employeeId == employee_id)).scalar_one_or_none()
        if not emp or not emp.candidateId:
            raise ApiError("AUTH_INVALID", "Employee not found")
        candidate_id = str(emp.candidateId or "").strip()
        
        # Check if training is assigned
        assigned = db.execute(
            select(AssignedTraining)
            .where(AssignedTraining.candidate_id == candidate_id)
            .where(AssignedTraining.training_id == module_id)
            .order_by(AssignedTraining.assigned_date.desc())
        ).scalars().first()
        
        if not assigned:
            raise ApiError("FORBIDDEN", "Training not assigned")
    else:
        # For ADMIN/HR/OWNER, use the passed candidate_id
        candidate_id = passed_candidate_id or employee_id
        assigned = None
        if candidate_id:
            assigned = db.execute(
                select(AssignedTraining)
                .where(AssignedTraining.candidate_id == candidate_id)
                .where(AssignedTraining.training_id == module_id)
                .order_by(AssignedTraining.assigned_date.desc())
            ).scalars().first()
    
    # Get training master for video info (fallback)
    master = db.execute(
        select(TrainingMaster).where(TrainingMaster.training_id == module_id)
    ).scalar_one_or_none()
    
    if not master and not assigned:
        raise ApiError("NOT_FOUND", "Training module not found")
    
    # Parse video links - prefer from AssignedTraining, fall back to TrainingMaster
    video_links = []
    
    # First try AssignedTraining (may have overridden videos)
    if assigned:
        raw_links = str(getattr(assigned, "videoLinksJson", "") or "").strip()
        if not raw_links:
            raw_links = str(getattr(assigned, "video_link", "") or "").strip()
    else:
        raw_links = ""
    
    # Fallback to TrainingMaster if no videos on assigned
    if not raw_links and master:
        raw_links = str(getattr(master, "videoLinksJson", "") or "").strip()
        if not raw_links:
            raw_links = str(getattr(master, "video_link", "") or "").strip()
    
    try:
        if raw_links.startswith("["):
            video_links = json.loads(raw_links)
        elif raw_links:
            video_links = [raw_links]
    except Exception:
        video_links = [raw_links] if raw_links else []
    
    # Filter out empty strings
    video_links = [str(v or "").strip() for v in video_links if str(v or "").strip()]
    
    if not video_links:
        raise ApiError("NOT_FOUND", "No video URLs configured for this training")
    
    if video_index < 0 or video_index >= len(video_links):
        raise ApiError("BAD_REQUEST", f"Invalid video_index: {video_index}, available: 0-{len(video_links)-1}")
    
    video_url = video_links[video_index]
    
    # Create signed token - include candidate_id for admin users
    secret = _get_video_secret(cfg)
    now = int(time.time())
    payload = {
        "mid": module_id,
        "vid": video_index,
        "uid": employee_id,
        "cid": candidate_id,  # Include candidate_id in token
        "iat": now,
        "exp": now + VIDEO_TOKEN_EXPIRY,
    }
    video_token = _sign_video_token(payload, secret)
    
    # Determine embed configuration
    embed_config = _get_embed_config(video_url)
    
    return {
        "ok": True,
        "token": video_token,
        "expires_at": iso_utc_now(),
        "expires_in": VIDEO_TOKEN_EXPIRY,
        "video_count": len(video_links),
        "video_index": video_index,
        "embed_config": embed_config,
        "debug_video_url": video_url,  # For debugging
    }


def _get_embed_config(video_url: str) -> dict:
    """
    Generate secure embed configuration based on video URL type.
    """
    url_lower = video_url.lower()
    
    if "youtube.com" in url_lower or "youtu.be" in url_lower:
        # Extract YouTube video ID
        video_id = _extract_youtube_id(video_url)
        return {
            "type": "youtube",
            "video_id": video_id,
            "embed_url": f"https://www.youtube.com/embed/{video_id}",
            "params": {
                "enablejsapi": 1,
                "modestbranding": 1,
                "rel": 0,
                "controls": 1,  # Keep basic controls
                "disablekb": 0,
                "fs": 0,  # Disable fullscreen external
                "iv_load_policy": 3,  # Hide annotations
                "playsinline": 1,
                "origin": "",  # Will be set by frontend
            },
            "security": {
                "sandbox": "allow-scripts allow-same-origin",
                "allow": "accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture",
            },
        }
    else:
        # Self-hosted or other video
        return {
            "type": "direct",
            "stream_url": f"/api/training/video/stream/{video_url}",
            "security": {
                "controlsList": "nodownload noremoteplayback",
                "disablePictureInPicture": True,
                "onContextMenu": "return false",
            },
        }


def _extract_youtube_id(url: str) -> str:
    """Extract YouTube video ID from various URL formats."""
    import re
    
    patterns = [
        r"(?:youtube\.com/watch\?v=|youtu\.be/)([a-zA-Z0-9_-]{11})",
        r"youtube\.com/embed/([a-zA-Z0-9_-]{11})",
        r"youtube\.com/v/([a-zA-Z0-9_-]{11})",
    ]
    
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    
    # If no pattern matches, assume the URL is just the ID
    if len(url) == 11 and re.match(r"^[a-zA-Z0-9_-]+$", url):
        return url
    
    return url


def training_video_heartbeat(data, auth: AuthContext | None, db, cfg):
    """
    Track video watch progress. Called periodically (every 30 sec) while watching.
    
    Request:
        video_token: The signed video token
        current_time: Current playback position in seconds
        duration: Total video duration in seconds
        
    Response:
        ok: True
        watched_percentage: Percentage of video watched
    """
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")
    
    video_token = str((data or {}).get("video_token") or (data or {}).get("videoToken") or "").strip()
    current_time = float((data or {}).get("current_time") or (data or {}).get("currentTime") or 0)
    duration = float((data or {}).get("duration") or 0)
    
    if not video_token:
        raise ApiError("BAD_REQUEST", "Missing video_token")
    
    # Verify token
    secret = _get_video_secret(cfg)
    payload = _verify_video_token(video_token, secret)
    if not payload:
        raise ApiError("TOKEN_EXPIRED", "Video token expired or invalid")
    
    module_id = payload.get("mid", "")
    video_index = payload.get("vid", 0)
    user_id = payload.get("uid", "")
    
    # Get employee's candidate ID
    role = normalize_role(auth.role if auth else "")
    employee_id = str(auth.userId or "").strip()
    
    if role == "EMPLOYEE":
        emp = db.execute(select(Employee).where(Employee.employeeId == employee_id)).scalar_one_or_none()
        if not emp or not emp.candidateId:
            raise ApiError("AUTH_INVALID", "Employee not found")
        candidate_id = str(emp.candidateId or "").strip()
    else:
        candidate_id = employee_id
    
    # Get assigned training
    assigned = db.execute(
        select(AssignedTraining)
        .where(AssignedTraining.candidate_id == candidate_id)
        .where(AssignedTraining.training_id == module_id)
    ).scalar_one_or_none()
    
    if not assigned:
        raise ApiError("NOT_FOUND", "Training assignment not found")
    
    # Calculate watched percentage
    watched_pct = (current_time / duration * 100) if duration > 0 else 0
    watched_pct = min(100, max(0, watched_pct))
    
    # Update video watch progress in assigned training
    now_iso = iso_utc_now()
    
    # Parse existing video progress
    video_progress = {}
    try:
        raw = getattr(assigned, "video_progress", "") or ""
        if raw:
            video_progress = json.loads(raw)
    except Exception:
        video_progress = {}
    
    # Update progress for this video
    key = str(video_index)
    if key not in video_progress:
        video_progress[key] = {"max_time": 0, "duration": duration, "completed": False}
    
    video_progress[key]["max_time"] = max(video_progress[key].get("max_time", 0), current_time)
    video_progress[key]["duration"] = duration
    video_progress[key]["last_heartbeat"] = now_iso
    
    # Check if video is effectively complete (90%+ watched)
    if duration > 0 and current_time >= duration * 0.9:
        video_progress[key]["completed"] = True
        video_progress[key]["completed_at"] = now_iso
    
    assigned.video_progress = json.dumps(video_progress)
    
    # Log heartbeat
    db.add(
        TrainingLog(
            timestamp=now_iso,
            candidate_id=candidate_id,
            training_id=module_id,
            assigned_id=str(assigned.assigned_id or ""),
            action="VIDEO_HEARTBEAT",
            performed_by=employee_id,
            remarks=f"Video {video_index}: {current_time:.1f}s / {duration:.1f}s ({watched_pct:.1f}%)",
            metaJson=safe_json_string({
                "video_index": video_index,
                "current_time": current_time,
                "duration": duration,
                "watched_pct": watched_pct,
            }, "{}"),
        )
    )
    
    return {
        "ok": True,
        "watched_percentage": round(watched_pct, 1),
        "video_completed": video_progress[key].get("completed", False),
    }


def training_video_complete(data, auth: AuthContext | None, db, cfg):
    """
    Mark a video as fully watched. Called when video reaches the end.
    
    Request:
        video_token: The signed video token
        duration: Total video duration in seconds
        
    Response:
        ok: True
        all_videos_complete: Whether all training videos are complete
        can_mark_complete: Whether training can be marked as complete
    """
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")
    
    video_token = str((data or {}).get("video_token") or (data or {}).get("videoToken") or "").strip()
    duration = float((data or {}).get("duration") or 0)
    
    if not video_token:
        raise ApiError("BAD_REQUEST", "Missing video_token")
    
    # Verify token
    secret = _get_video_secret(cfg)
    payload = _verify_video_token(video_token, secret)
    if not payload:
        raise ApiError("TOKEN_EXPIRED", "Video token expired or invalid")
    
    module_id = payload.get("mid", "")
    video_index = payload.get("vid", 0)
    candidate_id = payload.get("cid", "")  # Get candidate_id from token
    
    # Always get employee_id for logging
    employee_id = str(auth.userId or "").strip()
    
    # Fallback for old tokens without cid
    if not candidate_id:
        role = normalize_role(auth.role if auth else "")
        
        if role == "EMPLOYEE":
            emp = db.execute(select(Employee).where(Employee.employeeId == employee_id)).scalar_one_or_none()
            if not emp or not emp.candidateId:
                raise ApiError("AUTH_INVALID", "Employee not found")
            candidate_id = str(emp.candidateId or "").strip()
        else:
            candidate_id = employee_id
    
    # Get assigned training (use first() to handle multiple assignments)
    assigned = db.execute(
        select(AssignedTraining)
        .where(AssignedTraining.candidate_id == candidate_id)
        .where(AssignedTraining.training_id == module_id)
        .order_by(AssignedTraining.assigned_date.desc())
    ).scalars().first()
    
    if not assigned:
        raise ApiError("NOT_FOUND", f"Training assignment not found for candidate {candidate_id}")
    
    # Get training master to know total video count
    master = db.execute(
        select(TrainingMaster).where(TrainingMaster.training_id == module_id)
    ).scalar_one_or_none()
    
    total_videos = 1
    raw_links = str(getattr(master, "videoLinksJson", "") or "").strip() if master else ""
    if not raw_links and master:
        raw_links = str(getattr(master, "video_link", "") or "").strip()
    if raw_links:
        try:
            if raw_links.startswith("["):
                total_videos = len(json.loads(raw_links))
            elif raw_links:
                total_videos = 1
        except Exception:
            total_videos = 1
    
    # Update video progress
    now_iso = iso_utc_now()
    video_progress = {}
    try:
        raw = getattr(assigned, "video_progress", "") or ""
        if raw:
            video_progress = json.loads(raw)
    except Exception:
        video_progress = {}
    
    key = str(video_index)
    video_progress[key] = {
        "max_time": duration,
        "duration": duration,
        "completed": True,
        "completed_at": now_iso,
    }
    
    assigned.video_progress = json.dumps(video_progress)
    
    # Check if all videos are complete
    completed_count = sum(1 for v in video_progress.values() if v.get("completed", False))
    all_complete = completed_count >= total_videos
    
    # Log completion
    db.add(
        TrainingLog(
            timestamp=now_iso,
            candidate_id=candidate_id,
            training_id=module_id,
            assigned_id=str(assigned.assigned_id or ""),
            action="VIDEO_COMPLETE",
            performed_by=employee_id,
            remarks=f"Video {video_index} complete. {completed_count}/{total_videos} videos watched.",
            metaJson=safe_json_string({
                "video_index": video_index,
                "duration": duration,
                "completed_count": completed_count,
                "total_videos": total_videos,
                "all_complete": all_complete,
            }, "{}"),
        )
    )
    
    return {
        "ok": True,
        "video_index": video_index,
        "all_videos_complete": all_complete,
        "completed_count": completed_count,
        "total_videos": total_videos,
        "can_mark_complete": all_complete,
    }


def training_check_video_completion(data, auth: AuthContext | None, db, cfg):
    """
    Check if all videos for a training have been watched.
    Used by frontend to enable/disable "Mark Complete" button.
    
    Request:
        module_id: Training module ID
        
    Response:
        ok: True
        all_videos_complete: Boolean
        progress: Dict of video progress
    """
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")
    
    module_id = str((data or {}).get("module_id") or (data or {}).get("moduleId") or "").strip()
    passed_candidate_id = str((data or {}).get("candidate_id") or (data or {}).get("candidateId") or "").strip()
    
    if not module_id:
        raise ApiError("BAD_REQUEST", "Missing module_id")
    
    # Get candidate ID
    role = normalize_role(auth.role if auth else "")
    employee_id = str(auth.userId or "").strip()
    
    if role == "EMPLOYEE":
        emp = db.execute(select(Employee).where(Employee.employeeId == employee_id)).scalar_one_or_none()
        if not emp or not emp.candidateId:
            raise ApiError("AUTH_INVALID", "Employee not found")
        candidate_id = str(emp.candidateId or "").strip()
    else:
        # For ADMIN/HR/OWNER, use the passed candidate_id
        candidate_id = passed_candidate_id or employee_id
    
    # Get assigned training (use first() to handle multiple assignments)
    assigned = db.execute(
        select(AssignedTraining)
        .where(AssignedTraining.candidate_id == candidate_id)
        .where(AssignedTraining.training_id == module_id)
        .order_by(AssignedTraining.assigned_date.desc())
    ).scalars().first()
    
    if not assigned:
        raise ApiError("NOT_FOUND", "Training assignment not found")
    
    # Get training master to know total video count
    master = db.execute(
        select(TrainingMaster).where(TrainingMaster.training_id == module_id)
    ).scalar_one_or_none()
    
    total_videos = 0
    raw_links = str(getattr(master, "videoLinksJson", "") or "").strip() if master else ""
    if not raw_links and master:
        raw_links = str(getattr(master, "video_link", "") or "").strip()
    if raw_links:
        try:
            if raw_links.startswith("["):
                total_videos = len(json.loads(raw_links))
            elif raw_links:
                total_videos = 1
        except Exception:
            total_videos = 1 if raw_links else 0
    
    # No videos = can mark complete
    if total_videos == 0:
        return {
            "ok": True,
            "all_videos_complete": True,
            "completed_count": 0,
            "total_videos": 0,
            "progress": {},
        }
    
    # Get progress
    video_progress = {}
    try:
        raw = getattr(assigned, "video_progress", "") or ""
        if raw:
            video_progress = json.loads(raw)
    except Exception:
        video_progress = {}
    
    completed_count = sum(1 for v in video_progress.values() if v.get("completed", False))
    all_complete = completed_count >= total_videos
    
    return {
        "ok": True,
        "all_videos_complete": all_complete,
        "completed_count": completed_count,
        "total_videos": total_videos,
        "progress": video_progress,
    }
