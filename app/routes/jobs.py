"""
Job management endpoints for async task processing.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.tasks import celery_app
from app.tasks.example_task import example_long_running_task, send_notification_task

jobs_bp = Blueprint("jobs", __name__)


@jobs_bp.post("/example")
def enqueue_example_job():
    """
    Enqueue an example background job.
    
    Request body (optional):
        {
            "duration_seconds": 5,  # How long the job should run
            "data": {}              # Optional payload
        }
    
    Returns:
        { "ok": true, "data": { "job_id": "...", "status": "queued" } }
    """
    body = request.get_json(silent=True) or {}
    duration = min(max(int(body.get("duration_seconds", 5)), 1), 60)  # 1-60 seconds
    data = body.get("data")
    
    task = example_long_running_task.apply_async(
        kwargs={"duration_seconds": duration, "data": data}
    )
    
    return jsonify({
        "ok": True,
        "data": {
            "job_id": task.id,
            "status": "queued",
            "estimated_duration_seconds": duration,
        }
    }), 202


@jobs_bp.post("/notify")
def enqueue_notification():
    """
    Enqueue a notification job.
    
    Request body:
        {
            "user_id": "user123",
            "message": "Your order is ready!",
            "channel": "email"  # email, sms, push
        }
    """
    body = request.get_json(silent=True) or {}
    user_id = body.get("user_id")
    message = body.get("message")
    channel = body.get("channel", "email")
    
    if not user_id or not message:
        return jsonify({
            "ok": False,
            "error": {"code": "VALIDATION_ERROR", "message": "user_id and message are required"}
        }), 400
    
    task = send_notification_task.apply_async(
        kwargs={"user_id": user_id, "message": message, "channel": channel}
    )
    
    return jsonify({
        "ok": True,
        "data": {"job_id": task.id, "status": "queued"}
    }), 202


@jobs_bp.get("/<job_id>")
def get_job_status(job_id: str):
    """
    Get the status and result of a background job.
    
    Returns:
        {
            "ok": true,
            "data": {
                "job_id": "...",
                "status": "PENDING|PROGRESS|SUCCESS|FAILURE",
                "progress": 50,       # If in PROGRESS state
                "result": {...},      # If completed
                "error": "..."        # If failed
            }
        }
    """
    task = celery_app.AsyncResult(job_id)
    
    response_data = {
        "job_id": job_id,
        "status": task.state,
    }
    
    if task.state == "PENDING":
        response_data["message"] = "Job is queued or unknown"
    elif task.state == "PROGRESS":
        meta = task.info or {}
        response_data["progress"] = meta.get("progress", 0)
        response_data["message"] = meta.get("status", "Processing...")
    elif task.state == "SUCCESS":
        response_data["result"] = task.result
    elif task.state == "FAILURE":
        response_data["error"] = str(task.info) if task.info else "Unknown error"
    elif task.state == "REVOKED":
        response_data["message"] = "Job was cancelled"
    
    return jsonify({"ok": True, "data": response_data})


@jobs_bp.delete("/<job_id>")
def cancel_job(job_id: str):
    """
    Cancel/revoke a pending or running job.
    """
    celery_app.control.revoke(job_id, terminate=True)
    
    return jsonify({
        "ok": True,
        "data": {"job_id": job_id, "status": "revoked"}
    })
