"""
Example Celery task demonstrating async job processing.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

from app.tasks import celery_app


@celery_app.task(bind=True, max_retries=3, default_retry_delay=30)
def example_long_running_task(self, duration_seconds: int = 5, data: dict | None = None):
    """
    Example task that simulates long-running work.
    
    Args:
        duration_seconds: How long to "work" (default 5 seconds)
        data: Optional payload data
    
    Returns:
        dict with task result and metadata
    """
    start_time = datetime.now(timezone.utc)
    task_id = self.request.id
    
    # Update state to show progress
    self.update_state(state="PROGRESS", meta={"progress": 0, "status": "Starting..."})
    
    # Simulate work in chunks
    for i in range(duration_seconds):
        time.sleep(1)
        progress = int((i + 1) / duration_seconds * 100)
        self.update_state(
            state="PROGRESS",
            meta={"progress": progress, "status": f"Processing... {progress}%"}
        )
    
    end_time = datetime.now(timezone.utc)
    
    return {
        "task_id": task_id,
        "status": "completed",
        "started_at": start_time.isoformat(),
        "completed_at": end_time.isoformat(),
        "duration_seconds": duration_seconds,
        "input_data": data,
        "result": f"Processed successfully in {duration_seconds}s",
    }


@celery_app.task(bind=True, autoretry_for=(Exception,), retry_backoff=True)
def send_notification_task(self, user_id: str, message: str, channel: str = "email"):
    """
    Example notification task with automatic retry on failure.
    
    This demonstrates a common use case: sending notifications asynchronously.
    """
    # In production, this would call an email/SMS/push service
    return {
        "task_id": self.request.id,
        "user_id": user_id,
        "channel": channel,
        "message_preview": message[:50] + "..." if len(message) > 50 else message,
        "sent_at": datetime.now(timezone.utc).isoformat(),
        "status": "sent",
    }
