"""
Celery configuration and task autodiscovery.

Usage:
    celery -A app.tasks.celery_app worker --loglevel=INFO
"""
from __future__ import annotations

import os

from celery import Celery


def make_celery() -> Celery:
    """
    Create and configure Celery app with Redis broker.
    
    Environment variables:
        REDIS_URL: Redis connection URL (default: redis://localhost:6379/0)
        CELERY_RESULT_BACKEND: Optional separate result backend
    """
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    result_backend = os.getenv("CELERY_RESULT_BACKEND", redis_url)
    
    app = Celery(
        "ntwoods",
        broker=redis_url,
        backend=result_backend,
        include=["app.tasks.example_task"],
    )
    
    app.conf.update(
        # Task settings
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="Asia/Kolkata",
        enable_utc=True,
        
        # Result expiration (24 hours)
        result_expires=86400,
        
        # Task execution settings
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        
        # Worker settings
        worker_prefetch_multiplier=1,
        worker_concurrency=int(os.getenv("CELERY_CONCURRENCY", "4")),
        
        # Rate limiting
        task_default_rate_limit="100/m",
        
        # Retry settings
        task_default_retry_delay=60,
        task_max_retries=3,
    )
    
    return app


celery_app = make_celery()
