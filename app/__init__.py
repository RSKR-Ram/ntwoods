from __future__ import annotations

import logging

from dotenv import load_dotenv
from flask import Flask
from flask_cors import CORS

from app.config import get_config
from app.db import init_mongo
from app.middlewares.compression import init_compression
from app.middlewares.error_handler import init_error_handlers
from app.middlewares.logging import init_request_logging
from app.middlewares.rate_limit import init_rate_limiting
from app.middlewares.request_id import init_request_id
from app.middlewares.security_headers import init_security_headers
from app.routes.auth import auth_bp
from app.routes.core import core_bp
from app.routes.reports import reports_bp
from app.utils.logging import setup_logging

# Celery/jobs are optional - graceful degradation when not installed
try:
    from app.routes.jobs import jobs_bp
    CELERY_AVAILABLE = True
except ImportError:
    jobs_bp = None
    CELERY_AVAILABLE = False
    logging.getLogger(__name__).warning("Celery not installed, /api/v1/jobs/* endpoints disabled")


def create_app() -> Flask:
    load_dotenv()

    cfg = get_config()
    setup_logging(cfg.LOG_LEVEL)

    app = Flask(__name__)
    app.config["CFG"] = cfg

    # Performance: skip JSON key sorting for faster serialization
    app.config["JSON_SORT_KEYS"] = False

    CORS(
        app,
        origins=cfg.CORS_ORIGINS,
        supports_credentials=cfg.CORS_ALLOW_CREDENTIALS,
        allow_headers=["Content-Type", "Authorization", "X-Request-ID"],
        expose_headers=["X-Request-ID"],
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        max_age=3600,
    )

    init_request_id(app)
    init_security_headers(app)
    init_rate_limiting(app)
    init_request_logging(app)
    init_compression(app)
    init_error_handlers(app)

    init_mongo(app)

    app.register_blueprint(core_bp)
    app.register_blueprint(auth_bp, url_prefix="/api/v1/auth")
    app.register_blueprint(reports_bp, url_prefix="/api/v1/reports")
    
    if CELERY_AVAILABLE and jobs_bp:
        app.register_blueprint(jobs_bp, url_prefix="/api/v1/jobs")

    return app

