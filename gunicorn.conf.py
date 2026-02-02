import os


def _env_int(name: str, default: int) -> int:
    try:
        return int(str(os.getenv(name, "") or "").strip() or default)
    except Exception:
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    raw = str(os.getenv(name, "") or "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "y", "on"}


bind = f"0.0.0.0:{_env_int('PORT', 5002)}"

# Worker class: gthread provides better concurrency for I/O-bound workloads (DB, external APIs).
# Use "sync" for CPU-bound workloads or if encountering issues.
worker_class = os.getenv("GUNICORN_WORKER_CLASS", "gthread").strip() or "gthread"

# Concurrency: tune for your CPU + DB connection limits.
# Rule of thumb: workers = (2 * CPU cores) + 1, threads = 2-4 per worker.
workers = max(1, _env_int("WEB_CONCURRENCY", 2))
threads = max(1, _env_int("PYTHON_THREADS", 4))

# Preload app: shares DB connection pools across workers (saves memory).
# DISABLED by default: if DB connection fails at startup, the entire deploy fails.
# Enable with GUNICORN_PRELOAD_APP=1 only when you're confident DB is reachable.
preload_app = _env_bool("GUNICORN_PRELOAD_APP", False)

timeout = max(10, _env_int("GUNICORN_TIMEOUT", 120))
graceful_timeout = max(5, _env_int("GUNICORN_GRACEFUL_TIMEOUT", 30))

# Increased keepalive for connection reuse with load balancers/reverse proxies.
keepalive = max(1, _env_int("GUNICORN_KEEPALIVE", 30))

# Log to stdout/stderr (container friendly).
accesslog = "-"
errorlog = "-"
loglevel = os.getenv("GUNICORN_LOG_LEVEL", "info").strip().lower()

# Restart workers periodically to reduce impact of memory leaks.
# Production recommended: 1000 requests with 50 jitter.
max_requests = max(0, _env_int("GUNICORN_MAX_REQUESTS", 1000))
max_requests_jitter = max(0, _env_int("GUNICORN_MAX_REQUESTS_JITTER", 50))

# Graceful worker restart on SIGHUP (for zero-downtime deploys).
reload = _env_bool("GUNICORN_RELOAD", False)

