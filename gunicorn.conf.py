import os


def _env_int(name: str, default: int) -> int:
    try:
        return int(str(os.getenv(name, "") or "").strip() or default)
    except Exception:
        return default


bind = f"0.0.0.0:{_env_int('PORT', 5002)}"

# Concurrency: tune for your CPU + DB connection limits.
workers = max(1, _env_int("WEB_CONCURRENCY", 2))
threads = max(1, _env_int("PYTHON_THREADS", 4))

timeout = max(10, _env_int("GUNICORN_TIMEOUT", 120))
graceful_timeout = max(5, _env_int("GUNICORN_GRACEFUL_TIMEOUT", 30))
keepalive = max(1, _env_int("GUNICORN_KEEPALIVE", 5))

# Log to stdout/stderr (container friendly).
accesslog = "-"
errorlog = "-"

# Restart workers periodically to reduce impact of memory leaks.
max_requests = max(0, _env_int("GUNICORN_MAX_REQUESTS", 0))
max_requests_jitter = max(0, _env_int("GUNICORN_MAX_REQUESTS_JITTER", 0))

