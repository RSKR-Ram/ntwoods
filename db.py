from __future__ import annotations

import os
import re

from sqlalchemy import create_engine
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import ArgumentError
from sqlalchemy.orm import declarative_base, sessionmaker

from sharding import pick_shard_index

Base = declarative_base()

engine = None
shard_engines = []
SessionLocal = sessionmaker(autocommit=False, autoflush=False, future=True, expire_on_commit=False)


def _env_int(name: str, default: int) -> int:
    try:
        return int(str(os.getenv(name, "") or "").strip() or str(default))
    except Exception:
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    raw = str(os.getenv(name, "") or "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "y", "on"}


def _should_disable_prepared_statements(database_url: str) -> bool:
    """
    Supabase "pooler" endpoints are typically PgBouncer in transaction pooling mode.
    Server-side prepared statements don't work reliably there (connections switch between
    transactions), so disable them for stability.
    """

    if _env_bool("DB_DISABLE_PREPARED_STATEMENTS", False):
        return True

    s = str(database_url or "").strip()
    if not s.startswith("postgresql"):
        return False

    host = ""
    port = 0
    try:
        u = make_url(s)
        host = str(u.host or "").lower()
        port = int(u.port or 0)
    except Exception:
        host = s.lower()

    # Supabase pooler commonly uses port 6543 and `*.pooler.supabase.com` hosts.
    if port == 6543:
        return True
    if "pooler.supabase.com" in host:
        return True
    return False


def _normalize_database_url(database_url: str) -> str:
    """
    Keep production configuration ergonomic:

    - Supabase commonly provides `postgresql://...` (no explicit driver).
    - Some platforms use `postgres://...`.
    - Some platforms/tools provide libpq-style conninfo strings:
      `user=... password=... host=... port=... dbname=...` (optionally without spaces).
    - We standardize on psycopg (psycopg3) to avoid psycopg2 build issues on newer Pythons.
    """

    s = str(database_url or "").strip()
    if not s:
        return s

    # Common mispaste: an env var value accidentally includes a leading key (e.g. `user=postgresql://...`).
    # `sqlalchemy.create_engine()` can't parse this, but we can safely strip the prefix.
    # This keeps `.env` ergonomics forgiving without changing intended URLs.
    m = re.match(r"^(?:user|username|url|database_url)\s*=\s*([a-zA-Z][a-zA-Z0-9+.-]*://.*)$", s)
    if m:
        s = m.group(1).strip()

    # Accept libpq-style conninfo strings (commonly copy/pasted from provider dashboards).
    # Example: `user=foo password=bar host=example.com port=5432 dbname=baz sslmode=require`
    # Some copy flows omit spaces between pairs; handle both.
    if "://" not in s and ("host=" in s.lower() or "dbname=" in s.lower() or "database=" in s.lower()):
        lowered = s.lower()
        # Only attempt conversion when it looks like key/value pairs (avoid mangling arbitrary strings).
        if any(k in lowered for k in ("user=", "username=")) and any(k in lowered for k in ("password=", "pass=")):
            keys = ("user", "username", "password", "pass", "host", "port", "dbname", "database", "sslmode")
            occurrences: list[tuple[int, str]] = []
            for key in keys:
                for match in re.finditer(re.escape(key) + r"\s*=", lowered):
                    occurrences.append((match.start(), key))
            occurrences.sort(key=lambda t: t[0])

            if occurrences:
                parts: dict[str, str] = {}
                for idx, (pos, key) in enumerate(occurrences):
                    start = pos + len(key)
                    # Skip optional whitespace before '='.
                    while start < len(s) and s[start].isspace():
                        start += 1
                    if start >= len(s) or s[start] != "=":
                        continue
                    start += 1  # '='
                    while start < len(s) and s[start].isspace():
                        start += 1

                    end = occurrences[idx + 1][0] if idx + 1 < len(occurrences) else len(s)
                    value = s[start:end].strip().rstrip(";").strip()
                    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                        value = value[1:-1]
                    if value:
                        parts[key] = value

                username = parts.get("user") or parts.get("username")
                password = parts.get("password") or parts.get("pass")
                host = parts.get("host")
                database = parts.get("dbname") or parts.get("database")
                port_raw = parts.get("port")
                port = None
                if port_raw and str(port_raw).isdigit():
                    port = int(port_raw)

                if host and database and username and password:
                    query = {}
                    sslmode = parts.get("sslmode")
                    if sslmode:
                        query["sslmode"] = sslmode
                    return URL.create(
                        drivername="postgresql+psycopg",
                        username=username,
                        password=password,
                        host=host,
                        port=port,
                        database=database,
                        query=query or None,
                    ).render_as_string(hide_password=False)

    if s.startswith("postgresql+psycopg://"):
        return s

    if s.startswith("postgresql+psycopg2://"):
        return "postgresql+psycopg://" + s[len("postgresql+psycopg2://") :]

    if s.startswith("postgresql://"):
        return "postgresql+psycopg://" + s[len("postgresql://") :]

    if s.startswith("postgres://"):
        return "postgresql+psycopg://" + s[len("postgres://") :]

    return s


def _pool_kwargs(database_url: str) -> dict:
    """
    QueuePool tuning (Postgres/MySQL/etc). Keep defaults conservative to avoid
    exhausting Supabase connection limits.
    """

    if database_url.startswith("sqlite"):
        return {}

    pool_size = max(1, _env_int("DB_POOL_SIZE", 5))
    max_overflow = max(0, _env_int("DB_MAX_OVERFLOW", 5))
    pool_timeout = max(1, _env_int("DB_POOL_TIMEOUT", 30))
    pool_recycle = max(0, _env_int("DB_POOL_RECYCLE", 1800))
    use_lifo = _env_bool("DB_POOL_USE_LIFO", True)

    kwargs = {
        "pool_size": pool_size,
        "max_overflow": max_overflow,
        "pool_timeout": pool_timeout,
        "pool_use_lifo": use_lifo,
    }
    if pool_recycle:
        kwargs["pool_recycle"] = pool_recycle
    return kwargs


def init_engine(database_url: str):
    global engine

    database_url = _normalize_database_url(database_url)
    if not str(database_url or "").strip():
        raise ArgumentError(
            "DATABASE_URL is empty. Set DATABASE_URL in your environment or `.env` "
            "(e.g. `sqlite:///./hrms.db` or `postgresql+psycopg://user:pass@host:5432/db?sslmode=require`)."
        )

    connect_args: dict[str, object] = {}
    if database_url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
    else:
        sslmode = str(os.getenv("DB_SSLMODE", "") or "").strip()
        if sslmode and database_url.startswith("postgresql"):
            connect_args = {"sslmode": sslmode}
        if _should_disable_prepared_statements(database_url):
            # psycopg3 uses server-side prepared statements by default. Setting
            # prepare_threshold=None disables them entirely (required for PgBouncer
            # transaction pooling / Supabase pooler endpoints).
            connect_args["prepare_threshold"] = None

    pool_pre_ping = _env_bool("DB_POOL_PRE_PING", True)
    try:
        engine = create_engine(
            database_url,
            future=True,
            pool_pre_ping=pool_pre_ping,
            connect_args=connect_args,
            **_pool_kwargs(database_url),
        )
    except ArgumentError as e:
        raise ArgumentError(
            "Invalid DATABASE_URL. Set DATABASE_URL to a valid SQLAlchemy URL "
            "(e.g. `sqlite:///./hrms.db` for local dev or "
            "`postgresql+psycopg://user:pass@host:5432/db?sslmode=require` for Postgres). "
            "If you pasted a libpq conninfo string (`user=... password=... host=... dbname=...`), that's also supported."
        ) from e
    SessionLocal.configure(bind=engine)
    return engine


def init_shard_engines(database_urls: list[str]):
    """
    Sharding scaffold (off by default): create one engine per DB URL.

    This does not change existing SessionLocal routing; callers must explicitly use
    `engine_for_owner()` to pick a bind and create a dedicated Session.
    """
    global shard_engines
    urls = [_normalize_database_url(str(u or "").strip()) for u in (database_urls or []) if str(u or "").strip()]
    shard_engines = []
    if not urls:
        return shard_engines

    for url in urls:
        connect_args: dict[str, object] = {}
        if url.startswith("sqlite"):
            connect_args = {"check_same_thread": False}
        else:
            sslmode = str(os.getenv("DB_SSLMODE", "") or "").strip()
            if sslmode and url.startswith("postgresql"):
                connect_args = {"sslmode": sslmode}
            if _should_disable_prepared_statements(url):
                connect_args["prepare_threshold"] = None
        shard_engines.append(
            create_engine(
                url,
                future=True,
                pool_pre_ping=_env_bool("DB_POOL_PRE_PING", True),
                connect_args=connect_args,
                **_pool_kwargs(url),
            )
        )
    return shard_engines


def engine_for_owner(owner_user_id: str):
    """
    Returns a shard engine based on owner_user_id (when shards are configured).

    Safe default: returns the primary `engine` if sharding is not configured.
    """
    if not shard_engines:
        return engine
    idx = pick_shard_index(str(owner_user_id or ""), len(shard_engines))
    return shard_engines[idx]
