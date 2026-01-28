from __future__ import annotations

import os
from dataclasses import dataclass


def _csv(value: str) -> list[str]:
    items: list[str] = []
    for part in (value or "").split(","):
        item = part.strip()
        if item:
            items.append(item)
    return items


def _env_bool(name: str, default: bool = False) -> bool:
    raw = str(os.getenv(name, "") or "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default


@dataclass(frozen=True)
class BaseConfig:
    ENV: str = "development"
    DEBUG: bool = False
    TESTING: bool = False

    APP_VERSION: str = "dev"
    TIMEZONE_DISPLAY: str = "Asia/Kolkata"

    MONGODB_URI: str = "mongodb://localhost:27017"
    DB_NAME: str = "hrms"
    MONGO_SERVER_SELECTION_TIMEOUT_MS: int = 5000

    JWT_SECRET: str = "dev-secret"
    JWT_EXP_MINUTES: int = 720

    CORS_ORIGINS: list[str] | str = (
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000"
    )
    CORS_ALLOW_CREDENTIALS: bool = False

    LOG_LEVEL: str = "INFO"

    RATE_LIMIT_GLOBAL: str = "1200 per minute"
    RATE_LIMIT_DEFAULT: str = "300 per minute"
    RATE_LIMIT_LOGIN: str = "30 per minute"

    TRUST_PROXY_HEADERS: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "APP_VERSION", str(os.getenv("APP_VERSION", self.APP_VERSION) or self.APP_VERSION))
        object.__setattr__(
            self,
            "TIMEZONE_DISPLAY",
            str(os.getenv("TIMEZONE_DISPLAY", self.TIMEZONE_DISPLAY) or self.TIMEZONE_DISPLAY),
        )

        object.__setattr__(self, "MONGODB_URI", str(os.getenv("MONGODB_URI", self.MONGODB_URI) or self.MONGODB_URI))
        object.__setattr__(self, "DB_NAME", str(os.getenv("DB_NAME", self.DB_NAME) or self.DB_NAME))
        object.__setattr__(
            self,
            "MONGO_SERVER_SELECTION_TIMEOUT_MS",
            _env_int("MONGO_SERVER_SELECTION_TIMEOUT_MS", self.MONGO_SERVER_SELECTION_TIMEOUT_MS),
        )

        object.__setattr__(self, "JWT_SECRET", str(os.getenv("JWT_SECRET", self.JWT_SECRET) or self.JWT_SECRET))
        object.__setattr__(self, "JWT_EXP_MINUTES", _env_int("JWT_EXP_MINUTES", self.JWT_EXP_MINUTES))

        cors_raw = os.getenv("CORS_ORIGINS")
        if cors_raw is not None:
            cors_raw = str(cors_raw or "").strip()
            if cors_raw == "*":
                object.__setattr__(self, "CORS_ORIGINS", "*")
            else:
                object.__setattr__(self, "CORS_ORIGINS", _csv(cors_raw))
        else:
            object.__setattr__(self, "CORS_ORIGINS", _csv(str(self.CORS_ORIGINS)))

        object.__setattr__(
            self, "CORS_ALLOW_CREDENTIALS", _env_bool("CORS_ALLOW_CREDENTIALS", self.CORS_ALLOW_CREDENTIALS)
        )

        object.__setattr__(self, "LOG_LEVEL", str(os.getenv("LOG_LEVEL", self.LOG_LEVEL) or self.LOG_LEVEL).upper())

        object.__setattr__(
            self, "RATE_LIMIT_GLOBAL", str(os.getenv("RATE_LIMIT_GLOBAL", self.RATE_LIMIT_GLOBAL) or self.RATE_LIMIT_GLOBAL)
        )
        object.__setattr__(
            self, "RATE_LIMIT_DEFAULT", str(os.getenv("RATE_LIMIT_DEFAULT", self.RATE_LIMIT_DEFAULT) or self.RATE_LIMIT_DEFAULT)
        )
        object.__setattr__(
            self, "RATE_LIMIT_LOGIN", str(os.getenv("RATE_LIMIT_LOGIN", self.RATE_LIMIT_LOGIN) or self.RATE_LIMIT_LOGIN)
        )

        object.__setattr__(self, "TRUST_PROXY_HEADERS", _env_bool("TRUST_PROXY_HEADERS", self.TRUST_PROXY_HEADERS))

    @property
    def IS_PRODUCTION(self) -> bool:
        return str(self.ENV or "").lower() == "production"

    def validate(self) -> None:
        if self.IS_PRODUCTION and str(self.JWT_SECRET or "").strip() in {"", "dev-secret"}:
            raise RuntimeError("JWT_SECRET must be set in production")
        if self.IS_PRODUCTION and (not str(self.MONGODB_URI or "").strip() or not str(self.DB_NAME or "").strip()):
            raise RuntimeError("MONGODB_URI and DB_NAME must be set in production")


@dataclass(frozen=True)
class DevelopmentConfig(BaseConfig):
    ENV: str = "development"
    DEBUG: bool = True


@dataclass(frozen=True)
class ProductionConfig(BaseConfig):
    ENV: str = "production"
    DEBUG: bool = False


@dataclass(frozen=True)
class TestingConfig(BaseConfig):
    ENV: str = "testing"
    TESTING: bool = True
    JWT_SECRET: str = "test-secret"


def get_config() -> BaseConfig:
    env = str(os.getenv("ENV") or os.getenv("APP_ENV") or "development").strip().lower()
    if env in {"prod", "production"}:
        cfg: BaseConfig = ProductionConfig()
    elif env in {"test", "testing"}:
        cfg = TestingConfig()
    else:
        cfg = DevelopmentConfig()

    cfg.validate()
    return cfg
