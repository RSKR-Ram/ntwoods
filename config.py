import os


class Config:
    def __init__(self) -> None:
        self.APP_ENV = os.getenv("APP_ENV", "development")
        self.HOST = os.getenv("HOST", "0.0.0.0")
        self.PORT = int(os.getenv("PORT", "5002"))

        self.DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./hrms.db")

        # Deterministic PII hashing (HMAC-SHA256 pepper).
        self.PEPPER = os.getenv("PEPPER", "").strip()
        # Additional server-side salt for non-HMAC hashes (defaults to PEPPER).
        self.SERVER_SALT = os.getenv("SERVER_SALT", "").strip() or self.PEPPER

        # Encrypted-at-rest PII (AES-256-GCM). Optional; when unset, falls back to PEPPER.
        self.PII_ENC_KEY = os.getenv("PII_ENC_KEY", "").strip() or self.PEPPER
        self.PII_VIEW_ROLES = [
            s.strip().upper()
            for s in (os.getenv("PII_VIEW_ROLES", "ADMIN,HR,OWNER,EA,ACCOUNTS,MIS,DEO,EMPLOYEE") or "").split(",")
            if s.strip()
        ]

        # Sharding-ready (off by default): configure DB_URL_0..DB_URL_N to enable routing.
        self.DB_URLS = []
        i = 0
        while True:
            v = os.getenv(f"DB_URL_{i}", "").strip()
            if not v:
                break
            self.DB_URLS.append(v)
            i += 1

        self.GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
        self.SESSION_TTL_MINUTES = int(os.getenv("SESSION_TTL_MINUTES", "720"))
        self.APP_TIMEZONE = os.getenv("APP_TIMEZONE", "Asia/Kolkata")

        self.ALLOWED_ORIGINS = [
            s.strip() for s in (os.getenv("ALLOWED_ORIGINS", "*") or "*").split(",") if s.strip()
        ]

        self.UPLOAD_DIR = os.getenv("UPLOAD_DIR", "./uploads")

        # File storage for CVs/screenshots/docs:
        # - local: store bytes in UPLOAD_DIR and serve via GET /files/<fileId>?token=...
        # - gas: forward uploads to a Google Apps Script WebApp (Drive upload), return Drive fileId
        self.FILE_STORAGE_MODE = os.getenv("FILE_STORAGE_MODE", "local").strip().lower()

        # Google Apps Script WebApp uploader (used when FILE_STORAGE_MODE=gas)
        self.GAS_UPLOAD_URL = os.getenv("GAS_UPLOAD_URL", "").strip()
        self.GAS_UPLOAD_REQUEST_FORMAT = os.getenv("GAS_UPLOAD_REQUEST_FORMAT", "json").strip().lower()
        self.GAS_UPLOAD_TIMEOUT_SECONDS = float(os.getenv("GAS_UPLOAD_TIMEOUT_SECONDS", "30"))
        self.GAS_UPLOAD_API_KEY = os.getenv("GAS_UPLOAD_API_KEY", "").strip()
        self.GAS_UPLOAD_FOLDER_ID = os.getenv("GAS_UPLOAD_FOLDER_ID", "").strip()

        self.RATE_LIMIT_DEFAULT = os.getenv("RATE_LIMIT_DEFAULT", "300 per minute")
        self.RATE_LIMIT_GLOBAL = os.getenv("RATE_LIMIT_GLOBAL", "2000 per minute")
        self.RATE_LIMIT_LOGIN = os.getenv("RATE_LIMIT_LOGIN", "30 per minute")

        self.LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

        # Tests/dev only: bypass Google token verification.
        self.AUTH_ALLOW_TEST_TOKENS = os.getenv("AUTH_ALLOW_TEST_TOKENS", "0") == "1"

    @property
    def IS_PRODUCTION(self) -> bool:
        return str(self.APP_ENV or "").strip().lower() in {"prod", "production"}

    def validate(self) -> None:
        pepper = str(self.PEPPER or "").strip()
        if not pepper:
            raise RuntimeError("PEPPER must be set")
        if self.IS_PRODUCTION and len(pepper) < 16:
            raise RuntimeError("PEPPER must be a long random string in production")

        if self.IS_PRODUCTION and str(self.DATABASE_URL or "").startswith("sqlite"):
            raise RuntimeError("DATABASE_URL must be Postgres in production (Supabase recommended)")

        if self.IS_PRODUCTION and not str(self.GOOGLE_CLIENT_ID or "").strip():
            raise RuntimeError("GOOGLE_CLIENT_ID must be set in production")

        if self.IS_PRODUCTION and any(str(o or "").strip() == "*" for o in (self.ALLOWED_ORIGINS or [])):
            raise RuntimeError("ALLOWED_ORIGINS must not contain '*' in production")

        if self.IS_PRODUCTION and self.AUTH_ALLOW_TEST_TOKENS:
            raise RuntimeError("AUTH_ALLOW_TEST_TOKENS must be disabled in production")

        if str(self.FILE_STORAGE_MODE or "").strip().lower() == "gas" and not str(self.GAS_UPLOAD_URL or "").strip():
            raise RuntimeError("GAS_UPLOAD_URL must be set when FILE_STORAGE_MODE=gas")
