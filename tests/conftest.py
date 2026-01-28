import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))


@pytest.fixture()
def app_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_path = tmp_path / "hrms_test.db"
    upload_dir = tmp_path / "uploads"

    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")

    monkeypatch.setenv("PEPPER", "test-pepper-1234567890")
    monkeypatch.setenv("PII_ENC_KEY", "test-pii-key")

    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-google-client-id")
    monkeypatch.setenv("AUTH_ALLOW_TEST_TOKENS", "1")

    monkeypatch.setenv("ALLOWED_ORIGINS", "http://localhost:5173")
    monkeypatch.setenv("FILE_STORAGE_MODE", "local")
    monkeypatch.setenv("UPLOAD_DIR", str(upload_dir))

    monkeypatch.setenv("LOG_LEVEL", "WARNING")

    from legacy_app import create_app

    app = create_app()
    app.testing = True

    with app.test_client() as client:
        yield app, client
