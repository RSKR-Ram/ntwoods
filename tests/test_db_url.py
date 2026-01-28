from db import _normalize_database_url
from db import _should_disable_prepared_statements


def test_normalize_database_url_converts_libpq_conninfo():
    raw = "user=postgres.myref password=[pass] host=aws.pooler.supabase.com port=6543 dbname=postgres"
    normalized = _normalize_database_url(raw)

    assert normalized.startswith("postgresql+psycopg://postgres.myref:")
    assert "%5Bpass%5D" in normalized
    assert "@aws.pooler.supabase.com:6543/postgres" in normalized


def test_normalize_database_url_converts_libpq_conninfo_without_spaces():
    raw = "user=postgres.myrefpassword=[pass]host=aws.pooler.supabase.comport=6543dbname=postgres"
    normalized = _normalize_database_url(raw)

    assert normalized.startswith("postgresql+psycopg://postgres.myref:")
    assert "%5Bpass%5D" in normalized
    assert "@aws.pooler.supabase.com:6543/postgres" in normalized


def test_normalize_database_url_strips_leading_key_prefix_before_url():
    raw = "user=postgresql://postgres.myref:[pass]@aws.pooler.supabase.com:6543/postgres"
    normalized = _normalize_database_url(raw)

    assert normalized.startswith("postgresql+psycopg://postgres.myref:")
    assert normalized.endswith("@aws.pooler.supabase.com:6543/postgres")


def test_should_disable_prepared_statements_for_supabase_pooler_url():
    url = "postgresql+psycopg://postgres.myref:pass@aws-1-ap-south-1.pooler.supabase.com:6543/postgres"
    assert _should_disable_prepared_statements(url) is True


def test_should_not_disable_prepared_statements_for_direct_supabase_url():
    url = "postgresql+psycopg://postgres:pass@db.myref.supabase.co:5432/postgres"
    assert _should_disable_prepared_statements(url) is False


def test_init_engine_sets_prepare_threshold_for_pooler(monkeypatch):
    import db as dbmod

    monkeypatch.delenv("DB_SSLMODE", raising=False)
    monkeypatch.delenv("DB_DISABLE_PREPARED_STATEMENTS", raising=False)

    captured = {}

    def fake_create_engine(_url, **kwargs):
        captured["connect_args"] = kwargs.get("connect_args") or {}

        class DummyEngine:
            pass

        return DummyEngine()

    monkeypatch.setattr(dbmod, "create_engine", fake_create_engine)
    monkeypatch.setattr(dbmod.SessionLocal, "configure", lambda **_kwargs: None)

    dbmod.init_engine(
        "postgresql+psycopg://postgres.myref:pass@aws-1-ap-south-1.pooler.supabase.com:6543/postgres"
    )

    assert "prepare_threshold" in captured["connect_args"]
    assert captured["connect_args"].get("prepare_threshold") is None


def test_init_engine_does_not_set_prepare_threshold_for_non_pooler(monkeypatch):
    import db as dbmod

    monkeypatch.delenv("DB_SSLMODE", raising=False)
    monkeypatch.delenv("DB_DISABLE_PREPARED_STATEMENTS", raising=False)

    captured = {}

    def fake_create_engine(_url, **kwargs):
        captured["connect_args"] = kwargs.get("connect_args") or {}

        class DummyEngine:
            pass

        return DummyEngine()

    monkeypatch.setattr(dbmod, "create_engine", fake_create_engine)
    monkeypatch.setattr(dbmod.SessionLocal, "configure", lambda **_kwargs: None)

    dbmod.init_engine("postgresql+psycopg://postgres:pass@db.myref.supabase.co:5432/postgres")

    assert "prepare_threshold" not in captured["connect_args"]
