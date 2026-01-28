from __future__ import annotations


def test_health_ok(app_client):
    _app, client = app_client

    res = client.get("/health")
    assert res.status_code == 200
    assert res.headers.get("X-Request-ID")

    body = res.get_json()
    assert body["ok"] is True
    assert body["data"]["status"] == "ok"

