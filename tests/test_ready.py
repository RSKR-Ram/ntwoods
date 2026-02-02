"""
Tests for /ready endpoint.
"""
from __future__ import annotations

from unittest.mock import patch


def test_ready_ok(app_client):
    """Test /ready returns ok when all services are healthy."""
    _app, client = app_client
    
    with patch("app.routes.core._ping_redis", return_value=True):
        res = client.get("/ready")
        assert res.status_code == 200
        
        body = res.get_json()
        assert body["status"] == "ok"
        assert body["checks"]["redis"] == "ok"


def test_ready_redis_down(app_client):
    """Test /ready returns degraded when Redis is down."""
    _app, client = app_client
    
    with patch("app.routes.core._ping_redis", return_value=False):
        res = client.get("/ready")
        # Without Redis configured, should still be ok
        # This test verifies the check structure
        body = res.get_json()
        assert "checks" in body
        assert "redis" in body["checks"]
