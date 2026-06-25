"""Integration tests for the FastAPI server (auth + health + alerts).

fastapi is not installed locally, so the module skips cleanly there. In CI the
TestClient exercises the real app: the unauthenticated health probe, the Bearer
auth enforcement on ``/api/v1/alerts``, and a successful authenticated read.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

# Skip the whole module unless fastapi is importable.
pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from behaveguard.api.server import create_app  # noqa: E402


def _config(tmp_path):
    """Build the SimpleNamespace settings object create_app expects."""
    db_path = tmp_path / "events.db"
    return SimpleNamespace(
        storage=SimpleNamespace(
            backend="sqlite",
            sqlite_path=str(db_path),
            retention_days=30,
        ),
        alerts=SimpleNamespace(
            dedup_window_seconds=300,
            max_alerts_per_minute=10,
            # syslog disabled so no real channel is constructed during the test.
            channels=[{"type": "syslog", "enabled": False}],
        ),
        scoring=SimpleNamespace(
            alert_threshold_high=70,
            alert_threshold_critical=90,
            lstm_weight=0.6,
            vae_weight=0.4,
        ),
        features=SimpleNamespace(window_seconds=30, sequence_length=20),
    )


@pytest.fixture()
def app(tmp_path):
    return create_app(_config(tmp_path))


@pytest.fixture()
def client(app):
    # The context-manager form runs the lifespan (store .initialize()).
    with TestClient(app) as test_client:
        yield test_client


def test_health_is_ok_without_auth(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["version"]
    assert "uptime_seconds" in body


def test_alerts_requires_a_token(client):
    """Listing alerts without a Bearer token is rejected with 401."""
    response = client.get("/api/v1/alerts")
    assert response.status_code == 401


def test_alerts_with_valid_token_returns_200(app):
    token = app.state.bg.api_token
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/alerts",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 200
    body = response.json()
    # Fresh database -> an empty alert list and zero unacknowledged.
    assert body["alerts"] == []
    assert body["total"] == 0
    assert body["unacknowledged"] == 0


def test_alerts_with_wrong_token_is_401(app):
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/alerts",
            headers={"Authorization": "Bearer not-the-real-token"},
        )
    assert response.status_code == 401
