import os
import tempfile

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client():
    # isolated DB file per test run
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.environ["DATABASE_PATH"] = path
    # re-import app fresh with the new DATABASE_PATH picked up by app.config
    import importlib
    import app.config as config
    import app.storage as storage
    import app.main as main

    importlib.reload(config)
    importlib.reload(storage)
    importlib.reload(main)

    with TestClient(main.app) as c:
        yield c

    # Windows keeps the sqlite file handle open via the connection pool
    # until the engine is disposed; dispose before removing or cleanup
    # fails with PermissionError even though the test itself passed.
    storage.engine.dispose()
    os.remove(path)


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_ingest_login_alert_and_read_it_back(client):
    resp = client.post(
        "/alerts",
        json={"type": "login", "user": "r.srivastava", "failed_attempts_last_5min": 9},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["severity"] == "HIGH"
    assert body["id"] > 0

    fetched = client.get(f"/alerts/{body['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["severity"] == "HIGH"


def test_ip_alert_requires_source_ip(client):
    resp = client.post("/alerts", json={"type": "ip_traffic"})
    assert resp.status_code == 422


def test_list_alerts(client):
    client.post("/alerts", json={"type": "login", "user": "a", "failed_attempts_last_5min": 1})
    client.post("/alerts", json={"type": "login", "user": "b", "failed_attempts_last_5min": 9})
    resp = client.get("/alerts")
    assert resp.status_code == 200
    assert len(resp.json()) == 2


def test_missing_alert_is_404(client):
    resp = client.get("/alerts/999")
    assert resp.status_code == 404
