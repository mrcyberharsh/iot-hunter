import json
import time
import uuid

import pytest
from fastapi.testclient import TestClient

import webapp


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(webapp, "DB_PATH", tmp_path / "t.sqlite3")
    monkeypatch.setattr(webapp, "DATA_DIR", tmp_path)
    monkeypatch.setenv("IOT_HUNTER_ADMIN_SECRET", "correct-horse-battery")
    webapp.init_db()
    webapp.auth_failures.clear()
    return TestClient(webapp.app)


def test_admin_secret_brute_force_is_throttled(client):
    for _ in range(webapp.AUTH_MAX_FAILURES):
        assert client.post("/api/auth/token", headers={"X-Admin-Secret": "wrong"}).status_code == 401
    # Even the correct secret is refused while the client is locked out.
    locked = client.post("/api/auth/token", headers={"X-Admin-Secret": "correct-horse-battery"})
    assert locked.status_code == 429
    assert "Retry-After" in locked.headers


def test_successful_login_clears_failures(client):
    for _ in range(2):
        client.post("/api/auth/token", headers={"X-Admin-Secret": "wrong"})
    ok = client.post("/api/auth/token", headers={"X-Admin-Secret": "correct-horse-battery"})
    assert ok.status_code == 200
    assert not webapp.auth_failures


def test_pdf_temp_file_is_removed_after_download(client, tmp_path):
    token = client.post("/api/auth/token", headers={"X-Admin-Secret": "correct-horse-battery"}).json()["access_token"]
    scan_id = uuid.uuid4().hex
    with webapp.db() as conn:
        conn.execute("INSERT INTO scans(id,created_at,subnet,status,results) VALUES(?,?,?,?,?)",
                     (scan_id, "2026-01-01T00:00:00+00:00", "192.168.1.0/24", "completed",
                      json.dumps([{"ip": "192.168.1.5", "vendor": "x", "device_type": "camera", "open_ports": [80]}])))
    resp = client.get(f"/api/report/{scan_id}/pdf", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200 and resp.content.startswith(b"%PDF")
    assert list(tmp_path.glob("iot-hunter-report-*.pdf")) == []


def test_finished_jobs_are_pruned(monkeypatch):
    monkeypatch.setattr(webapp, "MAX_TRACKED_JOBS", 3)
    monkeypatch.setattr(webapp.threading, "Thread", lambda *a, **k: type("T", (), {"start": lambda self: None})())
    webapp.jobs.clear()
    for i in range(6):
        webapp.jobs[f"old{i}"] = {"status": "completed"}
    webapp.launch_scan("192.168.1.0/24", [80])
    assert len(webapp.jobs) <= 4


def test_lifespan_starts_and_stops_scheduler(tmp_path, monkeypatch):
    monkeypatch.setattr(webapp, "DB_PATH", tmp_path / "t.sqlite3")
    webapp.init_db()
    with TestClient(webapp.app):
        assert webapp.scheduler.running
