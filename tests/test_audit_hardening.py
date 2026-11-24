import hashlib
import json
import time
import uuid

import pytest
import webapp
from fastapi.testclient import TestClient

pytestmark = pytest.mark.integration
TEST_ADMIN_SECRET = "test-admin-secret-for-iot-hunter-ci-only-48chars"


def test_admin_secret_brute_force_is_throttled(client):
    for _ in range(webapp.AUTH_MAX_FAILURES):
        assert client.post("/api/auth/token", headers={"X-Admin-Secret": "wrong"}).status_code == 401
    # Even the correct secret is refused while the client is locked out.
    locked = client.post("/api/auth/token", headers={"X-Admin-Secret": TEST_ADMIN_SECRET})
    assert locked.status_code == 429
    assert "Retry-After" in locked.headers


def test_successful_login_clears_failures(client):
    for _ in range(2):
        client.post("/api/auth/token", headers={"X-Admin-Secret": "wrong"})
    ok = client.post("/api/auth/token", headers={"X-Admin-Secret": TEST_ADMIN_SECRET})
    assert ok.status_code == 200
    assert not webapp.auth_failures


def test_stale_auth_failure_entries_are_pruned(client):
    webapp.auth_failures["stale-client"] = [
        time.time() - webapp.AUTH_WINDOW_SEC - 1
    ]

    response = client.post(
        "/api/auth/token",
        headers={"X-Admin-Secret": "wrong"},
    )

    assert response.status_code == 401
    assert "stale-client" not in webapp.auth_failures


@pytest.mark.parametrize(
    "secret",
    [None, "too-short", "replace-with-a-long-random-secret"],
)
def test_startup_rejects_missing_or_weak_admin_secret(
    isolated_db,
    monkeypatch,
    secret,
):
    if secret is None:
        monkeypatch.delenv("IOT_HUNTER_ADMIN_SECRET", raising=False)
    else:
        monkeypatch.setenv("IOT_HUNTER_ADMIN_SECRET", secret)

    with pytest.raises(RuntimeError, match="at least 32 characters"):
        webapp.startup()
    assert not webapp.scheduler.running


def test_authentication_prunes_expired_tokens_and_rate_limits(client):
    now = time.time()
    expired_digest = hashlib.sha256(b"expired-cleanup-token").hexdigest()
    orphan_digest = hashlib.sha256(b"orphan-rate-limit").hexdigest()
    with webapp.db() as conn:
        conn.execute(
            "INSERT INTO api_tokens(token_hash,created_at,expires_at) VALUES(?,?,?)",
            (expired_digest, "2026-01-01T00:00:00+00:00", now - 1),
        )
        conn.executemany(
            "INSERT INTO api_rate_limits(token_hash,window_start,request_count) "
            "VALUES(?,?,?)",
            [
                (expired_digest, now - 120, 4),
                (orphan_digest, now - 120, 1),
            ],
        )

    response = client.post(
        "/api/auth/token",
        headers={"X-Admin-Secret": TEST_ADMIN_SECRET},
    )
    assert response.status_code == 200
    with webapp.db() as conn:
        assert conn.execute(
            "SELECT 1 FROM api_tokens WHERE token_hash=?",
            (expired_digest,),
        ).fetchone() is None
        assert conn.execute(
            "SELECT 1 FROM api_rate_limits WHERE token_hash IN (?,?)",
            (expired_digest, orphan_digest),
        ).fetchone() is None


def test_api_authentication_is_counted_once_and_headers_are_set(
    client,
    auth_headers,
):
    token = auth_headers["Authorization"].split(" ", 1)[1]
    digest = hashlib.sha256(token.encode()).hexdigest()
    response = client.get("/api/devices", headers=auth_headers)

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    with webapp.db() as conn:
        row = conn.execute(
            "SELECT request_count FROM api_rate_limits WHERE token_hash=?",
            (digest,),
        ).fetchone()
    assert row["request_count"] == 1


def test_v1_auth_and_device_aliases_remain_compatible(client):
    token_response = client.post(
        "/v1/auth/token",
        headers={"X-Admin-Secret": TEST_ADMIN_SECRET},
    )
    assert token_response.status_code == 200
    response = client.get(
        "/v1/devices",
        headers={
            "Authorization": f"Bearer {token_response.json()['access_token']}"
        },
    )
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == []


def test_validation_errors_do_not_echo_submitted_secrets(client, auth_headers):
    secret = "submitted-but-invalid-secret-value"
    response = client.post(
        "/api/alerts/config",
        headers=auth_headers,
        json={"smtp_port": 70000, "smtp_password": secret},
    )

    assert response.status_code == 422
    assert secret not in response.text
    error = response.json()["detail"][0]
    assert set(error) == {"loc", "msg", "type"}


def test_pdf_temp_file_is_removed_after_download(client, tmp_path):
    token = client.post(
        "/api/auth/token",
        headers={"X-Admin-Secret": TEST_ADMIN_SECRET},
    ).json()["access_token"]
    scan_id = uuid.uuid4().hex
    with webapp.db() as conn:
        conn.execute("INSERT INTO scans(id,created_at,subnet,status,results) VALUES(?,?,?,?,?)",
                     (scan_id, "2026-01-01T00:00:00+00:00", "192.168.1.0/24", "completed",
                      json.dumps([{"ip": "192.168.1.5", "vendor": "x", "device_type": "camera", "open_ports": [80]}])))
    resp = client.get(f"/api/report/{scan_id}/pdf", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200 and resp.content.startswith(b"%PDF")
    assert list(tmp_path.glob("iot-hunter-report-*.pdf")) == []


def test_pdf_generation_failure_returns_safe_error_and_removes_temp_file(
    client, tmp_path, monkeypatch
):
    token = client.post(
        "/api/auth/token",
        headers={"X-Admin-Secret": TEST_ADMIN_SECRET},
    ).json()["access_token"]
    scan_id = uuid.uuid4().hex
    with webapp.db() as conn:
        conn.execute(
            "INSERT INTO scans(id,created_at,subnet,status,results) VALUES(?,?,?,?,?)",
            (
                scan_id,
                "2026-01-01T00:00:00+00:00",
                "192.168.1.0/24",
                "completed",
                json.dumps([{"ip": "192.168.1.5", "open_ports": [80]}]),
            ),
        )

    def fail_build(self, *_args, **_kwargs):
        raise OSError("private report content must not be returned")

    monkeypatch.setattr("reportlab.platypus.SimpleDocTemplate.build", fail_build)
    response = client.get(
        f"/api/report/{scan_id}/pdf",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 500
    assert "private report content" not in response.text
    assert list(tmp_path.glob("iot-hunter-report-*.pdf")) == []


def test_finished_jobs_are_pruned(isolated_db, monkeypatch):
    monkeypatch.setattr(webapp, "MAX_TRACKED_JOBS", 3)
    monkeypatch.setattr(webapp.threading, "Thread", lambda *a, **k: type("T", (), {"start": lambda self: None})())
    webapp.jobs.clear()
    for i in range(6):
        webapp.jobs[f"old{i}"] = {"status": "completed"}
    webapp.launch_scan("192.168.1.0/24", [80])
    assert len(webapp.jobs) <= 4


def test_partial_scan_preserves_devices_in_failed_subnets(client, auth_headers, monkeypatch):
    scan_id = uuid.uuid4().hex
    with webapp.db() as conn:
        conn.execute(
            "INSERT INTO scans(id,created_at,subnet,status,results) VALUES(?,?,?,?,?)",
            (scan_id, "2026-01-01T00:00:00+00:00", "192.168.10.0/24,192.168.20.0/24", "queued", "[]"),
        )
        conn.executemany(
            "INSERT INTO devices(ip,subnet,online) VALUES(?,?,1)",
            [
                ("192.168.10.10", "192.168.10.0/24"),
                ("192.168.20.10", "192.168.20.0/24"),
            ],
        )

    def scan_target(subnet, _ports, _timeout):
        if subnet == "192.168.20.0/24":
            raise RuntimeError("subnet unavailable")
        return []

    monkeypatch.setattr(webapp, "scan_target_network", scan_target)
    monkeypatch.setattr(webapp.fingerprint, "run_fingerprint", lambda devices: devices)
    webapp.jobs[scan_id] = {
        "id": scan_id,
        "status": "queued",
        "progress": 0,
        "completed_subnets": 0,
        "total_subnets": 2,
        "results": [],
        "errors": [],
    }

    webapp.scan_worker(
        scan_id,
        ["192.168.10.0/24", "192.168.20.0/24"],
        [80],
        1,
    )

    with webapp.db() as conn:
        devices = {
            row["ip"]: row["online"]
            for row in conn.execute("SELECT ip,online FROM devices")
        }
    assert devices == {"192.168.10.10": 0, "192.168.20.10": 1}
    webapp.jobs.pop(scan_id)

    status = client.get(f"/api/scan/{scan_id}/status", headers=auth_headers).json()
    results = client.get(f"/api/scan/{scan_id}/results", headers=auth_headers).json()
    assert status["status"] == results["status"] == "partial"
    assert results["errors"] == [
        {"subnet": "192.168.20.0/24", "error": "subnet unavailable"}
    ]


def test_total_scan_failure_is_persisted_for_scan_and_schedule(
    client,
    auth_headers,
    monkeypatch,
):
    scan_id = uuid.uuid4().hex
    schedule_id = "failed-schedule"
    with webapp.db() as conn:
        conn.execute(
            "INSERT INTO scans(id,created_at,subnet,status,results) VALUES(?,?,?,?,?)",
            (scan_id, "2026-01-01T00:00:00+00:00", "192.168.10.0/24", "queued", "[]"),
        )
        conn.execute(
            "INSERT INTO schedules(id,cron_expr,subnet,ports,timeout,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (
                schedule_id,
                "*/5 * * * *",
                "192.168.10.0/24",
                "[80]",
                1.5,
                "2026-01-01T00:00:00+00:00",
            ),
        )

    def fail_scan(_subnet, _ports, _timeout):
        raise RuntimeError("scanner unavailable")

    monkeypatch.setattr(webapp, "scan_target_network", fail_scan)
    webapp.jobs[scan_id] = {
        "id": scan_id,
        "status": "queued",
        "progress": 0,
        "completed_subnets": 0,
        "total_subnets": 1,
        "results": [],
        "errors": [],
    }

    webapp.scan_worker(
        scan_id,
        ["192.168.10.0/24"],
        [80],
        1.5,
        schedule_id,
    )
    webapp.jobs.pop(scan_id)

    status = client.get(f"/api/scan/{scan_id}/status", headers=auth_headers).json()
    results = client.get(f"/api/scan/{scan_id}/results", headers=auth_headers).json()
    assert status["status"] == results["status"] == "failed"
    assert results["results"] == []
    assert results["errors"] == [
        {"subnet": "192.168.10.0/24", "error": "scanner unavailable"}
    ]
    with webapp.db() as conn:
        schedule = conn.execute(
            "SELECT last_status,last_error,last_scan_id FROM schedules WHERE id=?",
            (schedule_id,),
        ).fetchone()
    assert schedule["last_status"] == "failed"
    assert schedule["last_error"] == "scanner unavailable"
    assert schedule["last_scan_id"] == scan_id


def test_schedule_timeout_and_run_state_are_persisted(client, auth_headers):
    response = client.post(
        "/api/schedule",
        headers=auth_headers,
        json={
            "cron_expr": "*/5 * * * *",
            "subnet": "192.168.10.0/24",
            "ports": [80],
            "timeout": 1.25,
        },
    )
    assert response.status_code == 200
    schedule = response.json()
    scheduled_job = webapp.scheduler.get_job(schedule["id"])
    assert scheduled_job is not None
    assert scheduled_job.args[2:] == (1.25, schedule["id"])
    assert client.get("/api/schedule", headers=auth_headers).json() == [schedule]

    deleted = client.delete(
        f"/api/schedule/{schedule['id']}",
        headers=auth_headers,
    )
    assert deleted.status_code == 200
    assert webapp.scheduler.get_job(schedule["id"]) is None


def test_lifespan_recovers_interrupted_work_and_stops_scheduler(tmp_path, monkeypatch):
    monkeypatch.setattr(webapp, "DB_PATH", tmp_path / "t.sqlite3")
    monkeypatch.setenv("IOT_HUNTER_ADMIN_SECRET", TEST_ADMIN_SECRET)
    webapp.init_db()
    with webapp.db() as conn:
        conn.execute(
            "INSERT INTO scans(id,created_at,subnet,status,results) VALUES(?,?,?,?,?)",
            ("interrupted-scan", "2026-01-01T00:00:00+00:00", "192.168.10.0/24", "running", "[]"),
        )
        conn.execute(
            "INSERT INTO schedules(id,cron_expr,subnet,ports,timeout,created_at,last_status) "
            "VALUES(?,?,?,?,?,?,?)",
            ("interrupted-schedule", "*/5 * * * *", "192.168.10.0/24", "[80]", 1.5,
             "2026-01-01T00:00:00+00:00", "running"),
        )
    with TestClient(webapp.app):
        assert webapp.scheduler.running
        with webapp.db() as conn:
            scan = conn.execute(
                "SELECT status,errors FROM scans WHERE id='interrupted-scan'"
            ).fetchone()
            schedule = conn.execute(
                "SELECT last_status,last_error FROM schedules WHERE id='interrupted-schedule'"
            ).fetchone()
        assert scan["status"] == "failed"
        assert "restarted" in json.loads(scan["errors"])[0]["error"]
        assert schedule["last_status"] == "interrupted"
        assert "restarted" in schedule["last_error"]
        restored_job = webapp.scheduler.get_job("interrupted-schedule")
        assert restored_job.args[2:] == (1.5, "interrupted-schedule")
    assert not webapp.scheduler.running
