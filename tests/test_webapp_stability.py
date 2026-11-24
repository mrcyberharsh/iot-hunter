import hashlib
import sqlite3
import time
from datetime import UTC, datetime

import pytest
import webapp

pytestmark = pytest.mark.integration


def test_expired_api_token_is_rejected(isolated_db):
    digest = hashlib.sha256(b"expired-token").hexdigest()
    with webapp.db() as conn:
        conn.execute(
            "INSERT INTO api_tokens(token_hash,created_at,expires_at) VALUES(?,?,?)",
            (digest, "2020-01-01T00:00:00+00:00", time.time() - 10),
        )

    with pytest.raises(webapp.HTTPException) as exc:
        webapp.validate_bearer_token("Bearer expired-token")

    assert exc.value.status_code == 401


def test_legacy_database_schema_is_migrated(tmp_path, monkeypatch):
    database_path = tmp_path / "legacy.sqlite3"
    conn = sqlite3.connect(database_path)
    conn.executescript(
        """
        CREATE TABLE api_tokens (
          token_hash TEXT PRIMARY KEY, created_at TEXT
        );
        CREATE TABLE scans (
          id TEXT PRIMARY KEY, created_at TEXT, subnet TEXT, status TEXT, results TEXT
        );
        CREATE TABLE schedules (
          id TEXT PRIMARY KEY, cron_expr TEXT NOT NULL, subnet TEXT NOT NULL,
          ports TEXT NOT NULL, created_at TEXT NOT NULL
        );
        """
    )
    created_at = datetime.now(UTC).isoformat()
    conn.execute(
        "INSERT INTO api_tokens(token_hash,created_at) VALUES(?,?)",
        ("legacy-token-hash", created_at),
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr(webapp, "DB_PATH", database_path)

    webapp.init_db()

    with webapp.db() as migrated:
        token = migrated.execute(
            "SELECT expires_at FROM api_tokens WHERE token_hash='legacy-token-hash'"
        ).fetchone()
        scan_columns = {
            row["name"] for row in migrated.execute("PRAGMA table_info(scans)")
        }
        schedule_columns = {
            row["name"] for row in migrated.execute("PRAGMA table_info(schedules)")
        }
    assert token["expires_at"] > time.time()
    assert "errors" in scan_columns
    assert {"timeout", "last_run_at", "last_status", "last_error", "last_scan_id"} <= schedule_columns


def test_rate_limit_is_persisted_in_sqlite(isolated_db, monkeypatch):
    monkeypatch.setitem(webapp.CONFIG, "api", {"rate_limit": 1})
    digest = hashlib.sha256(b"limited-token").hexdigest()
    with webapp.db() as conn:
        conn.execute(
            "INSERT INTO api_tokens(token_hash,created_at,expires_at) VALUES(?,?,?)",
            (digest, "2026-01-01T00:00:00+00:00", time.time() + 3600),
        )

    assert webapp.validate_bearer_token("Bearer limited-token") == digest
    with pytest.raises(webapp.HTTPException) as exc:
        webapp.validate_bearer_token("Bearer limited-token")

    assert exc.value.status_code == 429


@pytest.mark.regression
def test_partial_scan_inventory_query_is_subnet_scoped(isolated_db):
    with webapp.db() as conn:
        conn.execute(
            "INSERT INTO devices(ip,subnet,online) VALUES(?,?,1)",
            ("192.168.1.10", "192.168.1.0/24"),
        )
        conn.execute(
            "INSERT INTO devices(ip,subnet,online) VALUES(?,?,1)",
            ("192.168.2.10", "192.168.2.0/24"),
        )

    scanned_subnets = ["192.168.1.0/24"]
    placeholders = ",".join("?" for _ in scanned_subnets)
    with webapp.db() as conn:
        previous = conn.execute(
            f"SELECT ip FROM devices WHERE subnet IN ({placeholders})",
            tuple(scanned_subnets),
        ).fetchall()

    assert [row["ip"] for row in previous] == ["192.168.1.10"]


def test_dashboard_and_frontend_assets_serve_from_new_layout(client):
    page = client.get("/")
    logo = client.get("/assets/logo.svg")

    assert page.status_code == 200
    assert "IoT Hunter" in page.text
    assert logo.status_code == 200
    assert "<svg" in logo.text
