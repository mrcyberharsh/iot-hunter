"""Shared fixtures for isolated database and API tests."""
import pytest
import webapp
from fastapi.testclient import TestClient


def pytest_collection_modifyitems(items):
    """Keep test selection explicit so category-based CI cannot miss tests."""
    unclassified = [
        item.nodeid
        for item in items
        if not item.get_closest_marker("unit")
        and not item.get_closest_marker("integration")
    ]
    if unclassified:
        raise pytest.UsageError(
            "Every test must be marked unit or integration: "
            + ", ".join(unclassified)
        )


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    """Give each test an independent SQLite database and data directory."""
    database_path = tmp_path / "iot-hunter-test.sqlite3"
    monkeypatch.setattr(webapp, "DB_PATH", database_path)
    monkeypatch.setattr(webapp, "DATA_DIR", tmp_path)
    webapp.init_db()
    return database_path


@pytest.fixture
def client(isolated_db, monkeypatch):
    """Provide an API client with a known test-only admin secret."""
    monkeypatch.setenv(
        "IOT_HUNTER_ADMIN_SECRET",
        "test-admin-secret-for-iot-hunter-ci-only-48chars",
    )
    webapp.auth_failures.clear()
    webapp.jobs.clear()
    webapp.schedule_jobs.clear()
    if webapp.scheduler.running:
        webapp.scheduler.remove_all_jobs()

    with TestClient(webapp.app) as test_client:
        yield test_client

    webapp.auth_failures.clear()
    webapp.jobs.clear()
    webapp.schedule_jobs.clear()
    if webapp.scheduler.running:
        webapp.scheduler.remove_all_jobs()


@pytest.fixture
def auth_headers(client):
    response = client.post(
        "/api/auth/token",
        headers={
            "X-Admin-Secret": "test-admin-secret-for-iot-hunter-ci-only-48chars"
        },
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}
