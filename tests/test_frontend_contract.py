import re
from html.parser import HTMLParser
from pathlib import Path

import pytest
import webapp

pytestmark = pytest.mark.integration
FRONTEND_HTML = Path(__file__).parents[1] / "frontend" / "index.html"


class DashboardParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.scripts = []
        self._inside_script = False

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if "id" in attributes:
            self.ids.append(attributes["id"])
        if tag == "script":
            self._inside_script = True

    def handle_endtag(self, tag):
        if tag == "script":
            self._inside_script = False

    def handle_data(self, data):
        if self._inside_script:
            self.scripts.append(data)


@pytest.fixture
def dashboard():
    parser = DashboardParser()
    parser.feed(FRONTEND_HTML.read_text(encoding="utf-8"))
    return parser, "\n".join(parser.scripts)


def test_frontend_api_operations_match_fastapi_openapi(dashboard):
    _, script = dashboard
    operations = [
        ("post", "/api/auth/token", "fetch('/api/auth/token'"),
        ("get", "/api/devices", "api('/api/devices')"),
        ("post", "/api/scan", "api('/api/scan', {method:'POST'"),
        (
            "get",
            "/api/scan/{scan_id}/status",
            "api('/api/scan/' + encodeURIComponent(currentJob) + '/status')",
        ),
        ("post", "/api/alerts/config", "api('/api/alerts/config', {method:'POST'"),
        ("get", "/api/schedule", "api('/api/schedule')"),
        ("post", "/api/schedule", "api('/api/schedule', {method:'POST'"),
        (
            "delete",
            "/api/schedule/{schedule_id}",
            "api('/api/schedule/' + encodeURIComponent(b.dataset.id), {method:'DELETE'})",
        ),
    ]
    openapi = webapp.app.openapi()["paths"]

    for method, path, source_marker in operations:
        assert source_marker in script
        assert method in openapi[path]


def test_frontend_dom_and_request_fields_match_backend_models(dashboard):
    parser, script = dashboard
    ids = set(parser.ids)
    referenced_ids = set(re.findall(r"\$\('([A-Za-z][\w-]*)'\)", script))

    assert len(parser.ids) == len(ids), "Dashboard element IDs must remain unique."
    assert referenced_ids <= ids
    assert "JSON.stringify({subnet, ports, timeout:3, authorized:true})" in script
    assert {"subnet", "ports", "timeout", "authorized"} <= set(
        webapp.ScanRequest.model_fields
    )
    assert "JSON.stringify({cron_expr, subnet, ports})" in script
    assert {"cron_expr", "subnet", "ports"} <= set(webapp.ScheduleRequest.model_fields)
    assert "telegram_bot_token: token, telegram_chat_id: chat" in script
    assert {"telegram_enabled", "telegram_bot_token", "telegram_chat_id"} <= set(
        webapp.AlertConfig.model_fields
    )


def test_frontend_represents_partial_scans_schedule_history_and_unavailable_telegram(
    dashboard,
):
    _, script = dashboard

    assert "'partial'" in script
    assert "s.completed_subnets" in script
    assert "s.total_subnets" in script
    assert "x.last_status" in script
    assert "x.last_run_at" in script
    assert "x.last_error" in script
    assert "Telegram delivery is not implemented by this backend." in FRONTEND_HTML.read_text(
        encoding="utf-8"
    )
