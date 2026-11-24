import json
import os
import stat
from pathlib import Path

import pytest

from modules import reporting

pytestmark = pytest.mark.unit


def test_report_sanitization_redacts_sensitive_fields_and_text():
    aws_key = "AKIA1234567890ABCDEF"
    password = "supersecret-password"
    private_key_material = "private-key-material-" * 8
    source = {
        "credential_findings": [
            {"ip": "192.168.1.4", "password": password, "match": password}
        ],
        "firmware_findings": [{"match": aws_key}],
        "hostname": f"password={password}",
        "notes": (
            f"Bearer {'a' * 24}\n"
            "-----BEGIN RSA PRIVATE KEY-----\n"
            f"{private_key_material}\n"
            "-----END RSA PRIVATE KEY-----"
        ),
        "device": {"ip": "192.168.1.4"},
    }

    sanitized = reporting.sanitize_report_data(source)

    assert sanitized["credential_findings"][0]["ip"] == "192.168.1.4"
    assert sanitized["credential_findings"][0]["password"] == "[REDACTED]"
    assert sanitized["credential_findings"][0]["match"] == "[REDACTED]"
    assert sanitized["firmware_findings"][0]["match"] == "[REDACTED]"
    assert password not in sanitized["hostname"]
    assert aws_key not in str(sanitized)
    assert "a" * 24 not in sanitized["notes"]
    assert private_key_material not in sanitized["notes"]
    assert source["credential_findings"][0]["password"] == password


def test_json_report_is_redacted_and_written_with_private_permissions(tmp_path):
    secret = "report-secret-value"
    path = reporting.generate_json_report(
        {"api_token": secret, "message": f"password={secret}"}, tmp_path
    )
    saved = Path(path).read_text(encoding="utf-8")

    assert secret not in saved
    assert json.loads(saved) == {
        "api_token": "[REDACTED]",
        "message": "[REDACTED]",
    }
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_json_report_failure_removes_temporary_file(tmp_path, monkeypatch):
    def fail_dump(*_args, **_kwargs):
        raise OSError("write failed")

    monkeypatch.setattr(reporting.json, "dump", fail_dump)

    with pytest.raises(OSError, match="write failed"):
        reporting.generate_json_report({"value": "safe"}, tmp_path)

    assert list(tmp_path.iterdir()) == []


def test_pdf_report_escapes_untrusted_text_and_cleans_failed_output(
    tmp_path, monkeypatch
):
    path = reporting.generate_pdf_report(
        {
            "discovery": {
                "subnet": "192.168.1.0/24 <invalid",
                "devices": [
                    {
                        "ip": "192.168.1.5",
                        "vendor": "<script>unsafe",
                        "hostname": "password=supersecret-password",
                        "open_ports": [80],
                    }
                ],
            },
            "remediation_plan": [
                {"priority": "high", "finding": "<bad>", "fix": "& unsafe"}
            ],
        },
        tmp_path,
    )
    assert Path(path).read_bytes().startswith(b"%PDF")

    def fail_build(self, *_args, **_kwargs):
        raise OSError("render failed")

    monkeypatch.setattr(reporting.SimpleDocTemplate, "build", fail_build)
    with pytest.raises(OSError, match="render failed"):
        reporting.generate_pdf_report({"discovery": {"devices": []}}, tmp_path)

    assert list(tmp_path.glob(".*.tmp")) == []


def test_generate_reports_removes_json_when_pdf_generation_fails(
    tmp_path, monkeypatch
):
    def fail_pdf(*_args, **_kwargs):
        raise OSError("PDF failed")

    monkeypatch.setattr(reporting, "generate_pdf_report", fail_pdf)

    with pytest.raises(OSError, match="PDF failed"):
        reporting.generate_reports({"value": "safe"}, tmp_path)

    assert list(tmp_path.iterdir()) == []
