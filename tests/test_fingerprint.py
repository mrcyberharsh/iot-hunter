import unittest

import pytest
import requests
from modules.fingerprint import classify_device, parse_banner_service

from modules import fingerprint

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def clear_nvd_cache():
    with fingerprint._nvd_cache_lock:
        fingerprint._nvd_cache.clear()


class FingerprintTests(unittest.TestCase):
    def test_parse_banner_service_known_services(self):
        cases = [
            ("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6", ("ssh", "8.9p1")),
            ("SSH-2.0-dropbear_2022.83", ("ssh", "2022.83")),
            ("SSH-2.0-CustomSSH", ("ssh", "2.0")),
            ("Server: Apache/2.4.54 (Unix)", ("apache", "2.4.54")),
            ("nginx/1.24.0", ("nginx", "1.24.0")),
            ("Mosquitto MQTT broker v2.0.15", ("mqtt", "2.0.15")),
            ("PostgreSQL 15.3", ("postgresql", "15.3")),
            ("Redis server", ("redis", None)),
        ]
        for banner, expected in cases:
            with self.subTest(banner=banner):
                self.assertEqual(parse_banner_service(banner), expected)

    def test_parse_banner_service_unknown_banner(self):
        self.assertEqual(parse_banner_service("CustomProprietaryDaemon/1.0"), ("unknown", None))

    def test_parse_banner_service_empty_and_none(self):
        self.assertEqual(parse_banner_service(""), ("unknown", None))
        self.assertEqual(parse_banner_service(None), ("unknown", None))

    def test_classify_device_known_and_unknown(self):
        self.assertEqual(classify_device("Hikvision IP Camera"), "camera")
        self.assertEqual(classify_device("", vendor="TP-Link"), "router")
        self.assertEqual(classify_device("Shelly Plug"), "bulb")
        self.assertEqual(classify_device("ESP32 telemetry node"), "sensor")
        self.assertEqual(classify_device("Generic service"), "unknown")
        self.assertEqual(classify_device(None, vendor=None), "unknown")


class NvdLookupTests(unittest.TestCase):
    def test_successful_results_are_cached_and_returned_independently(self):
        calls = []

        class Response:
            def raise_for_status(self):
                return None

            def json(self):
                return {
                    "vulnerabilities": [
                        {
                            "cve": {
                                "id": "CVE-2025-1234",
                                "descriptions": [{"value": "Example description"}],
                                "published": "2025-01-01T00:00:00.000",
                            }
                        }
                    ]
                }

        def fake_get(url, *, params, timeout):
            calls.append((url, params, timeout))
            return Response()

        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(fingerprint.requests, "get", fake_get)
            first = fingerprint.query_nvd_cves("nginx", "1.2")
            first[0]["id"] = "mutated"
            second = fingerprint.query_nvd_cves("nginx", "1.2")

        assert len(calls) == 1
        assert calls[0][1]["resultsPerPage"] == "5"
        assert calls[0][2] == fingerprint.NVD_REQUEST_TIMEOUT_SECONDS
        assert second[0]["id"] == "CVE-2025-1234"

    def test_transient_nvd_failure_retries_once_then_caches_success(self):
        calls = 0

        class Response:
            status_code = 503

            def raise_for_status(self):
                if self.status_code >= 500:
                    error = requests.HTTPError("temporary service error")
                    error.response = self
                    raise error

            def json(self):
                return {"vulnerabilities": []}

        def fake_get(*_args, **_kwargs):
            nonlocal calls
            calls += 1
            response = Response()
            if calls > 1:
                response.status_code = 200
            return response

        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(fingerprint.requests, "get", fake_get)
            monkeypatch.setattr(fingerprint.time, "sleep", lambda _seconds: None)
            first = fingerprint.query_nvd_cves("apache", "2.4")
            second = fingerprint.query_nvd_cves("apache", "2.4")

        assert first == second == []
        assert calls == 2

    def test_invalid_nvd_payload_fails_closed_without_retry(self):
        calls = 0

        class Response:
            def raise_for_status(self):
                return None

            def json(self):
                return {"vulnerabilities": "not-an-array"}

        def fake_get(*_args, **_kwargs):
            nonlocal calls
            calls += 1
            return Response()

        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(fingerprint.requests, "get", fake_get)
            result = fingerprint.query_nvd_cves("mqtt", "2.0")

        assert result == []
        assert calls == 1

    def test_nvd_cache_expires_after_its_ttl(self):
        calls = 0
        current_time = [10.0]

        class Response:
            def raise_for_status(self):
                return None

            def json(self):
                return {"vulnerabilities": []}

        def fake_get(*_args, **_kwargs):
            nonlocal calls
            calls += 1
            return Response()

        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(fingerprint.requests, "get", fake_get)
            monkeypatch.setattr(
                fingerprint.time,
                "monotonic",
                lambda: current_time[0],
            )
            fingerprint.query_nvd_cves("redis", "7.0")
            current_time[0] += fingerprint.NVD_CACHE_TTL_SECONDS + 1
            fingerprint.query_nvd_cves("redis", "7.0")

        assert calls == 2

    def test_unknown_services_skip_network_request(self):
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(
                fingerprint.requests,
                "get",
                lambda *_args, **_kwargs: self.fail("unexpected NVD request"),
            )
            self.assertEqual(fingerprint.query_nvd_cves("unknown"), [])

    def test_invalid_result_limit_is_rejected(self):
        with pytest.raises(TypeError, match="results_per_page"):
            fingerprint.query_nvd_cves("nginx", results_per_page=2.5)


if __name__ == "__main__":
    unittest.main()
