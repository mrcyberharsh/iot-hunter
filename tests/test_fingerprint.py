import unittest

from modules.fingerprint import classify_device, parse_banner_service


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


if __name__ == "__main__":
    unittest.main()
