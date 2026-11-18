"""Unit tests for IoT Hunter's vendor OUI database loading and lookup."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from modules import discovery


class OuiLookupTests(unittest.TestCase):
    def test_load_oui_db_parses_wildcards_and_ignores_comments(self):
        with tempfile.TemporaryDirectory() as folder:
            oui_file = Path(folder) / "oui.txt"
            oui_file.write_text(
                "# Sample OUI entries\n"
                "\n"
                "00:1A:11:*:*:* Google\n"
                "b8:27:eb:*:*:* Raspberry Pi Foundation\n"
                "invalid-line-without-space\n",
                encoding="utf-8",
            )
            db = discovery.load_oui_db(oui_file)
            self.assertEqual(
                db,
                {
                    "00:1A:11": "Google",
                    "B8:27:EB": "Raspberry Pi Foundation",
                },
            )

    def test_load_oui_db_returns_empty_dict_when_file_missing(self):
        with tempfile.TemporaryDirectory() as folder:
            missing_path = Path(folder) / "nonexistent_oui.txt"
            db = discovery.load_oui_db(missing_path)
            self.assertEqual(db, {})

    def test_lookup_vendor_matches_colon_and_hyphen_mac_formats(self):
        sample_db = {
            "00:1A:11": "Google",
            "B8:27:EB": "Raspberry Pi Foundation",
        }
        with patch.object(discovery, "MANUF_DB", None):
            self.assertEqual(
                discovery.lookup_vendor("00:1a:11:22:33:44", sample_db),
                "Google",
            )
            self.assertEqual(
                discovery.lookup_vendor("b8-27-eb-aa-bb-cc", sample_db),
                "Raspberry Pi Foundation",
            )

    def test_lookup_vendor_handles_unknown_empty_and_none_macs(self):
        sample_db = {"00:1A:11": "Google"}
        with patch.object(discovery, "MANUF_DB", None):
            self.assertEqual(discovery.lookup_vendor("FF:EE:DD:CC:BB:AA", sample_db), "Unknown")
            self.assertEqual(discovery.lookup_vendor("00:1A:11:22:33:44", {}), "Unknown")
            self.assertEqual(discovery.lookup_vendor("", sample_db), "Unknown")
            self.assertEqual(discovery.lookup_vendor(None, sample_db), "Unknown")

    def test_lookup_vendor_uses_manuf_db_when_available(self):
        class FakeManufDb:
            def get_vendor(self, mac):
                return "Espressif Inc."

        with patch.object(discovery, "MANUF_DB", FakeManufDb()):
            self.assertEqual(
                discovery.lookup_vendor("24:0A:C4:11:22:33", {"24:0A:C4": "Fallback Vendor"}),
                "Espressif Inc.",
            )


if __name__ == "__main__":
    unittest.main()
