"""Unit tests for IoT Hunter's local inventory history."""
import tempfile
import unittest
from pathlib import Path

from modules.inventory import compare_inventory, load_snapshots, record_inventory


class InventoryTests(unittest.TestCase):
    def test_detects_new_missing_and_changed_devices(self):
        before = [
            {"ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:01", "open_ports": [80]},
            {"ip": "192.168.1.11", "mac": "aa:bb:cc:dd:ee:02", "open_ports": [22]},
        ]
        after = [
            {"ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:01", "open_ports": [80, 443]},
            {"ip": "192.168.1.12", "mac": "aa:bb:cc:dd:ee:03", "open_ports": [1883]},
        ]
        result = compare_inventory(before, after)
        self.assertEqual(len(result["new_devices"]), 1)
        self.assertEqual(len(result["missing_devices"]), 1)
        self.assertEqual(result["changed_devices"][0]["changed_fields"], ["open_ports"])

    def test_records_snapshots_without_unapproved_fields(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "inventory.json"
            result = record_inventory([{
                "ip": "192.168.1.2", "mac": "aa:bb:cc:dd:ee:ff",
                "vendor": "Example", "hostname": "device.local",
                "device_type": "sensor", "open_ports": [1883],
                "password": "must-not-be-stored",
            }], path)
            snapshots = load_snapshots(path)
            self.assertEqual(result["new_devices"], 1)
            self.assertNotIn("password", str(snapshots))


if __name__ == "__main__":
    unittest.main()
