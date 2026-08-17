from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools import j2534_inventory


class J2534InventoryTests(unittest.TestCase):
    def test_replay_inventory_is_read_only_and_unassigned(self):
        fixture = Path(__file__).parent / "fixtures" / "j2534_inventory.json"
        inventory = j2534_inventory.build_inventory(
            j2534_inventory.ReplayBackend(fixture)
        )
        self.assertEqual(
            [row["response_id"] for row in inventory["responders"]],
            ["0x7E8", "0x7EA"],
        )
        self.assertEqual(inventory["request"]["service_id"], "0x09")
        self.assertTrue(
            all(row["atlas_module_id"] is None for row in inventory["responders"])
        )
        self.assertIn("0x27", inventory["prohibited_services"])
        self.assertIn("0x34", inventory["prohibited_services"])

    def test_report_excludes_payloads_and_vin(self):
        fixture = Path(__file__).parent / "fixtures" / "j2534_inventory.json"
        inventory = j2534_inventory.build_inventory(
            j2534_inventory.ReplayBackend(fixture)
        )
        report = j2534_inventory.inventory_markdown(inventory)
        self.assertIn("# Voltec Read-Only J2534 Inventory", report)
        self.assertNotIn("FFFFFFFF", report)
        self.assertNotIn("VIN", report.upper())

    def test_invalid_bitrate_is_rejected_before_backend_use(self):
        class FailBackend:
            name = "fail"

            def discover(self, bitrate):
                raise AssertionError("backend must not be opened")

        with self.assertRaises(ValueError):
            j2534_inventory.build_inventory(FailBackend(), bitrate=33333)

    def test_replay_rejects_malformed_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text("{}", encoding="utf-8")
            with self.assertRaises((TypeError, KeyError)):
                j2534_inventory.ReplayBackend(path).discover(500000)


if __name__ == "__main__":
    unittest.main()
