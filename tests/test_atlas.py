from __future__ import annotations
import json
import tempfile
import unittest
from pathlib import Path
from tools import atlas

class AtlasTests(unittest.TestCase):
    def test_validation(self):
        self.assertEqual(atlas.validate(), [])
    def test_inventory(self):
        data = atlas.load_all()
        self.assertEqual((len(data["vehicles"]), len(data["networks"]), len(data["modules"]), len(atlas.signals())), (2,2,5,14))
    def test_lookup(self):
        self.assertEqual({x["name"] for x in atlas.lookup("0x4D1")["signals"]}, {"Oil_Temperature","Oil_Pressure"})
        self.assertEqual(atlas.lookup("HPCM2")["modules"][0]["id"], "hpcm2")
    def test_exports(self):
        with tempfile.TemporaryDirectory() as directory:
            csv_path = Path(directory) / "signals.csv"
            json_path = Path(directory) / "atlas.json"
            atlas.export_signal_csv(csv_path)
            atlas.export_json(json_path)
            self.assertIn("Battery_Voltage,298,V", csv_path.read_text(encoding="utf-8"))
            self.assertEqual(len(json.loads(json_path.read_text())["signals"]), 14)

if __name__ == "__main__":
    unittest.main()
