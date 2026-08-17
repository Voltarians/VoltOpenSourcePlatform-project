from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from tools import log_analysis


class LogAnalysisTests(unittest.TestCase):
    def write(self, directory: str, name: str, content: str) -> Path:
        path = Path(directory) / name
        path.write_text(content, encoding="utf-8")
        return path

    def test_candump_detection_and_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(
                directory,
                "capture.log",
                "(1.000) can0 4D1#00010203\n"
                "(1.500) can0 4D1#00010303\n"
                "(2.000) can0 123#AA55\n",
            )
            capture_format, frames = log_analysis.read_capture(path)
        self.assertEqual(capture_format, "candump")
        summary = log_analysis.capture_summary(frames, capture_format, {0x4D1})
        self.assertEqual(summary["frames"], 3)
        self.assertEqual(summary["unique_ids"], 2)
        row = next(item for item in summary["messages"] if item["can_id"] == "0x4D1")
        self.assertEqual(row["changed_byte_mask"], "0x04")
        self.assertTrue(row["known"])

    def test_savvycan_csv_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(
                directory,
                "savvy.csv",
                "Time Stamp,ID,Extended,Dir,Bus,LEN,D1,D2,D3\n"
                "0.100,201,false,Rx,0,3,01,02,03\n",
            )
            capture_format, frames = log_analysis.read_capture(path)
        self.assertEqual(capture_format, "savvycan-csv")
        self.assertEqual(frames[0].can_id, 0x201)
        self.assertEqual(frames[0].data, bytes.fromhex("010203"))

    def test_canalyst_text_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(
                directory,
                "canalyst.txt",
                "0.250 CH1 4D1 Rx d 4 01 02 03 04\n",
            )
            capture_format, frames = log_analysis.read_capture(path)
        self.assertEqual(capture_format, "canalyst-text")
        self.assertEqual(frames[0].channel, "CH1")
        self.assertEqual(frames[0].can_id, 0x4D1)

    def test_normalized_output_excludes_source_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.write(
                directory,
                "source.csv",
                "timestamp,can_id,data,VIN,operator\n"
                "1.0,0x100,0102,1G1RA6E45DU100001,A Person\n",
            )
            capture_format, frames = log_analysis.read_capture(source)
            output = Path(directory) / "normalized.csv"
            log_analysis.write_normalized(frames, output)
            headers = next(csv.reader(output.open(encoding="utf-8")))
            text = output.read_text(encoding="utf-8")
        self.assertEqual(capture_format, "csv")
        self.assertEqual(headers, ["timestamp", "channel", "can_id", "dlc", "data"])
        self.assertNotIn("1G1RA6E45DU100001", text)
        self.assertNotIn("A Person", text)

    def test_comparison_finds_added_and_removed_ids(self):
        baseline = log_analysis.capture_summary(
            [log_analysis.Frame("0", "", 0x100, b"\x00")], "test"
        )
        candidate = log_analysis.capture_summary(
            [log_analysis.Frame("0", "", 0x200, b"\x00")], "test"
        )
        comparison = log_analysis.compare_summaries(baseline, candidate)
        self.assertEqual(comparison["added_ids"], ["0x200"])
        self.assertEqual(comparison["removed_ids"], ["0x100"])


if __name__ == "__main__":
    unittest.main()
