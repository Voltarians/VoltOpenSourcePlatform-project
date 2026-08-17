from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from tools import log_analysis, research


class CaptureResearchTests(unittest.TestCase):
    def test_unknown_ids_are_ranked_without_guessing_meaning(self):
        frames = [
            log_analysis.Frame("0.0", "can0", 0x100, b"\x00\x00"),
            log_analysis.Frame("0.1", "can0", 0x123, b"\x00\x00"),
            log_analysis.Frame("0.2", "can0", 0x123, b"\x01\x00"),
            log_analysis.Frame("0.3", "can0", 0x456, b"\x00\x00"),
        ]
        report = research.build_report(
            frames, "test", {0x100}, "a" * 64, top=10
        )
        self.assertEqual(report["safety_scope"], "offline-passive-analysis")
        self.assertEqual([row["can_id"] for row in report["candidates"]], ["0x123", "0x456"])
        self.assertTrue(
            all(row["status"] == "research-candidate" for row in report["candidates"])
        )
        self.assertNotIn("signal", report["candidates"][0])

    def test_top_limit_and_input_validation(self):
        frames = [
            log_analysis.Frame("0", "", 0x101, b"\x00"),
            log_analysis.Frame("1", "", 0x102, b"\x00"),
        ]
        report = research.build_report(frames, "test", set(), "b" * 64, top=1)
        self.assertEqual(len(report["candidates"]), 1)
        with self.assertRaises(ValueError):
            research.build_report(frames, "test", set(), "b" * 64, top=0)

    def test_hash_and_markdown_are_path_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.log"
            path.write_bytes(b"(0.0) can0 123#0001\n")
            digest = research.capture_sha256(path)
        self.assertEqual(digest, hashlib.sha256(b"(0.0) can0 123#0001\n").hexdigest())
        report = research.build_report(
            [log_analysis.Frame("0", "", 0x123, b"\x00\x01")],
            "candump",
            set(),
            digest,
        )
        markdown = research.report_markdown(report)
        self.assertIn("# Voltec Atlas Capture Research Report", markdown)
        self.assertNotIn(str(path), markdown)


if __name__ == "__main__":
    unittest.main()
