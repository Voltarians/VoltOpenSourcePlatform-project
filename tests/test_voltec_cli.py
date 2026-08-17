from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from tools import voltec_cli


SIGNAL_HEADER = (
    "name,can_id,units,start_bit,bit_length,offset,scale,max,min,"
    "signedness,endian,dlc\n"
)


class VoltecCliTests(unittest.TestCase):
    def run_cli(self, arguments):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = voltec_cli.main(arguments)
        return result, output.getvalue()

    def test_help_parser_exposes_commands(self):
        parser = voltec_cli.build_parser()
        help_text = parser.format_help()
        self.assertIn("decode-frame", help_text)
        self.assertIn("validate-dbc", help_text)

    def test_decode_unsigned_frame_as_json(self):
        with tempfile.TemporaryDirectory() as directory:
            signals = Path(directory) / "signals.csv"
            signals.write_text(
                SIGNAL_HEADER
                + "Example,0x100,count,0,8,0,1,255,0,Unsigned,Intel,8\n",
                encoding="utf-8",
            )
            result, output = self.run_cli(
                [
                    "decode-frame",
                    "0x100",
                    "FF",
                    "--signals",
                    str(signals),
                    "--json",
                ]
            )
        self.assertEqual(result, 0)
        decoded = json.loads(output)
        self.assertEqual(decoded[0]["raw"], 255)
        self.assertEqual(decoded[0]["value"], 255.0)

    def test_list_signals_filter(self):
        result, output = self.run_cli(["list-signals", "--can-id", "0x52A"])
        self.assertEqual(result, 0)
        self.assertIn("Tyre_Pressure_RR", output)
        self.assertNotIn("Engine_Speed", output)

    def test_repository_dbc_is_reproducible(self):
        result, output = self.run_cli(["validate-dbc"])
        self.assertEqual(result, 0)
        self.assertIn("validation passed", output)


if __name__ == "__main__":
    unittest.main()
