from __future__ import annotations

import tempfile
import unittest
import zlib
from pathlib import Path

from tools.parsers import csv_to_dbc
from tools.parsers import decode_frame_from_csv as frame
from tools.parsers import decode_log_from_csv as log
from tools.parsers import racelogic_ref_extract as ref


class ParserTests(unittest.TestCase):
    def test_can_id_parsing(self):
        self.assertEqual(frame.parse_can_id("0x4D1"), 0x4D1)
        self.assertEqual(frame.parse_can_id("1233"), 1233)
        self.assertEqual(log.parse_can_id("4D1"), 0x4D1)

    def test_frame_byte_validation(self):
        self.assertEqual(
            frame.parse_bytes("00 01 02 03 04 05 06 07"),
            bytes(range(8)),
        )
        with self.assertRaises(ValueError):
            frame.parse_bytes("00 01")

    def test_bit_decoding(self):
        data = bytes([0b10100000, 0x34, 0x12, 0, 0, 0, 0, 0])
        self.assertEqual(frame.get_big_endian(data, 0, 4), 0b1010)
        self.assertEqual(frame.get_little_endian(data, 8, 16), 0x1234)
        self.assertEqual(frame.to_signed(0xFF, 8), -1)
        self.assertEqual(frame.to_signed(0x7F, 8), 127)

    def test_candump_and_csv_lines(self):
        ts, can_id, data = log.parse_frame_line("(1.250) can0 4D1#01020304")
        self.assertEqual(ts, "1.250")
        self.assertEqual(can_id, 0x4D1)
        self.assertEqual(data, bytes.fromhex("01020304"))

        ts, can_id, data = log.parse_frame_line(
            "2.5,0x4D1,00,01,02,03,04,05,06,07"
        )
        self.assertEqual((ts, can_id), ("2.5", 0x4D1))
        self.assertEqual(data, bytes(range(8)))

    def test_name_and_definition_helpers(self):
        self.assertEqual(csv_to_dbc.sanitize_name("Engine Speed"), "Engine_Speed")
        self.assertEqual(csv_to_dbc.sanitize_name("12 V"), "_12_V")
        self.assertTrue(csv_to_dbc.is_signed("Signed"))
        self.assertTrue(csv_to_dbc.is_big_endian("Motorola"))

    def test_ref_block_extraction(self):
        payload = b"Engine_Speed,201,rpm,40,16,0,0.25,10000,0,Unsigned,Motorola,7"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.ref"
            path.write_bytes(b"header" + zlib.compress(payload) + b"tail")
            self.assertEqual(ref.extract_blocks(path), [payload.decode()])


if __name__ == "__main__":
    unittest.main()
