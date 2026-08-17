#!/usr/bin/env python3
"""Extract Racelogic 'Can Data File V1a' .REF channel definitions into CSV."""

import csv
import sys
import zlib


def _is_zlib_header(cmf: int, flg: int) -> bool:
    """Return True when two bytes form a valid deflate zlib header."""
    return (
        (cmf & 0x0F) == 8
        and (cmf >> 4) <= 7
        and ((cmf << 8) + flg) % 31 == 0
    )


def extract_blocks(path):
    with open(path, "rb") as source:
        raw = source.read()

    blocks = []
    i = 0

    while i < len(raw) - 1:
        j = raw.find(b"\x78", i)
        if j == -1 or j + 1 >= len(raw):
            break

        if not _is_zlib_header(raw[j], raw[j + 1]):
            i = j + 1
            continue

        try:
            decompressor = zlib.decompressobj()
            out = decompressor.decompress(raw[j:])
            out += decompressor.flush()
        except zlib.error:
            i = j + 1
            continue

        if not decompressor.eof:
            i = j + 1
            continue

        text = out.decode("utf-8", errors="replace").strip()
        if text:
            blocks.append(text)

        consumed = len(raw[j:]) - len(decompressor.unused_data)
        i = j + max(consumed, 2)

    return blocks


def main():
    if len(sys.argv) != 3:
        print("Usage: racelogic_ref_extract.py input.ref output.csv")
        return 2

    inp = sys.argv[1]
    out_csv = sys.argv[2]

    blocks = extract_blocks(inp)
    signal_lines = [block for block in blocks if "," in block and not block.isdigit()]

    headers = [
        "name", "can_id", "units", "start_bit", "bit_length",
        "offset", "scale", "max", "min", "signedness", "endian", "dlc"
    ]

    with open(out_csv, "w", newline="", encoding="utf-8") as output:
        writer = csv.writer(output)
        writer.writerow(headers)
        for line in signal_lines:
            parts = [part.strip() for part in line.split(",") if part.strip()]
            writer.writerow(parts)

    print("Done. Extracted", len(signal_lines), "signals.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
