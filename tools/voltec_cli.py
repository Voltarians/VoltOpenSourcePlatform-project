#!/usr/bin/env python3
"""Unified command-line interface for Volt Open Source Platform tools."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
import tempfile
from pathlib import Path
from typing import Sequence

from tools.parsers import csv_to_dbc
from tools.parsers import decode_log_from_csv as decoder

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SIGNALS = REPOSITORY_ROOT / "docs/can/racelogic/volt_public_signals.csv"
DEFAULT_DBC = REPOSITORY_ROOT / "docs/can/racelogic/volt_public.dbc"


def _data_bytes(value: str) -> bytes:
    cleaned = value.replace(",", " ").replace("0x", "")
    parts = cleaned.split()
    if len(parts) == 1:
        compact = parts[0]
        if len(compact) % 2:
            raise ValueError("Hex data must contain complete bytes.")
        data = bytes.fromhex(compact)
    else:
        data = bytes(int(part, 16) for part in parts)
    if len(data) > 8:
        raise ValueError("Classic CAN frames may contain at most 8 data bytes.")
    return data.ljust(8, b"\x00")


def _decoded_signals(signals_path: Path, can_id_text: str, data_text: str) -> list[dict]:
    can_id = decoder.parse_can_id(can_id_text)
    data = _data_bytes(data_text)
    definitions = decoder.load_signals(str(signals_path)).get(can_id, [])
    decoded = []
    for signal in definitions:
        if signal.big_endian:
            raw = decoder.get_big_endian(data, signal.start_bit, signal.bit_length)
        else:
            raw = decoder.get_little_endian(data, signal.start_bit, signal.bit_length)
        if signal.signed:
            raw = decoder.to_signed(raw, signal.bit_length)
        decoded.append(
            {
                "can_id": f"0x{can_id:X}",
                "signal": signal.name,
                "value": raw * signal.scale + signal.offset,
                "units": signal.units,
                "raw": raw,
            }
        )
    return decoded


def _run_legacy(main_function, arguments: list[str], quiet: bool = False) -> int:
    previous = sys.argv
    sys.argv = [main_function.__module__, *arguments]
    try:
        if quiet:
            with contextlib.redirect_stdout(io.StringIO()):
                return int(main_function() or 0)
        return int(main_function() or 0)
    finally:
        sys.argv = previous


def cmd_decode_frame(args: argparse.Namespace) -> int:
    rows = _decoded_signals(args.signals, args.can_id, args.data)
    if args.json:
        print(json.dumps(rows, indent=2))
    elif not rows:
        print("No signals for that CAN ID.")
    else:
        for row in rows:
            print(
                f"{row['signal']}: {row['value']} {row['units']} "
                f"(raw={row['raw']}, {row['can_id']})"
            )
    return 0


def cmd_decode_log(args: argparse.Namespace) -> int:
    return _run_legacy(
        decoder.main,
        [str(args.signals), str(args.input), str(args.output)],
    )


def cmd_generate_dbc(args: argparse.Namespace) -> int:
    return _run_legacy(
        csv_to_dbc.main,
        [str(args.signals), str(args.output)],
    )


def cmd_list_signals(args: argparse.Namespace) -> int:
    signals = decoder.load_signals(str(args.signals))
    can_filter = decoder.parse_can_id(args.can_id) if args.can_id else None
    rows = []
    for can_id in sorted(signals):
        if can_filter is not None and can_id != can_filter:
            continue
        for signal in signals[can_id]:
            rows.append(
                {
                    "can_id": f"0x{can_id:X}",
                    "signal": signal.name,
                    "units": signal.units,
                    "start_bit": signal.start_bit,
                    "bit_length": signal.bit_length,
                    "scale": signal.scale,
                    "offset": signal.offset,
                    "signed": signal.signed,
                    "endian": "big" if signal.big_endian else "little",
                }
            )
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for row in rows:
            print(
                f"{row['can_id']:>6}  {row['signal']:<30} "
                f"{row['bit_length']:>2} bit  {row['units']}"
            )
        print(f"Signals: {len(rows)}")
    return 0


def cmd_validate_dbc(args: argparse.Namespace) -> int:
    with tempfile.TemporaryDirectory() as directory:
        generated = Path(directory) / "generated.dbc"
        result = _run_legacy(
            csv_to_dbc.main,
            [str(args.signals), str(generated)],
            quiet=True,
        )
        if result:
            return result
        if generated.read_bytes() != args.dbc.read_bytes():
            print("DBC validation failed: generated output differs.", file=sys.stderr)
            return 1
    print(f"DBC validation passed: {args.dbc}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="voltec",
        description="Offline CAN research toolkit for Chevrolet Volt and Cadillac ELR.",
    )
    parser.add_argument("--version", action="version", version="voltec 0.2.0")
    commands = parser.add_subparsers(dest="command", required=True)

    frame_parser = commands.add_parser("decode-frame", help="Decode one CAN frame.")
    frame_parser.add_argument("can_id", help="CAN identifier, decimal or hexadecimal.")
    frame_parser.add_argument("data", help="Up to eight hexadecimal data bytes.")
    frame_parser.add_argument("--signals", type=Path, default=DEFAULT_SIGNALS)
    frame_parser.add_argument("--json", action="store_true")
    frame_parser.set_defaults(handler=cmd_decode_frame)

    log_parser = commands.add_parser("decode-log", help="Decode a CAN capture to CSV.")
    log_parser.add_argument("input", type=Path)
    log_parser.add_argument("output", type=Path)
    log_parser.add_argument("--signals", type=Path, default=DEFAULT_SIGNALS)
    log_parser.set_defaults(handler=cmd_decode_log)

    dbc_parser = commands.add_parser("generate-dbc", help="Generate a DBC from signal CSV.")
    dbc_parser.add_argument("output", type=Path)
    dbc_parser.add_argument("--signals", type=Path, default=DEFAULT_SIGNALS)
    dbc_parser.set_defaults(handler=cmd_generate_dbc)

    list_parser = commands.add_parser("list-signals", help="List known signal definitions.")
    list_parser.add_argument("--signals", type=Path, default=DEFAULT_SIGNALS)
    list_parser.add_argument("--can-id")
    list_parser.add_argument("--json", action="store_true")
    list_parser.set_defaults(handler=cmd_list_signals)

    validate_parser = commands.add_parser(
        "validate-dbc", help="Verify that a DBC matches its signal CSV."
    )
    validate_parser.add_argument("--signals", type=Path, default=DEFAULT_SIGNALS)
    validate_parser.add_argument("--dbc", type=Path, default=DEFAULT_DBC)
    validate_parser.set_defaults(handler=cmd_validate_dbc)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except (OSError, ValueError, KeyError) as error:
        parser.error(str(error))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
