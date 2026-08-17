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

from tools import atlas as atlas_store
from tools import log_analysis
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
        raw = (
            decoder.get_big_endian(data, signal.start_bit, signal.bit_length)
            if signal.big_endian
            else decoder.get_little_endian(data, signal.start_bit, signal.bit_length)
        )
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


def _known_ids(signals: Path) -> set[int]:
    return set(decoder.load_signals(str(signals)))


def _write_or_print(text: str, output: Path | None) -> None:
    if output:
        output.write_text(text, encoding="utf-8")
        print(f"Report written: {output}")
    else:
        print(text, end="")


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
    return _run_legacy(csv_to_dbc.main, [str(args.signals), str(args.output)])


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


def cmd_normalize_log(args: argparse.Namespace) -> int:
    capture_format, frames = log_analysis.read_capture(args.input)
    log_analysis.write_normalized(frames, args.output)
    print(f"Normalized {len(frames)} frames from {capture_format}: {args.output}")
    return 0


def cmd_inspect_log(args: argparse.Namespace) -> int:
    capture_format, frames = log_analysis.read_capture(args.input)
    summary = log_analysis.capture_summary(
        frames, capture_format, _known_ids(args.signals)
    )
    if args.json:
        _write_or_print(json.dumps(summary, indent=2) + "\n", args.output)
    else:
        _write_or_print(log_analysis.summary_markdown(summary), args.output)
    return 0


def cmd_unknown_ids(args: argparse.Namespace) -> int:
    capture_format, frames = log_analysis.read_capture(args.input)
    summary = log_analysis.capture_summary(
        frames, capture_format, _known_ids(args.signals)
    )
    unknown = [row for row in summary["messages"] if not row["known"]]
    if args.json:
        print(json.dumps(unknown, indent=2))
    else:
        for row in unknown:
            print(
                f"{row['can_id']:>6}  frames={row['frames']:<8} "
                f"dlc={','.join(map(str, row['dlc'])):<5} "
                f"changed={row['changed_byte_mask']}"
            )
        print(f"Unknown IDs: {len(unknown)}")
    return 0


def cmd_compare_logs(args: argparse.Namespace) -> int:
    known = _known_ids(args.signals)
    base_format, base_frames = log_analysis.read_capture(args.baseline)
    test_format, test_frames = log_analysis.read_capture(args.test)
    comparison = log_analysis.compare_summaries(
        log_analysis.capture_summary(base_frames, base_format, known),
        log_analysis.capture_summary(test_frames, test_format, known),
    )
    if args.json:
        _write_or_print(json.dumps(comparison, indent=2) + "\n", args.output)
    else:
        _write_or_print(log_analysis.comparison_markdown(comparison), args.output)
    return 0



def cmd_atlas_validate(args):
    errors = atlas_store.validate()
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("Voltec Atlas validation passed.")
    return 0

def cmd_atlas_list(args):
    rows = atlas_store.signals() if args.atlas_kind == "signals" else atlas_store.load_kind(args.atlas_kind)
    if args.atlas_kind == "signals" and args.can_id:
        wanted = decoder.parse_can_id(args.can_id)
        rows = [row for row in rows if int(row["can_id"], 16) == wanted]
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for row in rows:
            primary = row.get("can_id") or row.get("id", "")
            label = row.get("name") or row.get("model") or row.get("id", "")
            print(f"{primary:>8}  {label}")
        print(f"Records: {len(rows)}")
    return 0

def cmd_atlas_lookup(args):
    print(json.dumps(atlas_store.lookup(args.query), indent=2))
    return 0

def cmd_atlas_export_json(args):
    atlas_store.export_json(args.output)
    print(f"Atlas JSON written: {args.output}")
    return 0

def cmd_atlas_export_csv(args):
    atlas_store.export_signal_csv(args.output)
    print(f"Atlas CSV written: {args.output}")
    return 0

def cmd_atlas_export_dbc(args):
    with tempfile.TemporaryDirectory() as directory:
        signal_csv = Path(directory) / "signals.csv"
        atlas_store.export_signal_csv(signal_csv)
        return _run_legacy(csv_to_dbc.main, [str(signal_csv), str(args.output)])

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="voltec",
        description="Offline CAN research toolkit for Chevrolet Volt and Cadillac ELR.",
    )
    parser.add_argument("--version", action="version", version="voltec 0.4.0")
    commands = parser.add_subparsers(dest="command", required=True)

    frame_parser = commands.add_parser("decode-frame", help="Decode one CAN frame.")
    frame_parser.add_argument("can_id")
    frame_parser.add_argument("data")
    frame_parser.add_argument("--signals", type=Path, default=DEFAULT_SIGNALS)
    frame_parser.add_argument("--json", action="store_true")
    frame_parser.set_defaults(handler=cmd_decode_frame)

    log_parser = commands.add_parser("decode-log", help="Decode a CAN capture to CSV.")
    log_parser.add_argument("input", type=Path)
    log_parser.add_argument("output", type=Path)
    log_parser.add_argument("--signals", type=Path, default=DEFAULT_SIGNALS)
    log_parser.set_defaults(handler=cmd_decode_log)

    normalize = commands.add_parser("normalize-log", help="Normalize a CAN capture.")
    normalize.add_argument("input", type=Path)
    normalize.add_argument("output", type=Path)
    normalize.set_defaults(handler=cmd_normalize_log)

    inspect = commands.add_parser("inspect-log", help="Summarize a CAN capture.")
    inspect.add_argument("input", type=Path)
    inspect.add_argument("--signals", type=Path, default=DEFAULT_SIGNALS)
    inspect.add_argument("--json", action="store_true")
    inspect.add_argument("--output", type=Path)
    inspect.set_defaults(handler=cmd_inspect_log)

    unknown = commands.add_parser("unknown-ids", help="List undefined CAN IDs.")
    unknown.add_argument("input", type=Path)
    unknown.add_argument("--signals", type=Path, default=DEFAULT_SIGNALS)
    unknown.add_argument("--json", action="store_true")
    unknown.set_defaults(handler=cmd_unknown_ids)

    compare = commands.add_parser("compare-logs", help="Compare two CAN captures.")
    compare.add_argument("baseline", type=Path)
    compare.add_argument("test", type=Path)
    compare.add_argument("--signals", type=Path, default=DEFAULT_SIGNALS)
    compare.add_argument("--json", action="store_true")
    compare.add_argument("--output", type=Path)
    compare.set_defaults(handler=cmd_compare_logs)

    dbc_parser = commands.add_parser("generate-dbc", help="Generate a DBC.")
    dbc_parser.add_argument("output", type=Path)
    dbc_parser.add_argument("--signals", type=Path, default=DEFAULT_SIGNALS)
    dbc_parser.set_defaults(handler=cmd_generate_dbc)

    list_parser = commands.add_parser("list-signals", help="List signal definitions.")
    list_parser.add_argument("--signals", type=Path, default=DEFAULT_SIGNALS)
    list_parser.add_argument("--can-id")
    list_parser.add_argument("--json", action="store_true")
    list_parser.set_defaults(handler=cmd_list_signals)

    validate = commands.add_parser("validate-dbc", help="Validate generated DBC.")
    validate.add_argument("--signals", type=Path, default=DEFAULT_SIGNALS)
    validate.add_argument("--dbc", type=Path, default=DEFAULT_DBC)
    validate.set_defaults(handler=cmd_validate_dbc)


    atlas_parser = commands.add_parser("atlas", help="Query Voltec Atlas.")
    atlas_commands = atlas_parser.add_subparsers(dest="atlas_command", required=True)
    atlas_validate = atlas_commands.add_parser("validate")
    atlas_validate.set_defaults(handler=cmd_atlas_validate)
    for atlas_kind in ("vehicles", "networks", "modules", "signals"):
        item = atlas_commands.add_parser(atlas_kind)
        item.add_argument("--json", action="store_true")
        if atlas_kind == "signals":
            item.add_argument("--can-id")
        item.set_defaults(handler=cmd_atlas_list, atlas_kind=atlas_kind)
    lookup = atlas_commands.add_parser("lookup")
    lookup.add_argument("query")
    lookup.set_defaults(handler=cmd_atlas_lookup)
    for name, handler in (("export-json", cmd_atlas_export_json), ("export-csv", cmd_atlas_export_csv), ("export-dbc", cmd_atlas_export_dbc)):
        item = atlas_commands.add_parser(name)
        item.add_argument("output", type=Path)
        item.set_defaults(handler=handler)

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
