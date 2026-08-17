"""Automatic CAN capture import, normalization, inspection, and comparison."""

from __future__ import annotations

import csv
import json
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, TextIO

from tools.parsers import decode_log_from_csv as legacy


@dataclass(frozen=True)
class Frame:
    timestamp: str
    channel: str
    can_id: int
    data: bytes

    @property
    def dlc(self) -> int:
        return len(self.data)

    def record(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "channel": self.channel,
            "can_id": f"0x{self.can_id:X}",
            "dlc": self.dlc,
            "data": self.data.hex(" ").upper(),
        }


HEADER_ALIASES = {
    "timestamp": ("timestamp", "time_stamp", "time", "ts", "relative_time"),
    "can_id": ("can_id", "arbitration_id", "identifier", "id"),
    "channel": ("channel", "interface", "iface", "bus"),
    "payload": ("data", "data_hex", "payload", "bytes"),
}
CANALYST_RE = re.compile(
    r"^\s*(?P<ts>\d+(?:\.\d+)?)\s+"
    r"(?P<channel>\S+)\s+"
    r"(?P<id>(?:0x)?[0-9A-Fa-f]+)\s+"
    r"(?:Rx|Tx)\s+(?:d\s+)?(?P<dlc>\d+)\s+"
    r"(?P<data>(?:[0-9A-Fa-f]{2}(?:\s+|$))+)"
)


def _header_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")


def _find_column(headers: list[str], aliases: tuple[str, ...]) -> str | None:
    for alias in aliases:
        if alias in headers:
            return alias
    return None


def _parse_can_id(value: str, prefer_hex: bool = False) -> int:
    text = value.strip()
    if text.lower().startswith("0x"):
        return int(text, 16)
    if any(character in "abcdefABCDEF" for character in text):
        return int(text, 16)
    return int(text, 16 if prefer_hex else 10)


def _parse_payload(value: str) -> bytes:
    cleaned = value.strip().replace(",", " ").replace("-", " ")
    if not cleaned:
        return b""
    parts = cleaned.split()
    if len(parts) == 1:
        compact = parts[0].removeprefix("0x")
        if len(compact) % 2:
            compact += "0"
        return bytes.fromhex(compact)
    return bytes(int(part.removeprefix("0x"), 16) for part in parts)


def _byte_columns(headers: list[str]) -> list[str]:
    candidates = []
    for header in headers:
        match = re.fullmatch(r"(?:b|byte|d)_?(\d+)", header)
        if match:
            candidates.append((int(match.group(1)), header))
    candidates.sort()
    return [header for _, header in candidates[:8]]


def _read_dict_csv(lines: list[str]) -> tuple[str, list[Frame]]:
    reader = csv.DictReader(lines)
    if not reader.fieldnames:
        return "csv", []
    normalized = [_header_name(name) for name in reader.fieldnames]
    key_map = dict(zip(normalized, reader.fieldnames))
    timestamp_key = _find_column(normalized, HEADER_ALIASES["timestamp"])
    id_key = _find_column(normalized, HEADER_ALIASES["can_id"])
    channel_key = _find_column(normalized, HEADER_ALIASES["channel"])
    payload_key = _find_column(normalized, HEADER_ALIASES["payload"])
    byte_keys = _byte_columns(normalized)
    savvy = "extended" in normalized and "dir" in normalized and bool(byte_keys)
    if id_key is None:
        raise ValueError("CSV capture has no recognized CAN ID column.")

    frames = []
    for row in reader:
        if not row.get(key_map[id_key], "").strip():
            continue
        if payload_key:
            data = _parse_payload(row.get(key_map[payload_key], ""))
        else:
            values = [
                row.get(key_map[key], "").strip()
                for key in byte_keys
                if row.get(key_map[key], "").strip()
            ]
            data = bytes(int(value.removeprefix("0x"), 16) for value in values)
        frames.append(
            Frame(
                timestamp=row.get(key_map[timestamp_key], "").strip()
                if timestamp_key
                else "",
                channel=row.get(key_map[channel_key], "").strip()
                if channel_key
                else "",
                can_id=_parse_can_id(row[key_map[id_key]], prefer_hex=savvy),
                data=data[:8],
            )
        )
    return ("savvycan-csv" if savvy else "csv"), frames


def _looks_like_header(line: str) -> bool:
    if "," not in line:
        return False
    fields = {_header_name(value) for value in next(csv.reader([line]))}
    id_names = set(HEADER_ALIASES["can_id"])
    return bool(fields & id_names) and bool(
        fields & set(HEADER_ALIASES["timestamp"]) or _byte_columns(list(fields))
    )


def read_capture(path: Path) -> tuple[str, list[Frame]]:
    lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    useful = [line for line in lines if line.strip() and not line.lstrip().startswith("#")]
    if not useful:
        return "empty", []

    if _looks_like_header(useful[0]):
        return _read_dict_csv(useful)

    frames = []
    detected = "unknown"
    for line in useful:
        match = CANALYST_RE.match(line)
        if match:
            data = _parse_payload(match.group("data"))[: int(match.group("dlc"))]
            frames.append(
                Frame(
                    match.group("ts"),
                    match.group("channel"),
                    _parse_can_id(match.group("id"), prefer_hex=True),
                    data[:8],
                )
            )
            detected = "canalyst-text"
            continue

        parsed = legacy.parse_frame_line(line)
        if parsed is None:
            continue
        timestamp, can_id, data = parsed
        frames.append(Frame(timestamp or "", "", can_id, data[:8]))
        if "#" in line:
            detected = "candump" if " " in line.split("#", 1)[0] else "id-data"
        elif "," in line:
            detected = "byte-csv"

    if not frames:
        raise ValueError("No supported CAN frames were found.")
    return detected, frames


def write_normalized(frames: Iterable[Frame], output: Path) -> None:
    with output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=["timestamp", "channel", "can_id", "dlc", "data"],
        )
        writer.writeheader()
        for frame in frames:
            writer.writerow(frame.record())


def _number(value: str) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def capture_summary(
    frames: list[Frame],
    capture_format: str,
    known_ids: set[int] | None = None,
) -> dict:
    known_ids = known_ids or set()
    by_id: dict[int, list[Frame]] = defaultdict(list)
    for frame in frames:
        by_id[frame.can_id].append(frame)

    numeric_times = [
        timestamp
        for frame in frames
        if (timestamp := _number(frame.timestamp)) is not None
    ]
    duration = max(numeric_times) - min(numeric_times) if len(numeric_times) > 1 else 0.0
    messages = []
    for can_id, grouped in sorted(by_id.items()):
        first = grouped[0].data.ljust(8, b"\x00")
        changed = 0
        for frame in grouped[1:]:
            payload = frame.data.ljust(8, b"\x00")
            for index, (left, right) in enumerate(zip(first, payload)):
                if left != right:
                    changed |= 1 << index
        messages.append(
            {
                "can_id": f"0x{can_id:X}",
                "known": can_id in known_ids,
                "frames": len(grouped),
                "rate_hz": len(grouped) / duration if duration > 0 else None,
                "dlc": sorted({frame.dlc for frame in grouped}),
                "unique_payloads": len({frame.data for frame in grouped}),
                "changed_byte_mask": f"0x{changed:02X}",
            }
        )

    return {
        "format": capture_format,
        "frames": len(frames),
        "duration_seconds": duration,
        "unique_ids": len(by_id),
        "known_ids": sum(message["known"] for message in messages),
        "unknown_ids": sum(not message["known"] for message in messages),
        "messages": messages,
    }


def compare_summaries(baseline: dict, test: dict) -> dict:
    base = {row["can_id"]: row for row in baseline["messages"]}
    candidate = {row["can_id"]: row for row in test["messages"]}
    all_ids = sorted(set(base) | set(candidate), key=lambda value: int(value, 16))
    differences = []
    for can_id in all_ids:
        left = base.get(can_id)
        right = candidate.get(can_id)
        differences.append(
            {
                "can_id": can_id,
                "status": "added" if left is None else "removed" if right is None else "present",
                "baseline_frames": left["frames"] if left else 0,
                "test_frames": right["frames"] if right else 0,
                "frame_delta": (right["frames"] if right else 0)
                - (left["frames"] if left else 0),
                "baseline_change_mask": left["changed_byte_mask"] if left else None,
                "test_change_mask": right["changed_byte_mask"] if right else None,
            }
        )
    return {
        "baseline_frames": baseline["frames"],
        "test_frames": test["frames"],
        "added_ids": [row["can_id"] for row in differences if row["status"] == "added"],
        "removed_ids": [row["can_id"] for row in differences if row["status"] == "removed"],
        "differences": differences,
    }


def summary_markdown(summary: dict, title: str = "CAN Capture Inspection") -> str:
    lines = [
        f"# {title}",
        "",
        f"- Format: `{summary['format']}`",
        f"- Frames: {summary['frames']}",
        f"- Duration: {summary['duration_seconds']:.6f} seconds",
        f"- Unique CAN IDs: {summary['unique_ids']}",
        f"- Known IDs: {summary['known_ids']}",
        f"- Unknown IDs: {summary['unknown_ids']}",
        "",
        "| CAN ID | Known | Frames | Rate (Hz) | DLC | Unique payloads | Changed bytes |",
        "| --- | --- | ---: | ---: | --- | ---: | --- |",
    ]
    for row in summary["messages"]:
        rate = "" if row["rate_hz"] is None else f"{row['rate_hz']:.3f}"
        lines.append(
            f"| {row['can_id']} | {'yes' if row['known'] else 'no'} | "
            f"{row['frames']} | {rate} | {','.join(map(str, row['dlc']))} | "
            f"{row['unique_payloads']} | {row['changed_byte_mask']} |"
        )
    return "\n".join(lines) + "\n"


def comparison_markdown(comparison: dict) -> str:
    lines = [
        "# CAN Capture Comparison",
        "",
        f"- Baseline frames: {comparison['baseline_frames']}",
        f"- Test frames: {comparison['test_frames']}",
        f"- Added IDs: {', '.join(comparison['added_ids']) or 'none'}",
        f"- Removed IDs: {', '.join(comparison['removed_ids']) or 'none'}",
        "",
        "| CAN ID | Status | Baseline | Test | Delta | Baseline changes | Test changes |",
        "| --- | --- | ---: | ---: | ---: | --- | --- |",
    ]
    for row in comparison["differences"]:
        lines.append(
            f"| {row['can_id']} | {row['status']} | {row['baseline_frames']} | "
            f"{row['test_frames']} | {row['frame_delta']} | "
            f"{row['baseline_change_mask'] or ''} | {row['test_change_mask'] or ''} |"
        )
    return "\n".join(lines) + "\n"


def write_json(value: dict | list, output: TextIO) -> None:
    json.dump(value, output, indent=2)
    output.write("\n")
