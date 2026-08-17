"""Voltec Atlas loading, validation, lookup, and export."""

from __future__ import annotations
import csv
import json
from pathlib import Path
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1] / "atlas"
KINDS = {
    "vehicles": ("vehicles", "vehicle.schema.json"),
    "networks": ("networks", "network.schema.json"),
    "modules": ("modules", "module.schema.json"),
    "signal_sets": ("signals", "signal-set.schema.json"),
}

def _read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))

def load_kind(kind: str, root: Path = ROOT) -> list[dict]:
    directory, _ = KINDS[kind]
    return [_read(path) for path in sorted((root / directory).glob("*.yaml"))]

def load_all(root: Path = ROOT) -> dict:
    return {kind: load_kind(kind, root) for kind in KINDS}

def signals(root: Path = ROOT) -> list[dict]:
    result = []
    for group in load_kind("signal_sets", root):
        for item in group["signals"]:
            row = dict(item)
            row["source_id"] = group["id"]
            row["confidence"] = group["source"]["confidence"]
            result.append(row)
    return result

def validate(root: Path = ROOT) -> list[str]:
    errors, records = [], {}
    for kind, (directory, schema_name) in KINDS.items():
        validator = Draft202012Validator(_read(root / "schema" / schema_name))
        records[kind] = []
        for path in sorted((root / directory).glob("*.yaml")):
            try:
                record = _read(path)
            except (OSError, json.JSONDecodeError) as error:
                errors.append(f"{path}: {error}")
                continue
            records[kind].append(record)
            for error in validator.iter_errors(record):
                location = ".".join(map(str, error.path)) or "<root>"
                errors.append(f"{path}:{location}: {error.message}")
    vehicle_ids = {row["id"] for row in records.get("vehicles", [])}
    network_ids = {row["id"] for row in records.get("networks", [])}
    for module in records.get("modules", []):
        for value in module["vehicle_ids"]:
            if value not in vehicle_ids:
                errors.append(f"module {module['id']} references unknown vehicle {value}")
        for value in module["network_ids"]:
            if value not in network_ids:
                errors.append(f"module {module['id']} references unknown network {value}")
    seen = set()
    for signal in signals(root):
        key = (signal["can_id"], signal["name"])
        if key in seen:
            errors.append(f"duplicate signal {key}")
        seen.add(key)
        if signal["network_id"] not in network_ids:
            errors.append(f"signal {signal['name']} references unknown network")
        exceeds_dlc = signal["start_bit"] + signal["bit_length"] > signal["dlc"] * 8
        documented = "dlc-bit-range" in signal.get("source_conflicts", [])
        if exceeds_dlc and not documented:
            errors.append(f"signal {signal['name']} exceeds DLC")
    return errors

def lookup(query: str, root: Path = ROOT) -> dict:
    q = query.strip().lower()
    result = {"vehicles": [], "networks": [], "modules": [], "signals": []}
    for kind in ("vehicles", "networks", "modules"):
        for row in load_kind(kind, root):
            text = " ".join(str(row.get(k, "")) for k in ("id", "name", "make", "model")).lower()
            if q in text:
                result[kind].append(row)
    try:
        numeric = int(q, 16 if q.startswith("0x") else 10)
    except ValueError:
        numeric = None
    for row in signals(root):
        if q in row["name"].lower() or (numeric is not None and numeric == int(row["can_id"], 16)):
            result["signals"].append(row)
    return result

def export_json(output: Path, root: Path = ROOT) -> None:
    data = load_all(root)
    data["signals"] = signals(root)
    output.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

def export_signal_csv(output: Path, root: Path = ROOT) -> None:
    fields = ["name","can_id","units","start_bit","bit_length","offset","scale","max","min","signedness","endian","dlc"]
    with output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for s in signals(root):
            writer.writerow({"name":s["name"],"can_id":int(s["can_id"],16),"units":s["units"],"start_bit":s["start_bit"],"bit_length":s["bit_length"],"offset":s["offset"],"scale":s["scale"],"max":s["maximum"],"min":s["minimum"],"signedness":"Signed" if s["signed"] else "Unsigned","endian":"Motorola" if s["endian"]=="motorola" else "Intel","dlc":s["dlc"]})
