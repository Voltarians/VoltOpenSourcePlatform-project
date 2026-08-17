"""Strictly read-only J2534 module inventory support."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

PROTOCOL_ISO15765 = 6
PASS_FILTER = 1
ISO15765_FRAME_PAD = 0x40
STATUS_NOERROR = 0
ERR_TIMEOUT = 0x09
MAX_MSG_SIZE = 4128
FUNCTIONAL_REQUEST_ID = 0x7DF
OBD_VEHICLE_INFO_SERVICE = 0x09
SUPPORTED_INFO_TYPES_PID = 0x00


@dataclass(frozen=True)
class Response:
    response_id: int
    payload: bytes


class InventoryBackend(Protocol):
    name: str

    def discover(self, bitrate: int) -> list[Response]: ...


class PassThruMsg(ctypes.Structure):
    _fields_ = [
        ("ProtocolID", ctypes.c_ulong),
        ("RxStatus", ctypes.c_ulong),
        ("TxFlags", ctypes.c_ulong),
        ("Timestamp", ctypes.c_ulong),
        ("DataSize", ctypes.c_ulong),
        ("ExtraDataIndex", ctypes.c_ulong),
        ("Data", ctypes.c_ubyte * MAX_MSG_SIZE),
    ]


def _message(can_id: int, payload: bytes, tx_flags: int = 0) -> PassThruMsg:
    message = PassThruMsg()
    message.ProtocolID = PROTOCOL_ISO15765
    message.TxFlags = tx_flags
    raw = can_id.to_bytes(4, "big") + payload
    message.DataSize = len(raw)
    message.ExtraDataIndex = len(raw)
    for index, value in enumerate(raw):
        message.Data[index] = value
    return message


def _check(status: int, operation: str) -> None:
    if status != STATUS_NOERROR:
        raise OSError(f"J2534 {operation} failed with status 0x{status:02X}")


class WindowsJ2534Backend:
    """Minimal SAE J2534 backend for one allowlisted OBD information query."""

    name = "windows-j2534"

    def __init__(self, dll_path: Path, timeout_ms: int = 750):
        if os.name != "nt":
            raise OSError("Live J2534 scanning requires Windows.")
        self.dll_path = dll_path
        self.timeout_ms = timeout_ms

    def discover(self, bitrate: int) -> list[Response]:
        dll = ctypes.WinDLL(str(self.dll_path))
        device_id = ctypes.c_ulong()
        channel_id = ctypes.c_ulong()
        _check(dll.PassThruOpen(None, ctypes.byref(device_id)), "PassThruOpen")
        try:
            _check(
                dll.PassThruConnect(
                    device_id,
                    PROTOCOL_ISO15765,
                    0,
                    bitrate,
                    ctypes.byref(channel_id),
                ),
                "PassThruConnect",
            )
            try:
                self._install_response_filter(dll, channel_id)
                request = _message(
                    FUNCTIONAL_REQUEST_ID,
                    bytes.fromhex("0209000000000000"),
                    ISO15765_FRAME_PAD,
                )
                count = ctypes.c_ulong(1)
                _check(
                    dll.PassThruWriteMsgs(
                        channel_id, ctypes.byref(request), ctypes.byref(count), 500
                    ),
                    "PassThruWriteMsgs",
                )
                return self._read_responses(dll, channel_id)
            finally:
                dll.PassThruDisconnect(channel_id)
        finally:
            dll.PassThruClose(device_id)

    @staticmethod
    def _install_response_filter(dll, channel_id: ctypes.c_ulong) -> None:
        mask = _message(0, (0x7F8).to_bytes(4, "big"))
        pattern = _message(0, (0x7E8).to_bytes(4, "big"))
        # Filter messages consist only of the four-byte arbitration ID.
        mask.DataSize = pattern.DataSize = 4
        mask.ExtraDataIndex = pattern.ExtraDataIndex = 4
        filter_id = ctypes.c_ulong()
        _check(
            dll.PassThruStartMsgFilter(
                channel_id,
                PASS_FILTER,
                ctypes.byref(mask),
                ctypes.byref(pattern),
                None,
                ctypes.byref(filter_id),
            ),
            "PassThruStartMsgFilter",
        )

    def _read_responses(self, dll, channel_id: ctypes.c_ulong) -> list[Response]:
        deadline = time.monotonic() + self.timeout_ms / 1000
        found: dict[int, Response] = {}
        while time.monotonic() < deadline:
            message = PassThruMsg()
            count = ctypes.c_ulong(1)
            status = dll.PassThruReadMsgs(
                channel_id, ctypes.byref(message), ctypes.byref(count), 100
            )
            if status == ERR_TIMEOUT:
                continue
            _check(status, "PassThruReadMsgs")
            if not count.value or message.DataSize < 7:
                continue
            raw = bytes(message.Data[: message.DataSize])
            response_id = int.from_bytes(raw[:4], "big")
            payload = raw[4:]
            if (
                0x7E8 <= response_id <= 0x7EF
                and len(payload) >= 3
                and payload[1] == 0x49
                and payload[2] == SUPPORTED_INFO_TYPES_PID
            ):
                found[response_id] = Response(response_id, payload)
        return [found[key] for key in sorted(found)]


class ReplayBackend:
    name = "validated-replay"

    def __init__(self, path: Path):
        self.path = path

    def discover(self, bitrate: int) -> list[Response]:
        del bitrate
        rows = json.loads(self.path.read_text(encoding="utf-8"))
        return [
            Response(
                int(row["response_id"], 16),
                bytes.fromhex(row["payload"].replace(" ", "")),
            )
            for row in rows
        ]


def build_inventory(backend: InventoryBackend, bitrate: int = 500_000) -> dict:
    if bitrate not in (125_000, 250_000, 500_000):
        raise ValueError("Bitrate must be 125000, 250000, or 500000.")
    responses = backend.discover(bitrate)
    observations = [
        {
            "response_id": f"0x{row.response_id:X}",
            "request_id": f"0x{FUNCTIONAL_REQUEST_ID:X}",
            "service": "OBD vehicle information",
            "service_id": "0x09",
            "pid": "0x00",
            "classification": "emissions-related responder",
            "atlas_module_id": None,
            "confidence": "observed-response",
        }
        for row in sorted(responses, key=lambda item: item.response_id)
    ]
    evidence = json.dumps(observations, sort_keys=True, separators=(",", ":")).encode()
    return {
        "schema_version": "0.1",
        "safety_scope": "read-only-obd-information",
        "transport": "J2534 ISO 15765",
        "bitrate": bitrate,
        "backend": backend.name,
        "request": {
            "can_id": f"0x{FUNCTIONAL_REQUEST_ID:X}",
            "service_id": "0x09",
            "pid": "0x00",
            "description": "Read supported vehicle-information PIDs",
        },
        "prohibited_services": ["0x10", "0x11", "0x27", "0x2E", "0x31", "0x34", "0x36", "0x3D"],
        "responders": observations,
        "evidence_sha256": hashlib.sha256(evidence).hexdigest(),
        "limitations": [
            "Only emissions-related responders to functional OBD service 0x09 PID 0x00 are inventoried.",
            "A response ID is not assigned to an Atlas module without independent evidence.",
            "No VIN, calibration payload, DTC, security access, actuator command, or programming request is collected.",
        ],
    }


def inventory_markdown(inventory: dict) -> str:
    lines = [
        "# Voltec Read-Only J2534 Inventory",
        "",
        f"- Safety scope: `{inventory['safety_scope']}`",
        f"- Transport: {inventory['transport']}",
        f"- Bitrate: {inventory['bitrate']}",
        f"- Evidence SHA-256: `{inventory['evidence_sha256']}`",
        f"- Responders: {len(inventory['responders'])}",
        "",
        "| Response ID | Classification | Atlas module | Confidence |",
        "| --- | --- | --- | --- |",
    ]
    for row in inventory["responders"]:
        lines.append(
            f"| {row['response_id']} | {row['classification']} | "
            f"{row['atlas_module_id'] or 'unassigned'} | {row['confidence']} |"
        )
    lines.extend(["", "## Limits", ""])
    lines.extend(f"- {item}" for item in inventory["limitations"])
    return "\n".join(lines) + "\n"
