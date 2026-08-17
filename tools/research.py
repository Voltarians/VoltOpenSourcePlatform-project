"""Read-only CAN capture research reports for Voltec Atlas."""

from __future__ import annotations

import hashlib
from pathlib import Path

from tools import log_analysis


def capture_sha256(path: Path) -> str:
    """Return a reproducible evidence hash without exposing the source path."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _priority(row: dict) -> tuple[int, str]:
    """Score an unknown ID for follow-up; this does not infer signal meaning."""
    changed = int(row["changed_byte_mask"], 16).bit_count()
    frames = row["frames"]
    diversity = row["unique_payloads"]
    score = round(
        35 * min(diversity / max(frames, 1), 1)
        + 30 * min(changed / 8, 1)
        + 25 * min(frames / 100, 1)
        + 10 * (1 if len(row["dlc"]) == 1 else 0)
    )
    rationale = (
        f"{frames} frames, {diversity} unique payloads, "
        f"{changed} changing byte positions"
    )
    return score, rationale


def build_report(
    frames: list[log_analysis.Frame],
    capture_format: str,
    known_ids: set[int],
    evidence_sha256: str,
    top: int = 20,
) -> dict:
    if top < 1:
        raise ValueError("--top must be at least 1.")
    summary = log_analysis.capture_summary(frames, capture_format, known_ids)
    candidates = []
    for row in summary["messages"]:
        if row["known"]:
            continue
        score, rationale = _priority(row)
        candidates.append(
            {
                **row,
                "priority_score": score,
                "status": "research-candidate",
                "rationale": rationale,
                "next_step": "Correlate against a controlled baseline; do not assign meaning from one capture.",
            }
        )
    candidates.sort(
        key=lambda row: (-row["priority_score"], int(row["can_id"], 16))
    )
    return {
        "schema_version": "0.1",
        "safety_scope": "offline-passive-analysis",
        "evidence_sha256": evidence_sha256,
        "capture": {
            key: summary[key]
            for key in (
                "format",
                "frames",
                "duration_seconds",
                "unique_ids",
                "known_ids",
                "unknown_ids",
            )
        },
        "ranking_method": (
            "Activity, payload diversity, changing-byte coverage, and DLC consistency. "
            "The score prioritizes research and does not identify signal semantics."
        ),
        "candidates": candidates[:top],
    }


def report_markdown(report: dict) -> str:
    capture = report["capture"]
    lines = [
        "# Voltec Atlas Capture Research Report",
        "",
        f"- Safety scope: `{report['safety_scope']}`",
        f"- Evidence SHA-256: `{report['evidence_sha256']}`",
        f"- Format: `{capture['format']}`",
        f"- Frames: {capture['frames']}",
        f"- Known IDs: {capture['known_ids']}",
        f"- Unknown IDs: {capture['unknown_ids']}",
        "",
        "Scores prioritize follow-up only. They do not establish a CAN ID or signal meaning.",
        "",
        "| Rank | CAN ID | Score | Frames | Unique payloads | Changed bytes | DLC |",
        "| ---: | --- | ---: | ---: | ---: | --- | --- |",
    ]
    for rank, row in enumerate(report["candidates"], 1):
        lines.append(
            f"| {rank} | {row['can_id']} | {row['priority_score']} | "
            f"{row['frames']} | {row['unique_payloads']} | "
            f"{row['changed_byte_mask']} | {','.join(map(str, row['dlc']))} |"
        )
    lines.extend(
        [
            "",
            "## Promotion gate",
            "",
            "A candidate belongs in Atlas only after repeatable controlled captures, "
            "vehicle/model-year applicability, source notes, and an explicit confidence level.",
        ]
    )
    return "\n".join(lines) + "\n"
