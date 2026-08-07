"""Atomically regenerate the three static interaction/recovery reports.

This script reads bounded JSON metadata and Python evidence contracts only.  It
does not load or execute any Sony program, communicate with a camera, or write
to a device.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from pmca.analysis import creative_style_interaction_surface as interaction
from pmca.analysis.cxd90045_transition_report import (
    build_cxd90045_transition_report,
    validate_cxd90045_transition_report,
)
from pmca.analysis.recovery_path import build_recovery_report, validate_recovery_report
from tools.static.export_a6400_packaged_selector_scan import (
    build_raw_export as build_packaged_selector_export,
)


INTERACTION_PATH = REPOSITORY_ROOT / "analysis" / "a6400-creative-style-interaction-surface.json"
TRANSITION_PATH = REPOSITORY_ROOT / "analysis" / "a6400-cxd90045-transition-boundary.json"
RECOVERY_PATH = REPOSITORY_ROOT / "analysis" / "a6400-stock-200-recovery.json"


def _load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"{path.name} is not an object")
    return value


def _write_atomic(path: Path, document: dict) -> None:
    serialized = document
    marker = '"__STATIC_GATE_EXPORT__"'
    if path == RECOVERY_PATH:
        serialized = dict(document)
        gate_export = serialized["static_gate_export"]
        serialized["static_gate_export"] = "__STATIC_GATE_EXPORT__"
    encoded = json.dumps(serialized, indent=2, ensure_ascii=True)
    if path == RECOVERY_PATH:
        encoded = encoded.replace(
            marker,
            json.dumps(gate_export, separators=(",", ":"), ensure_ascii=True),
            1,
        )
    encoded += "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", text=True
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
        os.replace(temporary_name, path)
    except BaseException:
        try:
            Path(temporary_name).unlink(missing_ok=True)
        finally:
            raise


def _build_interaction_report() -> dict:
    builder = getattr(interaction, "build_creative_style_interaction_surface_report", None)
    if callable(builder):
        report = builder(interaction.EXPECTED_EXPORT)
    else:
        # Compatibility while the independently-owned interaction track lands.
        # Its current report is still validated before it can be retained.
        report = _load(INTERACTION_PATH)
    return interaction.validate_creative_style_interaction_surface_report(report)


def build_reports() -> tuple[dict, dict, dict]:
    """Build and validate the exact three offline reports in dependency order."""
    interaction_report = _build_interaction_report()
    transition_report = build_cxd90045_transition_report(
        _load(TRANSITION_PATH),
        packaged_selector_evidence=build_packaged_selector_export(),
    )
    validate_cxd90045_transition_report(transition_report)
    recovery_report = build_recovery_report(
        _load(RECOVERY_PATH), transition_document=transition_report
    )
    validate_recovery_report(
        recovery_report, transition_document=transition_report
    )
    return interaction_report, transition_report, recovery_report


def main() -> None:
    # Build and validate every dependent result before replacing any report.
    interaction_report, transition_report, recovery_report = build_reports()
    _write_atomic(INTERACTION_PATH, interaction_report)
    _write_atomic(TRANSITION_PATH, transition_report)
    _write_atomic(RECOVERY_PATH, recovery_report)


if __name__ == "__main__":
    main()
