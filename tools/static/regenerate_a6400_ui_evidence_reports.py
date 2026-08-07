#!/usr/bin/env python3
"""Regenerate the four corrected static UI evidence reports.

This script consumes only checked-in JSON metadata.  It neither opens nor
executes target camera binaries and it never communicates with a camera.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from pmca.analysis.target_features import build_target_feature_report
from pmca.analysis.ui_dispatch import build_ui_dispatch_report
from pmca.analysis.ui_factory_owner_registration import (
    build_ui_factory_owner_registration_report,
    validate_ui_factory_owner_registration_report,
)
from pmca.analysis.vertical_layout_factory_trace import (
    build_vertical_layout_factory_report,
    validate_vertical_layout_factory_report,
)


ANALYSIS_ROOT = REPOSITORY_ROOT / "analysis"
ARTIFACT_ROOT = REPOSITORY_ROOT / ".artifacts"
VERTICAL_EXPORT_PATH = (
    ARTIFACT_ROOT / "ui-trace" / "a6400-v2.00" / "raw-vertical-layout-factory.json"
)
REGISTRATION_EXPORT_PATH = (
    ARTIFACT_ROOT
    / "ui-factory-owner-registration-trace"
    / "a6400-v2.00"
    / "raw-ui-factory-owner-registration.json"
)
VERTICAL_PATH = ANALYSIS_ROOT / "a6400-vertical-layout-factory.json"
REGISTRATION_PATH = ANALYSIS_ROOT / "a6400-ui-factory-owner-registration.json"
DISPATCH_PATH = ANALYSIS_ROOT / "a6400-ui-dispatch-boundary.json"
TARGET_PATH = ANALYSIS_ROOT / "a6400-target-features.json"


def _load(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as stream:
        document = json.load(stream)
    if not isinstance(document, dict):
        raise RuntimeError(f"evidence report is not an object: {path.name}")
    return document


def _stage(path: Path, document: dict) -> Path:
    handle, temporary_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.stem}-", suffix=".tmp"
    )
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(document, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
    return Path(temporary_name)


def build_reports() -> dict[Path, dict]:
    """Build every output before any checked-in report is replaced."""

    vertical = validate_vertical_layout_factory_report(
        build_vertical_layout_factory_report(_load(VERTICAL_EXPORT_PATH))
    )
    registration = validate_ui_factory_owner_registration_report(
        build_ui_factory_owner_registration_report(_load(REGISTRATION_EXPORT_PATH))
    )
    dispatch = build_ui_dispatch_report(_load(DISPATCH_PATH))
    target = build_target_feature_report(_load(TARGET_PATH), dispatch)
    return {
        VERTICAL_PATH: vertical,
        REGISTRATION_PATH: registration,
        DISPATCH_PATH: dispatch,
        TARGET_PATH: target,
    }


def main() -> None:
    reports = build_reports()
    staged: dict[Path, Path] = {}
    try:
        for path, document in reports.items():
            staged[path] = _stage(path, document)
        for path, temporary in staged.items():
            os.replace(temporary, path)
    finally:
        for temporary in staged.values():
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    print("A6400_UI_EVIDENCE_REPORTS|reports=4|camera_access=0|binary_execution=0")


if __name__ == "__main__":
    main()
