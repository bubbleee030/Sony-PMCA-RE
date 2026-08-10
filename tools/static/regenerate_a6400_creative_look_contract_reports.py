#!/usr/bin/env python3
"""Atomically regenerate the five Creative Look contract outputs.

This script consumes checked-in metadata only. It neither opens nor executes
camera binaries and never communicates with a camera or storage device.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from pmca.analysis.creative_look_stack import validate_creative_look_stack
from pmca.analysis.creative_looks import render_recipe_guide, validate_recipe_document
from pmca.analysis.decisions import (
    derive_creative_look_capabilities,
    derive_recovery_capability,
    render_markdown,
    validate_evidence,
)
from pmca.analysis.recovery_path import validate_recovery_report
from pmca.analysis.target_features import (
    build_target_feature_report,
    validate_target_feature_report,
)


ANALYSIS_ROOT = REPOSITORY_ROOT / "analysis"
STACK_PATH = ANALYSIS_ROOT / "a6400-creative-look-stack.json"
RECIPES_PATH = ANALYSIS_ROOT / "creative-look-recipes.json"
GUIDE_PATH = ANALYSIS_ROOT / "a6400-creative-look-guide.md"
EVIDENCE_PATH = ANALYSIS_ROOT / "feature-evidence.json"
TARGET_PATH = ANALYSIS_ROOT / "a6400-target-features.json"
FEASIBILITY_PATH = ANALYSIS_ROOT / "a6400-feasibility-report.md"
RECOVERY_PATH = ANALYSIS_ROOT / "a6400-stock-200-recovery.json"
SOURCES_PATH = ANALYSIS_ROOT / "a6400-creative-look-sources.json"
BOUNDARY_PATH = ANALYSIS_ROOT / "a6400-creative-look-boundary.json"
OUTPUT_PATHS = (
    STACK_PATH,
    GUIDE_PATH,
    EVIDENCE_PATH,
    TARGET_PATH,
    FEASIBILITY_PATH,
)
_INTEGRATED_MARKER = "# Integrated Offline Research Result"


def _load(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as stream:
        document = json.load(stream)
    if not isinstance(document, dict):
        raise RuntimeError(f"report is not an object: {path.name}")
    return document


def _canonical_digest(document: dict) -> str:
    encoded = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validated_safety(stack: dict) -> None:
    recovery = validate_recovery_report(_load(RECOVERY_PATH))
    safety = stack["safety"]
    expected = {
        "reference": "analysis/a6400-stock-200-recovery.json",
        "canonical_report_sha256": _canonical_digest(recovery),
        "readiness": recovery["readiness"],
        "recovery_validated": recovery["recovery_validated"],
        "camera_test_eligible": recovery["camera_test_eligible"],
        "installable": recovery["installable"],
    }
    if safety != expected:
        raise RuntimeError("Creative Look safety snapshot is stale or inconsistent")


def _build_evidence(stack: dict, recipes: dict) -> dict:
    document = _load(EVIDENCE_PATH)
    replacements = {
        item["id"]: item
        for item in derive_creative_look_capabilities(stack, recipes)
    }
    replacements["recovery"] = derive_recovery_capability()
    document["capabilities"] = [
        replacements.get(item["id"], item) for item in document["capabilities"]
    ]
    return validate_evidence(document)


def _build_feasibility(evidence: dict) -> str:
    current = FEASIBILITY_PATH.read_text(encoding="utf-8")
    marker_offset = current.find(_INTEGRATED_MARKER)
    if marker_offset < 0:
        raise RuntimeError("Integrated feasibility suffix marker is unavailable")
    suffix = current[marker_offset:]
    return render_markdown(evidence) + "\n" + suffix


def build_reports() -> dict[Path, str | dict]:
    """Build and validate all outputs in memory before any file is replaced."""

    stack_text = STACK_PATH.read_text(encoding="utf-8")
    try:
        stack_source = json.loads(stack_text)
    except json.JSONDecodeError as error:
        raise RuntimeError("Creative Look stack is not valid JSON") from error
    stack = validate_creative_look_stack(stack_source)
    recipes = validate_recipe_document(_load(RECIPES_PATH))
    _validated_safety(stack)
    guide = render_recipe_guide(recipes)
    evidence = _build_evidence(stack, recipes)
    creative_reports = {
        "creative_look_stack": stack,
        "creative_look_sources": _load(SOURCES_PATH),
        "creative_look_boundary": _load(BOUNDARY_PATH),
    }
    target = validate_target_feature_report(
        build_target_feature_report(
            _load(TARGET_PATH), creative_reports=creative_reports
        ),
        creative_reports=creative_reports,
    )
    feasibility = _build_feasibility(evidence)
    prefix_marker = "\n\n" + _INTEGRATED_MARKER
    if feasibility.split(prefix_marker, 1)[0] + "\n" != render_markdown(evidence):
        raise RuntimeError("Generated feasibility decision prefix is inconsistent")
    return {
        STACK_PATH: stack_text,
        GUIDE_PATH: guide,
        EVIDENCE_PATH: evidence,
        TARGET_PATH: target,
        FEASIBILITY_PATH: feasibility,
    }


def _stage(path: Path, value: str | dict) -> Path:
    descriptor, temporary_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            if isinstance(value, dict):
                json.dump(value, stream, indent=2)
                stream.write("\n")
            else:
                stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return temporary


def main() -> None:
    reports = build_reports()
    staged: dict[Path, Path] = {}
    try:
        for path, value in reports.items():
            staged[path] = _stage(path, value)
        for path, temporary in staged.items():
            os.replace(temporary, path)
    finally:
        for temporary in staged.values():
            temporary.unlink(missing_ok=True)
    print(
        "A6400_CREATIVE_LOOK_CONTRACT_REPORTS|reports=5|"
        "camera_access=0|binary_execution=0"
    )


if __name__ == "__main__":
    main()
