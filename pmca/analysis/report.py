"""Deterministic, metadata-only firmware inspection reports."""

import json
import math
import os
import tempfile
from pathlib import Path

from .manifest import sha256_file, verify_manifest_entry
from .static import inspect_artifact


SCHEMA_VERSION = 1
_REPORT_FIELDS = {
    "schema_version",
    "source_key",
    "filename",
    "size",
    "sha256",
    "format",
    "pe",
    "entropy",
    "token_hits",
}
_FORBIDDEN_KEYS = {
    "raw",
    "bytes",
    "payload",
    "base64",
    "hex_dump",
    "strings",
}


class ReportError(ValueError):
    """Raised when report generation violates an offline safety boundary."""


def _validate_json_value(value: object) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ReportError("Report object keys must be text")
            if key.casefold() in _FORBIDDEN_KEYS:
                raise ReportError("Report contains a reconstruction-capable key")
            _validate_json_value(child)
        return
    if isinstance(value, (list, tuple)):
        for child in value:
            _validate_json_value(child)
        return
    if isinstance(value, float) and not math.isfinite(value):
        raise ReportError("Report numbers must be finite")
    if value is None or isinstance(value, (str, int, float, bool)):
        return
    raise ReportError("Report contains a non-JSON value")


def _validate_report(report: object) -> dict:
    if not isinstance(report, dict) or set(report) != _REPORT_FIELDS:
        raise ReportError("Report fields do not match schema version 1")
    if report["schema_version"] != SCHEMA_VERSION:
        raise ReportError("Unsupported report schema version")
    _validate_json_value(report)
    return report


def analyze_verified_artifact(
    entry: dict,
    artifact: Path,
    artifacts_root: Path,
) -> dict:
    """Verify, inspect, and prove one firmware artifact stayed immutable."""
    artifact = Path(artifact)
    before_digest = sha256_file(artifact)
    verify_manifest_entry(entry, artifact, artifacts_root)
    inspection = inspect_artifact(artifact, entry["source_key"])
    after_digest = sha256_file(artifact)
    if before_digest != after_digest:
        raise ReportError("Firmware artifact changed during inspection")
    if before_digest != entry["sha256"]:
        raise ReportError("Firmware digest does not match the manifest")
    if inspection.get("source_key") != entry["source_key"]:
        raise ReportError("Inspection source does not match the manifest")

    report = {
        "schema_version": SCHEMA_VERSION,
        "source_key": entry["source_key"],
        "filename": entry["filename"],
        "size": entry["measured_size"],
        "sha256": before_digest,
        "format": inspection.get("format"),
        "pe": inspection.get("pe"),
        "entropy": inspection.get("entropy"),
        "token_hits": inspection.get("token_hits"),
    }
    return _validate_report(report)


def _resolved_report_path(path: Path, artifacts_root: Path) -> Path:
    path = Path(path)
    artifacts_root = Path(artifacts_root)
    if path.suffix.casefold() != ".json":
        raise ReportError("Report path must use a .json suffix")
    if path.is_symlink() or artifacts_root.is_symlink():
        raise ReportError("Report paths and artifact roots must not be symlinks")
    try:
        resolved_root = artifacts_root.resolve(strict=True)
        resolved_path = path.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise ReportError("Report path validation failed") from error
    if not resolved_root.is_dir():
        raise ReportError("Artifacts root must be a directory")

    try:
        relative = resolved_path.relative_to(resolved_root)
    except ValueError:
        return resolved_path
    if not relative.parts or relative.parts[0].casefold() != "analysis-runs":
        raise ReportError("Reports below .artifacts must be under analysis-runs")
    return resolved_path


def write_report(path: Path, report: dict, artifacts_root: Path) -> None:
    """Atomically write a deterministic safe report to an approved location."""
    _validate_report(report)
    resolved_path = _resolved_report_path(path, artifacts_root)
    try:
        serialized = json.dumps(
            report,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        ) + "\n"
    except (TypeError, ValueError) as error:
        raise ReportError("Report could not be serialized safely") from error

    resolved_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=resolved_path.parent,
        prefix=f".{resolved_path.name}.",
        suffix=".tmp",
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, resolved_path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise
