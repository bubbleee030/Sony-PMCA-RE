"""Deterministic, metadata-only firmware inspection reports."""

import json
import math
import os
import tempfile
from pathlib import Path

from .manifest import (
    ManifestError,
    _validated_artifact_path,
    sha256_file,
    verify_manifest_entry,
)
from .static import ALLOWED_TOKENS, inspect_artifact


SCHEMA_VERSION = 1
MAX_SERIALIZED_REPORT_BYTES = 1_048_576
MAX_ARTIFACT_SIZE = 8 * 1024**4
MAX_ENTROPY_WINDOWS = 16_384
MAX_TEXT_LENGTH = 256
MAX_TOKEN_OFFSETS = 8
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
_ENTROPY_FIELDS = {"window_size", "window_count", "windows"}
_WINDOW_FIELDS = {"offset", "size", "entropy"}
_TOKEN_HIT_FIELDS = {"token", "count", "offsets"}
_PE_FIELDS = {
    "machine",
    "section_count",
    "optional_header_kind",
    "certificate_offset",
    "certificate_size",
    "overlay_offset",
}
_ALLOWED_TOKEN_TEXT = {token.decode("ascii") for token in ALLOWED_TOKENS}


class ReportError(ValueError):
    """Raised when report generation violates an offline safety boundary."""


def _require_fields(value: object, fields: set[str], name: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise ReportError(f"{name} fields do not match schema version 1")
    return value


def _bounded_int(value: object, minimum: int, maximum: int, name: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ReportError(f"{name} must be an integer in the supported range")
    return value


def _bounded_text(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= MAX_TEXT_LENGTH
        or "\r" in value
        or "\n" in value
    ):
        raise ReportError(f"{name} must be bounded single-line text")
    return value


def _validate_entropy(value: object, artifact_size: int) -> None:
    entropy = _require_fields(value, _ENTROPY_FIELDS, "Entropy summary")
    window_size = _bounded_int(
        entropy["window_size"], 1, 1_048_576, "Entropy window size"
    )
    window_count = _bounded_int(
        entropy["window_count"], 0, MAX_ENTROPY_WINDOWS, "Entropy window count"
    )
    windows = entropy["windows"]
    if not isinstance(windows, list) or len(windows) != window_count:
        raise ReportError("Entropy windows must match the declared window count")
    expected_count = (
        (artifact_size + window_size - 1) // window_size if artifact_size else 0
    )
    if window_count != expected_count:
        raise ReportError("Entropy window count does not cover the artifact")

    expected_offset = 0
    for value in windows:
        window = _require_fields(value, _WINDOW_FIELDS, "Entropy window")
        offset = _bounded_int(
            window["offset"], 0, artifact_size, "Entropy window offset"
        )
        if offset != expected_offset:
            raise ReportError("Entropy windows must be contiguous and ordered")
        expected_size = min(window_size, artifact_size - expected_offset)
        size = _bounded_int(window["size"], 1, window_size, "Entropy window size")
        if size != expected_size:
            raise ReportError("Entropy window size does not match its position")
        measurement = window["entropy"]
        if (
            type(measurement) not in (int, float)
            or not math.isfinite(measurement)
            or not 0.0 <= measurement <= 8.0
        ):
            raise ReportError("Entropy measurement must be finite bits per byte")
        expected_offset += size


def _validate_pe(value: object, artifact_size: int, artifact_format: str) -> None:
    if artifact_format == "opaque-dat":
        if value is not None:
            raise ReportError("Opaque reports must not contain PE metadata")
        return

    pe = _require_fields(value, _PE_FIELDS, "PE summary")
    _bounded_int(pe["machine"], 0, 65_535, "PE machine")
    _bounded_int(pe["section_count"], 1, 96, "PE section count")
    if (
        type(pe["optional_header_kind"]) is not str
        or pe["optional_header_kind"] not in {"PE32", "PE32+"}
    ):
        raise ReportError("PE optional header kind is unsupported")
    certificate_offset = _bounded_int(
        pe["certificate_offset"], 0, artifact_size, "Certificate offset"
    )
    certificate_size = _bounded_int(
        pe["certificate_size"], 0, artifact_size, "Certificate size"
    )
    if bool(certificate_offset) != bool(certificate_size):
        raise ReportError("Certificate offset and size must both be zero or nonzero")
    if certificate_offset + certificate_size > artifact_size:
        raise ReportError("Certificate range exceeds the artifact")
    overlay_offset = pe["overlay_offset"]
    if overlay_offset is not None:
        _bounded_int(overlay_offset, 0, artifact_size, "PE overlay offset")


def _validate_token_hits(value: object, artifact_size: int) -> None:
    if not isinstance(value, list) or len(value) > len(_ALLOWED_TOKEN_TEXT):
        raise ReportError("Token hits must be a bounded list")
    seen_tokens = set()
    for value in value:
        hit = _require_fields(value, _TOKEN_HIT_FIELDS, "Token hit")
        token = hit["token"]
        if (
            type(token) is not str
            or token not in _ALLOWED_TOKEN_TEXT
            or token in seen_tokens
        ):
            raise ReportError("Token hit is not a unique allowlisted token")
        seen_tokens.add(token)
        count = _bounded_int(hit["count"], 1, artifact_size, "Token hit count")
        offsets = hit["offsets"]
        if (
            not isinstance(offsets, list)
            or len(offsets) > MAX_TOKEN_OFFSETS
            or len(offsets) > count
        ):
            raise ReportError("Token offsets must be a bounded list")
        maximum_offset = artifact_size - len(token.encode("ascii"))
        previous = -1
        for offset in offsets:
            _bounded_int(offset, 0, maximum_offset, "Token offset")
            if offset <= previous:
                raise ReportError("Token offsets must be strictly increasing")
            previous = offset


def _validate_report(report: object) -> dict:
    report = _require_fields(report, _REPORT_FIELDS, "Report")
    if (
        type(report["schema_version"]) is not int
        or report["schema_version"] != SCHEMA_VERSION
    ):
        raise ReportError("Unsupported report schema version")
    _bounded_text(report["source_key"], "Report source key")
    filename = _bounded_text(report["filename"], "Report filename")
    if Path(filename).name != filename or "/" in filename or "\\" in filename:
        raise ReportError("Report filename must be a basename")
    artifact_size = _bounded_int(
        report["size"], 0, MAX_ARTIFACT_SIZE, "Artifact size"
    )
    digest = report["sha256"]
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ReportError("Report SHA-256 must be lowercase hexadecimal")
    artifact_format = report["format"]
    if type(artifact_format) is not str or artifact_format not in {"pe", "opaque-dat"}:
        raise ReportError("Report format is unsupported")
    _validate_pe(report["pe"], artifact_size, artifact_format)
    _validate_entropy(report["entropy"], artifact_size)
    _validate_token_hits(report["token_hits"], artifact_size)

    try:
        serialized_size = len(
            (
                json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n"
            ).encode("utf-8")
        )
    except (TypeError, ValueError, UnicodeError) as error:
        raise ReportError("Report could not be serialized safely") from error
    if serialized_size > MAX_SERIALIZED_REPORT_BYTES:
        raise ReportError("Serialized report exceeds the safety limit")
    return report

def analyze_verified_artifact(
    entry: dict,
    artifact: Path,
    artifacts_root: Path,
) -> dict:
    """Verify, inspect, and prove one firmware artifact stayed immutable."""
    try:
        resolved_artifact = _validated_artifact_path(artifact, artifacts_root)
    except ManifestError as error:
        raise ReportError(
            "Firmware artifact path is outside the approved quarantine"
        ) from error
    before_digest = sha256_file(resolved_artifact)
    verify_manifest_entry(entry, resolved_artifact, artifacts_root)
    inspection = inspect_artifact(resolved_artifact, entry["source_key"])
    after_digest = sha256_file(resolved_artifact)
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
