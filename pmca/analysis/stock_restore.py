"""Authenticate the exact stock ILCE-6400 Taiwan 2.00 restore source.

This module is deliberately read-only.  It validates bounded metadata and can
hash a caller-selected copy of the official updater plus its embedded firmware
container.  It has no updater, device, transport, extraction, or write backend.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath

from .manifest import ManifestError, load_manifest
from .target_features import TargetFeatureError, validate_target_feature_report


_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}\Z")
_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")

_TOP_FIELDS = {
    "schema_version",
    "subject",
    "source_key",
    "model",
    "model_id",
    "region",
    "region_code",
    "version",
    "source_kind",
    "camera_policy",
    "camera_executed",
    "installable",
    "acquisition_provenance",
    "components",
    "references",
}
_PROVENANCE_FIELDS = {
    "manufacturer",
    "official_url",
    "release_date",
    "acquired_at",
    "advertised_size",
    "measured_size",
}
_OUTER_FIELDS = {
    "id",
    "role",
    "filename",
    "relative_path",
    "size",
    "sha256",
}
_EMBEDDED_FIELDS = {
    "id",
    "role",
    "filename",
    "container_id",
    "outer_offset",
    "container_prefix_size",
    "container_size",
    "fdat_size",
    "sha256",
}
_REFERENCE_PATHS = {
    "acquisition_manifest": "analysis/firmware-manifest.json",
    "outer_static_report": "analysis/reports/a6400-tw-v2.00.json",
    "target_component_manifest": "analysis/a6400-target-features.json",
}
_COMPONENT_IDS = ("outer-updater", "embedded-firmware-container")
_FORBIDDEN_KEYS = {
    "raw",
    "bytes",
    "payload",
    "private_key",
    "key_material",
    "hex_dump",
}
_MAX_HASHED_SIZE = 4 * 1024**3


class StockRestoreError(ValueError):
    """Raised when stock restore metadata or local source files are unsafe."""


def _forbidden_key(value: str) -> bool:
    normalized = value.strip().lower().replace("-", "_")
    return (
        normalized in _FORBIDDEN_KEYS
        or normalized.startswith("raw_")
        or normalized.endswith("_raw")
        or normalized.startswith("payload_")
        or normalized.endswith("_payload")
        or normalized.startswith("bytes_")
        or normalized.endswith("_bytes")
        or "private_key" in normalized
        or "key_material" in normalized
        or "hex_dump" in normalized
    )


def _reject_firmware_material(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise StockRestoreError("stock bundle keys must be text")
            if _forbidden_key(key):
                raise StockRestoreError("stock bundle contains forbidden firmware material")
            _reject_firmware_material(item)
        return
    if isinstance(value, list):
        for item in value:
            _reject_firmware_material(item)
        return
    if isinstance(value, (bytes, bytearray, memoryview)):
        raise StockRestoreError("stock bundle must not contain firmware bytes")
    if value is not None and not isinstance(value, (str, int, float, bool)):
        raise StockRestoreError("stock bundle contains a non-JSON value")


def _require_fields(value: object, fields: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise StockRestoreError(f"{label} fields are not exact")
    return value


def _require_positive_int(value: object, label: str) -> int:
    if type(value) is not int or not 0 < value <= _MAX_HASHED_SIZE:
        raise StockRestoreError(f"{label} is invalid")
    return value


def _require_nonnegative_int(value: object, label: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_HASHED_SIZE:
        raise StockRestoreError(f"{label} is invalid")
    return value


def _require_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise StockRestoreError(f"{label} is invalid")
    return value


def _require_relative_artifact_path(value: object) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise StockRestoreError("stock artifact path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise StockRestoreError("stock artifact path must be relative and bounded")
    if path.parts[0] == ".artifacts":
        raise StockRestoreError("stock artifact path must be relative to artifact root")
    return path


def _load_json(relative_path: str, label: str) -> dict:
    path = _REPOSITORY_ROOT / PurePosixPath(relative_path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise StockRestoreError(f"{label} is unavailable") from error
    if not isinstance(value, dict):
        raise StockRestoreError(f"{label} is invalid")
    return value


def _validated_sources() -> tuple[dict, dict, dict]:
    try:
        manifest = load_manifest(
            _REPOSITORY_ROOT
            / PurePosixPath(_REFERENCE_PATHS["acquisition_manifest"])
        )
    except ManifestError as error:
        raise StockRestoreError("stock manifest is invalid") from error
    matches = [
        item
        for item in manifest["artifacts"]
        if isinstance(item, dict) and item.get("source_key") == "a6400-tw-v2.00"
    ]
    if len(matches) != 1:
        raise StockRestoreError("stock manifest source is missing or duplicated")

    outer_report = _load_json(
        _REFERENCE_PATHS["outer_static_report"], "stock updater static report"
    )
    if outer_report.get("schema_version") != 1:
        raise StockRestoreError("stock updater static report is invalid")

    target_document = _load_json(
        _REFERENCE_PATHS["target_component_manifest"], "target component manifest"
    )
    try:
        target_report = validate_target_feature_report(target_document)
    except TargetFeatureError as error:
        raise StockRestoreError("target component manifest is invalid") from error
    return matches[0], outer_report, target_report


def validate_stock_restore_bundle(document: dict) -> dict:
    """Return an isolated validated copy of the exact stock source metadata."""

    _reject_firmware_material(document)
    bundle = _require_fields(document, _TOP_FIELDS, "Stock restore bundle")
    if type(bundle["schema_version"]) is not int or bundle["schema_version"] != 1:
        raise StockRestoreError("stock restore schema version is invalid")
    if bundle["references"] != _REFERENCE_PATHS:
        raise StockRestoreError("stock restore references are invalid")

    manifest_entry, outer_report, target_report = _validated_sources()
    target = target_report["target"]
    if type(bundle["region_code"]) is not int or type(target["region"]) is not int:
        raise StockRestoreError("stock restore region code is invalid")
    if (
        manifest_entry.get("sha256") != target["outer_updater_sha256"]
        or manifest_entry.get("version") != target["version"]
    ):
        raise StockRestoreError("stock manifest contradicts the target identity")

    expected_identity = {
        "subject": "ILCE-6400 exact Taiwan stock 2.00 restore source",
        "source_key": manifest_entry.get("source_key"),
        "model": manifest_entry.get("model"),
        "model_id": target["model_id"],
        "region": manifest_entry.get("region"),
        "region_code": target["region"],
        "version": target["version"],
        "source_kind": "official-sony-updater",
        "camera_policy": "physically-disconnected",
    }
    for field, expected in expected_identity.items():
        if bundle[field] != expected:
            raise StockRestoreError(f"stock restore {field} is invalid")
    if bundle["camera_executed"] is not False or bundle["installable"] is not False:
        raise StockRestoreError("static stock source cannot claim camera or installability")

    provenance = _require_fields(
        bundle["acquisition_provenance"],
        _PROVENANCE_FIELDS,
        "Stock acquisition provenance",
    )
    expected_provenance = {
        "manufacturer": manifest_entry.get("manufacturer"),
        "official_url": manifest_entry.get("source_page"),
        "release_date": manifest_entry.get("release_date"),
        "acquired_at": manifest_entry.get("acquired_at"),
        "advertised_size": manifest_entry.get("advertised_size"),
        "measured_size": manifest_entry.get("measured_size"),
    }
    if provenance != expected_provenance:
        raise StockRestoreError("stock acquisition provenance is invalid")
    if (
        provenance["manufacturer"] != "Sony"
        or not isinstance(provenance["official_url"], str)
        or not provenance["official_url"].startswith("https://www.sony.com.tw/")
        or not isinstance(provenance["release_date"], str)
        or not _DATE_RE.fullmatch(provenance["release_date"])
        or not isinstance(provenance["acquired_at"], str)
        or not _TIMESTAMP_RE.fullmatch(provenance["acquired_at"])
    ):
        raise StockRestoreError("stock acquisition provenance format is invalid")
    for field in ("advertised_size", "measured_size"):
        _require_positive_int(provenance[field], f"Stock provenance {field}")
    if provenance["advertised_size"] != provenance["measured_size"]:
        raise StockRestoreError("stock source advertised and measured sizes differ")

    components = bundle["components"]
    if not isinstance(components, list) or [
        item.get("id") if isinstance(item, dict) else None for item in components
    ] != list(_COMPONENT_IDS):
        raise StockRestoreError("stock component membership or order is invalid")

    outer = _require_fields(components[0], _OUTER_FIELDS, "Outer updater component")
    _require_relative_artifact_path(outer["relative_path"])
    _require_positive_int(outer["size"], "Outer updater size")
    _require_digest(outer["sha256"], "Outer updater digest")
    expected_outer = {
        "id": "outer-updater",
        "role": "official-host-updater",
        "filename": manifest_entry.get("filename"),
        "relative_path": "a6400-tw-v2.00/Update_ILCE6400V200.exe",
        "size": manifest_entry.get("measured_size"),
        "sha256": target["outer_updater_sha256"],
    }
    if outer != expected_outer:
        raise StockRestoreError("outer updater identity is invalid")
    if (
        outer_report.get("source_key") != bundle["source_key"]
        or outer_report.get("filename") != outer["filename"]
        or outer_report.get("size") != outer["size"]
        or outer_report.get("sha256") != outer["sha256"]
    ):
        raise StockRestoreError("outer updater static report contradicts the bundle")

    embedded = _require_fields(
        components[1], _EMBEDDED_FIELDS, "Embedded firmware component"
    )
    _require_nonnegative_int(embedded["outer_offset"], "Embedded outer offset")
    _require_positive_int(
        embedded["container_prefix_size"], "Embedded container prefix size"
    )
    _require_positive_int(embedded["container_size"], "Embedded container size")
    _require_positive_int(embedded["fdat_size"], "Embedded FDAT size")
    _require_digest(embedded["sha256"], "Embedded firmware digest")
    expected_embedded = {
        "id": "embedded-firmware-container",
        "role": "stock-camera-firmware-container",
        "filename": "FirmwareData.dat",
        "container_id": "outer-updater",
        "outer_offset": target["firmware_dat_offset"],
        "container_prefix_size": 120,
        "container_size": target["fdat_size"] + 120,
        "fdat_size": target["fdat_size"],
        "sha256": target["firmware_dat_sha256"],
    }
    if embedded != expected_embedded:
        raise StockRestoreError("embedded firmware identity or geometry is invalid")
    if embedded["container_size"] != (
        embedded["container_prefix_size"] + embedded["fdat_size"]
    ):
        raise StockRestoreError("embedded firmware container geometry is inconsistent")
    if embedded["outer_offset"] + embedded["container_size"] > outer["size"]:
        raise StockRestoreError("embedded firmware range exceeds the official updater")

    return copy.deepcopy(bundle)


def _is_reparse_point(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        attributes = path.stat(follow_symlinks=False).st_file_attributes
    except (AttributeError, OSError):
        return False
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_range(path: Path, offset: int, size: int) -> str:
    digest = hashlib.sha256()
    remaining = size
    with path.open("rb") as handle:
        handle.seek(offset, os.SEEK_SET)
        while remaining:
            chunk = handle.read(min(1024 * 1024, remaining))
            if not chunk:
                raise StockRestoreError("embedded stock source range is truncated")
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def verify_file(path: Path, expected_size: int, expected_sha256: str) -> None:
    """Verify one regular file without returning or retaining its bytes."""

    path = Path(path)
    _require_positive_int(expected_size, "Expected stock source size")
    _require_digest(expected_sha256, "Expected stock source digest")
    if _is_reparse_point(path):
        raise StockRestoreError("stock source must not be a link or reparse point")
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as error:
        raise StockRestoreError("stock source is unavailable") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != expected_size:
        raise StockRestoreError("stock source size mismatch")
    try:
        digest = _sha256_file(path)
    except OSError as error:
        raise StockRestoreError("stock source could not be read") from error
    if digest != expected_sha256:
        raise StockRestoreError("stock source digest mismatch")


def _bounded_stock_file(artifact_root: Path, relative_path: str) -> Path:
    pure_path = _require_relative_artifact_path(relative_path)
    candidate = artifact_root.joinpath(*pure_path.parts)
    current = artifact_root
    for part in pure_path.parts:
        current = current / part
        if _is_reparse_point(current):
            raise StockRestoreError("stock source path traverses a link or reparse point")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise StockRestoreError("stock source is unavailable") from error
    if artifact_root not in resolved.parents:
        raise StockRestoreError("stock source escapes the ignored artifact root")
    return resolved


def _absolute_lexical_path(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _same_lexical_path(left: Path, right: Path) -> bool:
    return os.path.normcase(os.fspath(_absolute_lexical_path(left))) == os.path.normcase(
        os.fspath(_absolute_lexical_path(right))
    )


def _reject_reparse_chain(path: Path) -> None:
    absolute = _absolute_lexical_path(path)
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if _is_reparse_point(current):
            raise StockRestoreError("stock artifact root traverses a reparse point")


def verify_stock_restore_files(document: dict, artifact_root: Path) -> dict:
    """Hash the ignored official updater and its embedded stock DAT range.

    ``artifact_root`` must be this checkout's ignored ``.artifacts/sony-firmware``
    directory.  The result contains metadata only and cannot be used to write,
    extract, launch, transfer, or install firmware.
    """

    bundle = validate_stock_restore_bundle(document)
    expected_root = _REPOSITORY_ROOT / ".artifacts" / "sony-firmware"
    supplied_root = Path(artifact_root)
    if ".." in supplied_root.parts or not _same_lexical_path(
        supplied_root, expected_root
    ):
        raise StockRestoreError("stock files must use the canonical ignored root")
    _reject_reparse_chain(expected_root)
    try:
        resolved_root = supplied_root.resolve(strict=True)
        resolved_expected = expected_root.resolve(strict=True)
    except OSError as error:
        raise StockRestoreError("ignored stock artifact root is unavailable") from error
    if resolved_root != resolved_expected or not resolved_root.is_dir():
        raise StockRestoreError("stock files must remain below .artifacts/sony-firmware")
    outer, embedded = bundle["components"]
    outer_path = _bounded_stock_file(resolved_root, outer["relative_path"])
    verify_file(outer_path, outer["size"], outer["sha256"])
    try:
        embedded_digest = _sha256_range(
            outer_path, embedded["outer_offset"], embedded["container_size"]
        )
    except OSError as error:
        raise StockRestoreError("embedded stock source could not be read") from error
    if embedded_digest != embedded["sha256"]:
        raise StockRestoreError("embedded stock source digest mismatch")

    return {
        "outer-updater": {
            "size": outer["size"],
            "sha256": outer["sha256"],
        },
        "embedded-firmware-container": {
            "offset": embedded["outer_offset"],
            "size": embedded["container_size"],
            "sha256": embedded["sha256"],
        },
    }
