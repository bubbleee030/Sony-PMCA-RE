"""Fail-closed validation for metadata-only firmware manifests."""

import hashlib
import json
import os
import tempfile
from datetime import date, datetime
from pathlib import Path

from .sources import SourceError, get_source


SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 128 * 1024
_TOP_LEVEL_FIELDS = {"schema_version", "artifacts"}
_ENTRY_FIELDS = {
    "source_key",
    "manufacturer",
    "model",
    "region",
    "version",
    "source_page",
    "filename",
    "advertised_size",
    "release_date",
    "measured_size",
    "sha256",
    "acquired_at",
}
_TEXT_FIELDS = {
    "source_key",
    "manufacturer",
    "model",
    "region",
    "version",
    "source_page",
    "filename",
    "release_date",
    "acquired_at",
}


class ManifestError(ValueError):
    """Raised when an artifact or manifest fails a validation gate."""

def _validate_release_date(value: object) -> str:
    if not isinstance(value, str) or len(value) != 10:
        raise ManifestError("Release date must use YYYY-MM-DD")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as error:
        raise ManifestError("Release date must use YYYY-MM-DD") from error
    if parsed.isoformat() != value:
        raise ManifestError("Release date must use YYYY-MM-DD")
    return value

def _validate_acquired_at(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 64
        or "\r" in value
        or "\n" in value
        or "T" not in value
    ):
        raise ManifestError("Acquisition timestamp must be bounded ISO-8601 text")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
        offset = parsed.utcoffset()
    except (TypeError, ValueError, OverflowError) as error:
        raise ManifestError("Acquisition timestamp must be valid ISO-8601") from error
    if offset is None:
        raise ManifestError("Acquisition timestamp must include a timezone")
    return value


def _reject_duplicate_members(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError("Manifest JSON contains duplicate object members")
        result[key] = value
    return result


def _is_artifacts_root_name(path: Path) -> bool:
    if os.name == "nt":
        return path.name.casefold() == ".artifacts"
    return path.name == ".artifacts"


def sha256_file(path: Path, chunk_size: int = 1_048_576) -> str:
    """Return the SHA-256 digest of *path* using bounded reads."""
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int):
        raise ManifestError("Hash chunk size must be a positive integer")
    if chunk_size <= 0:
        raise ManifestError("Hash chunk size must be a positive integer")

    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _validated_artifact_path(artifact: Path, artifacts_root: Path) -> Path:
    artifact = Path(artifact)
    artifacts_root = Path(artifacts_root)
    if not _is_artifacts_root_name(artifacts_root):
        raise ManifestError("Artifacts root must be named .artifacts")
    try:
        if artifact.is_symlink() or artifacts_root.is_symlink():
            raise ManifestError("Artifact paths and roots must not be symlinks")
        resolved_artifact = artifact.resolve(strict=True)
        resolved_root = artifacts_root.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ManifestError("Artifact path validation failed") from error

    if not _is_artifacts_root_name(resolved_root):
        raise ManifestError("Resolved artifacts root must be named .artifacts")
    if not resolved_root.is_dir():
        raise ManifestError("Artifacts root must be a directory")
    if not resolved_artifact.is_file():
        raise ManifestError("Artifact must be a regular file")
    try:
        resolved_artifact.relative_to(resolved_root)
    except ValueError as error:
        raise ManifestError("Artifact must be below the artifacts root") from error
    return resolved_artifact


def _validate_entry_schema(entry: object) -> dict:
    if not isinstance(entry, dict) or set(entry) != _ENTRY_FIELDS:
        raise ManifestError("Manifest entry fields do not match schema version 1")
    for field in _TEXT_FIELDS:
        if not isinstance(entry[field], str) or not entry[field]:
            raise ManifestError(f"Manifest entry field {field!r} must be text")
    for field in ("advertised_size", "measured_size"):
        value = entry[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ManifestError(f"Manifest entry field {field!r} must be a size")
    digest = entry["sha256"]
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ManifestError("Manifest SHA-256 must be lowercase hexadecimal")
    _validate_release_date(entry["release_date"])
    _validate_acquired_at(entry["acquired_at"])
    return entry


def _validate_entry_source(entry: dict):
    try:
        source = get_source(entry["source_key"])
    except SourceError as error:
        raise ManifestError("Manifest source is not allowlisted") from error
    expected_metadata = {
        "manufacturer": "Sony",
        "model": source.model,
        "region": source.region,
        "version": source.version,
        "source_page": source.page_url,
        "filename": source.filename,
        "advertised_size": source.advertised_size,
        "release_date": source.release_date,
    }
    if any(entry[field] != value for field, value in expected_metadata.items()):
        raise ManifestError("Manifest metadata does not match the allowlisted source")
    return source


def _validate_manifest(data: object) -> dict:
    if not isinstance(data, dict) or set(data) != _TOP_LEVEL_FIELDS:
        raise ManifestError("Manifest top-level fields do not match schema version 1")
    version = data["schema_version"]
    if isinstance(version, bool) or not isinstance(version, int) or version != SCHEMA_VERSION:
        raise ManifestError("Unsupported manifest schema version")
    artifacts = data["artifacts"]
    if not isinstance(artifacts, list):
        raise ManifestError("Manifest artifacts must be a list")

    source_keys = set()
    for entry in artifacts:
        validated_entry = _validate_entry_schema(entry)
        _validate_entry_source(validated_entry)
        source_key = validated_entry["source_key"]
        if source_key in source_keys:
            raise ManifestError("Manifest contains duplicate source keys")
        source_keys.add(source_key)
    return data


def record_artifact(
    source_key: str,
    artifact: Path,
    artifacts_root: Path,
    acquired_at: str,
) -> dict:
    """Validate and describe one allowlisted firmware artifact."""
    source = get_source(source_key)
    resolved_artifact = _validated_artifact_path(artifact, artifacts_root)
    measured_size = resolved_artifact.stat().st_size
    if resolved_artifact.name != source.filename:
        raise ManifestError("Artifact filename does not match the allowlisted source")
    if measured_size != source.advertised_size:
        raise ManifestError("Artifact size does not match the allowlisted source")
    _validate_acquired_at(acquired_at)

    return {
        "source_key": source_key,
        "manufacturer": "Sony",
        "model": source.model,
        "region": source.region,
        "version": source.version,
        "source_page": source.page_url,
        "filename": source.filename,
        "advertised_size": source.advertised_size,
        "release_date": source.release_date,
        "measured_size": measured_size,
        "sha256": sha256_file(resolved_artifact),
        "acquired_at": acquired_at,
    }


def load_manifest(path: Path) -> dict:
    """Load and strictly validate a bounded version 1 firmware manifest."""
    path = Path(path)
    if path.is_symlink():
        raise ManifestError("Manifest path must not be a symlink")
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            raise ManifestError("Manifest exceeds the metadata size limit")
        with path.open("rb") as stream:
            payload = stream.read(MAX_MANIFEST_BYTES + 1)
        if len(payload) > MAX_MANIFEST_BYTES:
            raise ManifestError("Manifest exceeds the metadata size limit")
        data = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_members,
        )
    except ManifestError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ManifestError("Manifest could not be loaded") from error
    return _validate_manifest(data)


def _is_below_artifacts(path: Path) -> bool:
    unresolved_parts = {part.casefold() for part in path.parts}
    resolved_parts = {part.casefold() for part in path.resolve(strict=False).parts}
    return ".artifacts" in unresolved_parts or ".artifacts" in resolved_parts


def write_manifest(path: Path, data: dict) -> None:
    """Atomically write a deterministic metadata-only manifest."""
    path = Path(path)
    _validate_manifest(data)
    if _is_below_artifacts(path):
        raise ManifestError("The committed manifest must not be below .artifacts")
    if path.is_symlink():
        raise ManifestError("Manifest path must not be a symlink")

    serialized = json.dumps(data, sort_keys=True, indent=2) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def verify_manifest_entry(
    entry: dict,
    artifact: Path,
    artifacts_root: Path,
) -> None:
    """Verify one artifact against its allowlisted manifest entry."""
    _validate_entry_schema(entry)
    source = _validate_entry_source(entry)

    resolved_artifact = _validated_artifact_path(artifact, artifacts_root)
    measured_size = resolved_artifact.stat().st_size
    if resolved_artifact.name != entry["filename"]:
        raise ManifestError("Artifact filename does not match the manifest")
    if measured_size != entry["measured_size"]:
        raise ManifestError("Artifact size does not match the manifest")
    if measured_size != source.advertised_size:
        raise ManifestError("Artifact size does not match the allowlisted source")
    if sha256_file(resolved_artifact) != entry["sha256"]:
        raise ManifestError("Artifact SHA-256 does not match the manifest")
