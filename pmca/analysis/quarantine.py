"""Immutable, digest-pinned firmware mutation inside a non-installable quarantine."""

import hashlib
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .manifest import sha256_file


MAX_PATCHES = 1024
MAX_REPLACEMENT_SIZE = 1_048_576
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_HYPOTHESIS = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")


class QuarantineError(ValueError):
    """Raised when a local mutation cannot satisfy quarantine safety gates."""


@dataclass(frozen=True, slots=True)
class Patch:
    offset: int
    expected_sha256: str
    replacement: bytes


def _validate_root(root: Path) -> Path:
    root = Path(root)
    if root.name.casefold() != ".artifacts" or root.is_symlink():
        raise QuarantineError("Artifacts root must be a real .artifacts directory")
    try:
        resolved = root.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise QuarantineError("Artifacts root could not be resolved") from error
    if not resolved.is_dir() or resolved.name.casefold() != ".artifacts":
        raise QuarantineError("Resolved artifacts root is invalid")
    return resolved


def _reject_symlinks(root: Path, path: Path) -> None:
    current = root
    for part in path.relative_to(root).parts:
        current = current / part
        if current.exists() and current.is_symlink():
            raise QuarantineError("Quarantine paths must not contain symlinks")


def _validate_source(source: Path, root: Path) -> Path:
    source = Path(source)
    if source.is_symlink():
        raise QuarantineError("Mutation source must not be a symlink")
    try:
        resolved = source.resolve(strict=True)
        relative = resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError) as error:
        raise QuarantineError("Mutation source is outside the artifacts root") from error
    _reject_symlinks(root, resolved)
    if not relative.parts or relative.parts[0].casefold() != "analysis-inputs":
        raise QuarantineError("Mutation source must be below analysis-inputs")
    if not resolved.is_file():
        raise QuarantineError("Mutation source must be a regular file")
    return resolved


def _validate_output(output: Path, root: Path) -> Path:
    output = Path(output)
    if "NOT_FOR_INSTALL" not in output.name:
        raise QuarantineError("Candidate filename must contain NOT_FOR_INSTALL")
    try:
        resolved = output.resolve(strict=False)
        relative = resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError) as error:
        raise QuarantineError("Candidate output is outside the artifacts root") from error
    _reject_symlinks(root, resolved)
    if not relative.parts or relative.parts[0].casefold() != "quarantine":
        raise QuarantineError("Candidate output must be below quarantine")
    if resolved.exists() or resolved.with_suffix(resolved.suffix + ".json").exists():
        raise QuarantineError("Candidate output and sidecar must not already exist")
    return resolved


def _validate_patches(
    patches: object,
    file_size: int,
) -> tuple[Patch, ...]:
    if not isinstance(patches, tuple) or not 1 <= len(patches) <= MAX_PATCHES:
        raise QuarantineError("Patches must be a bounded non-empty tuple")
    ordered = []
    for patch in patches:
        if not isinstance(patch, Patch):
            raise QuarantineError("Every patch must be a Patch")
        if type(patch.offset) is not int or patch.offset < 0:
            raise QuarantineError("Patch offset must be a non-negative integer")
        if not isinstance(patch.expected_sha256, str) or not _DIGEST.fullmatch(
            patch.expected_sha256
        ):
            raise QuarantineError("Patch preimage digest is invalid")
        if (
            not isinstance(patch.replacement, bytes)
            or not 1 <= len(patch.replacement) <= MAX_REPLACEMENT_SIZE
        ):
            raise QuarantineError("Patch replacement must be bounded bytes")
        size = len(patch.replacement)
        if size > file_size or patch.offset > file_size - size:
            raise QuarantineError("Patch range exceeds the source")
        ordered.append(patch)
    ordered.sort(key=lambda patch: patch.offset)
    previous_end = 0
    for index, patch in enumerate(ordered):
        if index and patch.offset < previous_end:
            raise QuarantineError("Patch ranges overlap")
        previous_end = patch.offset + len(patch.replacement)
    return tuple(ordered)


def _ensure_unique_hypothesis(root: Path, hypothesis_id: str) -> None:
    quarantine = root / "quarantine"
    if not quarantine.exists():
        return
    for sidecar in quarantine.rglob("*.json"):
        if sidecar.is_symlink() or sidecar.stat().st_size > 64 * 1024:
            raise QuarantineError("Existing quarantine sidecar is unsafe")
        try:
            document = json.loads(sidecar.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise QuarantineError("Existing quarantine sidecar is invalid") from error
        if document.get("hypothesis_id") == hypothesis_id:
            raise QuarantineError("Hypothesis ID already exists in quarantine")


def _write_json_atomic(path: Path, document: dict) -> None:
    serialized = json.dumps(document, sort_keys=True, indent=2) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def apply_quarantined_patches(
    source: Path,
    artifacts_root: Path,
    output: Path,
    patches: tuple[Patch, ...],
    hypothesis_id: str,
) -> dict:
    """Apply verified same-length patches without modifying the source artifact."""
    root = _validate_root(artifacts_root)
    source = _validate_source(source, root)
    output = _validate_output(output, root)
    if not isinstance(hypothesis_id, str) or not _HYPOTHESIS.fullmatch(hypothesis_id):
        raise QuarantineError("Hypothesis ID must be bounded lowercase slug text")
    _ensure_unique_hypothesis(root, hypothesis_id)
    patches = _validate_patches(patches, source.stat().st_size)

    parent_digest = sha256_file(source)
    patch_metadata = []
    with source.open("rb") as stream:
        for patch in patches:
            stream.seek(patch.offset)
            preimage = stream.read(len(patch.replacement))
            preimage_digest = hashlib.sha256(preimage).hexdigest()
            if preimage_digest != patch.expected_sha256:
                raise QuarantineError("Patch preimage digest does not match")
            patch_metadata.append(
                {
                    "offset": patch.offset,
                    "size": len(patch.replacement),
                    "preimage_sha256": preimage_digest,
                    "replacement_sha256": hashlib.sha256(
                        patch.replacement
                    ).hexdigest(),
                }
            )

    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=output.parent,
        prefix=f".{output.name}.",
        suffix=".tmp",
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with source.open("rb") as source_stream, temporary.open("wb") as target:
            shutil.copyfileobj(source_stream, target, length=1_048_576)
            target.flush()
            os.fsync(target.fileno())
        with temporary.open("r+b") as target:
            for patch in patches:
                target.seek(patch.offset)
                target.write(patch.replacement)
            target.flush()
            os.fsync(target.fileno())
        output_digest = sha256_file(temporary)
        if sha256_file(source) != parent_digest:
            raise QuarantineError("Mutation source changed during patching")
        os.replace(temporary, output)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise

    document = {
        "schema_version": 1,
        "hypothesis_id": hypothesis_id,
        "parent_sha256": parent_digest,
        "output_sha256": output_digest,
        "installable": False,
        "patches": patch_metadata,
    }
    sidecar = output.with_suffix(output.suffix + ".json")
    try:
        _write_json_atomic(sidecar, document)
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    return document
