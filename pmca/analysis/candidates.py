"""Evidence-gated construction of explicitly non-installable firmware candidates."""

import re
from dataclasses import dataclass
from pathlib import Path

from .manifest import sha256_file
from .quarantine import Patch, QuarantineError, apply_quarantined_patches


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_SOURCE_KEY = re.compile(r"[a-z0-9][a-z0-9-]{0,47}\Z")


@dataclass(frozen=True, slots=True)
class CandidateSpec:
    source_key: str
    parent_sha256: str
    patches: tuple[Patch, ...]
    unresolved_dependencies: tuple[str, ...]


def _rejection(spec: object, code: str, unresolved=()) -> dict:
    source_key = getattr(spec, "source_key", None)
    return {
        "schema_version": 1,
        "source_key": source_key if isinstance(source_key, str) else None,
        "status": "rejected",
        "installable": False,
        "reason_codes": [code],
        "unresolved_dependencies": list(unresolved),
    }


def _valid_spec(spec: object) -> bool:
    if not isinstance(spec, CandidateSpec):
        return False
    if not isinstance(spec.source_key, str) or not _SOURCE_KEY.fullmatch(
        spec.source_key
    ):
        return False
    if not isinstance(spec.parent_sha256, str) or not _DIGEST.fullmatch(
        spec.parent_sha256
    ):
        return False
    if not isinstance(spec.patches, tuple) or not spec.patches:
        return False
    for patch in spec.patches:
        if not isinstance(patch, Patch):
            return False
        if not isinstance(patch.expected_sha256, str) or not _DIGEST.fullmatch(
            patch.expected_sha256
        ):
            return False
    dependencies = spec.unresolved_dependencies
    if not isinstance(dependencies, tuple) or len(dependencies) > 1024:
        return False
    if any(
        not isinstance(value, str) or not value or len(value) > 128
        for value in dependencies
    ):
        return False
    return len(set(dependencies)) == len(dependencies)


def build_candidate(
    spec: CandidateSpec,
    source: Path,
    artifacts_root: Path,
    output: Path,
) -> dict:
    """Build only a dependency-complete, digest-pinned quarantine artifact."""
    if not _valid_spec(spec):
        return _rejection(spec, "invalid-specification")
    if spec.unresolved_dependencies:
        return _rejection(
            spec,
            "unresolved-dependencies",
            spec.unresolved_dependencies,
        )
    try:
        actual_parent = sha256_file(Path(source))
    except OSError:
        return _rejection(spec, "source-unavailable")
    if actual_parent != spec.parent_sha256:
        return _rejection(spec, "parent-digest-mismatch")
    try:
        quarantine = apply_quarantined_patches(
            Path(source),
            Path(artifacts_root),
            Path(output),
            spec.patches,
            f"candidate-{spec.source_key}",
        )
    except (OSError, QuarantineError):
        return _rejection(spec, "quarantine-gate-rejected")
    return {
        "schema_version": 1,
        "source_key": spec.source_key,
        "status": "built-quarantined",
        "installable": False,
        "reason_codes": [],
        "unresolved_dependencies": [],
        "parent_sha256": quarantine["parent_sha256"],
        "output_sha256": quarantine["output_sha256"],
        "hypothesis_id": quarantine["hypothesis_id"],
    }
