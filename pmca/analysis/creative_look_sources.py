"""Authenticate Creative Look research sources without exposing firmware bytes."""

from __future__ import annotations

import copy
import hashlib
import re
import unicodedata
from pathlib import Path


SOURCE_IDS = (
    "a6400-tw-v2.00",
    "a6400a-eu-v1.01",
    "a6700-tw-v2.00",
    "a7v-tw-v2.00",
)
STATES = {
    "UNAVAILABLE",
    "AUTHENTICATED_OPAQUE",
    "AUTHENTICATED_EXTRACTED",
}

_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_DOCUMENT_FIELDS = {"schema_version", "target", "sources", "claim_boundary"}
_SOURCE_FIELDS = {
    "id",
    "display_name",
    "model",
    "region",
    "version",
    "role",
    "state",
    "executable_evidence_available",
    "artifact",
    "extracted_evidence",
    "committed_evidence",
    "creative_look_limit",
}
_ARTIFACT_FIELDS = {"filename", "size", "sha256", "source_kind"}
_EXTRACTED_FIELDS = {"artifact_kind", "name", "size", "sha256"}
_SOURCE_IDENTITIES = {
    "a6400-tw-v2.00": {
        "display_name": "α6400",
        "model": "ILCE-6400",
        "region": "TW",
        "version": "2.00",
        "role": "target",
    },
    "a6400a-eu-v1.01": {
        "display_name": "α6400A",
        "model": "ILCE-6400A",
        "region": "EU",
        "version": "1.01",
        "role": "control-sample",
    },
    "a6700-tw-v2.00": {
        "display_name": "α6700",
        "model": "ILCE-6700",
        "region": "TW",
        "version": "2.00",
        "role": "interface-reference",
    },
    "a7v-tw-v2.00": {
        "display_name": "α7 V",
        "model": "ILCE-7M5",
        "region": "TW",
        "version": "2.00",
        "role": "interface-reference",
    },
}
_ARTIFACT_IDENTITIES = {
    "a6400-tw-v2.00": {
        "filename": "Update_ILCE6400V200.exe",
        "size": 314230712,
        "sha256": "ea460cbec5f8b62119630f0a653eeca4f4ffad887670e60c0fd9c0345e6b30a6",
        "source_kind": "official-windows-updater",
    },
    "a6400a-eu-v1.01": {
        "filename": "Update_ILCE6400AV101.exe",
        "size": 324175032,
        "sha256": "fd6ae50755a9202a8b506b6b77aa27ab41ae717e96f05a0d4e2ad699b40d9ad1",
        "source_kind": "official-windows-updater",
    },
    "a6700-tw-v2.00": {
        "filename": "BODYDATA.DAT",
        "size": 1024017848,
        "sha256": "d3c7db5b9b40c89b11ecf03addf0f6ff1d9b917acf9f55e46360462e86db847c",
        "source_kind": "official-bodydata",
    },
    "a7v-tw-v2.00": {
        "filename": "BODYDATA.DAT",
        "size": 376540720,
        "sha256": "098290778a84236a0f2be44ac8398fd428d522b5c2c6676f19df23d09ee293d6",
        "source_kind": "official-bodydata",
    },
}
_COMMITTED_EVIDENCE = {
    "a6400-tw-v2.00": [
        "analysis/firmware-manifest.json",
        "analysis/a6400-target-features.json",
    ],
    "a6400a-eu-v1.01": [
        "analysis/a6400a-updater-and-creative-style-deep-dive.md",
    ],
    "a6700-tw-v2.00": [
        "analysis/firmware-manifest.json",
        "analysis/reports/a6700-tw-v2.00.json",
        "analysis/structures/a6700-tw-v2.00.json",
        "analysis/a6400-feasibility-report.md",
    ],
    "a7v-tw-v2.00": [
        "analysis/firmware-manifest.json",
        "analysis/reports/a7v-tw-v2.00.json",
        "analysis/structures/a7v-tw-v2.00.json",
        "analysis/a6400-feasibility-report.md",
    ],
}
_MAX_TEXT_CHARS = 2048


class CreativeLookSourceError(ValueError):
    """Raised when source identity, availability, or provenance is unsafe."""


def _require_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise CreativeLookSourceError(f"{label} digest is invalid")
    return value


def _require_size(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise CreativeLookSourceError(f"{label} size is invalid")
    return value


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CreativeLookSourceError(f"{label} must be nonempty text")
    if len(value) > _MAX_TEXT_CHARS:
        raise CreativeLookSourceError(f"{label} exceeds the text size limit")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise CreativeLookSourceError(f"{label} contains a control character")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _inside_decrypted_artifacts(path: Path) -> bool:
    parts = tuple(part.casefold() for part in path.resolve().parts)
    return any(
        parts[index : index + 2] == (".artifacts", "decrypted")
        for index in range(len(parts) - 1)
    )


def classify_artifact(
    path: Path | None,
    expected_size: int,
    expected_sha256: str,
    extracted: bool,
) -> dict:
    """Classify one file by exact identity without returning its contents."""

    _require_size(expected_size, "Expected artifact")
    _require_digest(expected_sha256, "Expected artifact")
    if type(extracted) is not bool:
        raise CreativeLookSourceError("extracted state must be boolean")
    if path is None or not path.exists():
        return {"state": "UNAVAILABLE", "executable_evidence_available": False}

    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise CreativeLookSourceError("artifact must be a regular non-symlink file")
    if path.stat().st_size != expected_size:
        raise CreativeLookSourceError("artifact size mismatch")
    if _sha256_file(path) != expected_sha256:
        raise CreativeLookSourceError("artifact digest mismatch")
    if extracted and not _inside_decrypted_artifacts(path):
        raise CreativeLookSourceError(
            "extracted artifact is outside ignored .artifacts/decrypted storage"
        )

    state = "AUTHENTICATED_EXTRACTED" if extracted else "AUTHENTICATED_OPAQUE"
    return {
        "state": state,
        "executable_evidence_available": extracted,
    }


def _validate_relative_evidence_path(value: object) -> str:
    path = _require_text(value, "Committed evidence path")
    if (
        "\\" in path
        or ":" in path
        or path.startswith("/")
        or not path.startswith("analysis/")
        or ".." in Path(path).parts
    ):
        raise CreativeLookSourceError("committed evidence path is not repository-relative")
    return path


def validate_creative_look_sources(document: dict) -> dict:
    """Return an isolated validated copy of the fixed source-state report."""

    if not isinstance(document, dict) or set(document) != _DOCUMENT_FIELDS:
        raise CreativeLookSourceError("Creative Look source report fields are not exact")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise CreativeLookSourceError("Creative Look source schema version is invalid")
    if document["target"] != "ILCE-6400":
        raise CreativeLookSourceError("Creative Look source target is invalid")
    if document["claim_boundary"] != (
        "Opaque FDAT sources provide container and format evidence only; they do "
        "not provide donor functions, offsets, tables, decryption, or processing behavior."
    ):
        raise CreativeLookSourceError("Creative Look source claim boundary is invalid")

    sources = document["sources"]
    if not isinstance(sources, list) or [
        item.get("id") if isinstance(item, dict) else None for item in sources
    ] != list(SOURCE_IDS):
        raise CreativeLookSourceError("Creative Look source membership or order is invalid")

    for item in sources:
        if set(item) != _SOURCE_FIELDS:
            raise CreativeLookSourceError("Creative Look source fields are not exact")
        source_id = item["id"]
        identity = _SOURCE_IDENTITIES[source_id]
        for field, expected in identity.items():
            if item[field] != expected:
                raise CreativeLookSourceError(f"{source_id} {field} is invalid")

        state = item["state"]
        if state not in STATES or state == "UNAVAILABLE":
            raise CreativeLookSourceError(f"{source_id} committed source state is invalid")
        available = item["executable_evidence_available"]
        if type(available) is not bool:
            raise CreativeLookSourceError(
                f"{source_id} executable availability must be boolean"
            )
        if available != (state == "AUTHENTICATED_EXTRACTED"):
            raise CreativeLookSourceError(
                f"{source_id} state and executable availability disagree"
            )

        artifact = item["artifact"]
        if not isinstance(artifact, dict) or set(artifact) != _ARTIFACT_FIELDS:
            raise CreativeLookSourceError(f"{source_id} artifact fields are not exact")
        if artifact != _ARTIFACT_IDENTITIES[source_id]:
            raise CreativeLookSourceError(f"{source_id} artifact identity is invalid")
        _require_size(artifact["size"], f"{source_id} artifact")
        _require_digest(artifact["sha256"], f"{source_id} artifact")

        extracted_evidence = item["extracted_evidence"]
        if not isinstance(extracted_evidence, list):
            raise CreativeLookSourceError(
                f"{source_id} extracted evidence must be a list"
            )
        if available != bool(extracted_evidence):
            raise CreativeLookSourceError(
                f"{source_id} extracted evidence does not match availability"
            )
        names: set[str] = set()
        for evidence in extracted_evidence:
            if not isinstance(evidence, dict) or set(evidence) != _EXTRACTED_FIELDS:
                raise CreativeLookSourceError(
                    f"{source_id} extracted evidence fields are not exact"
                )
            if evidence["artifact_kind"] != "module":
                raise CreativeLookSourceError(
                    f"{source_id} extracted evidence kind is invalid"
                )
            name = _require_text(evidence["name"], f"{source_id} module name")
            if name in names or not name.startswith("lib/") or "\\" in name:
                raise CreativeLookSourceError(
                    f"{source_id} extracted module name is invalid"
                )
            names.add(name)
            _require_size(evidence["size"], f"{source_id} extracted module")
            _require_digest(evidence["sha256"], f"{source_id} extracted module")

        committed_evidence = item["committed_evidence"]
        if not isinstance(committed_evidence, list):
            raise CreativeLookSourceError(
                f"{source_id} committed evidence must be a list"
            )
        validated_paths = [
            _validate_relative_evidence_path(path) for path in committed_evidence
        ]
        if validated_paths != _COMMITTED_EVIDENCE[source_id]:
            raise CreativeLookSourceError(
                f"{source_id} committed evidence membership is invalid"
            )
        _require_text(item["creative_look_limit"], f"{source_id} Creative Look limit")

    return copy.deepcopy(document)
