"""Evidence-gated dependency mapping for α6400 feature-port research."""

from copy import deepcopy
from dataclasses import dataclass
from urllib.parse import urlsplit


FEATURE_IDS = (
    "vertical-orientation-state",
    "vertical-layout-selection",
    "vertical-render-transform",
    "vertical-input-transform",
    "touch-menu-widgets",
    "touch-event-routing",
    "creative-look-base-tables",
    "creative-look-adjustment-axes",
)
EVIDENCE_LEVELS = (
    "CONFIRMED",
    "PARTIAL",
    "INFERRED",
    "INSUFFICIENT_EVIDENCE",
)
STRATEGY_ORDER = (
    "direct-component-reuse",
    "resource-table-transplant",
    "a6400-subsystem-patch",
    "a6400-specific-reimplementation",
)
COMPATIBILITY_FIELDS = {
    "architecture",
    "imports",
    "relocations",
    "memory",
    "display_geometry",
    "input_coordinates",
    "dependent_services",
    "signature_layer",
}
_TOP_FIELDS = {
    "schema_version",
    "strategy_order",
    "features",
    "candidate_result",
    "marker_scan",
}
_FEATURE_FIELDS = {
    "id",
    "target",
    "dependencies",
    "evidence",
    "selected_strategy",
    "compatibility",
    "ready",
    "unresolved_dependencies",
}
_EVIDENCE_FIELDS = {"level", "source", "claim"}
_CANDIDATE_FIELDS = {
    "schema_version",
    "source_key",
    "status",
    "installable",
    "reason_codes",
    "unresolved_dependencies",
}
_MARKER_FIELDS = {"markers", "scopes", "interpretation"}
_SCOPE_FIELDS = {
    "source_key",
    "scan_scope",
    "ascii_hits",
    "utf16le_hits",
}


class FeatureError(ValueError):
    """Raised when feature evidence or dependency state is inconsistent."""


@dataclass(frozen=True, slots=True)
class FeatureEvidence:
    level: str
    source: str
    claim: str


@dataclass(frozen=True, slots=True)
class FeatureBoundary:
    name: str
    target: str
    dependencies: tuple[str, ...]
    evidence: tuple[FeatureEvidence, ...]


def _bounded_text(value: object, name: str, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or "\r" in value
        or "\n" in value
        or not value.isprintable()
    ):
        raise FeatureError(f"{name} must be bounded single-line text")
    return value


def _confirmed_source(source: str) -> bool:
    if source.startswith("artifact:"):
        return len(source) > len("artifact:")
    parsed = urlsplit(source)
    return (
        parsed.scheme == "https"
        and parsed.hostname in {"helpguide.sony.net", "www.sony.com.tw"}
        and not parsed.username
        and not parsed.password
        and parsed.port is None
    )


def _validate_evidence(value: object) -> FeatureEvidence:
    if isinstance(value, FeatureEvidence):
        evidence = value
    elif isinstance(value, dict) and set(value) == _EVIDENCE_FIELDS:
        evidence = FeatureEvidence(value["level"], value["source"], value["claim"])
    else:
        raise FeatureError("Feature evidence fields do not match schema version 1")
    if evidence.level not in EVIDENCE_LEVELS:
        raise FeatureError("Feature evidence level is unknown")
    source = _bounded_text(evidence.source, "Evidence source")
    _bounded_text(evidence.claim, "Evidence claim")
    if evidence.level == "CONFIRMED" and not _confirmed_source(source):
        raise FeatureError(
            "Confirmed evidence requires an official document or authenticated artifact"
        )
    return evidence


def _validate_boundary(boundary: object) -> FeatureBoundary:
    if not isinstance(boundary, FeatureBoundary):
        raise FeatureError("Feature boundary must be a FeatureBoundary")
    if boundary.name not in FEATURE_IDS:
        raise FeatureError("Feature boundary ID is unknown")
    _bounded_text(boundary.target, "Feature target", maximum=64)
    if not isinstance(boundary.dependencies, tuple):
        raise FeatureError("Feature dependencies must be a tuple")
    if (
        len(set(boundary.dependencies)) != len(boundary.dependencies)
        or boundary.name in boundary.dependencies
        or any(value not in FEATURE_IDS for value in boundary.dependencies)
    ):
        raise FeatureError("Feature dependencies are invalid")
    if not isinstance(boundary.evidence, tuple) or not boundary.evidence:
        raise FeatureError("Feature boundary requires evidence")
    for evidence in boundary.evidence:
        _validate_evidence(evidence)
    return boundary


def candidate_readiness(
    boundary: FeatureBoundary,
    boundaries: dict[str, FeatureBoundary] | None = None,
) -> tuple[bool, tuple[str, ...]]:
    """Require confirmed evidence across the full transitive dependency graph."""
    boundary = _validate_boundary(boundary)
    registry = dict(boundaries or {boundary.name: boundary})
    registry[boundary.name] = boundary
    unresolved = []
    visited = set()
    visiting = set()

    def visit(name: str) -> None:
        if name in visited:
            return
        if name in visiting:
            raise FeatureError("Feature dependency graph contains a cycle")
        current = registry.get(name)
        if current is None:
            unresolved.append(f"missing:{name}")
            return
        current = _validate_boundary(current)
        visiting.add(name)
        levels = {evidence.level for evidence in current.evidence}
        if "CONFIRMED" not in levels or "INSUFFICIENT_EVIDENCE" in levels:
            unresolved.append(f"evidence:{name}")
        for dependency in current.dependencies:
            visit(dependency)
        visiting.remove(name)
        visited.add(name)

    visit(boundary.name)
    unique = tuple(dict.fromkeys(unresolved))
    return not unique, unique


def _feature_boundary(value: dict) -> FeatureBoundary:
    evidence = tuple(_validate_evidence(item) for item in value["evidence"])
    dependencies = value["dependencies"]
    if not isinstance(dependencies, list):
        raise FeatureError("Serialized dependencies must be a list")
    return _validate_boundary(
        FeatureBoundary(
            value["id"],
            value["target"],
            tuple(dependencies),
            evidence,
        )
    )


def _validate_candidate(value: object) -> None:
    if not isinstance(value, dict) or set(value) != _CANDIDATE_FIELDS:
        raise FeatureError("Candidate result fields do not match schema version 1")
    if value["schema_version"] != 1 or value["status"] != "rejected":
        raise FeatureError("Compatibility candidate must be a structured rejection")
    if value["installable"] is not False:
        raise FeatureError("Compatibility candidate must be non-installable")
    _bounded_text(value["source_key"], "Candidate source", maximum=64)
    for field in ("reason_codes", "unresolved_dependencies"):
        entries = value[field]
        if not isinstance(entries, list) or not entries:
            raise FeatureError("Candidate rejection must enumerate its blockers")
        for entry in entries:
            _bounded_text(entry, "Candidate blocker", maximum=128)


def _validate_marker_scan(value: object) -> None:
    if not isinstance(value, dict) or set(value) != _MARKER_FIELDS:
        raise FeatureError("Marker scan fields do not match schema version 1")
    markers = value["markers"]
    if (
        not isinstance(markers, list)
        or not markers
        or len(markers) > 32
        or len(set(markers)) != len(markers)
    ):
        raise FeatureError("Marker scan requires unique bounded markers")
    for marker in markers:
        _bounded_text(marker, "Marker", maximum=64)
    scopes = value["scopes"]
    if not isinstance(scopes, list) or not scopes:
        raise FeatureError("Marker scan requires at least one scope")
    for scope in scopes:
        if not isinstance(scope, dict) or set(scope) != _SCOPE_FIELDS:
            raise FeatureError("Marker scope fields do not match schema version 1")
        _bounded_text(scope["source_key"], "Marker source", maximum=64)
        _bounded_text(scope["scan_scope"], "Marker scope", maximum=128)
        for field in ("ascii_hits", "utf16le_hits"):
            hits = scope[field]
            if not isinstance(hits, dict) or set(hits) != set(markers):
                raise FeatureError("Marker counts must cover every marker")
            if any(type(count) is not int or count < 0 for count in hits.values()):
                raise FeatureError("Marker counts must be non-negative integers")
    _bounded_text(value["interpretation"], "Marker interpretation")


def count_feature_markers(
    path,
    offset: int,
    size: int,
    markers: tuple[str, ...],
    chunk_size: int = 1_048_576,
) -> tuple[dict[str, int], dict[str, int]]:
    """Count allowlisted ASCII/UTF-16LE markers without returning firmware bytes."""
    from pathlib import Path

    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise FeatureError("Marker input must be a real regular file")
    file_size = path.stat().st_size
    if (
        type(offset) is not int
        or type(size) is not int
        or offset < 0
        or size <= 0
        or size > file_size
        or offset > file_size - size
    ):
        raise FeatureError("Marker scan range is outside the input")
    if (
        not isinstance(markers, tuple)
        or not markers
        or len(markers) > 32
        or len(set(markers)) != len(markers)
        or type(chunk_size) is not int
        or not 1 <= chunk_size <= 8 * 1_048_576
    ):
        raise FeatureError("Marker scan configuration is invalid")
    encoded = []
    for marker in markers:
        _bounded_text(marker, "Marker", maximum=64)
        try:
            ascii_pattern = marker.encode("ascii")
        except UnicodeEncodeError as error:
            raise FeatureError("Feature markers must be ASCII text") from error
        encoded.append(("ascii", marker, ascii_pattern))
        encoded.append(("utf16le", marker, marker.encode("utf-16le")))
    maximum = max(len(pattern) for _, _, pattern in encoded)
    counts = {
        "ascii": {marker: 0 for marker in markers},
        "utf16le": {marker: 0 for marker in markers},
    }
    last_start = {(encoding, marker): -1 for encoding, marker, _ in encoded}
    range_end = offset + size
    cursor = offset
    remaining = size
    carry = b""
    with path.open("rb") as stream:
        stream.seek(offset)
        while remaining:
            block = stream.read(min(chunk_size, remaining))
            if not block:
                raise FeatureError("Marker input ended before the approved range")
            data = carry + block
            data_offset = cursor - len(carry)
            for encoding, marker, pattern in encoded:
                position = data.find(pattern)
                while position != -1:
                    absolute = data_offset + position
                    key = (encoding, marker)
                    if (
                        absolute >= offset
                        and absolute + len(pattern) <= range_end
                        and absolute > last_start[key]
                    ):
                        counts[encoding][marker] += 1
                        last_start[key] = absolute
                    position = data.find(pattern, position + 1)
            keep = min(maximum - 1, len(data))
            carry = data[-keep:] if keep else b""
            cursor += len(block)
            remaining -= len(block)
    return counts["ascii"], counts["utf16le"]


def validate_compatibility_matrix(document: object) -> dict:
    """Validate, dependency-check, and normalize a feature matrix."""
    if not isinstance(document, dict) or set(document) != _TOP_FIELDS:
        raise FeatureError("Compatibility fields do not match schema version 1")
    if document["schema_version"] != 1 or type(document["schema_version"]) is not int:
        raise FeatureError("Unsupported compatibility schema version")
    if document["strategy_order"] != list(STRATEGY_ORDER):
        raise FeatureError("Port strategies must use the fixed order")
    features = document["features"]
    if not isinstance(features, list) or len(features) != len(FEATURE_IDS):
        raise FeatureError("Compatibility matrix must contain every feature")
    by_id = {}
    for value in features:
        if not isinstance(value, dict) or set(value) != _FEATURE_FIELDS:
            raise FeatureError("Feature fields do not match schema version 1")
        boundary = _feature_boundary(value)
        if boundary.name in by_id:
            raise FeatureError("Compatibility feature IDs must be unique")
        if value["selected_strategy"] not in STRATEGY_ORDER:
            raise FeatureError("Selected port strategy is unknown")
        compatibility = value["compatibility"]
        if not isinstance(compatibility, dict) or set(compatibility) != COMPATIBILITY_FIELDS:
            raise FeatureError("Compatibility dimensions are incomplete")
        for claim in compatibility.values():
            _bounded_text(claim, "Compatibility claim")
        if type(value["ready"]) is not bool:
            raise FeatureError("Feature readiness must be boolean")
        unresolved = value["unresolved_dependencies"]
        if not isinstance(unresolved, list):
            raise FeatureError("Unresolved dependencies must be a list")
        by_id[boundary.name] = (boundary, value)
    if set(by_id) != set(FEATURE_IDS):
        raise FeatureError("Compatibility matrix feature set is not exact")

    registry = {name: pair[0] for name, pair in by_id.items()}
    normalized_features = []
    for feature_id in FEATURE_IDS:
        boundary, value = by_id[feature_id]
        ready, unresolved = candidate_readiness(boundary, registry)
        if value["ready"] is not ready or value["unresolved_dependencies"] != list(
            unresolved
        ):
            raise FeatureError("Declared readiness does not match feature evidence")
        normalized_features.append(deepcopy(value))

    _validate_candidate(document["candidate_result"])
    _validate_marker_scan(document["marker_scan"])
    normalized = deepcopy(document)
    normalized["features"] = normalized_features
    return normalized
