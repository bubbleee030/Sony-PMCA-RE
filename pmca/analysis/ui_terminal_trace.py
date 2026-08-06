"""Validate the two smallest unresolved α6400 orientation/layout terminals."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path

from .ui_dispatch import UiDispatchError, validate_ui_dispatch_report


class UiTerminalTraceError(ValueError):
    """Raised when terminal metadata is malformed or promoted into a UI claim."""


VIEW_UNIFIED2_SIZE = 11_530_552
VIEW_UNIFIED2_SHA256 = (
    "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2"
)
SOURCE_GRAPH_SHA256 = (
    "d19fc94fd52583f3d321535fd8b6a01aa03f4efc0c4dadde52adce3a9d246f22"
)
CANONICAL_EXPORT_SHA256 = (
    "caf4f85e3edc4f558915fcbe5e6926f901c64c75a5a24c83b742449d94d8a16c"
)
RESOLUTION_METHODS = (
    "instruction-flow",
    "pcode-literal",
    "reference-target",
)

_ROOT = Path(__file__).resolve().parents[2]
_UI_BOUNDARY_REFERENCE = "analysis/a6400-ui-dispatch-boundary.json"
_TRACK_SPECS = (
    {
        "id": "orientation-handler-terminal",
        "root": 0x1BB41C,
        "predecessor_edges": (
            {
                "caller": 0x1BB41C,
                "site": 0x1BB74C,
                "target": 0x1B9B44,
                "kind": "direct",
            },
        ),
        "terminal": {
            "caller": 0x1B9B44,
            "site": 0x1B9B6A,
            "kind": "unresolved-indirect",
        },
    },
    {
        "id": "layout-attach-terminal",
        "root": 0x1BB2D2,
        "predecessor_edges": (),
        "terminal": {
            "caller": 0x1BB2D2,
            "site": 0x1BB30E,
            "kind": "unresolved-indirect",
        },
    },
)

_RAW_FIELDS = {
    "schema_version",
    "program",
    "sha256",
    "image_size",
    "analysis_mode",
    "source_graph_sha256",
    "resolution_methods",
    "tracks",
    "truncated",
}
_RAW_TRACK_FIELDS = {
    "id",
    "root",
    "predecessor_edges",
    "terminal",
    "candidates",
}
_EDGE_FIELDS = {"caller", "site", "target", "kind"}
_TERMINAL_FIELDS = {"caller", "site", "kind"}
_CANDIDATE_FIELDS = {"kind", "target", "table", "slot", "provenance"}
_CANDIDATE_KINDS = {"vtable-slot", "function-pointer-table"}
_PROVENANCE = set(RESOLUTION_METHODS)
_FORBIDDEN_KEYS = {
    "bytes",
    "device_path",
    "disassembly",
    "hex_dump",
    "instructions",
    "key_material",
    "private_key",
    "raw_bytes",
    "write_command",
}
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")

_REPORT_FIELDS = {
    "schema_version",
    "analysis_scope",
    "camera_policy",
    "camera_executed",
    "installable",
    "camera_test_eligible",
    "source",
    "export_summary",
    "tracks",
    "claims",
    "behavior_support",
    "readiness",
    "conclusion",
}
_SOURCE_FIELDS = {
    "module",
    "size",
    "sha256",
    "ui_boundary_reference",
    "source_graph_sha256",
}
_SUMMARY_FIELDS = {
    "canonical_export_sha256",
    "resolution_methods",
    "resolved_track_count",
    "ambiguous_track_count",
    "unresolved_track_count",
}
_REPORT_TRACK_FIELDS = {"id", "root", "terminal", "resolution"}
_REPORT_TERMINAL_FIELDS = {"caller", "site", "kind"}
_RESOLUTION_FIELDS = {
    "status",
    "candidate_count",
    "kind",
    "target",
    "table",
    "slot",
    "provenance",
}
_CONCLUSION = (
    "The two smallest orientation/layout indirect terminals are bounded, but no "
    "complete ordered path from orientation state to a vertical layout owner is "
    "established. All modern UI behavior claims remain false."
)


def _reject_forbidden(value: object) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise UiTerminalTraceError("terminal metadata keys must be text")
            normalized = key.strip().casefold().replace("-", "_")
            if normalized in _FORBIDDEN_KEYS:
                raise UiTerminalTraceError("raw, secret, device, or write fields are forbidden")
            _reject_forbidden(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_forbidden(nested)


def _exact(value: object, fields: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise UiTerminalTraceError(f"{label} fields are not exact")
    return value


def _address(value: object, label: str) -> int:
    if type(value) is not int or not 0 <= value < VIEW_UNIFIED2_SIZE or value % 2:
        raise UiTerminalTraceError(f"{label} is outside the pinned module")
    return value


def _normalized_candidate(value: object) -> dict:
    candidate = _exact(value, _CANDIDATE_FIELDS, "terminal candidate")
    if candidate["kind"] not in _CANDIDATE_KINDS:
        raise UiTerminalTraceError("terminal candidate kind is invalid")
    target = _address(candidate["target"], "terminal candidate target")
    table = _address(candidate["table"], "terminal candidate table")
    slot = candidate["slot"]
    if type(slot) is not int or not 0 <= slot <= 1023:
        raise UiTerminalTraceError("terminal candidate slot is invalid")
    if candidate["provenance"] not in _PROVENANCE:
        raise UiTerminalTraceError("terminal candidate provenance is invalid")
    return {
        "kind": candidate["kind"],
        "target": target,
        "table": table,
        "slot": slot,
        "provenance": candidate["provenance"],
    }


def _resolution(candidates: list[dict]) -> dict:
    if not candidates:
        status = "UNRESOLVED"
        selected = None
    elif len(candidates) == 1:
        status = "RESOLVED"
        selected = candidates[0]
    else:
        status = "AMBIGUOUS"
        selected = None
    return {
        "status": status,
        "candidate_count": len(candidates),
        "kind": None if selected is None else selected["kind"],
        "target": None if selected is None else selected["target"],
        "table": None if selected is None else selected["table"],
        "slot": None if selected is None else selected["slot"],
        "provenance": None if selected is None else selected["provenance"],
    }


def normalize_ui_terminal_export(document: object) -> dict:
    """Normalize metadata for exactly two unresolved indirect call sites."""

    _reject_forbidden(document)
    raw = _exact(document, _RAW_FIELDS, "terminal export")
    if raw["schema_version"] != 1 or type(raw["schema_version"]) is not int:
        raise UiTerminalTraceError("terminal export schema is invalid")
    if (
        raw["program"] != "viewUnified2.so"
        or raw["sha256"] != VIEW_UNIFIED2_SHA256
        or raw["image_size"] != VIEW_UNIFIED2_SIZE
        or type(raw["image_size"]) is not int
        or raw["source_graph_sha256"] != SOURCE_GRAPH_SHA256
    ):
        raise UiTerminalTraceError("terminal export source identity is invalid")
    if raw["analysis_mode"] != {"read_only": True, "noanalysis": True}:
        raise UiTerminalTraceError("terminal export was not read-only/noanalysis")
    if raw["resolution_methods"] != list(RESOLUTION_METHODS):
        raise UiTerminalTraceError("terminal resolution methods are invalid")
    if raw["truncated"] is not False:
        raise UiTerminalTraceError("truncated terminal evidence is invalid")
    if not isinstance(raw["tracks"], list) or len(raw["tracks"]) != len(_TRACK_SPECS):
        raise UiTerminalTraceError("terminal track membership is invalid")

    normalized_tracks = []
    for item, spec in zip(raw["tracks"], _TRACK_SPECS):
        track = _exact(item, _RAW_TRACK_FIELDS, "terminal track")
        if track["id"] != spec["id"] or track["root"] != spec["root"]:
            raise UiTerminalTraceError("terminal track identity or order is invalid")
        _address(track["root"], "terminal track root")
        predecessors = track["predecessor_edges"]
        if not isinstance(predecessors, list) or len(predecessors) != len(
            spec["predecessor_edges"]
        ):
            raise UiTerminalTraceError("terminal predecessor membership is invalid")
        normalized_predecessors = []
        for edge, expected in zip(predecessors, spec["predecessor_edges"]):
            record = _exact(edge, _EDGE_FIELDS, "terminal predecessor")
            if record != expected:
                raise UiTerminalTraceError("terminal predecessor is not pinned")
            for field in ("caller", "site", "target"):
                _address(record[field], f"terminal predecessor {field}")
            normalized_predecessors.append(dict(record))
        terminal = _exact(track["terminal"], _TERMINAL_FIELDS, "terminal site")
        if terminal != spec["terminal"]:
            raise UiTerminalTraceError("terminal site is not pinned")
        _address(terminal["caller"], "terminal caller")
        _address(terminal["site"], "terminal site")
        candidates = track["candidates"]
        if not isinstance(candidates, list) or len(candidates) > 32:
            raise UiTerminalTraceError("terminal candidates are invalid or unbounded")
        normalized_candidates = [_normalized_candidate(candidate) for candidate in candidates]
        normalized_candidates.sort(
            key=lambda value: (
                value["kind"],
                value["target"],
                value["table"],
                value["slot"],
                value["provenance"],
            )
        )
        identities = [tuple(candidate.values()) for candidate in normalized_candidates]
        if len(set(identities)) != len(identities):
            raise UiTerminalTraceError("terminal candidates are duplicated")
        normalized_tracks.append(
            {
                "id": spec["id"],
                "root": spec["root"],
                "predecessor_edges": normalized_predecessors,
                "terminal": dict(spec["terminal"]),
                "candidates": normalized_candidates,
                "resolution": _resolution(normalized_candidates),
            }
        )

    return {
        "schema_version": 1,
        "program": "viewUnified2.so",
        "sha256": VIEW_UNIFIED2_SHA256,
        "image_size": VIEW_UNIFIED2_SIZE,
        "analysis_mode": {"read_only": True, "noanalysis": True},
        "source_graph_sha256": SOURCE_GRAPH_SHA256,
        "resolution_methods": list(RESOLUTION_METHODS),
        "tracks": normalized_tracks,
        "claims": {"orientation_layout_selector_found": False},
        "behavior_support": {"orientation-layout-selection": False},
        "truncated": False,
    }


def summarize_ui_terminal_export(document: object) -> dict:
    """Create a digest-pinned, non-reconstructive terminal summary."""

    normalized = normalize_ui_terminal_export(document)
    encoded = (
        json.dumps(normalized, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    statuses = [item["resolution"]["status"] for item in normalized["tracks"]]
    return {
        "canonical_export_sha256": hashlib.sha256(encoded).hexdigest(),
        "resolution_methods": list(RESOLUTION_METHODS),
        "resolved_track_count": statuses.count("RESOLVED"),
        "ambiguous_track_count": statuses.count("AMBIGUOUS"),
        "unresolved_track_count": statuses.count("UNRESOLVED"),
        "tracks": copy.deepcopy(normalized["tracks"]),
        "claims": copy.deepcopy(normalized["claims"]),
        "behavior_support": copy.deepcopy(normalized["behavior_support"]),
    }


def _load_ui_boundary() -> dict:
    try:
        document = json.loads((_ROOT / _UI_BOUNDARY_REFERENCE).read_text("utf-8"))
        return validate_ui_dispatch_report(document)
    except (OSError, UnicodeError, json.JSONDecodeError, UiDispatchError) as error:
        raise UiTerminalTraceError("UI dispatch dependency is invalid") from error


def _hex(value: int) -> str:
    return f"0x{value:x}"


def validate_ui_terminal_report(document: object) -> dict:
    """Validate the committed terminal result without promoting UI behavior."""

    _reject_forbidden(document)
    report = _exact(document, _REPORT_FIELDS, "terminal report")
    if report["schema_version"] != 1 or type(report["schema_version"]) is not int:
        raise UiTerminalTraceError("terminal report schema is invalid")
    if report["analysis_scope"] != "offline-static-target-ui-terminal-trace":
        raise UiTerminalTraceError("terminal report scope is invalid")
    if report["camera_policy"] != "physically-disconnected":
        raise UiTerminalTraceError("terminal report camera policy is invalid")
    for field in ("camera_executed", "installable", "camera_test_eligible"):
        if report[field] is not False:
            raise UiTerminalTraceError(f"{field} must remain false")

    dependency = _load_ui_boundary()
    source = _exact(report["source"], _SOURCE_FIELDS, "terminal source")
    expected_source = {
        "module": "lib/viewUnified2.so",
        "size": VIEW_UNIFIED2_SIZE,
        "sha256": VIEW_UNIFIED2_SHA256,
        "ui_boundary_reference": _UI_BOUNDARY_REFERENCE,
        "source_graph_sha256": dependency["bounded_export_summary"]["artifact_sha256"],
    }
    if source != expected_source or source["source_graph_sha256"] != SOURCE_GRAPH_SHA256:
        raise UiTerminalTraceError("terminal report source is invalid")

    summary = _exact(report["export_summary"], _SUMMARY_FIELDS, "terminal summary")
    if summary["canonical_export_sha256"] != CANONICAL_EXPORT_SHA256:
        raise UiTerminalTraceError("terminal export digest is invalid")
    if summary["resolution_methods"] != list(RESOLUTION_METHODS):
        raise UiTerminalTraceError("terminal summary methods are invalid")
    counts = [
        summary["resolved_track_count"],
        summary["ambiguous_track_count"],
        summary["unresolved_track_count"],
    ]
    if counts != [0, 0, 2]:
        raise UiTerminalTraceError("terminal summary counts are invalid")

    tracks = report["tracks"]
    if not isinstance(tracks, list) or len(tracks) != len(_TRACK_SPECS):
        raise UiTerminalTraceError("terminal report tracks are invalid")
    observed_statuses = []
    for item, spec in zip(tracks, _TRACK_SPECS):
        track = _exact(item, _REPORT_TRACK_FIELDS, "terminal report track")
        expected_terminal = {
            "caller": _hex(spec["terminal"]["caller"]),
            "site": _hex(spec["terminal"]["site"]),
            "kind": "unresolved-indirect",
        }
        if (
            track["id"] != spec["id"]
            or track["root"] != _hex(spec["root"])
            or _exact(track["terminal"], _REPORT_TERMINAL_FIELDS, "report terminal")
            != expected_terminal
        ):
            raise UiTerminalTraceError("terminal report track identity is invalid")
        resolution = _exact(track["resolution"], _RESOLUTION_FIELDS, "track resolution")
        expected_resolution = {
            "status": "UNRESOLVED",
            "candidate_count": 0,
            "kind": None,
            "target": None,
            "table": None,
            "slot": None,
            "provenance": None,
        }
        if resolution != expected_resolution:
            raise UiTerminalTraceError("terminal resolution differs from pinned export")
        observed_statuses.append("UNRESOLVED")
    if [observed_statuses.count(value) for value in ("RESOLVED", "AMBIGUOUS", "UNRESOLVED")] != counts:
        raise UiTerminalTraceError("terminal report counts disagree with tracks")

    if report["claims"] != {"orientation_layout_selector_found": False}:
        raise UiTerminalTraceError("terminal report cannot establish a selector")
    if report["behavior_support"] != {"orientation-layout-selection": False}:
        raise UiTerminalTraceError("terminal report cannot establish UI behavior")
    if report["readiness"] != "UNRESOLVED" or report["conclusion"] != _CONCLUSION:
        raise UiTerminalTraceError("terminal report conclusion is not fail-closed")
    return copy.deepcopy(report)
