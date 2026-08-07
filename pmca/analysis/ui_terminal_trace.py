"""Validate two corrected, non-handoff α6400 UI site classifications."""

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
    "eee7ccf337eb16545a67cb9b57a03ed476ee867076939e602208a65d5092cfc2"
)
CLASSIFICATION_METHODS = (
    "instruction-flow",
    "reference-target",
    "symbol-identity",
)
EXPOSURE_GETTER_SYMBOL = (
    "_ZN33CmnViewModelWrpCameraExposureMode21getExposureModeActValEv"
)

_ROOT = Path(__file__).resolve().parents[2]
_UI_BOUNDARY_REFERENCE = "analysis/a6400-ui-dispatch-boundary.json"
_TRACK_SPECS = (
    {
        "id": "orientation-handler-local-branch-landing",
        "root": 0x1BB41C,
        "predecessor_edges": (
            {
                "caller": 0x1BB41C,
                "site": 0x1BB74C,
                "target": 0x1B9B44,
                "kind": "direct",
            },
        ),
        "site": {
            "owner": 0x1B9B44,
            "offset": 0x1B9B6A,
            "classification": "local-branch-landing",
            "flow_target": None,
            "symbol": None,
        },
    },
    {
        "id": "layout-attach-exposure-mode-getter",
        "root": 0x1BB2D2,
        "predecessor_edges": (),
        "site": {
            "owner": 0x1BB2D2,
            "offset": 0x1BB30E,
            "classification": "exposure-mode-getter-plt-call",
            "flow_target": 0x14E688,
            "symbol": EXPOSURE_GETTER_SYMBOL,
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
    "classification_methods",
    "tracks",
    "truncated",
}
_RAW_TRACK_FIELDS = {
    "id",
    "root",
    "predecessor_edges",
    "site",
}
_EDGE_FIELDS = {"caller", "site", "target", "kind"}
_SITE_FIELDS = {"owner", "offset", "classification", "flow_target", "symbol"}
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
    "classification_methods",
    "local_branch_landing_count",
    "exposure_mode_getter_plt_call_count",
}
_REPORT_TRACK_FIELDS = {"id", "root", "site"}
_REPORT_SITE_FIELDS = {
    "owner",
    "offset",
    "classification",
    "flow_target",
    "symbol",
}
_CONCLUSION = (
    "The previously misclassified sites are a local branch landing and an exposure-"
    "mode getter PLT call. Neither establishes a viewUnified2-to-viewUnified7 "
    "factory handoff or an orientation-driven UI path; all modern UI behavior "
    "claims remain false."
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


def normalize_ui_terminal_export(document: object) -> dict:
    """Normalize metadata for exactly two non-handoff UI sites."""

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
    if raw["classification_methods"] != list(CLASSIFICATION_METHODS):
        raise UiTerminalTraceError("UI site classification methods are invalid")
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
        site = _exact(track["site"], _SITE_FIELDS, "UI site")
        if site != spec["site"]:
            raise UiTerminalTraceError("UI site classification is not pinned")
        _address(site["owner"], "UI site owner")
        _address(site["offset"], "UI site offset")
        if site["flow_target"] is not None:
            _address(site["flow_target"], "UI site flow target")
        if site["symbol"] is not None and (
            not isinstance(site["symbol"], str) or not site["symbol"]
        ):
            raise UiTerminalTraceError("UI site symbol is invalid")
        normalized_tracks.append(
            {
                "id": spec["id"],
                "root": spec["root"],
                "predecessor_edges": normalized_predecessors,
                "site": dict(spec["site"]),
            }
        )

    return {
        "schema_version": 1,
        "program": "viewUnified2.so",
        "sha256": VIEW_UNIFIED2_SHA256,
        "image_size": VIEW_UNIFIED2_SIZE,
        "analysis_mode": {"read_only": True, "noanalysis": True},
        "source_graph_sha256": SOURCE_GRAPH_SHA256,
        "classification_methods": list(CLASSIFICATION_METHODS),
        "tracks": normalized_tracks,
        "claims": {
            "view_unified2_to_view_unified7_factory_edge_found": False,
            "orientation_layout_selector_found": False,
            "orientation_to_vertical_layout_path_found": False,
        },
        "behavior_support": {
            "orientation-layout-selection": False,
            "portrait-landscape-geometry": False,
            "control-direction-transform": False,
            "touch-coordinate-transform": False,
            "hit-test": False,
            "menu-selection-dispatch": False,
            "creative-look": False,
        },
        "truncated": False,
    }


def summarize_ui_terminal_export(document: object) -> dict:
    """Create a digest-pinned, non-reconstructive UI-site summary."""

    normalized = normalize_ui_terminal_export(document)
    encoded = (
        json.dumps(normalized, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    classifications = [item["site"]["classification"] for item in normalized["tracks"]]
    return {
        "canonical_export_sha256": hashlib.sha256(encoded).hexdigest(),
        "classification_methods": list(CLASSIFICATION_METHODS),
        "local_branch_landing_count": classifications.count("local-branch-landing"),
        "exposure_mode_getter_plt_call_count": classifications.count(
            "exposure-mode-getter-plt-call"
        ),
        "tracks": copy.deepcopy(normalized["tracks"]),
        "claims": copy.deepcopy(normalized["claims"]),
        "behavior_support": copy.deepcopy(normalized["behavior_support"]),
    }


def build_ui_terminal_report(document: object) -> dict:
    """Build the committed fail-closed report from pinned static site metadata."""

    summary = summarize_ui_terminal_export(document)
    return {
        "schema_version": 1,
        "analysis_scope": "offline-static-target-ui-terminal-trace",
        "camera_policy": "physically-disconnected",
        "camera_executed": False,
        "installable": False,
        "camera_test_eligible": False,
        "source": {
            "module": "lib/viewUnified2.so",
            "size": VIEW_UNIFIED2_SIZE,
            "sha256": VIEW_UNIFIED2_SHA256,
            "ui_boundary_reference": _UI_BOUNDARY_REFERENCE,
            "source_graph_sha256": SOURCE_GRAPH_SHA256,
        },
        "export_summary": {
            key: summary[key]
            for key in (
                "canonical_export_sha256",
                "classification_methods",
                "local_branch_landing_count",
                "exposure_mode_getter_plt_call_count",
            )
        },
        "tracks": [
            {
                "id": track["id"],
                "root": _hex(track["root"]),
                "site": {
                    "owner": _hex(track["site"]["owner"]),
                    "offset": _hex(track["site"]["offset"]),
                    "classification": track["site"]["classification"],
                    "flow_target": (
                        None
                        if track["site"]["flow_target"] is None
                        else _hex(track["site"]["flow_target"])
                    ),
                    "symbol": track["site"]["symbol"],
                },
            }
            for track in summary["tracks"]
        ],
        "claims": summary["claims"],
        "behavior_support": summary["behavior_support"],
        "readiness": "CLASSIFIED_NO_FACTORY_HANDOFF",
        "conclusion": _CONCLUSION,
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
    if summary["classification_methods"] != list(CLASSIFICATION_METHODS):
        raise UiTerminalTraceError("UI site summary methods are invalid")
    counts = [
        summary["local_branch_landing_count"],
        summary["exposure_mode_getter_plt_call_count"],
    ]
    if counts != [1, 1]:
        raise UiTerminalTraceError("UI site summary counts are invalid")

    tracks = report["tracks"]
    if not isinstance(tracks, list) or len(tracks) != len(_TRACK_SPECS):
        raise UiTerminalTraceError("terminal report tracks are invalid")
    observed_classifications = []
    for item, spec in zip(tracks, _TRACK_SPECS):
        track = _exact(item, _REPORT_TRACK_FIELDS, "UI site report track")
        expected_site = {
            "owner": _hex(spec["site"]["owner"]),
            "offset": _hex(spec["site"]["offset"]),
            "classification": spec["site"]["classification"],
            "flow_target": (
                None
                if spec["site"]["flow_target"] is None
                else _hex(spec["site"]["flow_target"])
            ),
            "symbol": spec["site"]["symbol"],
        }
        if (
            track["id"] != spec["id"]
            or track["root"] != _hex(spec["root"])
            or _exact(track["site"], _REPORT_SITE_FIELDS, "report UI site")
            != expected_site
        ):
            raise UiTerminalTraceError("UI site report identity is invalid")
        observed_classifications.append(spec["site"]["classification"])
    if [
        observed_classifications.count("local-branch-landing"),
        observed_classifications.count("exposure-mode-getter-plt-call"),
    ] != counts:
        raise UiTerminalTraceError("UI site report counts disagree with tracks")

    if report["claims"] != {
        "view_unified2_to_view_unified7_factory_edge_found": False,
        "orientation_layout_selector_found": False,
        "orientation_to_vertical_layout_path_found": False,
    }:
        raise UiTerminalTraceError("UI site report cannot establish a factory or selector path")
    if report["behavior_support"] != {
        "orientation-layout-selection": False,
        "portrait-landscape-geometry": False,
        "control-direction-transform": False,
        "touch-coordinate-transform": False,
        "hit-test": False,
        "menu-selection-dispatch": False,
        "creative-look": False,
    }:
        raise UiTerminalTraceError("UI site report cannot establish UI behavior")
    if (
        report["readiness"] != "CLASSIFIED_NO_FACTORY_HANDOFF"
        or report["conclusion"] != _CONCLUSION
    ):
        raise UiTerminalTraceError("terminal report conclusion is not fail-closed")
    return copy.deepcopy(report)
