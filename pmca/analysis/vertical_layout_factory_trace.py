"""Fail-closed metadata validation for the α6400 vertical layout factory."""

from __future__ import annotations

import copy
import hashlib
import json
import re


class VerticalLayoutFactoryTraceError(ValueError):
    """Raised when factory metadata exceeds this bounded static claim."""


VIEW_UNIFIED7_SIZE = 541_024
VIEW_UNIFIED7_SHA256 = "c48cde43ff22d808ad23c42019ddae516fff7da060004eb81ed2bb85012aa538"
FACTORY_ROOT = 0x52840
CONSTRUCTORS = (
    ("header-manual-info", 0x52914, 0x14148),
    ("error", 0x52924, 0x14B04),
    ("info", 0x52934, 0x14E9C),
    ("footer", 0x52944, 0x14028),
    ("manual", 0x52954, 0x14D64),
)
REVERSE_CALLERS = ({"caller": 0x529CC, "site": 0x529D6, "target": FACTORY_ROOT, "kind": "direct"},)
CAMERA_ORIENTATION_OWNERS = (0x2D2C6, 0x30750)
STATUS_ORIENTATION_OWNERS = (0x189DC, 0x1B070, 0x1C56C)
_FORBIDDEN = {"bytes", "disassembly", "instructions", "raw_bytes", "key_material", "private_key", "write_command", "device_path"}
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_CONCLUSION = (
    "The exact five-way vertical-classical factory is bounded. An ordered "
    "orientation or layout-mode path to it is not established by this bounded slice. "
    "Orientation and touch behavior claims remain false."
)
CANONICAL_EXPORT_SHA256 = "509bdf3b80321498378186043c273d84a1a45167c81994c8b8536e497128a3b1"


def _reject_forbidden(value):
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str) or key.strip().casefold().replace("-", "_") in _FORBIDDEN:
                raise VerticalLayoutFactoryTraceError("forbidden metadata field")
            _reject_forbidden(nested)
    elif isinstance(value, list):
        for item in value:
            _reject_forbidden(item)


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise VerticalLayoutFactoryTraceError(f"{label} fields are not exact")
    return value


def _address(value, label):
    if type(value) is not int or not 0 <= value < VIEW_UNIFIED7_SIZE or value % 2:
        raise VerticalLayoutFactoryTraceError(f"{label} is outside the pinned module")
    return value


def normalize_vertical_layout_factory_export(document):
    """Validate exact five-way factory metadata without deriving a UI path."""

    _reject_forbidden(document)
    raw = _exact(document, {"schema_version", "program", "sha256", "image_size", "analysis_mode", "factory", "upstream_roots", "truncated"}, "factory export")
    if raw["schema_version"] != 1 or raw["program"] != "viewUnified7.so" or raw["sha256"] != VIEW_UNIFIED7_SHA256 or raw["image_size"] != VIEW_UNIFIED7_SIZE:
        raise VerticalLayoutFactoryTraceError("factory source identity is invalid")
    if raw["analysis_mode"] != {"engine": "elf-capstone-thumb", "read_only": True, "source_unchanged": True} or raw["truncated"] is not False:
        raise VerticalLayoutFactoryTraceError("factory export is not a complete read-only/noanalysis result")
    factory = _exact(raw["factory"], {"root", "branch_value_classification", "constructors", "reverse_callers", "unresolved_indirect_terminals"}, "factory")
    if factory["root"] != FACTORY_ROOT or factory["branch_value_classification"] != "local-branching-observed":
        raise VerticalLayoutFactoryTraceError("factory root or branch classification is invalid")
    constructors = factory["constructors"]
    if not isinstance(constructors, list) or len(constructors) != len(CONSTRUCTORS):
        raise VerticalLayoutFactoryTraceError("factory constructor membership is invalid")
    normalized_constructors = []
    for item, (identifier, site, target) in zip(constructors, CONSTRUCTORS):
        edge = _exact(item, {"id", "caller", "site", "target", "kind"}, "factory constructor")
        if edge != {"id": identifier, "caller": FACTORY_ROOT, "site": site, "target": target, "kind": "direct"}:
            raise VerticalLayoutFactoryTraceError("factory constructor is not pinned")
        normalized_constructors.append(copy.deepcopy(edge))
    if not isinstance(factory["reverse_callers"], list) or len(factory["reverse_callers"]) > 32:
        raise VerticalLayoutFactoryTraceError("factory reverse callers are unbounded")
    # These are typed reverse references to this root. They do not prove an
    # orientation-state path merely because other roots exist in the module.
    reverse = []
    for item in factory["reverse_callers"]:
        edge = _exact(item, {"caller", "site", "target", "kind"}, "factory reverse caller")
        _address(edge["caller"], "factory reverse caller")
        _address(edge["site"], "factory reverse site")
        if edge["kind"] != "direct" or edge["target"] != FACTORY_ROOT:
            raise VerticalLayoutFactoryTraceError("factory reverse caller must be direct")
        reverse.append(copy.deepcopy(edge))
    if tuple(reverse) != REVERSE_CALLERS:
        raise VerticalLayoutFactoryTraceError("factory reverse caller evidence is disconnected")
    if not isinstance(factory["unresolved_indirect_terminals"], list) or factory["unresolved_indirect_terminals"]:
        raise VerticalLayoutFactoryTraceError("unproven factory terminals cannot be promoted")
    upstream = _exact(raw["upstream_roots"], {"camera_orientation_owners", "status_orientation_owners", "layout_mode"}, "upstream roots")
    if upstream["camera_orientation_owners"] != list(CAMERA_ORIENTATION_OWNERS) or upstream["status_orientation_owners"] != list(STATUS_ORIENTATION_OWNERS):
        raise VerticalLayoutFactoryTraceError("orientation owners are not pinned")
    if upstream["layout_mode"] != {"site_count": 28, "owner_count": 15, "owner_overlap_with_factory": False}:
        raise VerticalLayoutFactoryTraceError("layout-mode root summary is invalid")
    return {
        "schema_version": 1, "program": "viewUnified7.so", "sha256": VIEW_UNIFIED7_SHA256,
        "image_size": VIEW_UNIFIED7_SIZE, "analysis_mode": {"engine": "elf-capstone-thumb", "read_only": True, "source_unchanged": True},
        "factory": {"root": FACTORY_ROOT, "branch_value_classification": factory["branch_value_classification"], "constructors": normalized_constructors, "reverse_callers": reverse, "unresolved_indirect_terminals": []},
        "upstream_roots": copy.deepcopy(upstream),
        "claims": {"vertical_layout_factory_found": True, "orientation_layout_selector_found": False},
        "behavior_support": {"orientation-layout-selection": False, "touch-coordinate-transform": False, "menu-touch-hit-test": False, "menu-touch-selection": False},
        "truncated": False,
    }


def summarize_vertical_layout_factory_export(document):
    normalized = normalize_vertical_layout_factory_export(document)
    encoded = (json.dumps(normalized, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    return {"canonical_export_sha256": hashlib.sha256(encoded).hexdigest(), "constructor_count": len(CONSTRUCTORS), "reverse_caller_count": len(normalized["factory"]["reverse_callers"]), "claims": copy.deepcopy(normalized["claims"]), "behavior_support": copy.deepcopy(normalized["behavior_support"])}


def validate_vertical_layout_factory_report(document):
    """Validate the committed bounded result and prohibit behavior promotion."""

    _reject_forbidden(document)
    report = _exact(document, {"schema_version", "analysis_scope", "camera_policy", "camera_executed", "installable", "camera_test_eligible", "source", "export_summary", "factory", "upstream_roots", "claims", "behavior_support", "readiness", "conclusion"}, "factory report")
    if report["schema_version"] != 1 or report["analysis_scope"] != "offline-static-target-vertical-layout-factory" or report["camera_policy"] != "physically-disconnected":
        raise VerticalLayoutFactoryTraceError("factory report scope is invalid")
    if any(report[key] is not False for key in ("camera_executed", "installable", "camera_test_eligible")):
        raise VerticalLayoutFactoryTraceError("factory report camera safety is invalid")
    if report["source"] != {"module": "lib/viewUnified7.so", "size": VIEW_UNIFIED7_SIZE, "sha256": VIEW_UNIFIED7_SHA256}:
        raise VerticalLayoutFactoryTraceError("factory report source is invalid")
    summary = _exact(report["export_summary"], {"canonical_export_sha256", "constructor_count", "reverse_caller_count"}, "factory summary")
    if summary["canonical_export_sha256"] != CANONICAL_EXPORT_SHA256 or not _DIGEST.fullmatch(summary["canonical_export_sha256"]) or summary["constructor_count"] != 5 or summary["reverse_caller_count"] != 1:
        raise VerticalLayoutFactoryTraceError("factory report summary is invalid")
    expected_factory = {"root": "0x52840", "branch_value_classification": "local-branching-observed", "constructors": [{"id": name, "site": f"0x{site:x}", "target": f"0x{target:x}"} for name, site, target in CONSTRUCTORS], "reverse_callers": [{"caller": "0x529cc", "site": "0x529d6", "target": "0x52840", "kind": "direct"}]}
    if report["factory"] != expected_factory:
        raise VerticalLayoutFactoryTraceError("factory report membership is invalid")
    if report["upstream_roots"] != {"camera_orientation_owners": [f"0x{x:x}" for x in CAMERA_ORIENTATION_OWNERS], "status_orientation_owners": [f"0x{x:x}" for x in STATUS_ORIENTATION_OWNERS], "layout_mode": {"site_count": 28, "owner_count": 15, "owner_overlap_with_factory": False}}:
        raise VerticalLayoutFactoryTraceError("factory report upstream roots are invalid")
    if report["claims"] != {"vertical_layout_factory_found": True, "orientation_layout_selector_found": False}:
        raise VerticalLayoutFactoryTraceError("factory report claims are over-promoted")
    expected_behavior = {"orientation-layout-selection": False, "touch-coordinate-transform": False, "menu-touch-hit-test": False, "menu-touch-selection": False}
    if report["behavior_support"] != expected_behavior or report["readiness"] != "FACTORY_BOUNDED_PATH_UNESTABLISHED" or report["conclusion"] != _CONCLUSION:
        raise VerticalLayoutFactoryTraceError("factory report conclusion is invalid")
    return copy.deepcopy(report)
