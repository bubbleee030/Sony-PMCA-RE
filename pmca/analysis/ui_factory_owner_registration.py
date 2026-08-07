"""Fail-closed contract for the bounded α6400 UI factory forwarding owner."""

from __future__ import annotations

import copy
import hashlib
import json
import re


class UIFactoryOwnerRegistrationError(ValueError):
    """Raised when static owner-registration metadata exceeds this slice."""


VIEW_UNIFIED7_SHA256 = "c48cde43ff22d808ad23c42019ddae516fff7da060004eb81ed2bb85012aa538"
VIEW_UNIFIED7_SIZE = 541_024
OWNER_RANGE = {"start": 0x529CC, "end": 0x529E8}
FORWARDING_EDGE = {"caller": 0x529CC, "site": 0x529D6, "target": 0x52840, "kind": "direct"}
RELATIVE_REGISTRATIONS = [
    {"index": 1268, "address": 0x70EE8, "target": 0x529CC, "thumb_pointer": 0x529CD, "evidence_kind": "relocation", "relocation_type": "R_ARM_RELATIVE", "section_name": ".rel.dyn"},
    {"index": 1286, "address": 0x70FA0, "target": 0x529CC, "thumb_pointer": 0x529CD, "evidence_kind": "relocation", "relocation_type": "R_ARM_RELATIVE", "section_name": ".rel.dyn"},
    {"index": 1305, "address": 0x71040, "target": 0x529CC, "thumb_pointer": 0x529CD, "evidence_kind": "relocation", "relocation_type": "R_ARM_RELATIVE", "section_name": ".rel.dyn"},
    {"index": 1327, "address": 0x710F0, "target": 0x529CC, "thumb_pointer": 0x529CD, "evidence_kind": "relocation", "relocation_type": "R_ARM_RELATIVE", "section_name": ".rel.dyn"},
    {"index": 1349, "address": 0x711A0, "target": 0x529CC, "thumb_pointer": 0x529CD, "evidence_kind": "relocation", "relocation_type": "R_ARM_RELATIVE", "section_name": ".rel.dyn"},
]
ORIENTATION_ROOTS = [0x2D2C6, 0x30750, 0x189DC, 0x1B070, 0x1C56C]
ORIENTATION_IMPORTS = [
    {"id": "camera_orientation", "symbol": "_ZN27CmnWrpOrientationRegisterAF20getCameraOrientationEv", "plt": 0x14958, "owners": [{"owner": 0x2D2C6, "site": 0x2D2CC}, {"owner": 0x30750, "site": 0x30934}]},
    {"id": "status_orientation", "symbol": "_ZN27CmnWrpOrientationRegisterAF23getStsCameraOrientationEv", "plt": 0x15008, "owners": [{"owner": 0x189DC, "site": 0x189EE}, {"owner": 0x1B070, "site": 0x1B08C}, {"owner": 0x1C56C, "site": 0x1C584}, {"owner": 0x1C56C, "site": 0x1C5E4}]},
]
LAYOUT_MODE_ROOTS = [0x193E0, 0x27458, 0x27540, 0x29660, 0x2D68C, 0x2D770, 0x2D82C, 0x3260C, 0x53598, 0x53B9C, 0x54440, 0x56CCC, 0x56D8C, 0x56E4C, 0x56F0C]
PATH_SUMMARY = {
    "max_depth": 32,
    "orientation_roots": ORIENTATION_ROOTS,
    "layout_mode_roots": LAYOUT_MODE_ROOTS,
    "paths_to_owner": [],
    "paths_to_factory": [],
}
CLAIMS = {
    "vertical_layout_factory_found": True,
    "factory_forwarding_owner_found": True,
    "typed_owner_registration_found": True,
    "orientation_layout_selector_found": False,
    "five_wrapper_registrations_found": True,
    "runtime_factory_invocation_proven": False,
    "view_unified2_to_factory_edge_found": False,
    "orientation_to_factory_join_proven": False,
    "portrait_geometry_proven": False,
    "touch_coordinate_transform_proven": False,
    "menu_selection_dispatch_proven": False,
}
BEHAVIOR_SUPPORT = {
    "touch-coordinate-transform": False,
    "menu-touch-hit-test": False,
    "menu-touch-selection": False,
}
READINESS = "TYPED_OWNER_REGISTRATION_BOUNDED_ROUTE_UNESTABLISHED"
REPORT_CANONICAL_EXPORT_SHA256 = "5406b615542a0af4ab6ad07060126b98e00e673456d9958dbd9733a2f3508bab"
CONCLUSION = (
    "Five typed .rel.dyn R_ARM_RELATIVE registrations preserve the unnamed "
    "forwarding owner's Thumb pointer through PT_LOAD-mapped addends. No direct "
    "orientation/layout-mode path to that owner or the factory is established "
    "within depth 32; this does not "
    "exclude an indirect, callback, dataflow, or cross-module route."
)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_FORBIDDEN = {"bytes", "raw_bytes", "disassembly", "instructions", "key_material", "private_key", "device_path", "write", "write_command"}


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise UIFactoryOwnerRegistrationError(f"{label} fields are not exact")
    return value


def _forbid(value):
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str) or key.casefold().replace("-", "_") in _FORBIDDEN:
                raise UIFactoryOwnerRegistrationError("forbidden raw or device material")
            _forbid(nested)
    elif isinstance(value, list):
        for nested in value:
            _forbid(nested)


def _address(value, label):
    if type(value) is not int or value < 0 or value >= VIEW_UNIFIED7_SIZE or value & 1:
        raise UIFactoryOwnerRegistrationError(f"{label} is not a normalized module address")
    return value


def _normalized_reference(reference):
    if not isinstance(reference, dict):
        raise UIFactoryOwnerRegistrationError("typed registration reference is invalid")
    kind = reference.get("evidence_kind")
    allowed = {
        "relocation": {"index", "address", "target", "thumb_pointer", "evidence_kind", "relocation_type", "section_name"},
        "symbol": {"address", "target", "evidence_kind", "symbol_name", "section_name"},
        "section-membership": {"address", "target", "evidence_kind", "section_name"},
    }
    if kind not in allowed or set(reference) != allowed[kind]:
        raise UIFactoryOwnerRegistrationError("registration evidence is not typed ELF metadata")
    _address(reference["address"], "registration address")
    if reference["target"] != OWNER_RANGE["start"]:
        raise UIFactoryOwnerRegistrationError("registration target is not the forwarding owner")
    if kind == "relocation" and (reference["relocation_type"] != "R_ARM_RELATIVE" or reference["section_name"] != ".rel.dyn" or reference["thumb_pointer"] != OWNER_RANGE["start"] | 1):
        raise UIFactoryOwnerRegistrationError("relative relocation does not preserve the forwarding-owner Thumb pointer")
    if kind == "relocation" and type(reference["index"]) is not int:
        raise UIFactoryOwnerRegistrationError("relative relocation index is invalid")
    for field in set(reference) - {"index", "address", "target", "thumb_pointer", "evidence_kind"}:
        if not isinstance(reference[field], str) or not reference[field]:
            raise UIFactoryOwnerRegistrationError("registration metadata is empty")
    return copy.deepcopy(reference)


def normalize_ui_factory_owner_registration_export(document):
    """Normalize only typed metadata; arbitrary pointer-like values are rejected."""

    _forbid(document)
    raw = _exact(document, {
        "schema_version", "program", "sha256", "image_size", "analysis_mode", "owner",
        "typed_registration_references", "orientation_imports", "direct_path_summary", "truncated",
    }, "owner registration export")
    if raw["schema_version"] != 1 or raw["program"] != "viewUnified7.so" or raw["sha256"] != VIEW_UNIFIED7_SHA256 or raw["image_size"] != VIEW_UNIFIED7_SIZE:
        raise UIFactoryOwnerRegistrationError("source identity is not pinned")
    if raw["analysis_mode"] != {"engine": "elf-capstone-thumb-metadata", "read_only": True, "source_unchanged": True} or raw["truncated"] is not False:
        raise UIFactoryOwnerRegistrationError("export mode is not complete and read-only")
    owner = _exact(raw["owner"], {"range", "forwarding_edge", "direct_callers"}, "owner")
    if owner["range"] != OWNER_RANGE or owner["forwarding_edge"] != FORWARDING_EDGE or owner["direct_callers"] != []:
        raise UIFactoryOwnerRegistrationError("owner range, edge, or direct caller result is not exact")
    references = raw["typed_registration_references"]
    if not isinstance(references, list) or len(references) > 128:
        raise UIFactoryOwnerRegistrationError("typed registration references are unbounded")
    normalized_references = [_normalized_reference(reference) for reference in references]
    if len({json.dumps(reference, sort_keys=True) for reference in normalized_references}) != len(normalized_references):
        raise UIFactoryOwnerRegistrationError("duplicate typed registration reference")
    if normalized_references != RELATIVE_REGISTRATIONS:
        raise UIFactoryOwnerRegistrationError("typed owner registration result is not the exact relative-relocation set")
    if raw["orientation_imports"] != ORIENTATION_IMPORTS:
        raise UIFactoryOwnerRegistrationError("orientation import-to-PLT owner evidence is not exact")
    paths = raw["direct_path_summary"]
    expected_paths = {key: list(value) if isinstance(value, tuple) else value for key, value in PATH_SUMMARY.items()}
    if paths != expected_paths:
        raise UIFactoryOwnerRegistrationError("direct-path negative result is not exact or bounded")
    return {
        "schema_version": 1,
        "program": "viewUnified7.so",
        "sha256": VIEW_UNIFIED7_SHA256,
        "image_size": VIEW_UNIFIED7_SIZE,
        "analysis_mode": copy.deepcopy(raw["analysis_mode"]),
        "owner": copy.deepcopy(owner),
        "typed_registration_references": normalized_references,
        "orientation_imports": copy.deepcopy(ORIENTATION_IMPORTS),
        "direct_path_summary": copy.deepcopy(paths),
        "claims": copy.deepcopy(CLAIMS),
        "behavior_support": copy.deepcopy(BEHAVIOR_SUPPORT),
        "truncated": False,
    }


def summarize_ui_factory_owner_registration_export(document):
    normalized = normalize_ui_factory_owner_registration_export(document)
    encoded = (json.dumps(normalized, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    return {
        "canonical_export_sha256": hashlib.sha256(encoded).hexdigest(),
        "typed_registration_reference_count": len(normalized["typed_registration_references"]),
        "direct_owner_caller_count": len(normalized["owner"]["direct_callers"]),
    }


def build_ui_factory_owner_registration_report(export_document):
    """Build the deterministic registration report from validated ELF metadata."""
    normalized = normalize_ui_factory_owner_registration_export(export_document)
    summary = summarize_ui_factory_owner_registration_export(export_document)
    return {
        "schema_version": 1, "analysis_scope": "offline-static-ui-factory-owner-registration",
        "camera_policy": "physically-disconnected", "camera_executed": False, "installable": False,
        "camera_test_eligible": False,
        "source": {"module": "lib/viewUnified7.so", "size": VIEW_UNIFIED7_SIZE, "sha256": VIEW_UNIFIED7_SHA256},
        "export_summary": summary,
        "owner": {"range": {key: f"0x{value:x}" for key, value in OWNER_RANGE.items()}, "forwarding_edge": {key: (f"0x{value:x}" if key in {"caller", "site", "target"} else value) for key, value in FORWARDING_EDGE.items()}, "direct_callers": []},
        "registrations": [{key: (f"0x{value:x}" if key in {"address", "target", "thumb_pointer"} else value) for key, value in item.items()} for item in RELATIVE_REGISTRATIONS],
        "claims": copy.deepcopy(normalized["claims"]), "behavior_support": copy.deepcopy(normalized["behavior_support"]),
        "readiness": "TYPED_WRAPPER_REGISTRATION_BOUNDED_INVOCATION_UNESTABLISHED",
        "conclusion": "Five R_ARM_RELATIVE address-taken wrapper registrations are bounded. Registration is not invocation; no direct viewUnified2-to-factory, orientation, geometry, touch, or menu join is established by this static slice.",
    }


def validate_ui_factory_owner_registration_report(document):
    _forbid(document)
    report = _exact(document, {
        "schema_version", "analysis_scope", "camera_policy", "camera_executed", "installable",
        "camera_test_eligible", "source", "export_summary", "owner", "registrations", "claims",
        "behavior_support", "readiness", "conclusion",
    }, "owner registration report")
    if report["schema_version"] != 1 or report["analysis_scope"] != "offline-static-ui-factory-owner-registration" or report["camera_policy"] != "physically-disconnected":
        raise UIFactoryOwnerRegistrationError("report scope is invalid")
    if any(report[field] is not False for field in ("camera_executed", "installable", "camera_test_eligible")):
        raise UIFactoryOwnerRegistrationError("report camera safety is invalid")
    if report["source"] != {"module": "lib/viewUnified7.so", "size": VIEW_UNIFIED7_SIZE, "sha256": VIEW_UNIFIED7_SHA256}:
        raise UIFactoryOwnerRegistrationError("report source is invalid")
    summary = _exact(report["export_summary"], {"canonical_export_sha256", "typed_registration_reference_count", "direct_owner_caller_count"}, "report summary")
    if summary["canonical_export_sha256"] != REPORT_CANONICAL_EXPORT_SHA256 or not _DIGEST.fullmatch(summary["canonical_export_sha256"]) or summary["typed_registration_reference_count"] != 5 or summary["direct_owner_caller_count"] != 0:
        raise UIFactoryOwnerRegistrationError("report summary is invalid")
    if report["owner"] != {"range": {"start": "0x529cc", "end": "0x529e8"}, "forwarding_edge": {"caller": "0x529cc", "site": "0x529d6", "target": "0x52840", "kind": "direct"}, "direct_callers": []}:
        raise UIFactoryOwnerRegistrationError("report owner result is invalid")
    expected_registrations = [{key: (f"0x{value:x}" if key in {"address", "target", "thumb_pointer"} else value) for key, value in item.items()} for item in RELATIVE_REGISTRATIONS]
    if report["registrations"] != expected_registrations or report["claims"] != CLAIMS or report["behavior_support"] != BEHAVIOR_SUPPORT or report["readiness"] != "TYPED_WRAPPER_REGISTRATION_BOUNDED_INVOCATION_UNESTABLISHED" or "Registration is not invocation" not in report["conclusion"]:
        raise UIFactoryOwnerRegistrationError("report promotes unestablished behavior")
    return copy.deepcopy(report)
