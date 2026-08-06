"""Fail-closed loader/GOT boundary for α6400 UI layout-header relocations."""

from __future__ import annotations

import copy
import hashlib
import json
import re


class UILayoutHeaderGotBoundaryError(ValueError):
    """Raised when evidence exceeds the bounded static loader/GOT result."""


VIEW_UNIFIED7_SIZE = 541_024
VIEW_UNIFIED7_SHA256 = "c48cde43ff22d808ad23c42019ddae516fff7da060004eb81ed2bb85012aa538"
VTABLE_DIGEST = "5091e8d299df9b16b043b11578d3ed306c6d289dd778a1c72ccff0c76b0adca9"
SLOT34_DISPATCH_DIGEST = "7ffc38879262336103be44ea060ec8d958d98ec6ae6b7b67a43f893b2d633ab5"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_FORBIDDEN = {
    "bytes", "raw", "raw_bytes", "disassembly", "instructions", "key_material",
    "private_key", "device", "device_path", "write", "write_command", "flash",
    "package", "object_membership", "table_membership", "adjacency_inference",
}

_LAYOUT_HEADER_RELOCATIONS = (
    (1629, 0x72288, 0x70F10),
    (1633, 0x72298, 0x70FB0),
    (1684, 0x7236C, 0x71060),
    (1739, 0x72468, 0x71110),
    (1744, 0x7247C, 0x70E58),
)
_PRIOR_VTABLE = {"analysis_contract": "ui_layout_vtable_interface", "canonical_export_sha256": VTABLE_DIGEST}
_PRIOR_SLOT34 = {"analysis_contract": "ui_slot34_dispatch", "canonical_export_sha256": SLOT34_DISPATCH_DIGEST}
CLAIMS = {
    "typed_consumer_found": False,
    "factory_or_resource_owner_found": False,
    "orientation_layout_selector_found": False,
}
BEHAVIOR_SUPPORT = {
    "touch_coordinate_transform": False,
    "menu_touch_hit_test": False,
    "menu_touch_selection": False,
}
READINESS = "LOADER_GOT_METADATA_BOUNDARY_EXTERNAL_CONSUMERS_UNRESOLVED"
CONCLUSION = "The five layout-header records are unsymbolized R_ARM_RELATIVE loader/GOT metadata, not typed object or factory evidence. The separately named Creative Style root is an independent R_ARM_GLOB_DAT import; typed consumers, selection, coordinate, and touch routes remain unresolved."


def _forbid(value):
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str) or key.casefold().replace("-", "_") in _FORBIDDEN:
                raise UILayoutHeaderGotBoundaryError("forbidden reconstructive or unsafe field")
            _forbid(nested)
    elif isinstance(value, list):
        for nested in value:
            _forbid(nested)


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise UILayoutHeaderGotBoundaryError(f"{label} fields are not exact")
    return value


def _address(value, label):
    if type(value) is not int or value < 0 or value >= VIEW_UNIFIED7_SIZE or value & 3:
        raise UILayoutHeaderGotBoundaryError(f"{label} is not an aligned module address")
    return value


def _layout_header_record(index, site, header):
    return {
        "relocation_index": index,
        "site": site,
        "relocation_type": "R_ARM_RELATIVE",
        "symbol_index": 0,
        "addend": header,
        "header": header,
        "site_symbol_coverage": {"exact": [], "covering": []},
        "header_symbol_coverage": {"exact": [], "covering": []},
    }


EXPECTED_RAW_EXPORT = {
    "schema_version": 1,
    "program": "viewUnified7.so",
    "sha256": VIEW_UNIFIED7_SHA256,
    "image_size": VIEW_UNIFIED7_SIZE,
    "analysis_mode": {"engine": "elf-got-relocation-dynsym", "read_only": True, "source_unchanged": True},
    "prior_vtable_interface": copy.deepcopy(_PRIOR_VTABLE),
    "prior_slot34_dispatch": copy.deepcopy(_PRIOR_SLOT34),
    "got_section": {"name": ".got", "start": 0x71B0C, "end": 0x724F0},
    "layout_header_relocations": [_layout_header_record(*item) for item in _LAYOUT_HEADER_RELOCATIONS],
    "unsymbolized_relative_got_count": 194,
    "separated_named_import": {
        "relocation_index": 3858,
        "site": 0x72434,
        "relocation_type": "R_ARM_GLOB_DAT",
        "symbol_index": 544,
        "symbol": "cmnViewSettingNodeRootCreativeStyle",
    },
    "claims": copy.deepcopy(CLAIMS),
    "behavior_support": copy.deepcopy(BEHAVIOR_SUPPORT),
    "truncated": False,
}


def normalize_ui_layout_header_got_boundary_export(document):
    """Accept only the exact five unsymbolized loader/GOT records."""

    _forbid(document)
    raw = _exact(document, set(EXPECTED_RAW_EXPORT), "layout-header GOT export")
    if raw["schema_version"] != 1 or raw["program"] != "viewUnified7.so" or raw["sha256"] != VIEW_UNIFIED7_SHA256 or raw["image_size"] != VIEW_UNIFIED7_SIZE:
        raise UILayoutHeaderGotBoundaryError("source identity is not exact")
    if raw["analysis_mode"] != EXPECTED_RAW_EXPORT["analysis_mode"] or raw["truncated"] is not False:
        raise UILayoutHeaderGotBoundaryError("analysis mode is not read-only and complete")
    if raw["prior_vtable_interface"] != _PRIOR_VTABLE or raw["prior_slot34_dispatch"] != _PRIOR_SLOT34:
        raise UILayoutHeaderGotBoundaryError("prior evidence linkage is not pinned")
    got = _exact(raw["got_section"], {"name", "start", "end"}, "GOT section")
    if got != EXPECTED_RAW_EXPORT["got_section"]:
        raise UILayoutHeaderGotBoundaryError("GOT section bounds are not exact")
    records = raw["layout_header_relocations"]
    if not isinstance(records, list) or records != EXPECTED_RAW_EXPORT["layout_header_relocations"]:
        raise UILayoutHeaderGotBoundaryError("layout-header relocation evidence is not exact")
    for record in records:
        _exact(record, {"relocation_index", "site", "relocation_type", "symbol_index", "addend", "header", "site_symbol_coverage", "header_symbol_coverage"}, "layout-header relocation")
        _address(record["site"], "layout-header relocation site")
        _address(record["addend"], "layout-header addend")
        _address(record["header"], "layout-header header")
        _exact(record["site_symbol_coverage"], {"exact", "covering"}, "GOT-cell dynamic-symbol coverage")
        _exact(record["header_symbol_coverage"], {"exact", "covering"}, "header dynamic-symbol coverage")
    if raw["unsymbolized_relative_got_count"] != 194:
        raise UILayoutHeaderGotBoundaryError("unsymbolized relative GOT population is not exact")
    if raw["separated_named_import"] != EXPECTED_RAW_EXPORT["separated_named_import"]:
        raise UILayoutHeaderGotBoundaryError("named import was conflated with loader records")
    if raw["claims"] != CLAIMS or raw["behavior_support"] != BEHAVIOR_SUPPORT:
        raise UILayoutHeaderGotBoundaryError("unestablished UI behavior was promoted")
    return copy.deepcopy(raw)


def summarize_ui_layout_header_got_boundary_export(document):
    normalized = normalize_ui_layout_header_got_boundary_export(document)
    encoded = (json.dumps(normalized, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    return {
        "canonical_export_sha256": hashlib.sha256(encoded).hexdigest(),
        "layout_header_relocation_count": 5,
        "unsymbolized_relative_got_count": 194,
        "named_import_count": 1,
    }


def validate_ui_layout_header_got_boundary_report(document):
    _forbid(document)
    report = _exact(document, {
        "schema_version", "analysis_scope", "camera_policy", "camera_executed", "installable",
        "camera_test_eligible", "source", "export_summary", "prior_vtable_interface",
        "prior_slot34_dispatch", "got_section", "layout_header_relocations", "separated_named_import",
        "claims", "behavior_support", "readiness", "conclusion",
    }, "layout-header GOT report")
    if report["schema_version"] != 1 or report["analysis_scope"] != "offline-static-ui-layout-header-got-boundary" or report["camera_policy"] != "physically-disconnected":
        raise UILayoutHeaderGotBoundaryError("report scope is invalid")
    if any(report[key] is not False for key in ("camera_executed", "installable", "camera_test_eligible")):
        raise UILayoutHeaderGotBoundaryError("report safety flags are invalid")
    if report["source"] != {"module": "lib/viewUnified7.so", "size": VIEW_UNIFIED7_SIZE, "sha256": VIEW_UNIFIED7_SHA256}:
        raise UILayoutHeaderGotBoundaryError("report source is invalid")
    expected = summarize_ui_layout_header_got_boundary_export(EXPECTED_RAW_EXPORT)
    if report["export_summary"] != expected or not _DIGEST.fullmatch(report["export_summary"]["canonical_export_sha256"]):
        raise UILayoutHeaderGotBoundaryError("report summary is not pinned")
    if report["prior_vtable_interface"] != _PRIOR_VTABLE or report["prior_slot34_dispatch"] != _PRIOR_SLOT34:
        raise UILayoutHeaderGotBoundaryError("report prior linkage is invalid")
    if report["got_section"] != {"name": ".got", "start": "0x71b0c", "end": "0x724f0"}:
        raise UILayoutHeaderGotBoundaryError("report GOT boundary is invalid")
    expected_records = [
        {"relocation_index": item["relocation_index"], "site": f"0x{item['site']:x}", "addend": f"0x{item['addend']:x}", "symbol_index": 0, "site_symbol_coverage": {"exact": [], "covering": []}, "header_symbol_coverage": {"exact": [], "covering": []}}
        for item in EXPECTED_RAW_EXPORT["layout_header_relocations"]
    ]
    if report["layout_header_relocations"] != expected_records or report["separated_named_import"] != EXPECTED_RAW_EXPORT["separated_named_import"]:
        raise UILayoutHeaderGotBoundaryError("report relocation facts are invalid")
    if report["claims"] != CLAIMS or report["behavior_support"] != BEHAVIOR_SUPPORT or report["readiness"] != READINESS or report["conclusion"] != CONCLUSION:
        raise UILayoutHeaderGotBoundaryError("report promotes unestablished behavior")
    return copy.deepcopy(report)
