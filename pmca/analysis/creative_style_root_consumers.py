"""Fail-closed α6400 Creative Style root-cell consumer evidence contract."""

from __future__ import annotations

import copy
import hashlib
import json
import re


class CreativeStyleRootConsumersError(ValueError):
    """Raised when evidence exceeds the bounded static root-cell result."""


VIEW_UNIFIED7_SIZE = 541_024
VIEW_UNIFIED7_SHA256 = "c48cde43ff22d808ad23c42019ddae516fff7da060004eb81ed2bb85012aa538"
UI_LAYOUT_HEADER_GOT_BOUNDARY_DIGEST = "339ee0b43ca7f8e23dff6118733bf028e0d0446e5294130a4fe82f77815e51de"
CREATIVE_STYLE_SYMBOL = "cmnViewSettingNodeRootCreativeStyle"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_FORBIDDEN = {
    "bytes", "raw", "raw_bytes", "disassembly", "instructions", "key_material",
    "private_key", "device", "device_path", "write", "write_command", "flash",
    "package", "installation", "camera_testing", "arbitrary_pointer_scan",
    "unknown_base_guess", "unknown_base_candidates", "adjacency_inference",
    "object_membership", "table_membership", "fabricated_consumer",
}

_PRIOR = {
    "analysis_contract": "ui_layout_header_got_boundary",
    "canonical_export_sha256": UI_LAYOUT_HEADER_GOT_BOUNDARY_DIGEST,
}
_SYMBOL = {
    "index": 544,
    "name": CREATIVE_STYLE_SYMBOL,
    "binding": "STB_GLOBAL",
    "visibility": "STV_DEFAULT",
    "section_index": "SHN_UNDEF",
}
_RELOCATIONS = (
    {
        "index": 3858,
        "site": 0x72434,
        "relocation_type": "R_ARM_GLOB_DAT",
        "symbol_index": 544,
        "section": ".got",
    },
    {
        "index": 3859,
        "site": 0x8056C,
        "relocation_type": "R_ARM_ABS32",
        "symbol_index": 544,
        "section": ".data",
    },
)
_EMPTY_COVERAGE = {
    "dynamic": {"exact": [], "covering": []},
    "static": {"table_present": False, "exact": [], "covering": []},
}
CLAIMS = {
    "creative_style_selection_found": False,
    "layout_or_orientation_selection_found": False,
    "touch_coordinate_transform": False,
    "menu_touch_hit_test": False,
    "menu_touch_selection": False,
}
READINESS = "LOCAL_CREATIVE_STYLE_ROOT_CONSUMERS_NOT_FOUND_EXTERNAL_ROUTES_UNRESOLVED"
CONCLUSION = "No provenance-backed local load from either Creative Style root relocation cell was found across the bounded Thumb and ARM executable-range scan. External-module, callback, and unknown-base consumers remain unresolved."

EXPECTED_RAW_EXPORT = {
    "schema_version": 1,
    "program": "viewUnified7.so",
    "sha256": VIEW_UNIFIED7_SHA256,
    "image_size": VIEW_UNIFIED7_SIZE,
    "analysis_mode": {
        "engine": "elf-capstone-root-cell-provenance",
        "read_only": True,
        "source_unchanged": True,
    },
    "prior_ui_layout_header_got_boundary": copy.deepcopy(_PRIOR),
    "dynamic_symbol": copy.deepcopy(_SYMBOL),
    "relocations": [copy.deepcopy(item) for item in _RELOCATIONS],
    "plt": {"relocation_section": ".rel.plt", "symbol_relocation_indices": []},
    "data_cell_symbol_coverage": copy.deepcopy(_EMPTY_COVERAGE),
    "executable_scan": {
        "range_count": 1358,
        "thumb_range_count": 1358,
        "arm_range_count": 1358,
        "address_provenance": {
            "literal_load": True,
            "pc_relative_arithmetic": True,
            "movw_movt": True,
        },
        "root_cells": [0x72434, 0x8056C],
        "accepted_candidates": [],
    },
    "root_path_summary": {
        "pinned_layout_or_orientation_root_count": 20,
        "paths_to_accepted_candidates": [],
    },
    "claims": copy.deepcopy(CLAIMS),
    "truncated": False,
}


def _forbid(value):
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str) or key.casefold().replace("-", "_") in _FORBIDDEN:
                raise CreativeStyleRootConsumersError("forbidden reconstructive or unsafe field")
            _forbid(nested)
    elif isinstance(value, list):
        for nested in value:
            _forbid(nested)


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise CreativeStyleRootConsumersError(f"{label} fields are not exact")
    return value


def _address(value, label):
    if type(value) is not int or value < 0 or value >= VIEW_UNIFIED7_SIZE or value & 3:
        raise CreativeStyleRootConsumersError(f"{label} is not an aligned source address")
    return value


def normalize_creative_style_root_consumers_export(document):
    """Accept only the exact bounded zero-result local root-cell search."""

    _forbid(document)
    raw = _exact(document, set(EXPECTED_RAW_EXPORT), "Creative Style root consumer export")
    if raw["schema_version"] != 1 or raw["program"] != "viewUnified7.so" or raw["sha256"] != VIEW_UNIFIED7_SHA256 or raw["image_size"] != VIEW_UNIFIED7_SIZE:
        raise CreativeStyleRootConsumersError("source identity is not exact")
    if raw["analysis_mode"] != EXPECTED_RAW_EXPORT["analysis_mode"] or raw["truncated"] is not False:
        raise CreativeStyleRootConsumersError("analysis mode is not complete and read-only")
    if raw["prior_ui_layout_header_got_boundary"] != _PRIOR:
        raise CreativeStyleRootConsumersError("prior UI layout-header evidence is not pinned")
    if raw["dynamic_symbol"] != _SYMBOL:
        raise CreativeStyleRootConsumersError("Creative Style dynamic symbol is not exact")
    if raw["relocations"] != list(_RELOCATIONS):
        raise CreativeStyleRootConsumersError("Creative Style relocation records are not exact")
    for record in raw["relocations"]:
        _address(record["site"], "Creative Style relocation site")
    if raw["plt"] != EXPECTED_RAW_EXPORT["plt"]:
        raise CreativeStyleRootConsumersError("Creative Style PLT evidence is not exact")
    if raw["data_cell_symbol_coverage"] != _EMPTY_COVERAGE:
        raise CreativeStyleRootConsumersError("data root cell has fabricated symbol coverage")
    scan = _exact(raw["executable_scan"], {
        "range_count", "thumb_range_count", "arm_range_count", "address_provenance",
        "root_cells", "accepted_candidates",
    }, "executable scan")
    if scan != EXPECTED_RAW_EXPORT["executable_scan"]:
        raise CreativeStyleRootConsumersError("root-cell consumer scan exceeds the pinned provenance result")
    for cell in scan["root_cells"]:
        _address(cell, "root relocation cell")
    if raw["root_path_summary"] != EXPECTED_RAW_EXPORT["root_path_summary"]:
        raise CreativeStyleRootConsumersError("layout/orientation root path was fabricated")
    if raw["claims"] != CLAIMS:
        raise CreativeStyleRootConsumersError("unestablished Creative Style or touch behavior was promoted")
    return copy.deepcopy(raw)


def summarize_creative_style_root_consumers_export(document):
    normalized = normalize_creative_style_root_consumers_export(document)
    encoded = (json.dumps(normalized, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    return {
        "canonical_export_sha256": hashlib.sha256(encoded).hexdigest(),
        "root_relocation_count": 2,
        "executable_range_count": 1358,
        "accepted_candidate_count": 0,
        "plt_relocation_count": 0,
    }


def validate_creative_style_root_consumers_report(document):
    _forbid(document)
    report = _exact(document, {
        "schema_version", "analysis_scope", "camera_policy", "camera_executed", "installable",
        "camera_test_eligible", "source", "export_summary", "prior_ui_layout_header_got_boundary",
        "root_relocations", "data_cell_symbol_coverage", "executable_scan", "root_path_summary",
        "claims", "readiness", "conclusion",
    }, "Creative Style root consumer report")
    if report["schema_version"] != 1 or report["analysis_scope"] != "offline-static-creative-style-root-consumers" or report["camera_policy"] != "physically-disconnected":
        raise CreativeStyleRootConsumersError("report scope is invalid")
    if any(report[key] is not False for key in ("camera_executed", "installable", "camera_test_eligible")):
        raise CreativeStyleRootConsumersError("report safety flags are invalid")
    if report["source"] != {"module": "lib/viewUnified7.so", "size": VIEW_UNIFIED7_SIZE, "sha256": VIEW_UNIFIED7_SHA256}:
        raise CreativeStyleRootConsumersError("report source is invalid")
    expected = summarize_creative_style_root_consumers_export(EXPECTED_RAW_EXPORT)
    if report["export_summary"] != expected or not _DIGEST.fullmatch(report["export_summary"]["canonical_export_sha256"]):
        raise CreativeStyleRootConsumersError("report export digest is unpinned")
    if report["prior_ui_layout_header_got_boundary"] != _PRIOR:
        raise CreativeStyleRootConsumersError("report prior UI evidence is invalid")
    expected_relocations = [
        {"index": item["index"], "site": f"0x{item['site']:x}", "relocation_type": item["relocation_type"], "section": item["section"]}
        for item in _RELOCATIONS
    ]
    expected_scan = {
        "range_count": 1358,
        "thumb_range_count": 1358,
        "arm_range_count": 1358,
        "accepted_candidate_count": 0,
    }
    if report["root_relocations"] != expected_relocations or report["data_cell_symbol_coverage"] != _EMPTY_COVERAGE or report["executable_scan"] != expected_scan or report["root_path_summary"] != EXPECTED_RAW_EXPORT["root_path_summary"] or report["claims"] != CLAIMS or report["readiness"] != READINESS or report["conclusion"] != CONCLUSION:
        raise CreativeStyleRootConsumersError("report promotes unestablished root consumers")
    return copy.deepcopy(report)
