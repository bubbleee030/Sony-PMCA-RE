"""Fail-closed metadata contract for α6400 UI layout virtual dispatch."""

from __future__ import annotations

import copy
import hashlib
import json
import re


class UILayoutVtableInterfaceError(ValueError):
    """Raised when metadata exceeds this bounded typed-interface result."""


VIEW_UNIFIED7_SIZE = 541_024
VIEW_UNIFIED7_SHA256 = "c48cde43ff22d808ad23c42019ddae516fff7da060004eb81ed2bb85012aa538"
OWNER = 0x529CC
THUMB_OWNER = OWNER | 1
TYPEINFO_SYMBOL = "_ZTVN10__cxxabiv120__si_class_type_infoE"
OWNER_REGISTRATION_DIGEST = "a6a669db167c7335a65cd3015c59a20a08af4b8de46330a4ca1c3231fa2b8e0a"
EXPECTED_PRIOR_OWNER_REGISTRATION = {"analysis_contract": "ui_factory_owner_registration", "canonical_export_sha256": OWNER_REGISTRATION_DIGEST}
EXPECTED_OWNER = {"range": {"start": OWNER, "end": 0x529E8}, "forwarding_edge": {"caller": OWNER, "site": 0x529D6, "target": 0x52840, "kind": "direct"}, "evidence": {"owner_kind": "ARM.exidx-function", "call_kind": "thumb-direct"}}
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_FORBIDDEN = {"bytes", "raw_bytes", "disassembly", "instructions", "key_material", "private_key", "device", "device_path", "write", "write_command", "flash", "package"}

_TABLE_LAYOUT = (
    ("N14LG_viewtridial13LayoutST_DIALE", 0x70EF8, 0x70E58, 0x70E60, 0x70EF8, ((32, 0x520E5), (33, 0x520C9), (35, 0x518E5))),
    ("N14LG_viewtridial19LayoutConverterBaseE", 0x70F04, 0x70F10, 0x70F18, 0x70FB0, ((32, "_ZN2ux6wgtlay15LayoutConverter20isValidWidgetVersionEjjjjPKc"), (33, "_ZN2ux6wgtlay15LayoutConverter23isValidAnimationVersionEjjjjPKc"), (35, "_ZN2ux6wgtlay15LayoutConverter23getLayoutMasterWidgetIDEjRj"))),
    ("N14LG_viewtridial23LayoutST_DIAL_CLASSICALE", 0x71050, 0x70FB0, 0x70FB8, 0x71050, ((32, 0x52199), (33, 0x5217D), (35, 0x519B1))),
    ("N14LG_viewtridial32LayoutST_DIAL_CLASSICAL_PANORAMAE", 0x71100, 0x71060, 0x71068, 0x71100, ((32, 0x52259), (33, 0x5223D), (35, 0x51C25))),
    ("N14LG_viewtridial17LayoutST_DIAL_EVFE", 0x711B0, 0x71110, 0x71118, 0x711B0, ((32, 0x52319), (33, 0x522FD), (35, 0x51E79))),
)
_RTTI_NAMES = {
    "N14LG_viewtridial13LayoutST_DIALE": 0x5E7BE,
    "N14LG_viewtridial19LayoutConverterBaseE": 0x5E7E0,
    "N14LG_viewtridial23LayoutST_DIAL_CLASSICALE": 0x5E808,
    "N14LG_viewtridial32LayoutST_DIAL_CLASSICAL_PANORAMAE": 0x5E834,
    "N14LG_viewtridial17LayoutST_DIAL_EVFE": 0x5E869,
}
CLAIMS = {"common_layout_virtual_dispatch_hook_found": True, "target_native_layout_interface_types_found": 5, "factory_forwarding_owner_found": True, "orientation_layout_object_selector_found": False}
BEHAVIOR_SUPPORT = {"orientation_layout_object_selection": False, "touch_coordinate_transform": False, "menu_touch_hit_test": False, "menu_touch_selection": False}
READINESS = "COMMON_VIRTUAL_DISPATCH_HOOK_OBJECT_SELECTION_UNESTABLISHED"
CONCLUSION = "Five RTTI-backed target-native layout vtables share slot 34, which resolves through typed relocations to the bounded forwarding owner. No ordered orientation or layout-mode path selecting one of these objects is established; coordinate and touch behavior remain unproven."
CANONICAL_EXPORT_SHA256 = "5091e8d299df9b16b043b11578d3ed306c6d289dd778a1c72ccff0c76b0adca9"


def _forbid(value):
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str) or key.casefold().replace("-", "_") in _FORBIDDEN:
                raise UILayoutVtableInterfaceError("forbidden material")
            _forbid(nested)
    elif isinstance(value, list):
        for nested in value:
            _forbid(nested)


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise UILayoutVtableInterfaceError(f"{label} fields are not exact")
    return value


def _address(value, label):
    if type(value) is not int or not 0 <= value < VIEW_UNIFIED7_SIZE or value & 3:
        raise UILayoutVtableInterfaceError(f"{label} is not an aligned module address")
    return value


def _relative_data(address, target):
    return {"address": address, "section_name": ".rel.dyn", "relocation_type": "R_ARM_RELATIVE", "evidence_kind": "relocation", "target": target}


def _relative_code(address, thumb_target):
    return {"address": address, "section_name": ".rel.dyn", "relocation_type": "R_ARM_RELATIVE", "evidence_kind": "relocation", "thumb_target": thumb_target}


def _rtti_record(name, rtti, header):
    return {"address": rtti, "class_typeinfo_relocation": {"address": rtti, "section_name": ".rel.dyn", "relocation_type": "R_ARM_ABS32", "symbol": TYPEINFO_SYMBOL, "evidence_kind": "relocation"}, "name_relocation": _relative_data(rtti + 4, _RTTI_NAMES[name])}


def _slot(index, address, expected):
    if index == 34:
        return {"index": 34, "address": address, "relocation": _relative_code(address, THUMB_OWNER), "normalized_owner": OWNER}
    if isinstance(expected, str):
        relocation = {"address": address, "section_name": ".rel.dyn", "relocation_type": "R_ARM_ABS32", "evidence_kind": "relocation", "symbol": expected}
        return {"index": index, "address": address, "relocation": relocation}
    return {"index": index, "address": address, "relocation": _relative_code(address, expected), "normalized_owner": expected & ~1}


def _table(name, rtti, header, address_point, end, adjacent):
    lookup = dict(adjacent)
    slots = [_slot(index, address_point + index * 4, lookup.get(index, THUMB_OWNER)) for index in (32, 33, 34, 35)]
    return {"class_name": name, "rtti": _rtti_record(name, rtti, header), "vtable": {"header": header, "address_point": address_point, "end": end, "rtti_relocation": _relative_data(header + 4, rtti), "slots": slots}}


EXPECTED_TABLES = tuple(_table(*item) for item in _TABLE_LAYOUT)


def normalize_ui_layout_vtable_interface_export(document):
    """Accept only the five relocation- and RTTI-backed layout tables."""

    _forbid(document)
    raw = _exact(document, {"schema_version", "program", "sha256", "image_size", "analysis_mode", "prior_owner_registration", "owner", "tables", "truncated"}, "layout vtable export")
    if raw["schema_version"] != 1 or raw["program"] != "viewUnified7.so" or raw["sha256"] != VIEW_UNIFIED7_SHA256 or raw["image_size"] != VIEW_UNIFIED7_SIZE:
        raise UILayoutVtableInterfaceError("source identity is invalid")
    if raw["analysis_mode"] != {"engine": "elf-relocation-rtti", "read_only": True, "source_unchanged": True} or raw["truncated"] is not False:
        raise UILayoutVtableInterfaceError("analysis mode is not complete and read-only")
    if raw["prior_owner_registration"] != EXPECTED_PRIOR_OWNER_REGISTRATION or raw["owner"] != EXPECTED_OWNER:
        raise UILayoutVtableInterfaceError("forwarding-owner provenance is not exact")
    if not isinstance(raw["tables"], list) or len(raw["tables"]) != len(EXPECTED_TABLES):
        raise UILayoutVtableInterfaceError("vtable membership is incomplete")
    for table in raw["tables"]:
        _exact(table, {"class_name", "rtti", "vtable"}, "layout vtable")
        rtti = _exact(table["rtti"], {"address", "class_typeinfo_relocation", "name_relocation"}, "RTTI")
        vtable = _exact(table["vtable"], {"header", "address_point", "end", "rtti_relocation", "slots"}, "vtable")
        for field in ("address",): _address(rtti[field], "RTTI")
        for field in ("header", "address_point", "end"): _address(vtable[field], "vtable")
        if not vtable["header"] < vtable["address_point"] < vtable["end"]:
            raise UILayoutVtableInterfaceError("vtable range is invalid")
    if raw["tables"] != [copy.deepcopy(item) for item in EXPECTED_TABLES]:
        raise UILayoutVtableInterfaceError("vtable typed evidence is not the exact pinned result")
    ranges = [(item["vtable"]["header"], item["vtable"]["end"]) for item in raw["tables"]]
    if any(left[1] > right[0] for left, right in zip(ranges, ranges[1:])):
        raise UILayoutVtableInterfaceError("vtable ranges overlap")
    return {"schema_version": 1, "program": "viewUnified7.so", "sha256": VIEW_UNIFIED7_SHA256, "image_size": VIEW_UNIFIED7_SIZE, "analysis_mode": copy.deepcopy(raw["analysis_mode"]), "prior_owner_registration": copy.deepcopy(EXPECTED_PRIOR_OWNER_REGISTRATION), "owner": copy.deepcopy(EXPECTED_OWNER), "tables": copy.deepcopy(raw["tables"]), "claims": copy.deepcopy(CLAIMS), "behavior_support": copy.deepcopy(BEHAVIOR_SUPPORT), "truncated": False}


def summarize_ui_layout_vtable_interface_export(document):
    normalized = normalize_ui_layout_vtable_interface_export(document)
    encoded = (json.dumps(normalized, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    return {"canonical_export_sha256": hashlib.sha256(encoded).hexdigest(), "table_count": len(normalized["tables"]), "slot_34_owner_count": len(normalized["tables"]), "claims": copy.deepcopy(CLAIMS)}


def validate_ui_layout_vtable_interface_report(document):
    _forbid(document)
    report = _exact(document, {"schema_version", "analysis_scope", "camera_policy", "camera_executed", "installable", "camera_test_eligible", "source", "export_summary", "prior_owner_registration", "owner", "tables", "claims", "behavior_support", "readiness", "conclusion"}, "layout vtable report")
    if report["schema_version"] != 1 or report["analysis_scope"] != "offline-static-ui-layout-vtable-interface" or report["camera_policy"] != "physically-disconnected":
        raise UILayoutVtableInterfaceError("report scope is invalid")
    if any(report[key] is not False for key in ("camera_executed", "installable", "camera_test_eligible")):
        raise UILayoutVtableInterfaceError("report safety flags are invalid")
    if report["source"] != {"module": "lib/viewUnified7.so", "size": VIEW_UNIFIED7_SIZE, "sha256": VIEW_UNIFIED7_SHA256}:
        raise UILayoutVtableInterfaceError("report source is invalid")
    expected_owner = {"range": {"start": "0x529cc", "end": "0x529e8"}, "forwarding_edge": {"caller": "0x529cc", "site": "0x529d6", "target": "0x52840", "kind": "direct"}, "evidence": copy.deepcopy(EXPECTED_OWNER["evidence"])}
    if report["prior_owner_registration"] != EXPECTED_PRIOR_OWNER_REGISTRATION or report["owner"] != expected_owner:
        raise UILayoutVtableInterfaceError("report owner provenance is invalid")
    summary = _exact(report["export_summary"], {"canonical_export_sha256", "table_count", "slot_34_owner_count"}, "report export summary")
    if summary["canonical_export_sha256"] != CANONICAL_EXPORT_SHA256 or not _DIGEST.fullmatch(summary["canonical_export_sha256"]) or summary["table_count"] != 5 or summary["slot_34_owner_count"] != 5:
        raise UILayoutVtableInterfaceError("report export summary is invalid")
    expected_tables = [{"class_name": item["class_name"], "rtti": f"0x{item['rtti']['address']:x}", "header": f"0x{item['vtable']['header']:x}", "address_point": f"0x{item['vtable']['address_point']:x}", "end": f"0x{item['vtable']['end']:x}", "slot_34": {"address": f"0x{item['vtable']['slots'][2]['address']:x}", "thumb_target": "0x529cd", "normalized_owner": "0x529cc"}} for item in EXPECTED_TABLES]
    if report["tables"] != expected_tables or report["claims"] != CLAIMS or report["behavior_support"] != BEHAVIOR_SUPPORT or report["readiness"] != READINESS or report["conclusion"] != CONCLUSION:
        raise UILayoutVtableInterfaceError("report promotes unestablished behavior")
    return copy.deepcopy(report)
