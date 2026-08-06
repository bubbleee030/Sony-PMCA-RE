"""Fail-closed evidence contract for the bounded α6400 UI slot-34 search."""

from __future__ import annotations

import copy
import hashlib
import json
import re


class UISlot34DispatchError(ValueError):
    """Raised when metadata exceeds the bounded static slot-34 result."""


VIEW_UNIFIED7_SIZE = 541_024
VIEW_UNIFIED7_SHA256 = "c48cde43ff22d808ad23c42019ddae516fff7da060004eb81ed2bb85012aa538"
OWNER = 0x529CC
SLOT_OFFSET = 0x88
VTABLE_DIGEST = "5091e8d299df9b16b043b11578d3ed306c6d289dd778a1c72ccff0c76b0adca9"
OWNER_DIGEST = "a6a669db167c7335a65cd3015c59a20a08af4b8de46330a4ca1c3231fa2b8e0a"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_FORBIDDEN = {"bytes", "raw", "raw_bytes", "disassembly", "instructions", "key_material", "private_key", "device", "device_path", "write", "flash", "package"}

_TABLES = (
    ("N14LG_viewtridial13LayoutST_DIALE", 0x70EF8, 0x70E58, 0x70E60, 0x70EF8, 0x70EE8, 0x7247C),
    ("N14LG_viewtridial19LayoutConverterBaseE", 0x70F04, 0x70F10, 0x70F18, 0x70FB0, 0x70FA0, 0x72288),
    ("N14LG_viewtridial23LayoutST_DIAL_CLASSICALE", 0x71050, 0x70FB0, 0x70FB8, 0x71050, 0x71040, 0x72298),
    ("N14LG_viewtridial32LayoutST_DIAL_CLASSICAL_PANORAMAE", 0x71100, 0x71060, 0x71068, 0x71100, 0x710F0, 0x7236C),
    ("N14LG_viewtridial17LayoutST_DIAL_EVFE", 0x711B0, 0x71110, 0x71118, 0x711B0, 0x711A0, 0x72468),
)
_ROOTS = (0x2D2C6, 0x30750, 0x189DC, 0x1B070, 0x1C56C, 0x193E0, 0x27458, 0x27540, 0x29660, 0x2D68C, 0x2D770, 0x2D82C, 0x3260C, 0x53598, 0x53B9C, 0x54440, 0x56CCC, 0x56D8C, 0x56E4C, 0x56F0C)


def _forbid(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or key.casefold().replace("-", "_") in _FORBIDDEN:
                raise UISlot34DispatchError("forbidden reconstructive or unsafe field")
            _forbid(child)
    elif isinstance(value, list):
        for child in value:
            _forbid(child)


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise UISlot34DispatchError(f"{label} fields are not exact")
    return value


def _address(value, label):
    if type(value) is not int or value < 0 or value >= VIEW_UNIFIED7_SIZE or value & 1:
        raise UISlot34DispatchError(f"{label} is not a normalized source address")
    return value


def _reference(name, rtti, header, address_point, end, slot_cell, reference_address):
    return {"class_name": name, "reference_address": reference_address, "addend": header, "relocation_type": "R_ARM_RELATIVE", "evidence_kind": "typed-relocation"}


def _table(name, rtti, header, address_point, end, slot_cell, reference_address):
    return {"class_name": name, "rtti": rtti, "header": header, "address_point": address_point, "end": end, "rtti_header_relocation": {"address": header + 4, "target": rtti, "relocation_type": "R_ARM_RELATIVE"}, "slot_34": {"address": slot_cell, "thumb_target": OWNER | 1, "normalized_owner": OWNER, "relocation_type": "R_ARM_RELATIVE"}, "incoming_header_reference": {"address": reference_address, "addend": header, "relocation_type": "R_ARM_RELATIVE"}}


def _rejected(kind, function, site, precedent=None):
    if kind == "pc-literal-slot-precedent":
        # These are direct PC-relative +0x88 loads, not a claim about a
        # preceding instruction.  The legacy call shape is normalized away.
        return {"kind": "direct-pc-literal-load", "function": function, "site": site}
    result = {"kind": kind, "function": function, "site": site}
    if precedent is not None:
        result["precedent"] = precedent
    return result


# The source-verifying exporter fills these exact bounded rejection records.
EXPECTED_STACK_REJECTIONS = (_rejected("stack-slot-load", 0x50058, 0x501EA),)
EXPECTED_LITERAL_REJECTIONS = tuple(_rejected("pc-literal-slot-precedent", function, site, site) for function, site in ((0x16014, 0x16AA2), (0x16014, 0x178E4), (0x16014, 0x17E54), (0x16014, 0x17F4C), (0x16014, 0x18044), (0x16014, 0x1813C), (0x197BC, 0x19B50), (0x19CB8, 0x19ED4), (0x1B418, 0x1B526), (0x1E484, 0x1E4C4), (0x1E484, 0x1E4CA), (0x1E484, 0x1E4CE), (0x1E484, 0x1E5F4), (0x1E484, 0x1E5F8), (0x1EB94, 0x1FC32), (0x1EB94, 0x20D70), (0x23324, 0x236E8), (0x26578, 0x2699C), (0x26C58, 0x26CB4), (0x2897C, 0x289F4), (0x28B54, 0x28C64), (0x2B210, 0x2B238), (0x2B210, 0x2B23E), (0x2ECB8, 0x2EF1C), (0x2EFC0, 0x2F106), (0x2F194, 0x2F2DA), (0x2F368, 0x2F4B0), (0x2F540, 0x2F678), (0x30750, 0x30902), (0x31A48, 0x31DD8), (0x31A48, 0x31F28), (0x3220C, 0x32210), (0x3220C, 0x32216), (0x34D70, 0x34F92), (0x35780, 0x35798), (0x37390, 0x373E8), (0x3A4C2, 0x3A604), (0x3E868, 0x3ED20), (0x4B830, 0x4B950), (0x51432, 0x514BC), (0x54D54, 0x54DB0), (0x54D54, 0x54DB6), (0x54D54, 0x54DBA), (0x54D54, 0x54ED8), (0x54D54, 0x54EDE), (0x54D54, 0x54EE2), (0x55924, 0x55D2E), (0x55924, 0x55E48), (0x5B0E0, 0x5B330), (0x5B3C8, 0x5BBFE), (0x5C0D4, 0x5C442)))
EXPECTED_LITERAL_REJECTIONS = EXPECTED_LITERAL_REJECTIONS + (_rejected("pc-literal-slot-precedent", 0x3EEC4, 0x3F53E, 0x3F53E),)
EXPECTED_LITERAL_REJECTIONS = tuple(sorted(EXPECTED_LITERAL_REJECTIONS, key=lambda item: (item["function"], item["site"])))
EXPECTED_RAW_EXPORT = {
    "schema_version": 1,
    "program": "viewUnified7.so",
    "sha256": VIEW_UNIFIED7_SHA256,
    "image_size": VIEW_UNIFIED7_SIZE,
    "analysis_mode": {"engine": "elf-capstone-thumb-structural", "read_only": True, "source_unchanged": True},
    "prior_vtable_interface": {"analysis_contract": "ui_layout_vtable_interface", "canonical_export_sha256": VTABLE_DIGEST},
    "prior_owner_registration": {"analysis_contract": "ui_factory_owner_registration", "canonical_export_sha256": OWNER_DIGEST},
    "owner": {"start": OWNER, "end": 0x529E8, "slot_offset": SLOT_OFFSET},
    "table_evidence": [_table(*item) for item in _TABLES],
    "header_references": [_reference(*item) for item in _TABLES],
    "structural_scan": {"rule": {"receiver_vptr_load_offset": 0, "slot_load_offset": SLOT_OFFSET, "indirect_call": "blx-register", "function_bounded": True}, "accepted_candidates": [], "rejected_stack_candidates": list(EXPECTED_STACK_REJECTIONS), "direct_pc_literal_loads": list(EXPECTED_LITERAL_REJECTIONS)},
    "direct_owner_inbound_edges": [],
    "root_path_summary": {"max_depth": 32, "roots": list(_ROOTS), "paths_to_owner": [], "paths_to_slot34_dispatch": []},
    "claims": {"slot_34_dispatch_found": False, "orientation_layout_selector_found": False},
    "behavior_support": {"touch_coordinate_transform": False, "menu_touch_hit_test": False, "menu_touch_selection": False},
    "truncated": False,
}


def _validate_rejection(value, kind, require_precedent):
    fields = {"kind", "function", "site"} | ({"precedent"} if require_precedent else set())
    record = _exact(value, fields, "rejected structural candidate")
    if record["kind"] != kind:
        raise UISlot34DispatchError("rejected candidate kind is invalid")
    _address(record["function"], "rejected candidate function")
    _address(record["site"], "rejected candidate site")
    if require_precedent:
        _address(record["precedent"], "PC-literal precedent")
    return record


def normalize_ui_slot34_dispatch_export(document):
    """Accept only the zero-result local structural dispatch search."""

    _forbid(document)
    raw = _exact(document, set(EXPECTED_RAW_EXPORT), "slot-34 export")
    if raw["schema_version"] != 1 or raw["program"] != "viewUnified7.so" or raw["sha256"] != VIEW_UNIFIED7_SHA256 or raw["image_size"] != VIEW_UNIFIED7_SIZE:
        raise UISlot34DispatchError("source identity is not exact")
    if raw["analysis_mode"] != EXPECTED_RAW_EXPORT["analysis_mode"] or raw["truncated"] is not False:
        raise UISlot34DispatchError("analysis mode is not complete and read-only")
    for key, expected in (("prior_vtable_interface", EXPECTED_RAW_EXPORT["prior_vtable_interface"]), ("prior_owner_registration", EXPECTED_RAW_EXPORT["prior_owner_registration"]), ("owner", EXPECTED_RAW_EXPORT["owner"]), ("table_evidence", EXPECTED_RAW_EXPORT["table_evidence"]), ("header_references", EXPECTED_RAW_EXPORT["header_references"]), ("direct_owner_inbound_edges", []), ("root_path_summary", EXPECTED_RAW_EXPORT["root_path_summary"]), ("claims", EXPECTED_RAW_EXPORT["claims"]), ("behavior_support", EXPECTED_RAW_EXPORT["behavior_support"])):
        if raw[key] != expected:
            raise UISlot34DispatchError(f"{key} is not the pinned bounded result")
    scan = _exact(raw["structural_scan"], {"rule", "accepted_candidates", "rejected_stack_candidates", "direct_pc_literal_loads"}, "structural scan")
    if scan["rule"] != EXPECTED_RAW_EXPORT["structural_scan"]["rule"] or scan["accepted_candidates"] != []:
        raise UISlot34DispatchError("structural virtual dispatch was fabricated")
    stack = [_validate_rejection(item, "stack-slot-load", False) for item in scan["rejected_stack_candidates"]]
    literals = [_validate_rejection(item, "direct-pc-literal-load", False) for item in scan["direct_pc_literal_loads"]]
    if tuple(stack) != EXPECTED_STACK_REJECTIONS or tuple(literals) != EXPECTED_LITERAL_REJECTIONS:
        raise UISlot34DispatchError("structural rejection evidence is not the exact bounded result")
    return copy.deepcopy(raw)


def summarize_ui_slot34_dispatch_export(document):
    normalized = normalize_ui_slot34_dispatch_export(document)
    encoded = (json.dumps(normalized, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    return {"canonical_export_sha256": hashlib.sha256(encoded).hexdigest(), "header_reference_count": 5, "accepted_candidate_count": 0, "stack_rejection_count": len(EXPECTED_STACK_REJECTIONS), "direct_pc_literal_load_count": len(EXPECTED_LITERAL_REJECTIONS)}


def validate_ui_slot34_dispatch_report(document):
    _forbid(document)
    report = _exact(document, {"schema_version", "analysis_scope", "camera_policy", "camera_executed", "installable", "camera_test_eligible", "source", "export_summary", "prior_vtable_interface", "prior_owner_registration", "structural_scan", "claims", "behavior_support", "readiness", "conclusion"}, "slot-34 report")
    if report["schema_version"] != 1 or report["analysis_scope"] != "offline-static-ui-slot34-dispatch" or report["camera_policy"] != "physically-disconnected":
        raise UISlot34DispatchError("report scope is invalid")
    if any(report[field] is not False for field in ("camera_executed", "installable", "camera_test_eligible")):
        raise UISlot34DispatchError("report safety flags are invalid")
    if report["source"] != {"module": "lib/viewUnified7.so", "size": VIEW_UNIFIED7_SIZE, "sha256": VIEW_UNIFIED7_SHA256}:
        raise UISlot34DispatchError("report source is invalid")
    summary = _exact(report["export_summary"], {"canonical_export_sha256", "header_reference_count", "accepted_candidate_count", "stack_rejection_count", "direct_pc_literal_load_count"}, "report summary")
    expected = summarize_ui_slot34_dispatch_export(EXPECTED_RAW_EXPORT)
    if summary != expected or not _DIGEST.fullmatch(summary["canonical_export_sha256"]):
        raise UISlot34DispatchError("report digest is unpinned")
    expected_scan = {"rule": EXPECTED_RAW_EXPORT["structural_scan"]["rule"], "accepted_candidate_count": 0, "stack_rejection_count": len(EXPECTED_STACK_REJECTIONS), "direct_pc_literal_load_count": len(EXPECTED_LITERAL_REJECTIONS)}
    if report["prior_vtable_interface"] != EXPECTED_RAW_EXPORT["prior_vtable_interface"] or report["prior_owner_registration"] != EXPECTED_RAW_EXPORT["prior_owner_registration"] or report["structural_scan"] != expected_scan or report["claims"] != EXPECTED_RAW_EXPORT["claims"] or report["behavior_support"] != EXPECTED_RAW_EXPORT["behavior_support"] or report["readiness"] != "LOCAL_SLOT34_STRUCTURAL_DISPATCH_NOT_FOUND" or report["conclusion"] != "No local structurally exact slot-34 virtual dispatch was found. External, cross-module, callback, and nonlocal indirect routes remain unresolved.":
        raise UISlot34DispatchError("report promotes unestablished behavior")
    return copy.deepcopy(report)
