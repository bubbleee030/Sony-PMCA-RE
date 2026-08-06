"""Fail-closed contract for the bounded α6400 orientation/AF helper trace."""
from __future__ import annotations

import copy
import hashlib
import json
import re


VIEW_UNIFIED2_SIZE = 11_530_552
VIEW_UNIFIED2_SHA256 = "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2"
PRIOR_WIDGET_DIGEST = "62faece4c717e17b6d434d2d2d8a1b13e6902e0a5406248af915d57fb02edbdc"
MEMBER_INVENTORY = {
    "method_count": 42,
    "aggregate_size": 780,
    "canonical_digest": "9949b0d1da4a57aa2645e00ef7d7b3c8e404761e4bedf488fbb078d897467c2c",
}
HELPER_CALL_INVENTORY = {
    "helper": 0x35F424,
    "total_count": 62,
    "typed_member_count": 42,
    "non_member_count": 20,
    "typed_member_digest": "a0dd30d96733d977fe2c486522773926690195b64838c66d3cfa641f6f07590b",
    "non_member_digest": "b0189feb776434dd5abcdf17ebfaf4408e5b8d9217c9c86b66336a231199fbd1",
    "all_call_digest": "ebfee8fcbe1e712903cbce1ed3ddde66e1ec14e7cf73d428eca88b604aee2a1c",
}
JUMP_SLOT_RELOCATION_INDICES = (5, 124, 177, 211, 254, 680, 944, 1001, 1076, 1322, 1363, 1509, 1854, 1892, 2227, 2386, 2389)
GETTER_BINDING = {
    "method": "getRecallRegisteredAfFrame()",
    "dynsym": 1718,
    "entry": 0x35F66C,
    "size": 18,
    "relocation_index": 254,
    "got": 0x944AA4,
    "plt": 0x14F1FC,
    "direct_site_count": 15,
    "direct_owner_count": 13,
    "callsite_digest": "f513997145508f2955d32846568272e0aea973fa4f836a33dd59151bf1900e7b",
}
SETTER_BINDING = {
    "method": "setRecallRegisteredAfFrame(int)",
    "dynsym": 2248,
    "entry": 0x35F656,
    "size": 22,
    "relocation_index": 211,
    "got": 0x9449F8,
    "plt": 0x14EFA8,
    "direct_site_count": 42,
    "direct_owner_count": 31,
    "callsite_digest": "fab457060ad1312bc20965ffd865b6eb472887877b1f0bea2fe5f877cae1a8a8",
}
HELPER = {
    "address": 0x35F424,
    "end": 0x35F494,
    "range_size": 112,
    "executable_prefix_end": 0x35F470,
    "decoded_prefix_size": 76,
    "literal_table_tail_size": 36,
    "decoded_item_count": 31,
    "executable_prefix_complete": True,
    "normal_outcome_count": 2,
    "normal_ingress_count": 3,
    "return_site": 0x35F462,
    "return_storage": 0xB2EFF4,
    "guard_storage": 0xB2EFF0,
    "initialization_got": 0x9446A0,
    "initializer_target": 0x30E9E8,
    "initializer_call_site": 0x35F442,
    "return_materialization_sites": [0x35F45E, 0x35F460],
    "guard_materialization_sites": [0x35F424, 0x35F428],
    "object_initialization_materialization_sites": [0x35F43E, 0x35F440],
    "control_edges": [
        {"kind": "conditional", "site": 0x35F436, "target": 0x35F45E},
        {"kind": "call-unresolved-plt", "site": 0x35F438, "target": 0x1508E8},
        {"kind": "conditional", "site": 0x35F43C, "target": 0x35F45E},
        {"kind": "call-local", "site": 0x35F442, "target": 0x30E9E8},
        {"kind": "call-unresolved-plt", "site": 0x35F44A, "target": 0x156344},
        {"kind": "call-unresolved-plt", "site": 0x35F45A, "target": 0x1563BC},
        {"kind": "call-guard-abort", "site": 0x35F468, "target": 0x152778},
        {"kind": "call-unresolved-plt", "site": 0x35F46C, "target": 0x1506D8},
    ],
    "guard_abort_binding": {"dynsym": 923, "relocation_index": 1262, "got": 0x945A64, "plt": 0x152778},
    "entry_argument_read_count": 0,
    "lr_callsite_indexed": False,
    "linear_exidx_complete": False,
}
RELOCATION_SUMMARY = {
    "rel_dyn_count": 137_966,
    "rel_plt_count": 2_433,
    "method_entry_addend_hit_count": 0,
    "object_or_guard_named_relocation_count": 0,
    "class_ctor_dtor_vtable_rtti_symbol_count": 0,
}
CLAIMS = {
    "stable_local_object_storage_found": True,
    "helper_object_to_hit_dispatch_linked": True,
    "concrete_widget_type_found": False,
    "constructor_identity_found": False,
    "vtable_or_rtti_identity_found": False,
    "menu_touch_behavior_found": False,
    "selection_result_found": False,
}
EXPECTED_RAW_EXPORT = {
    "schema_version": 1,
    "program": "viewUnified2.so",
    "sha256": VIEW_UNIFIED2_SHA256,
    "file_size": VIEW_UNIFIED2_SIZE,
    "analysis_mode": {"read_only": True, "static_elf_metadata": True, "cfg_dataflow": True, "source_unchanged": True},
    "prior_widget_dispatch": {"analysis_contract": "widget_ishit_dispatch", "canonical_export_sha256": PRIOR_WIDGET_DIGEST},
    "member_inventory": MEMBER_INVENTORY,
    "helper_call_inventory": HELPER_CALL_INVENTORY,
    "jump_slot_relocation_indices": list(JUMP_SLOT_RELOCATION_INDICES),
    "getter_binding": GETTER_BINDING,
    "setter_binding": SETTER_BINDING,
    "helper": HELPER,
    "relocation_summary": RELOCATION_SUMMARY,
    "claims": CLAIMS,
    "truncated": False,
}

_FORBIDDEN = ("raw", "byte", "disassembly", "instruction", "key", "device", "usb", "write", "flash", "package", "payload")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


class OrientationAfHelperError(ValueError):
    """Raised when helper evidence exceeds the bounded static result."""


def _forbid(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if any(token in str(key).casefold() for token in _FORBIDDEN):
                raise OrientationAfHelperError("unsafe or reconstructive evidence field")
            _forbid(child)
    elif isinstance(value, list):
        for child in value:
            _forbid(child)


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise OrientationAfHelperError(label + " fields differ")
    return value


def _canonical(value):
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    return hashlib.sha256(encoded).hexdigest()


def normalize_orientation_af_helper_export(document):
    """Accept only the exact static wrapper/helper evidence."""
    _forbid(document)
    raw = _exact(document, set(EXPECTED_RAW_EXPORT), "orientation/AF helper export")
    for key, expected in EXPECTED_RAW_EXPORT.items():
        if raw[key] != expected:
            raise OrientationAfHelperError(key + " differs from the pinned result")
    return copy.deepcopy(raw)


def summarize_orientation_af_helper_export(document):
    raw = normalize_orientation_af_helper_export(document)
    return {
        "canonical_export_sha256": _canonical(raw),
        "method_count": MEMBER_INVENTORY["method_count"],
        "helper_caller_count": HELPER_CALL_INVENTORY["total_count"],
        "stable_object_storage_count": 1,
    }


CONCLUSION = (
    "Forty-two orientation/AF wrapper methods and 20 neighboring non-member sites call one bounded helper. "
    "Its normal CFG paths return stable local object storage at 0xb2eff4 to the proven hit-test dispatch, but "
    "the concrete object type, constructor identity, vtable/RTTI, menu-touch semantics, and selection result remain unresolved."
)


def validate_orientation_af_helper_report(document):
    _forbid(document)
    report = _exact(document, {"schema_version", "analysis_scope", "camera_policy", "camera_executed", "installable", "camera_test_eligible", "source", "summary", "prior_widget_dispatch", "member_inventory", "helper_call_inventory", "jump_slot_relocation_indices", "getter_binding", "setter_binding", "helper", "relocation_summary", "claims", "readiness", "conclusion"}, "report")
    if report["schema_version"] != 1 or report["analysis_scope"] != "offline-static-orientation-af-helper" or report["camera_policy"] != "physically-disconnected":
        raise OrientationAfHelperError("report scope differs")
    if any(report[key] is not False for key in ("camera_executed", "installable", "camera_test_eligible")):
        raise OrientationAfHelperError("report promotes camera activity")
    if report["source"] != {"module": "lib/viewUnified2.so", "size": VIEW_UNIFIED2_SIZE, "sha256": VIEW_UNIFIED2_SHA256}:
        raise OrientationAfHelperError("report source differs")
    if report["summary"] != summarize_orientation_af_helper_export(EXPECTED_RAW_EXPORT) or not _SHA.fullmatch(report["summary"]["canonical_export_sha256"]):
        raise OrientationAfHelperError("report summary differs")
    for key in ("prior_widget_dispatch", "member_inventory", "helper_call_inventory", "jump_slot_relocation_indices", "getter_binding", "setter_binding", "helper", "relocation_summary", "claims"):
        if report[key] != EXPECTED_RAW_EXPORT[key]:
            raise OrientationAfHelperError("report evidence differs")
    if report["readiness"] != "STABLE_LOCAL_OBJECT_TYPE_UNRESOLVED" or report["conclusion"] != CONCLUSION:
        raise OrientationAfHelperError("report promotes unresolved behavior")
    return copy.deepcopy(report)
