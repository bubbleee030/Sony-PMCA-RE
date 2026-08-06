"""Fail-closed evidence contract for the α6400 orientation object/table boundary."""
from __future__ import annotations

import copy
import hashlib
import json
import re


VIEW_UNIFIED2_SIZE = 11_530_552
VIEW_UNIFIED2_SHA256 = "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2"
PRIOR_ORIENTATION_DIGEST = "05abc1883d29d3bc4780cde2a67d5ee13912e2296936f9e9e76b713042318f0d"
PRIOR_SLOT37_DIGEST = "bf4e9ea3ea1f4841bdcda6ecdf337a9cb064be2b560ace7b533a6a5e7f83f12f"
PRIOR_WIDGET_TABLE_DIGEST = "3d88983377538b2fc98ddc1170bdb5848cebf4a28d319c35365a105075ca2035"

INITIALIZERS = (
    {
        "role": "base",
        "owner": 0x30E9CC,
        "end": 0x30E9E8,
        "range_size": 28,
        "decoded_item_count": 14,
        "complete": True,
        "direct_calls": [],
        "offset_zero_store_site": 0x30E9DA,
        "store_base_register": "r0",
        "store_receiver_provenance": "entry-r0",
    },
    {
        "role": "derived",
        "owner": 0x30E9E8,
        "end": 0x30EA0C,
        "range_size": 36,
        "decoded_item_count": 17,
        "complete": True,
        "direct_calls": [{"site": 0x30E9F0, "target": 0x30E9CC}],
        "offset_zero_store_site": 0x30E9FE,
        "base_call_receiver_provenance": "entry-r0",
        "saved_entry_register": "r5",
        "store_base_register": "r5",
        "store_receiver_provenance": "entry-r0",
    },
)

TABLE_STORES = (
    {
        "role": "base",
        "site": 0x30E9DA,
        "source_cell": 0x949D70,
        "source_section": ".got",
        "relocation_index": 57459,
        "relocation_type": 23,
        "target": 0x8E6118,
        "target_section": ".data.rel.ro",
        "widget_address_point_match_count": 0,
    },
    {
        "role": "derived",
        "site": 0x30E9FE,
        "source_cell": 0x94C1F4,
        "source_section": ".got",
        "relocation_index": 59685,
        "relocation_type": 23,
        "target": 0x8E6228,
        "target_section": ".data.rel.ro",
        "widget_address_point_match_count": 0,
    },
)

TYPE_TABLES = (
    {
        "role": "abstract-base",
        "type_name": "AfOrientImpl",
        "rtti_encoding": "12AfOrientImpl",
        "typeinfo": 0x8E6108,
        "abi_type_info": "__class_type_info",
        "base_typeinfo": None,
        "address_point": 0x8E6118,
        "window_start": 0x8E6110,
        "window_end": 0x8E6220,
        "slot_count": 66,
        "relocation_count": 66,
        "relative_relocation_count": 3,
        "absolute_relocation_count": 63,
        "pure_virtual_reference_count": 63,
        "relocation_digest": "58689094ff707a2ded98dacdf427350e56ecce073f9df7bcb8f0fa5b1b954773",
    },
    {
        "role": "derived",
        "type_name": "AfImplForOrientationRegisterAF",
        "rtti_encoding": "30AfImplForOrientationRegisterAF",
        "typeinfo": 0x8E6360,
        "abi_type_info": "__si_class_type_info",
        "base_typeinfo": 0x8E6108,
        "base_link_cell": 0x8E6368,
        "base_link_relocation_index": 20071,
        "base_link_relocation_type": 23,
        "base_link_relocation_symbol": 0,
        "address_point": 0x8E6228,
        "window_start": 0x8E6220,
        "window_end": 0x8E6330,
        "slot_count": 66,
        "relocation_count": 67,
        "relative_relocation_count": 67,
        "absolute_relocation_count": 0,
        "pure_virtual_reference_count": 0,
        "relocation_digest": "0c9f737b5f170bb0023e2ff326592b1b691db182f457c087a55b3f36b3149100",
    },
)

SLOT37_BINDING = {
    "slot": 37,
    "offset": 0x94,
    "cell": 0x8E62BC,
    "relocation_index": 20029,
    "relocation_type": 23,
    "target": 0x30C578,
    "target_section": ".text",
    "defined_dynsym_match_count": 0,
}

_STORAGE_CONSUMER_CORE = {
    "guard_storage": 0xB2EFF0,
    "object_storage": 0xB2EFF4,
    "guard_materialization_sites": [0x35F428, 0x35F448],
    "object_materialization_sites": [0x35F440, 0x35F454, 0x35F460],
    "offset_zero_load_sites": [0x35F42E],
    "initializer_calls": [{"site": 0x35F442, "target": 0x30E9E8}],
    "post_initializer_unresolved_calls": [
        {"site": 0x35F44A, "target": 0x156344},
        {"site": 0x35F45A, "target": 0x1563BC},
    ],
}
STORAGE_CONSUMERS = {
    **_STORAGE_CONSUMER_CORE,
    "canonical_digest": "d45002a0c1e392f1958022bc6ee86e636d0a6d3c1646a1c35953910a1a762984",
}

DIRECT_GRAPH_SUMMARY = {
    "scope": "pinned-complete-helper-prefix-only",
    "owner": 0x35F424,
    "prefix_end": 0x35F470,
    "prefix_complete": True,
    "path_analysis_performed": False,
    "cross_module_path_analysis_performed": False,
}

CLAIMS = {
    "initializer_chain_found": True,
    "concrete_af_type_found": True,
    "derived_slot37_target_found": True,
    "widget_compatible_table_found": False,
    "ui_widget_identity_found": False,
    "menu_touch_behavior_found": False,
    "selection_result_found": False,
    "transitive_graph_absence_established": False,
}

EXPECTED_RAW_EXPORT = {
    "schema_version": 1,
    "program": "viewUnified2.so",
    "sha256": VIEW_UNIFIED2_SHA256,
    "file_size": VIEW_UNIFIED2_SIZE,
    "analysis_mode": {"read_only": True, "static_elf_metadata": True, "cfg_dataflow": True, "source_unchanged": True},
    "prior_orientation_helper": {"analysis_contract": "orientation_af_helper", "canonical_export_sha256": PRIOR_ORIENTATION_DIGEST},
    "prior_slot37_dispatch": {"analysis_contract": "generic_slot37_dispatch", "canonical_export_sha256": PRIOR_SLOT37_DIGEST},
    "prior_widget_compatible_tables": {"analysis_contract": "widget_hit_test_vtables", "artifact_sha256": PRIOR_WIDGET_TABLE_DIGEST, "address_point_count": 407},
    "initializers": list(INITIALIZERS),
    "table_stores": list(TABLE_STORES),
    "type_tables": list(TYPE_TABLES),
    "slot37_binding": SLOT37_BINDING,
    "storage_consumers": STORAGE_CONSUMERS,
    "direct_graph_summary": DIRECT_GRAPH_SUMMARY,
    "claims": CLAIMS,
    "truncated": False,
}

_FORBIDDEN = ("raw", "byte", "disassembly", "instruction", "key", "device", "usb", "write", "flash", "package", "payload")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


class OrientationObjectTableBoundaryError(ValueError):
    """Raised when object/table evidence exceeds the bounded static result."""


def _forbid(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if any(token in str(key).casefold() for token in _FORBIDDEN):
                raise OrientationObjectTableBoundaryError("unsafe or reconstructive evidence field")
            _forbid(child)
    elif isinstance(value, list):
        for child in value:
            _forbid(child)


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise OrientationObjectTableBoundaryError(label + " fields differ")
    return value


def _canonical(value):
    return hashlib.sha256((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()).hexdigest()


def normalize_orientation_object_table_boundary_export(document):
    """Accept only the exact bounded initializer, table, and consumer evidence."""
    _forbid(document)
    raw = _exact(document, set(EXPECTED_RAW_EXPORT), "orientation object/table export")
    for key, expected in EXPECTED_RAW_EXPORT.items():
        if raw[key] != expected:
            raise OrientationObjectTableBoundaryError(key + " differs from the pinned result")
    core = {key: raw["storage_consumers"][key] for key in _STORAGE_CONSUMER_CORE}
    if _canonical(core) != raw["storage_consumers"]["canonical_digest"]:
        raise OrientationObjectTableBoundaryError("storage consumer digest differs")
    return copy.deepcopy(raw)


def summarize_orientation_object_table_boundary_export(document):
    raw = normalize_orientation_object_table_boundary_export(document)
    return {
        "canonical_export_sha256": _canonical(raw),
        "initializer_count": len(INITIALIZERS),
        "identified_type_count": len(TYPE_TABLES),
        "widget_address_point_match_count": sum(item["widget_address_point_match_count"] for item in TABLE_STORES),
    }


CONCLUSION = (
    "The stable orientation/AF object is initialized first as AfOrientImpl and then as "
    "AfImplForOrientationRegisterAF. Its derived slot-37 target is local and unnamed, and neither "
    "vtable address point matches the 407 Widget-compatible tables; this branch is a bounded false lead "
    "for concrete menu-touch routing, while indirect, incomplete-owner, and cross-module paths remain open."
)


def validate_orientation_object_table_boundary_report(document):
    _forbid(document)
    fields = {
        "schema_version", "analysis_scope", "camera_policy", "camera_executed", "installable",
        "camera_test_eligible", "source", "summary", "prior_orientation_helper",
        "prior_slot37_dispatch", "prior_widget_compatible_tables", "initializers", "table_stores",
        "type_tables", "slot37_binding", "storage_consumers", "direct_graph_summary", "claims",
        "readiness", "conclusion",
    }
    report = _exact(document, fields, "report")
    if report["schema_version"] != 1 or report["analysis_scope"] != "offline-static-orientation-object-table-boundary" or report["camera_policy"] != "physically-disconnected":
        raise OrientationObjectTableBoundaryError("report scope differs")
    if any(report[key] is not False for key in ("camera_executed", "installable", "camera_test_eligible")):
        raise OrientationObjectTableBoundaryError("report promotes camera activity")
    if report["source"] != {"module": "lib/viewUnified2.so", "size": VIEW_UNIFIED2_SIZE, "sha256": VIEW_UNIFIED2_SHA256}:
        raise OrientationObjectTableBoundaryError("report source differs")
    if report["summary"] != summarize_orientation_object_table_boundary_export(EXPECTED_RAW_EXPORT) or not _SHA.fullmatch(report["summary"]["canonical_export_sha256"]):
        raise OrientationObjectTableBoundaryError("report summary differs")
    for key in ("prior_orientation_helper", "prior_slot37_dispatch", "prior_widget_compatible_tables", "initializers", "table_stores", "type_tables", "slot37_binding", "storage_consumers", "direct_graph_summary", "claims"):
        if report[key] != EXPECTED_RAW_EXPORT[key]:
            raise OrientationObjectTableBoundaryError("report evidence differs")
    if report["readiness"] != "AF_INTERNAL_FALSE_LEAD_FOR_MENU_TOUCH" or report["conclusion"] != CONCLUSION:
        raise OrientationObjectTableBoundaryError("report promotes unresolved behavior")
    return copy.deepcopy(report)
