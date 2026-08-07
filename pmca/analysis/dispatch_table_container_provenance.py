"""Fail-closed typed ownership for α6400 generic model dispatch tables."""
from __future__ import annotations

import copy
import hashlib
import json
import re


MODULES = [
    {
        "module": "lib/viewUnified4.so",
        "size": 2_614_628,
        "sha256": "0fe8f852b0f028ac7d1d55c613726b3949879cf7fdd44074e525ae302a6f2e62",
    },
    {
        "module": "lib/viewUnified7.so",
        "size": 541_024,
        "sha256": "c48cde43ff22d808ad23c42019ddae516fff7da060004eb81ed2bb85012aa538",
    },
]

PRIOR_OWNER_REPORT = {
    "path": "analysis/a6400-generic-model-owner-provenance.json",
    "sha256": "77f6befb580a89c91d16017dfb317984f3678dd3e651d323e089b49229a42512",
}


def _base(type_name, offset):
    return {"type": type_name, "offset": offset, "public": True, "virtual": False}


def _primary(header, address_point, end):
    return {
        "header": header,
        "address_point": address_point,
        "end": end,
        "slot_count": (end - address_point) // 4,
    }


def _secondary(end):
    return {"offset_to_top_cell": end, "offset_to_top": -0x28, "typeinfo_cell": end + 4}


def _to_instance_symbol(symbol_index, symbol, start, end):
    return {
        "symbol_index": symbol_index,
        "symbol": symbol,
        "range": {"start": start, "end": end},
        "defined_function": True,
    }


DISPATCHER_OWNERS = [
    {
        "module": "lib/viewUnified4.so",
        "type_name": "ViewFocusArea_C",
        "type_name_encoding": "15ViewFocusArea_C",
        "rtti": 0x2677EC,
        "abi_type_info": "__vmi_class_type_info",
        "bases": [_base("ViewBaseForMR", 0), _base("WrapperSettingUtil", 0x140)],
        "primary_vtable": _primary(0x267828, 0x267830, 0x2679A8),
        "next_secondary_header": _secondary(0x2679A8),
        "slot_relocation_shape": {"absolute": 67, "relative": 27, "unrelocated_zero": 0},
        "dispatcher_cell": 0x267930,
        "dispatcher_relocation": {"index": 2812, "type": 23},
        "dispatcher_slot": 64,
        "dispatcher": 0xCF106,
        "target": 0xCE0A8,
        "utility_member_offset": 0x180,
        "to_instance_symbol": _to_instance_symbol(1614, "ViewFocusArea_CToInstance", 0xC91F8, 0xC921C),
        "typed_rtti_vtable_membership": True,
        "creative_style_typed_relocation_count": 0,
    },
    {
        "module": "lib/viewUnified4.so",
        "type_name": "ViewCustomZebra",
        "type_name_encoding": "15ViewCustomZebra",
        "rtti": 0x273E50,
        "abi_type_info": "__si_class_type_info",
        "bases": [_base("ViewBaseProduct", 0)],
        "primary_vtable": _primary(0x273CD8, 0x273CE0, 0x273E3C),
        "next_secondary_header": _secondary(0x273E3C),
        "slot_relocation_shape": {"absolute": 61, "relative": 26, "unrelocated_zero": 0},
        "dispatcher_cell": 0x273DE0,
        "dispatcher_relocation": {"index": 8525, "type": 23},
        "dispatcher_slot": 64,
        "dispatcher": 0x17AD50,
        "target": 0x17A95A,
        "utility_member_offset": 0x188,
        "adjacent_split_entry": {"cell": 0x273DE4, "slot": 65, "target": 0x17A91C},
        "to_instance_symbol": _to_instance_symbol(1593, "ViewCustomZebraToInstance", 0x179046, 0x17906A),
        "typed_rtti_vtable_membership": True,
        "creative_style_typed_relocation_count": 0,
    },
    {
        "module": "lib/viewUnified7.so",
        "type_name": "ViewFocusArea",
        "type_name_encoding": "13ViewFocusArea",
        "rtti": 0x6FDC4,
        "abi_type_info": "__vmi_class_type_info",
        "bases": [_base("ViewBaseForMR", 0), _base("WrapperSettingUtil", 0x140)],
        "primary_vtable": _primary(0x6FDE8, 0x6FDF0, 0x6FF6C),
        "next_secondary_header": _secondary(0x6FF6C),
        "slot_relocation_shape": {"absolute": 68, "relative": 27, "unrelocated_zero": 0},
        "initializer_cell": 0x6FEC8,
        "initializer_relocation": {"index": 840, "type": 23},
        "initializer": 0x30750,
        "initializer_slot": 54,
        "dispatcher_cell": 0x6FEF0,
        "dispatcher_relocation": {"index": 850, "type": 23},
        "dispatcher_slot": 64,
        "dispatcher": 0x31040,
        "target": 0x2D284,
        "utility_member_offset": 0x14C,
        "local_relative_window": {
            "start": 0x6FEBC,
            "end": 0x6FEFC,
            "first_slot": 51,
            "last_slot": 66,
            "relocation_count": 16,
        },
        "wrapper_secondary_vtable": {
            "header": 0x6FF7C,
            "offset_to_top": -0x140,
            "typeinfo_cell": 0x6FF80,
            "address_point": 0x6FF84,
        },
        "to_instance_symbol": _to_instance_symbol(718, "ViewFocusAreaToInstance", 0x2B6D0, 0x2B6F4),
        "typed_rtti_vtable_membership": True,
        "initializer_and_dispatcher_same_typed_vtable": True,
        "runtime_same_instance_or_order_proven": False,
        "creative_style_typed_relocation_count": 0,
    },
]

CREATIVE_STYLE_BOUNDARY = {
    "typed_dispatcher_owner_match_count": 0,
    "owner_type_names": ["ViewFocusArea_C", "ViewCustomZebra", "ViewFocusArea"],
    "owner_name_contains_creative_style": False,
    "typed_primary_vtable_creative_relocation_count": 0,
    "typed_primary_vtable_creative_style_edge_found": False,
}

CLAIMS = {
    "concrete_dispatcher_owner_types_found": True,
    "shared_generic_slot_64_pattern_found": True,
    "vu7_initializer_dispatcher_same_typed_vtable_found": True,
    "to_instance_to_vtable_binding_proven": False,
    "creative_style_owner_binding_found": False,
    "selected_model_value_storage_found": False,
    "final_model_setter_or_commit_found": False,
    "renderer_binding_found": False,
    "touch_routing_found": False,
    "commit_or_persistence_found": False,
    "creative_look_equivalence_found": False,
    "runtime_execution_proven": False,
}


def canonical_digest(value):
    return hashlib.sha256(
        (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    ).hexdigest()


EXPECTED_EXPORT = {
    "schema_version": 1,
    "analysis_mode": {
        "read_only": True,
        "static_elf_metadata": True,
        "typed_itanium_rtti_and_vtable": True,
        "source_unchanged": True,
    },
    "modules": MODULES,
    "prior_owner_report": PRIOR_OWNER_REPORT,
    "dispatcher_owners": DISPATCHER_OWNERS,
    "creative_style_boundary": CREATIVE_STYLE_BOUNDARY,
    "evidence_digest": canonical_digest(
        {"dispatcher_owners": DISPATCHER_OWNERS, "creative_style_boundary": CREATIVE_STYLE_BOUNDARY}
    ),
    "claims": CLAIMS,
    "truncated": False,
}

READINESS = "TYPED_NON_CREATIVE_GENERIC_DISPATCH_OWNERS"
CONCLUSION = (
    "The three generic model-sequence dispatchers are slot-64 overrides owned by typed "
    "ViewFocusArea_C, ViewCustomZebra, and ViewFocusArea primary vtables. ViewFocusArea also "
    "contains the utility initializer at slot 54 and WrapperSettingUtil at offset 0x140. These "
    "concrete owners map the sequences to Focus Area and Custom Zebra views rather than Creative "
    "Style; they do not prove a selected-value store, final commit, renderer, touch route, or persistence."
)

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FORBIDDEN_KEYS = ("payload", "key_material", "device_write", "usb_write", "flash_image", "package_bytes")


class DispatchTableContainerProvenanceError(ValueError):
    """Raised when typed table evidence is broadened beyond its static scope."""


def _forbid(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if any(token in str(key).casefold() for token in _FORBIDDEN_KEYS):
                raise DispatchTableContainerProvenanceError("unsafe or reconstructive evidence field")
            _forbid(child)
    elif isinstance(value, list):
        for child in value:
            _forbid(child)


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise DispatchTableContainerProvenanceError(label + " fields differ")
    return value


def normalize_dispatch_table_container_provenance_export(document):
    _forbid(document)
    export = _exact(document, set(EXPECTED_EXPORT), "dispatch-container export")
    if export != EXPECTED_EXPORT:
        differing = sorted(key for key in EXPECTED_EXPORT if export.get(key) != EXPECTED_EXPORT[key])
        raise DispatchTableContainerProvenanceError("dispatch-container export differs in: " + ",".join(differing))
    if export["evidence_digest"] != canonical_digest({
        "dispatcher_owners": export["dispatcher_owners"],
        "creative_style_boundary": export["creative_style_boundary"],
    }):
        raise DispatchTableContainerProvenanceError("evidence digest differs")
    owners = export["dispatcher_owners"]
    if [owner["dispatcher_slot"] for owner in owners] != [64, 64, 64]:
        raise DispatchTableContainerProvenanceError("shared generic slot differs")
    if len({owner["type_name"] for owner in owners}) != 3 or any(not owner["typed_rtti_vtable_membership"] for owner in owners):
        raise DispatchTableContainerProvenanceError("typed owner identity differs")
    if not owners[2]["initializer_and_dispatcher_same_typed_vtable"] or owners[2]["runtime_same_instance_or_order_proven"]:
        raise DispatchTableContainerProvenanceError("VU7 typed structural link was promoted")
    promoted = (
        "to_instance_to_vtable_binding_proven", "creative_style_owner_binding_found",
        "selected_model_value_storage_found", "final_model_setter_or_commit_found",
        "renderer_binding_found", "touch_routing_found", "commit_or_persistence_found",
        "creative_look_equivalence_found", "runtime_execution_proven",
    )
    if any(export["claims"][key] for key in promoted):
        raise DispatchTableContainerProvenanceError("non-Creative table evidence was promoted")
    return copy.deepcopy(export)


def summarize_dispatch_table_container_provenance_export(document):
    export = normalize_dispatch_table_container_provenance_export(document)
    return {
        "canonical_export_sha256": canonical_digest(export),
        "typed_owner_count": len(export["dispatcher_owners"]),
        "slot_64_owner_count": sum(owner["dispatcher_slot"] == 64 for owner in export["dispatcher_owners"]),
        "creative_style_owner_count": 0,
        "vu7_same_vtable_initializer_count": 1,
    }


def validate_dispatch_table_container_provenance_report(document):
    _forbid(document)
    fields = {
        "schema_version", "analysis_scope", "camera_policy", "camera_executed", "installable",
        "camera_test_eligible", "sources", "prior_owner_report", "summary", "evidence_digest",
        "creative_style_boundary", "claims", "readiness", "conclusion",
    }
    report = _exact(document, fields, "dispatch-container report")
    if report["schema_version"] != 1 or report["analysis_scope"] != "offline-static-dispatch-table-container-provenance" or report["camera_policy"] != "physically-disconnected":
        raise DispatchTableContainerProvenanceError("report scope differs")
    if any(report[key] is not False for key in ("camera_executed", "installable", "camera_test_eligible")):
        raise DispatchTableContainerProvenanceError("report promotes camera activity")
    expected_summary = summarize_dispatch_table_container_provenance_export(EXPECTED_EXPORT)
    if report["sources"] != MODULES or report["prior_owner_report"] != PRIOR_OWNER_REPORT or report["summary"] != expected_summary:
        raise DispatchTableContainerProvenanceError("report source or summary differs")
    if _SHA.fullmatch(report["summary"].get("canonical_export_sha256", "")) is None:
        raise DispatchTableContainerProvenanceError("report digest shape differs")
    if report["evidence_digest"] != EXPECTED_EXPORT["evidence_digest"] or report["creative_style_boundary"] != CREATIVE_STYLE_BOUNDARY or report["claims"] != CLAIMS:
        raise DispatchTableContainerProvenanceError("report evidence differs")
    if report["readiness"] != READINESS or report["conclusion"] != CONCLUSION:
        raise DispatchTableContainerProvenanceError("report conclusion differs")
    return copy.deepcopy(report)
