"""Fail-closed evidence contract for α6400 Creative Style menu-list construction."""
from __future__ import annotations

import copy
import hashlib
import json
import re


VIEW_UNIFIED2_SIZE = 11_530_552
VIEW_UNIFIED2_SHA256 = "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2"
PRIOR_DEFINITION_DIGEST = "783507c05654f172a03966c259635677430c78801c9a067f122e21752dda0d16"
PRIOR_REGISTRY_DIGEST = "4bb7a45b472e4c9f6d690579100d63493ec40281e9eacaccf33edccb0062c28d"

ROOT_INVENTORY = {
    "root_pointer_relocation_count": 6824,
    "maximal_contiguous_run_count": 321,
    "creative_style_occurrence_count": 51,
    "creative_style_contiguous_run_count": 47,
    "creative_style_contiguous_run_digest": "b153a80dbb8cd7ecb1350251af0b3bd5f260b8f3512ce14589b19fd3b5e3a135",
    "contiguous_runs_are_constructor_boundaries": False,
    "constructor_bounded_list_count": 3,
}

CONSTRUCTOR_BINDING = {
    "symbol": "_ZN18CmnViewSettingNodeC1EPPS_iPK24CmnViewSettingProperties",
    "demangled": "CmnViewSettingNode::CmnViewSettingNode(CmnViewSettingNode**, int, CmnViewSettingProperties const*)",
    "symbol_index": 1209,
    "symbol_defined": False,
    "relocation_index": 1727,
    "relocation_type": 22,
    "got": 0x9461A8,
    "plt": 0x154024,
}


def _entry(index, cell, relocation_index, symbol):
    return {
        "index": index,
        "cell": cell,
        "relocation_index": relocation_index,
        "relocation_type": 2,
        "symbol": symbol,
        "addend": 0,
    }


LIST_CONSTRUCTIONS = (
    {
        "role": "view-stlrec-slot61-owner",
        "owner": 0x1CCDA8,
        "owner_end": 0x1D9FD0,
        "owner_range_size": 53_800,
        "decoded_item_count": 17_150,
        "owner_complete": True,
        "entry_path_mode": "bounded-direct-intra-owner-cfg-dataflow",
        "entry_path_reachable": True,
        "entry_path_edge_count": 64,
        "runtime_branch_feasibility_proven": False,
        "incoming_reference": {"section": ".data.rel.ro", "cell": 0x8DEE84, "relocation_index": 16312, "relocation_type": 23},
        "root_list_load_site": 0x1D9F84,
        "constructor_call_site": 0x1D9F88,
        "constructor_target": 0x154024,
        "this_source": {"cell": 0x94BE84, "relocation_index": 59476, "relocation_type": 23, "target": 0xB06E58},
        "root_list_source": {"cell": 0x94F8A4, "relocation_index": 63014, "relocation_type": 23, "target": 0x951284},
        "root_list_start": 0x951284,
        "root_list_end": 0x951294,
        "entry_count": 4,
        "creative_style_index": 2,
        "entries": [
            _entry(0, 0x951284, 131184, "cmnViewSettingNodeRootWhiteBalance"),
            _entry(1, 0x951288, 131346, "cmnViewSettingNodeRootISOSensitivity"),
            _entry(2, 0x95128C, 130927, "cmnViewSettingNodeRootCreativeStyle"),
            _entry(3, 0x951290, 131418, "cmnViewSettingNodeRootPictureEffect_Wheel"),
        ],
        "argument_definition_sites": {
            "r0_indexed_load": 0x1D9F7E,
            "r0_move": 0x1D9F82,
            "r1_root_list_load": 0x1D9F84,
            "r2_count_immediate": 0x1D9F7C,
            "r3_null_immediate": 0x1D9F86,
        },
        "prep_chain_sites": [0x1D9F7C, 0x1D9F7E, 0x1D9F80, 0x1D9F82, 0x1D9F84, 0x1D9F86, 0x1D9F88],
        "prep_chain_entry_reachable": True,
        "prep_chain_direct_fallthrough": True,
        "prep_chain_unique_predecessors": True,
        "r0_flows_directly_to_constructor": True,
        "r1_flows_directly_to_constructor": True,
        "r2_immediate_count": 4,
        "r3_properties_null": True,
    },
    {
        "role": "startup-four-root-list",
        "owner": 0x62B348,
        "owner_end": 0x62B40C,
        "owner_range_size": 196,
        "decoded_item_count": 87,
        "owner_complete": True,
        "entry_path_mode": "bounded-direct-intra-owner-cfg-dataflow",
        "entry_path_reachable": True,
        "entry_path_edge_count": 52,
        "runtime_branch_feasibility_proven": False,
        "incoming_reference": {"section": ".init_array", "cell": 0x8B5640, "relocation_index": 1424, "relocation_type": 23},
        "root_list_load_site": 0x62B3C0,
        "constructor_call_site": 0x62B3C4,
        "constructor_target": 0x154024,
        "this_source": {"cell": 0x94CCF8, "relocation_index": 60354, "relocation_type": 23, "target": 0xB78AB8},
        "root_list_source": {"cell": 0x94EBBC, "relocation_index": 62237, "relocation_type": 23, "target": 0xB068D8},
        "root_list_start": 0xB068D8,
        "root_list_end": 0xB068E8,
        "entry_count": 4,
        "creative_style_index": 2,
        "entries": [
            _entry(0, 0xB068D8, 131237, "cmnViewSettingNodeRootWhiteBalance"),
            _entry(1, 0xB068DC, 131396, "cmnViewSettingNodeRootISOSensitivity"),
            _entry(2, 0xB068E0, 130976, "cmnViewSettingNodeRootCreativeStyle"),
            _entry(3, 0xB068E4, 131419, "cmnViewSettingNodeRootPictureEffect_Wheel"),
        ],
        "argument_definition_sites": {
            "r0_indexed_load": 0x62B3BA,
            "r0_move": 0x62B3BE,
            "r1_root_list_load": 0x62B3C0,
            "r2_count_immediate": 0x62B3B8,
            "r3_null_immediate": 0x62B3C2,
        },
        "prep_chain_sites": [0x62B3B8, 0x62B3BA, 0x62B3BC, 0x62B3BE, 0x62B3C0, 0x62B3C2, 0x62B3C4],
        "prep_chain_entry_reachable": True,
        "prep_chain_direct_fallthrough": True,
        "prep_chain_unique_predecessors": True,
        "r0_flows_directly_to_constructor": True,
        "r1_flows_directly_to_constructor": True,
        "r2_immediate_count": 4,
        "r3_properties_null": True,
    },
    {
        "role": "startup-two-root-list",
        "owner": 0x65BE20,
        "owner_end": 0x65BEE4,
        "owner_range_size": 196,
        "decoded_item_count": 87,
        "owner_complete": True,
        "entry_path_mode": "bounded-direct-intra-owner-cfg-dataflow",
        "entry_path_reachable": True,
        "entry_path_edge_count": 52,
        "runtime_branch_feasibility_proven": False,
        "incoming_reference": {"section": ".init_array", "cell": 0x8B5648, "relocation_index": 1426, "relocation_type": 23},
        "root_list_load_site": 0x65BE98,
        "constructor_call_site": 0x65BE9C,
        "constructor_target": 0x154024,
        "this_source": {"cell": 0x94C208, "relocation_index": 59689, "relocation_type": 23, "target": 0xB78BC0},
        "root_list_source": {"cell": 0x94BE94, "relocation_index": 59480, "relocation_type": 23, "target": 0xB06910},
        "root_list_start": 0xB06910,
        "root_list_end": 0xB06918,
        "entry_count": 2,
        "creative_style_index": 1,
        "entries": [
            _entry(0, 0xB06910, 131238, "cmnViewSettingNodeRootWhiteBalance"),
            _entry(1, 0xB06914, 130977, "cmnViewSettingNodeRootCreativeStyle"),
        ],
        "argument_definition_sites": {
            "r0_indexed_load": 0x65BE92,
            "r0_move": 0x65BE96,
            "r1_root_list_load": 0x65BE98,
            "r2_count_immediate": 0x65BE90,
            "r3_null_immediate": 0x65BE9A,
        },
        "prep_chain_sites": [0x65BE90, 0x65BE92, 0x65BE94, 0x65BE96, 0x65BE98, 0x65BE9A, 0x65BE9C],
        "prep_chain_entry_reachable": True,
        "prep_chain_direct_fallthrough": True,
        "prep_chain_unique_predecessors": True,
        "r0_flows_directly_to_constructor": True,
        "r1_flows_directly_to_constructor": True,
        "r2_immediate_count": 2,
        "r3_properties_null": True,
    },
)

CONSTRUCTOR_TRACE_DIGEST = "484bd875feb7b1dac4c0f30247319ce13bbe95b5c08a69e7ca5e3f1145df6993"

VIEW_STLREC_VTABLE = {
    "section": ".data.rel.ro",
    "typeinfo": 0x8DED7C,
    "abi_vptr_cell": 0x8DED7C,
    "abi_vptr_relocation_index": 67626,
    "abi_vptr_relocation_type": 2,
    "abi_vptr_symbol_index": 278,
    "abi_vptr_symbol": "_ZTVN10__cxxabiv120__si_class_type_infoE",
    "abi_vptr_addend": 8,
    "name_cell": 0x8DED80,
    "name_relocation_index": 16290,
    "name_relocation_type": 23,
    "name_symbol_index": 0,
    "name_target": 0x66875A,
    "type_name_encoding": "10ViewStlrec",
    "type_name": "ViewStlrec",
    "base_link_cell": 0x8DED84,
    "base_link_relocation_index": 88414,
    "base_link_relocation_type": 2,
    "base_link_symbol_index": 1679,
    "base_link_addend": 0,
    "base_rtti_symbol": "_ZTI13ViewBaseForMR",
    "base_rtti_defined": True,
    "base_rtti_value": 0x8E5E68,
    "base_rtti_size": 12,
    "offset_to_top_cell": 0x8DED88,
    "offset_to_top_value": 0,
    "vtable_typeinfo_cell": 0x8DED8C,
    "vtable_typeinfo_relocation_index": 16291,
    "vtable_typeinfo_relocation_type": 23,
    "vtable_typeinfo_symbol_index": 0,
    "vtable_typeinfo_target": 0x8DED7C,
    "address_point": 0x8DED90,
    "slot": 61,
    "slot_cell": 0x8DEE84,
    "slot_relocation_index": 16312,
    "slot_relocation_type": 23,
    "slot_symbol_index": 0,
    "target_thumb_addend": 0x1CCDA9,
    "target": 0x1CCDA8,
    "observed_prefix_start_slot": 0,
    "observed_prefix_end_slot": 61,
    "observed_prefix_slot_count": 62,
    "prefix_absolute_named_slot_count": 41,
    "prefix_relative_local_slot_count": 21,
    "prefix_relocation_shape_digest": "a34c408200e725bf58bb98e4c06f8d37e9edc17f166aa76959554ed337aa4d01",
    "table_end_established": False,
}

CLAIMS = {
    "creative_style_constructor_list_membership_found": True,
    "constructor_argument_flow_found": True,
    "startup_list_construction_found": True,
    "view_stlrec_owner_found": True,
    "view_base_for_mr_base_link_found": True,
    "selected_state_found": False,
    "renderer_binding_found": False,
    "touch_routing_found": False,
    "commit_or_persistence_found": False,
    "creative_look_equivalence_found": False,
    "runtime_branch_feasibility_proven": False,
    "cross_module_absence_established": False,
}

EXPECTED_RAW_EXPORT = {
    "schema_version": 1,
    "program": "viewUnified2.so",
    "sha256": VIEW_UNIFIED2_SHA256,
    "file_size": VIEW_UNIFIED2_SIZE,
    "analysis_mode": {"read_only": True, "static_elf_metadata": True, "bounded_direct_cfg_dataflow": True, "source_unchanged": True},
    "prior_definition_registration": {"analysis_contract": "creative_style_definition_registration", "artifact_sha256": PRIOR_DEFINITION_DIGEST},
    "prior_registry_consumers": {"analysis_contract": "creative_style_registry_consumers", "artifact_sha256": PRIOR_REGISTRY_DIGEST},
    "root_inventory": ROOT_INVENTORY,
    "constructor_binding": CONSTRUCTOR_BINDING,
    "list_constructions": list(LIST_CONSTRUCTIONS),
    "constructor_trace_digest": CONSTRUCTOR_TRACE_DIGEST,
    "view_stlrec_vtable": VIEW_STLREC_VTABLE,
    "claims": CLAIMS,
    "truncated": False,
}

_FORBIDDEN = ("raw", "byte", "disassembly", "instruction", "key_material", "device", "usb", "flash", "package", "payload")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


class CreativeStyleMenuListConstructionError(ValueError):
    """Raised when evidence exceeds the exact bounded static result."""


def _forbid(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if any(token in str(key).casefold() for token in _FORBIDDEN):
                raise CreativeStyleMenuListConstructionError("unsafe or reconstructive evidence field")
            _forbid(child)
    elif isinstance(value, list):
        for child in value:
            _forbid(child)


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise CreativeStyleMenuListConstructionError(label + " fields differ")
    return value


def _canonical(value):
    return hashlib.sha256((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()).hexdigest()


def normalize_creative_style_menu_list_construction_export(document):
    """Accept only exact constructor-bounded menu-list construction evidence."""
    _forbid(document)
    raw = _exact(document, set(EXPECTED_RAW_EXPORT), "Creative Style menu-list export")
    for key, expected in EXPECTED_RAW_EXPORT.items():
        if raw[key] != expected:
            raise CreativeStyleMenuListConstructionError(key + " differs from the pinned result")
    for item in raw["list_constructions"]:
        if item["root_list_end"] != item["root_list_start"] + item["entry_count"] * 4:
            raise CreativeStyleMenuListConstructionError("constructor list boundary differs")
        if len(item["entries"]) != item["entry_count"] or item["r2_immediate_count"] != item["entry_count"]:
            raise CreativeStyleMenuListConstructionError("constructor count differs")
        if item["root_list_source"]["target"] != item["root_list_start"]:
            raise CreativeStyleMenuListConstructionError("list pointer provenance differs")
        if item["entries"][item["creative_style_index"]]["symbol"] != "cmnViewSettingNodeRootCreativeStyle":
            raise CreativeStyleMenuListConstructionError("Creative Style member index differs")
        if [entry["cell"] for entry in item["entries"]] != list(range(item["root_list_start"], item["root_list_end"], 4)):
            raise CreativeStyleMenuListConstructionError("list cells are not contiguous within the constructor count")
        if any(entry["addend"] != 0 for entry in item["entries"]):
            raise CreativeStyleMenuListConstructionError("root-pointer relocation addend differs")
        definitions = item["argument_definition_sites"]
        if definitions["r1_root_list_load"] != item["root_list_load_site"] or item["prep_chain_sites"][-1] != item["constructor_call_site"]:
            raise CreativeStyleMenuListConstructionError("constructor preparation sites differ")
        if not all(item[key] is True for key in ("prep_chain_entry_reachable", "prep_chain_direct_fallthrough", "prep_chain_unique_predecessors")):
            raise CreativeStyleMenuListConstructionError("constructor preparation CFG proof differs")
    table = raw["view_stlrec_vtable"]
    if table["slot_cell"] != table["address_point"] + table["slot"] * 4 or raw["list_constructions"][0]["incoming_reference"]["cell"] != table["slot_cell"]:
        raise CreativeStyleMenuListConstructionError("ViewStlrec slot provenance differs")
    if table["vtable_typeinfo_target"] != table["typeinfo"] or table["base_link_cell"] != table["typeinfo"] + 8:
        raise CreativeStyleMenuListConstructionError("ViewStlrec RTTI chain differs")
    if table["observed_prefix_end_slot"] != table["slot"] or table["observed_prefix_slot_count"] != table["slot"] + 1 or table["table_end_established"] is not False:
        raise CreativeStyleMenuListConstructionError("ViewStlrec observed-prefix boundary differs")
    return copy.deepcopy(raw)


def summarize_creative_style_menu_list_construction_export(document):
    raw = normalize_creative_style_menu_list_construction_export(document)
    return {
        "canonical_export_sha256": _canonical(raw),
        "list_count": len(raw["list_constructions"]),
        "entry_counts": [item["entry_count"] for item in raw["list_constructions"]],
        "creative_style_membership_count": sum(any(entry["symbol"] == "cmnViewSettingNodeRootCreativeStyle" for entry in item["entries"]) for item in raw["list_constructions"]),
        "startup_initializer_count": sum(item["incoming_reference"]["section"] == ".init_array" for item in raw["list_constructions"]),
    }


CONCLUSION = (
    "Creative Style is a constructor-bounded member of three CmnViewSettingNode root-pointer lists "
    "with exact sizes 4, 4, and 2. Two lists are built by startup initializers and one construction "
    "site lies in the complete ViewStlrec slot-61 exception-index owner; ViewStlrec is RTTI-linked "
    "to its ViewBaseForMR base. This establishes menu "
    "composition only, not selected state, rendering, touch routing, commit, or persistence behavior."
)


def validate_creative_style_menu_list_construction_report(document):
    _forbid(document)
    fields = {
        "schema_version", "analysis_scope", "camera_policy", "camera_executed", "installable",
        "camera_test_eligible", "source", "summary", "prior_definition_registration",
        "prior_registry_consumers", "root_inventory", "constructor_binding", "list_constructions",
        "constructor_trace_digest", "view_stlrec_vtable", "claims", "readiness", "conclusion",
    }
    report = _exact(document, fields, "report")
    if report["schema_version"] != 1 or report["analysis_scope"] != "offline-static-creative-style-menu-list-construction" or report["camera_policy"] != "physically-disconnected":
        raise CreativeStyleMenuListConstructionError("report scope differs")
    if any(report[key] is not False for key in ("camera_executed", "installable", "camera_test_eligible")):
        raise CreativeStyleMenuListConstructionError("report promotes camera activity")
    if report["source"] != {"module": "lib/viewUnified2.so", "size": VIEW_UNIFIED2_SIZE, "sha256": VIEW_UNIFIED2_SHA256}:
        raise CreativeStyleMenuListConstructionError("report source differs")
    expected_summary = summarize_creative_style_menu_list_construction_export(EXPECTED_RAW_EXPORT)
    if report["summary"] != expected_summary or not _SHA.fullmatch(report["summary"]["canonical_export_sha256"]):
        raise CreativeStyleMenuListConstructionError("report summary differs")
    for key in (
        "prior_definition_registration", "prior_registry_consumers", "root_inventory",
        "constructor_binding", "list_constructions", "constructor_trace_digest",
        "view_stlrec_vtable", "claims",
    ):
        if report[key] != EXPECTED_RAW_EXPORT[key]:
            raise CreativeStyleMenuListConstructionError("report evidence differs")
    if report["readiness"] != "MENU_ROOT_LIST_CONSTRUCTION_ONLY" or report["conclusion"] != CONCLUSION:
        raise CreativeStyleMenuListConstructionError("report promotes unresolved behavior")
    return copy.deepcopy(report)
