"""Fail-closed evidence contract for α6400 Creative Style selected-state dispatch."""
from __future__ import annotations

import copy
import hashlib
import json
import re


CAUTION_CONFIG_SIZE = 12_070_800
CAUTION_CONFIG_SHA256 = "bfd1bd7bad0ab3478b894da5dbb51c15464b1bedc4201240ccb61cd743150ef7"

CREATIVE_STYLE_VTABLE = {
    "symbol": "_ZTV31CmnViewSettingNodeCreativeStyle",
    "symbol_index": 63566,
    "start": 0xAC8900,
    "address_point": 0xAC8908,
    "size": 268,
    "word_count": 67,
    "typed_relocation_count": 66,
}

BACKUP_READ_BINDING = {
    "symbol": "_ZN13BackupManager9Bkup_ReadEiPv",
    "symbol_index": 14,
    "symbol_defined": False,
    "relocation_index": 2304,
    "relocation_type": 22,
    "got": 0xB0E5D4,
    "plt": 0x7B81A0,
}

PRODUCT_SELECTORS = [
    {
        "role": "creative-style-product-graph",
        "symbol": "_ZN31CmnViewSettingNodeCreativeStyle11_getSubNodeEv",
        "symbol_index": 60476,
        "owner": 0x7DB958,
        "size": 232,
        "call_site": 0x7DB970,
        "target": 0x7B81A0,
        "backup_id_literal_cell": 0x7DBA08,
        "backup_id": 0x01070316,
        "output": {
            "kind": "stack-local", "width": 1, "zero_initialized": True,
            "zero_init_site": 0x7DB96C, "readback_site": 0x7DB978,
            "same_storage": True, "write_before_call": True, "read_after_call": True,
            "pre_call_straight_line": True,
        },
    },
    {
        "role": "picture-profile-product-graph",
        "symbol": "_ZN32CmnViewSettingNodePictureProfile11_getSubNodeEv",
        "symbol_index": 50626,
        "owner": 0x7DBC04,
        "size": 184,
        "call_site": 0x7DBC1C,
        "target": 0x7B81A0,
        "backup_id_literal_cell": 0x7DBC94,
        "backup_id": 0x01070316,
        "output": {
            "kind": "stack-local", "width": 1, "zero_initialized": True,
            "zero_init_site": 0x7DBC18, "readback_site": 0x7DBC24,
            "same_storage": True, "write_before_call": True, "read_after_call": True,
            "pre_call_straight_line": True,
        },
    },
]


def _method(table_word, symbol, owner, size, relocation_index):
    return {
        "table_word": table_word,
        "vptr_offset": (table_word - 2) * 4,
        "symbol": symbol,
        "owner": owner,
        "size": size,
        "relocation_index": relocation_index,
        "relocation_type": 2,
    }


METHODS = [
    _method(12, "_ZN18CmnViewSettingNode15getSelectedItemEPPS_", 0x7C6BD2, 68, 15901),
    _method(13, "_ZN18CmnViewSettingNode20getIndexSelectedItemERi", 0x7C6C16, 20, 17090),
    _method(14, "_ZN18CmnViewSettingNode20getSRNumSelectedItemERi", 0x7C6C2A, 36, 18279),
    _method(21, "_ZN18CmnViewSettingNode8getStateERi", 0x7C6D52, 12, 26602),
    _method(22, "_ZN18CmnViewSettingNode15getStateByIndexEiRi", 0x7C6D5E, 36, 27791),
    _method(23, "_ZN18CmnViewSettingNode15getStateBySRNumEiRi", 0x7C6D82, 36, 28980),
    _method(39, "_ZN18CmnViewSettingNode14isItemSelectedEv", 0x7C6F26, 34, 48004),
    _method(40, "_ZN18CmnViewSettingNode21isItemSelectedByIndexEi", 0x7C6F48, 34, 49193),
    _method(41, "_ZN18CmnViewSettingNode21isItemSelectedBySRNumEi", 0x7C6F6A, 34, 50382),
    _method(48, "_ZN18CmnViewSettingNode15setItemSelectedEv", 0x7C705A, 128, 58705),
    _method(49, "_ZN18CmnViewSettingNode22setItemSelectedByIndexEi", 0x7C70DA, 34, 59894),
    _method(50, "_ZN18CmnViewSettingNode22setItemSelectedBySRNumEi", 0x7C70FC, 34, 61083),
    _method(51, "_ZN18CmnViewSettingNode26setItemSelectedByDiffSRNumEi", 0x7C711E, 62, 62272),
    _method(58, "_ZN18CmnViewSettingNode17updateSettingNodeEv", 0x7C72B8, 20, 70595),
    _method(62, "_ZN18CmnViewSettingNode10getSubNodeEPPPS_Ri", 0x7C72CC, 30, 74163),
    _method(63, "_ZN18CmnViewSettingNode17setItemUnselectedEv", 0x7C72FA, 50, 75352),
]


TARGET_SYMBOLS = {
    9: "_ZN18CmnViewSettingNode12getSuperItemEPPS_",
    12: "_ZN18CmnViewSettingNode15getSelectedItemEPPS_",
    14: "_ZN18CmnViewSettingNode20getSRNumSelectedItemERi",
    15: "_ZN18CmnViewSettingNode12getIdByIndexEiPPS_",
    16: "_ZN18CmnViewSettingNode12getIdBySRNumEiPPS_",
    19: "_ZN18CmnViewSettingNode12getSRNumByIdERi",
    21: "_ZN18CmnViewSettingNode8getStateERi",
    39: "_ZN18CmnViewSettingNode14isItemSelectedEv",
    48: "_ZN18CmnViewSettingNode15setItemSelectedEv",
    62: "_ZN18CmnViewSettingNode10getSubNodeEPPPS_Ri",
    63: "_ZN18CmnViewSettingNode17setItemUnselectedEv",
    64: "_ZN18CmnViewSettingNode4initEPPS_ii",
}


def _edge(caller, site, target, receiver):
    return {
        "caller_table_word": caller,
        "call_site": site,
        "dispatch": "indirect-vtable",
        "receiver": receiver,
        "target_table_word": target,
        "target_vptr_offset": (target - 2) * 4,
        "interface_symbol": TARGET_SYMBOLS[target],
        "final_target_resolved": receiver == "this",
    }


EDGES = [
    _edge(12, 0x7C6BEA, 62, "this"),
    _edge(14, 0x7C6C38, 12, "this"),
    _edge(14, 0x7C6C44, 19, "resolved-object"),
    _edge(22, 0x7C6D6C, 15, "this"),
    _edge(22, 0x7C6D78, 21, "resolved-object"),
    _edge(23, 0x7C6D90, 16, "this"),
    _edge(23, 0x7C6D9C, 21, "resolved-object"),
    _edge(40, 0x7C6F54, 15, "this"),
    _edge(40, 0x7C6F60, 39, "resolved-object"),
    _edge(41, 0x7C6F76, 16, "this"),
    _edge(41, 0x7C6F82, 39, "resolved-object"),
    _edge(48, 0x7C7084, 9, "this"),
    _edge(48, 0x7C7090, 12, "resolved-object"),
    _edge(48, 0x7C709E, 63, "resolved-object"),
    _edge(49, 0x7C70E6, 15, "this"),
    _edge(49, 0x7C70F2, 48, "resolved-object"),
    _edge(50, 0x7C7108, 16, "this"),
    _edge(50, 0x7C7114, 48, "resolved-object"),
    _edge(51, 0x7C7136, 14, "this"),
    _edge(51, 0x7C7146, 16, "this"),
    _edge(51, 0x7C7152, 48, "resolved-object"),
    _edge(58, 0x7C72C8, 64, "this"),
]

FIELD_ACCESSES = [
    {
        "offset": 0x18,
        "width": 4,
        "role": "selected-item-cache-field",
        "accesses": [
            {"table_word": 12, "site": 0x7C6BEE, "access": "read"},
            {"table_word": 12, "site": 0x7C6C00, "access": "write"},
            {"table_word": 13, "site": 0x7C6C16, "access": "read"},
        ],
    },
    {
        "offset": 0x20,
        "width": 4,
        "role": "set-selection-adjacent-field",
        "accesses": [
            {"table_word": 48, "site": 0x7C70A4, "access": "read"},
        ],
    },
    {
        "offset": 0x24,
        "width": 4,
        "role": "generic-selection-state-field",
        "accesses": [
            {"table_word": 21, "site": 0x7C6D52, "access": "read"},
            {"table_word": 39, "site": 0x7C6F26, "access": "read"},
            {"table_word": 48, "site": 0x7C7062, "access": "read"},
            {"table_word": 48, "site": 0x7C70A2, "access": "read"},
            {"table_word": 48, "site": 0x7C70B0, "access": "write"},
            {"table_word": 48, "site": 0x7C70BC, "access": "write"},
            {"table_word": 48, "site": 0x7C70C8, "access": "write"},
            {"table_word": 63, "site": 0x7C72FA, "access": "read"},
            {"table_word": 63, "site": 0x7C7316, "access": "write"},
            {"table_word": 63, "site": 0x7C7322, "access": "write"},
        ],
    },
]

UNRESOLVED_CALLBACK_SITES = [
    0x7C6C44, 0x7C6D78, 0x7C6D9C, 0x7C6F60, 0x7C6F82,
    0x7C7090, 0x7C709E, 0x7C70F2, 0x7C7114, 0x7C7152,
]

BOUNDED_TABLE_BRANCH = {
    "caller_table_word": 63,
    "site": 0x7C7304,
    "entry_count": 7,
    "data_start": 0x7C7308,
    "data_end": 0x7C730F,
    "resume": 0x7C7310,
    "targets": [0x7C7314, 0x7C731C, 0x7C7320, 0x7C7328],
}


def _canonical(value):
    return hashlib.sha256(
        (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    ).hexdigest()


CLAIMS = {
    "product_graph_selector_found": True,
    "product_graph_selector_is_user_selection": False,
    "generic_selected_state_dispatch_found": True,
    "creative_style_vtable_binding_found": True,
    "in_memory_selection_state_fields_found": True,
    "selected_model_value_storage_found": False,
    "resolved_object_callback_binding_found": False,
    "model_value_path_found": False,
    "model_setter_path_found": False,
    "menu_event_binding_found": False,
    "renderer_binding_found": False,
    "touch_routing_found": False,
    "commit_or_persistence_found": False,
    "creative_look_equivalence_found": False,
    "runtime_execution_proven": False,
}

EXPECTED_RAW_EXPORT = {
    "schema_version": 1,
    "program": "CautionConfig.so",
    "sha256": CAUTION_CONFIG_SHA256,
    "file_size": CAUTION_CONFIG_SIZE,
    "analysis_mode": {
        "read_only": True,
        "static_elf_metadata": True,
        "bounded_virtual_dataflow": True,
        "source_unchanged": True,
    },
    "creative_style_vtable": CREATIVE_STYLE_VTABLE,
    "product_graph_selector": {
        "backup_read_binding": BACKUP_READ_BINDING,
        "selectors": PRODUCT_SELECTORS,
        "classification": "shared-product-menu-graph-selector",
        "is_current_user_selection": False,
    },
    "methods": METHODS,
    "selected_state_dispatch": {
        "edges": EDGES,
        "edge_count": 22,
        "edge_digest": _canonical(EDGES),
        "local_leaf_table_words": [13, 21, 39, 62, 63],
        "field_accesses": FIELD_ACCESSES,
        "field_access_digest": _canonical(FIELD_ACCESSES),
        "unresolved_callback_sites": UNRESOLVED_CALLBACK_SITES,
        "method_decode_complete": True,
        "reported_sites_cfg_reachable": True,
        "receiver_identity_checked": True,
        "unhandled_register_writes_invalidated": True,
        "bounded_table_branch": BOUNDED_TABLE_BRANCH,
    },
    "claims": CLAIMS,
    "truncated": False,
}

READINESS = "GENERIC_SELECTED_STATE_DISPATCH_ONLY"
CONCLUSION = (
    "Creative Style inherits an exact generic selected-item interface: lookup, state, selection, "
    "unselection, and reinitialization resolve through 22 bounded virtual dispatches. The shared "
    "backup read in Creative Style and Picture Profile selects a product/menu graph, not the "
    "current user choice. The selected model value's storage, getter/setter, renderer, menu event, "
    "commit, and persistence paths remain unlocated."
)

_FORBIDDEN = (
    "raw", "byte", "disassembly", "instruction", "key_material", "device", "usb",
    "flash", "package", "payload",
)
_SHA = re.compile(r"[0-9a-f]{64}\Z")


class CreativeStyleSelectedStateDispatchError(ValueError):
    """Raised when selected-state evidence exceeds the exact static boundary."""


def _forbid(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if any(token in str(key).casefold() for token in _FORBIDDEN):
                raise CreativeStyleSelectedStateDispatchError("unsafe or reconstructive evidence field")
            _forbid(child)
    elif isinstance(value, list):
        for child in value:
            _forbid(child)


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise CreativeStyleSelectedStateDispatchError(label + " fields differ")
    return value


def normalize_creative_style_selected_state_dispatch_export(document):
    """Accept only the exact bounded product-selector and virtual-dispatch result."""
    _forbid(document)
    export = _exact(document, set(EXPECTED_RAW_EXPORT), "selected-state export")
    if export != EXPECTED_RAW_EXPORT:
        differing = sorted(key for key in EXPECTED_RAW_EXPORT if export[key] != EXPECTED_RAW_EXPORT[key])
        if differing == ["selected_state_dispatch"]:
            expected_dispatch = EXPECTED_RAW_EXPORT["selected_state_dispatch"]
            differing = ["selected_state_dispatch." + key for key in sorted(expected_dispatch) if export["selected_state_dispatch"].get(key) != expected_dispatch[key]]
        if "selected_state_dispatch.field_accesses" in differing:
            actual_fields = {item["offset"]: item for item in export["selected_state_dispatch"]["field_accesses"]}
            expected_fields = {item["offset"]: item for item in EXPECTED_RAW_EXPORT["selected_state_dispatch"]["field_accesses"]}
            field_offsets = [offset for offset in sorted(expected_fields) if actual_fields.get(offset) != expected_fields[offset]]
            differing = [item for item in differing if item not in ("selected_state_dispatch.field_accesses", "selected_state_dispatch.field_access_digest")]
            for offset in field_offsets:
                actual_sites = {item["site"] for item in actual_fields.get(offset, {}).get("accesses", [])}
                expected_sites = {item["site"] for item in expected_fields[offset]["accesses"]}
                missing = "+".join(f"{site:x}" for site in sorted(expected_sites - actual_sites)) or "none"
                extra = "+".join(f"{site:x}" for site in sorted(actual_sites - expected_sites)) or "none"
                differing.append(f"selected_state_dispatch.field_accesses.{offset:x}.missing-{missing}.extra-{extra}")
        raise CreativeStyleSelectedStateDispatchError("selected-state export differs in: " + ",".join(differing))
    if export["product_graph_selector"]["is_current_user_selection"] is not False:
        raise CreativeStyleSelectedStateDispatchError("product selector was promoted to user state")
    dispatch = export["selected_state_dispatch"]
    if dispatch["edge_count"] != len(dispatch["edges"]) or dispatch["edge_digest"] != _canonical(dispatch["edges"]):
        raise CreativeStyleSelectedStateDispatchError("dispatch boundary differs")
    method_words = {item["table_word"] for item in export["methods"]}
    if any(edge["caller_table_word"] not in method_words for edge in dispatch["edges"]):
        raise CreativeStyleSelectedStateDispatchError("dispatch caller is outside the method surface")
    if any(edge["target_vptr_offset"] != (edge["target_table_word"] - 2) * 4 for edge in dispatch["edges"]):
        raise CreativeStyleSelectedStateDispatchError("dispatch vptr offset differs")
    if dispatch["field_access_digest"] != _canonical(dispatch["field_accesses"]):
        raise CreativeStyleSelectedStateDispatchError("selection field access boundary differs")
    if [edge["call_site"] for edge in dispatch["edges"] if not edge["final_target_resolved"]] != dispatch["unresolved_callback_sites"]:
        raise CreativeStyleSelectedStateDispatchError("resolved-object callback boundary differs")
    if not all(dispatch[key] is True for key in ("method_decode_complete", "reported_sites_cfg_reachable", "receiver_identity_checked", "unhandled_register_writes_invalidated")):
        raise CreativeStyleSelectedStateDispatchError("virtual dataflow proof is incomplete")
    if dispatch["bounded_table_branch"] != BOUNDED_TABLE_BRANCH:
        raise CreativeStyleSelectedStateDispatchError("bounded table branch differs")
    return copy.deepcopy(export)


def summarize_creative_style_selected_state_dispatch_export(document):
    export = normalize_creative_style_selected_state_dispatch_export(document)
    return {
        "canonical_export_sha256": _canonical(export),
        "method_count": len(export["methods"]),
        "dispatch_edge_count": export["selected_state_dispatch"]["edge_count"],
        "product_selector_count": len(export["product_graph_selector"]["selectors"]),
    }


def validate_creative_style_selected_state_dispatch_report(document):
    _forbid(document)
    fields = {
        "schema_version", "analysis_scope", "camera_policy", "camera_executed", "installable",
        "camera_test_eligible", "source", "summary", "creative_style_vtable",
        "product_graph_selector", "selected_state_dispatch", "claims", "readiness",
        "conclusion",
    }
    report = _exact(document, fields, "selected-state report")
    if report["schema_version"] != 1 or report["analysis_scope"] != "offline-static-creative-style-selected-state-dispatch" or report["camera_policy"] != "physically-disconnected":
        raise CreativeStyleSelectedStateDispatchError("report scope differs")
    if any(report[key] is not False for key in ("camera_executed", "installable", "camera_test_eligible")):
        raise CreativeStyleSelectedStateDispatchError("report promotes camera activity")
    if report["source"] != {"module": "lib/CautionConfig.so", "size": CAUTION_CONFIG_SIZE, "sha256": CAUTION_CONFIG_SHA256}:
        raise CreativeStyleSelectedStateDispatchError("report source differs")
    expected_summary = summarize_creative_style_selected_state_dispatch_export(EXPECTED_RAW_EXPORT)
    if report["summary"] != expected_summary or _SHA.fullmatch(report["summary"]["canonical_export_sha256"] or "") is None:
        raise CreativeStyleSelectedStateDispatchError("report summary differs")
    if report["creative_style_vtable"] != CREATIVE_STYLE_VTABLE or report["product_graph_selector"] != EXPECTED_RAW_EXPORT["product_graph_selector"] or report["claims"] != CLAIMS:
        raise CreativeStyleSelectedStateDispatchError("report evidence differs")
    dispatch = EXPECTED_RAW_EXPORT["selected_state_dispatch"]
    expected_dispatch = {
        "method_count": len(METHODS),
        "edge_count": dispatch["edge_count"],
        "edge_digest": dispatch["edge_digest"],
        "field_offsets": [item["offset"] for item in dispatch["field_accesses"]],
        "field_access_digest": dispatch["field_access_digest"],
        "local_leaf_table_words": dispatch["local_leaf_table_words"],
        "unresolved_callback_count": len(dispatch["unresolved_callback_sites"]),
        "method_decode_complete": dispatch["method_decode_complete"],
        "reported_sites_cfg_reachable": dispatch["reported_sites_cfg_reachable"],
        "receiver_identity_checked": dispatch["receiver_identity_checked"],
        "unhandled_register_writes_invalidated": dispatch["unhandled_register_writes_invalidated"],
        "bounded_table_branch": dispatch["bounded_table_branch"],
    }
    if report["selected_state_dispatch"] != expected_dispatch:
        raise CreativeStyleSelectedStateDispatchError("report dispatch summary differs")
    if report["readiness"] != READINESS or report["conclusion"] != CONCLUSION:
        raise CreativeStyleSelectedStateDispatchError("report promotes unresolved behavior")
    return copy.deepcopy(report)
