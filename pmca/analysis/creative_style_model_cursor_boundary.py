"""Fail-closed evidence contract for the α6400 generic model/cursor boundary."""
from __future__ import annotations

import copy
import hashlib
import json
import re


VIEW_UNIFIED2_SIZE = 11_530_552
VIEW_UNIFIED2_SHA256 = "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2"


def _method(role, symbol_index, symbol, owner, size):
    return {
        "role": role,
        "symbol_index": symbol_index,
        "symbol": symbol,
        "owner": owner,
        "size": size,
    }


METHODS = [
    _method("move-cursor", 1737, "_ZN18CmnSettingNodeUtil10moveCursorENS_10CMN_CURSOREb", 0x2FE8E2, 148),
    _method("get-value", 3213, "_ZN18CmnSettingNodeUtil8getValueEv", 0x2FEA0E, 44),
    _method("get-process-value-id-for-item", 2981, "_ZN18CmnSettingNodeUtil19getProcValIdForItemEP18CmnViewSettingNode", 0x2FEA3A, 80),
    _method("set-cursor", 2779, "_ZN18CmnSettingNodeUtil9setCursorEi", 0x2FED32, 70),
    _method("update-belt-widget", 1930, "_ZN18CmnSettingNodeUtil16updateBeltWidgetEP22PAS_MenuSelectBeltZako", 0x2FEEF8, 32),
    _method("set-cursor-on-item-change", 1973, "_ZN18CmnSettingNodeUtil21setCursorOnItemChangeEv", 0x2FEF78, 340),
    _method("set-value-to-model", 3127, "_ZN18CmnSettingNodeUtil15setValueToModelEv", 0x2FF0CC, 112),
]


def _accesses(role, *items):
    return {"method_role": role, "accesses": list(items)}


def _access(site, offset, access):
    return {"site": site, "offset": offset, "width": 4, "access": access}


FIELD_ACCESSES = [
    _accesses("move-cursor"),
    _accesses("get-value", _access(0x2FEA1A, 0x0C, "read"), _access(0x2FEA28, 0x10, "read")),
    _accesses("get-process-value-id-for-item", _access(0x2FEA46, 0x0C, "read")),
    _accesses(
        "set-cursor",
        _access(0x2FED36, 0x08, "read"),
        _access(0x2FED3E, 0x0C, "read"),
        _access(0x2FED46, 0x0C, "read"),
        _access(0x2FED52, 0x30, "read"),
        _access(0x2FED5E, 0x34, "read"),
    ),
    _accesses("update-belt-widget", _access(0x2FEEFE, 0x18, "write"), _access(0x2FEF02, 0x0C, "read")),
    _accesses(
        "set-cursor-on-item-change",
        _access(0x2FEF82, 0x0C, "read"),
        _access(0x2FEF98, 0x18, "read"),
        _access(0x2FEFA2, 0x18, "read"),
        _access(0x2FEFAA, 0x08, "read"),
        _access(0x2FEFB4, 0x0C, "read"),
        _access(0x2FEFC0, 0x0C, "read"),
        _access(0x2FF000, 0x0C, "read"),
        _access(0x2FF048, 0x0C, "read"),
        _access(0x2FF064, 0x10, "read"),
    ),
    _accesses(
        "set-value-to-model",
        _access(0x2FF0D6, 0x0C, "read"),
        _access(0x2FF0F8, 0x0C, "read"),
        _access(0x2FF120, 0x10, "read"),
    ),
]


def _virtual(role, site, receiver, cell, symbol):
    return {
        "method_role": role,
        "site": site,
        "receiver": receiver,
        "interface_cell": cell,
        "interface_symbol": symbol,
        "concrete_target_resolved": False,
    }


VIRTUAL_CALLS = [
    _virtual("get-value", 0x2FEA2E, "this+0x10", 3, "interface-cell-3"),
    _virtual("get-process-value-id-for-item", 0x2FEA56, "this+0x0c", 23, "CmnViewSettingNode::getIntProperty"),
    _virtual("get-process-value-id-for-item", 0x2FEA64, "typed-argument-node", 23, "CmnViewSettingNode::getIntProperty"),
    _virtual("get-process-value-id-for-item", 0x2FEA7E, "typed-argument-node", 23, "CmnViewSettingNode::getIntProperty"),
    _virtual("set-cursor", 0x2FED50, "this+0x0c", 46, "_ZN18CmnViewSettingNode15setItemSelectedEv"),
    _virtual("set-cursor", 0x2FED5C, "this+0x30", 46, "_ZN18CmnViewSettingNode15setItemSelectedEv"),
    _virtual("set-cursor", 0x2FED68, "this+0x34", 46, "_ZN18CmnViewSettingNode15setItemSelectedEv"),
    _virtual("set-cursor-on-item-change", 0x2FEF94, "this+0x0c", 10, "_ZN18CmnViewSettingNode15getSelectedItemEPPS_"),
    _virtual("set-cursor-on-item-change", 0x2FEFB2, "this+0x08", 46, "_ZN18CmnViewSettingNode15setItemSelectedEv"),
    _virtual("set-cursor-on-item-change", 0x2FEFBE, "this+0x0c", 46, "_ZN18CmnViewSettingNode15setItemSelectedEv"),
    _virtual("set-cursor-on-item-change", 0x2FEFCC, "this+0x0c", 9, "interface-cell-9"),
    _virtual("set-cursor-on-item-change", 0x2FF010, "this+0x0c", 10, "_ZN18CmnViewSettingNode15getSelectedItemEPPS_"),
    _virtual("set-cursor-on-item-change", 0x2FF06E, "this+0x10", 23, "CmnViewSettingNode::getIntProperty"),
    _virtual("set-value-to-model", 0x2FF0E6, "this+0x0c", 10, "_ZN18CmnViewSettingNode15getSelectedItemEPPS_"),
    _virtual("set-value-to-model", 0x2FF0F4, "intermediate-untyped", 40, "interface-cell-40"),
    _virtual("set-value-to-model", 0x2FF10A, "intermediate-untyped", 10, "_ZN18CmnViewSettingNode15getSelectedItemEPPS_"),
    _virtual("set-value-to-model", 0x2FF126, "this+0x10", 15, "interface-cell-15"),
]


NAMED_LOOKUP_CALLS = [
    {
        "site": 0x2FF0FC,
        "symbol": "_ZN18CmnSettingNodeUtil16getProcIdForItemEP18CmnViewSettingNode",
        "symbol_index": 2806,
        "defined_owner": 0x2FE9EA,
        "defined_size": 36,
    },
    {
        "site": 0x2FF118,
        "symbol": "_ZN18CmnSettingNodeUtil19getProcValIdForItemEP18CmnViewSettingNode",
        "symbol_index": 2981,
        "defined_owner": 0x2FEA3A,
        "defined_size": 80,
    },
]


LOCAL_TERMINAL_CALLS = [
    {"site": 0x2FF12A, "target": 0x2FE74C, "name_resolved": False},
    {"site": 0x2FF130, "target": 0x2FE806, "name_resolved": False},
]

SET_DISP_STATE_BINDING = {
    "symbol": "_ZN20LayoutableWidgetBase12setDispStateEb",
    "symbol_index": 1018,
    "symbol_defined": False,
    "relocation_index": 1432,
    "got": 0x945D0C,
    "plt": 0x1530B4,
}

LOCAL_TERMINAL_ROUTINES = [
    {
        "start": 0x2FE74C,
        "end": 0x2FE806,
        "virtual_cells": [43, 10, 32, 108],
        "named_call_sites": [0x2FE7F8],
        "named_callee": SET_DISP_STATE_BINDING,
        "full_semantics_resolved": False,
        "unresolved_virtual_effects": True,
    },
    {
        "start": 0x2FE806,
        "end": 0x2FE8E2,
        "virtual_cells": [12, 43, 10, 32, 108],
        "named_call_sites": [0x2FE8BA, 0x2FE8C8, 0x2FE8D0],
        "named_callee": SET_DISP_STATE_BINDING,
        "full_semantics_resolved": False,
        "unresolved_virtual_effects": True,
    },
]

BELT_WIDGET_UPDATE = {
    "site": 0x2FEF0A,
    "plt": 0x1513B4,
    "symbol": "_ZN22PAS_MenuSelectBeltZako12updateWidgetEP18CmnViewSettingNode",
    "symbol_index": 2950,
    "symbol_defined": True,
    "relocation_index": 892,
    "got": 0x94549C,
    "defined_owner": 0x5CC38C,
    "defined_size": 372,
    "arguments": {"receiver": "incoming-belt", "node": "this+0x0c"},
    "tail_target": 0x2FE74C,
    "icon_content_setter": {
        "site": 0x5CC454,
        "plt": 0x152908,
        "symbol": "_ZN8GEN_Icon8setImageEjb",
        "symbol_index": 940,
        "symbol_defined": False,
        "relocation_index": 1290,
        "got": 0x945AD4,
    },
}


MOVE_CURSOR_LOCAL_TARGETS = [
    0x2FDF0C, 0x2FDE9A, 0x2FDF96, 0x2FDFE4, 0x2FE030,
    0x2FE168, 0x2FE26C, 0x2FE59A, 0x2FE74C, 0x2FE806,
]


CLAIMS = {
    "generic_cursor_selection_path_found": True,
    "named_set_value_to_model_helper_found": True,
    "process_id_lookup_found": True,
    "process_value_id_lookup_found": True,
    "ui_widget_state_update_found": True,
    "belt_widget_update_binding_found": True,
    "icon_content_setter_found": True,
    "creative_style_specific_binding_found": False,
    "selected_model_value_storage_found": False,
    "final_model_setter_or_commit_found": False,
    "menu_event_binding_found": False,
    "renderer_binding_found": False,
    "touch_routing_found": False,
    "commit_or_persistence_found": False,
    "backup_manager_binding_found": False,
    "creative_look_equivalence_found": False,
    "runtime_execution_proven": False,
}


def canonical_digest(value):
    return hashlib.sha256(
        (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    ).hexdigest()


MODEL_CURSOR_BOUNDARY = {
    "field_accesses": FIELD_ACCESSES,
    "field_access_digest": canonical_digest(FIELD_ACCESSES),
    "virtual_calls": VIRTUAL_CALLS,
    "virtual_call_digest": canonical_digest(VIRTUAL_CALLS),
    "virtual_call_scope": "bounded-utility-field-typed-argument-and-local-intermediate-receivers",
    "move_cursor_local_targets": MOVE_CURSOR_LOCAL_TARGETS,
    "update_belt_widget_call": BELT_WIDGET_UPDATE,
    "set_value_to_model": {
        "named_lookup_calls": NAMED_LOOKUP_CALLS,
        "local_terminal_calls": LOCAL_TERMINAL_CALLS,
        "local_terminal_routines": LOCAL_TERMINAL_ROUTINES,
        "local_terminal_semantics_resolved": False,
        "local_terminal_classification": "contains-widget-display-state-updates-with-unresolved-virtual-effects",
    },
    "reported_sites_structurally_present": True,
    "receiver_object_register_match_checked": True,
    "receiver_field_origin_linear_trace_checked": True,
    "path_sensitive_cfg_proof": False,
    "method_decode_complete": True,
}


EXPECTED_EXPORT = {
    "schema_version": 1,
    "program": "viewUnified2.so",
    "sha256": VIEW_UNIFIED2_SHA256,
    "file_size": VIEW_UNIFIED2_SIZE,
    "analysis_mode": {
        "read_only": True,
        "static_elf_metadata": True,
        "bounded_thumb_structural_trace": True,
        "source_unchanged": True,
    },
    "methods": METHODS,
    "model_cursor_boundary": MODEL_CURSOR_BOUNDARY,
    "claims": CLAIMS,
    "truncated": False,
}

READINESS = "GENERIC_MODEL_CURSOR_BOUNDARY_ONLY"
CONCLUSION = (
    "The generic setting-node utility connects cursor changes and selected-item interface calls "
    "to named process-ID/value-ID lookup helpers and a method named setValueToModel. Its final "
    "local targets contain proven widget display-state updates but retain unresolved virtual "
    "effects, and the belt path reaches a named "
    "widget update plus icon-content setter. No exact Creative Style binding, model commit, "
    "renderer, menu-event, touch, BackupManager, or durable-persistence edge is proven."
)

_FORBIDDEN_KEYS = ("payload", "key_material", "device_write", "usb_write", "flash_image", "package_bytes")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


class CreativeStyleModelCursorBoundaryError(ValueError):
    """Raised when model/cursor evidence exceeds the exact static boundary."""


def _forbid(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if any(token in str(key).casefold() for token in _FORBIDDEN_KEYS):
                raise CreativeStyleModelCursorBoundaryError("unsafe or reconstructive evidence field")
            _forbid(child)
    elif isinstance(value, list):
        for child in value:
            _forbid(child)


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise CreativeStyleModelCursorBoundaryError(label + " fields differ")
    return value


def normalize_creative_style_model_cursor_boundary_export(document):
    """Accept only the exact generic helper and unresolved-terminal boundary."""
    _forbid(document)
    export = _exact(document, set(EXPECTED_EXPORT), "model/cursor export")
    if export != EXPECTED_EXPORT:
        differing = sorted(key for key in EXPECTED_EXPORT if export.get(key) != EXPECTED_EXPORT[key])
        raise CreativeStyleModelCursorBoundaryError("model/cursor export differs in: " + ",".join(differing))
    boundary = export["model_cursor_boundary"]
    if boundary["field_access_digest"] != canonical_digest(boundary["field_accesses"]):
        raise CreativeStyleModelCursorBoundaryError("field-access digest differs")
    if boundary["virtual_call_digest"] != canonical_digest(boundary["virtual_calls"]):
        raise CreativeStyleModelCursorBoundaryError("virtual-call digest differs")
    if any(item["concrete_target_resolved"] for item in boundary["virtual_calls"]):
        raise CreativeStyleModelCursorBoundaryError("unresolved virtual target was promoted")
    if boundary["set_value_to_model"]["local_terminal_semantics_resolved"] is not False:
        raise CreativeStyleModelCursorBoundaryError("unresolved terminal semantics were promoted")
    if not all(boundary[key] is True for key in (
        "reported_sites_structurally_present", "receiver_object_register_match_checked",
        "receiver_field_origin_linear_trace_checked", "method_decode_complete",
    )) or boundary["path_sensitive_cfg_proof"] is not False:
        raise CreativeStyleModelCursorBoundaryError("bounded structural proof flags differ")
    if any(export["claims"][key] for key in (
        "creative_style_specific_binding_found", "selected_model_value_storage_found",
        "final_model_setter_or_commit_found", "menu_event_binding_found", "renderer_binding_found",
        "touch_routing_found", "commit_or_persistence_found", "backup_manager_binding_found",
        "creative_look_equivalence_found", "runtime_execution_proven",
    )):
        raise CreativeStyleModelCursorBoundaryError("negative claim was promoted")
    return copy.deepcopy(export)


def summarize_creative_style_model_cursor_boundary_export(document):
    export = normalize_creative_style_model_cursor_boundary_export(document)
    boundary = export["model_cursor_boundary"]
    return {
        "canonical_export_sha256": canonical_digest(export),
        "method_count": len(export["methods"]),
        "field_access_count": sum(len(item["accesses"]) for item in boundary["field_accesses"]),
        "virtual_call_count": len(boundary["virtual_calls"]),
        "local_terminal_count": len(boundary["set_value_to_model"]["local_terminal_calls"]),
    }


def validate_creative_style_model_cursor_boundary_report(document):
    _forbid(document)
    fields = {
        "schema_version", "analysis_scope", "camera_policy", "camera_executed", "installable",
        "camera_test_eligible", "source", "summary", "method_summary", "boundary_summary",
        "claims", "readiness", "conclusion",
    }
    report = _exact(document, fields, "model/cursor report")
    if report["schema_version"] != 1 or report["analysis_scope"] != "offline-static-creative-style-model-cursor-boundary" or report["camera_policy"] != "physically-disconnected":
        raise CreativeStyleModelCursorBoundaryError("report scope differs")
    if any(report[key] is not False for key in ("camera_executed", "installable", "camera_test_eligible")):
        raise CreativeStyleModelCursorBoundaryError("report promotes camera activity")
    if report["source"] != {"module": "lib/viewUnified2.so", "size": VIEW_UNIFIED2_SIZE, "sha256": VIEW_UNIFIED2_SHA256}:
        raise CreativeStyleModelCursorBoundaryError("report source differs")
    expected_summary = summarize_creative_style_model_cursor_boundary_export(EXPECTED_EXPORT)
    if report["summary"] != expected_summary or _SHA.fullmatch(report["summary"].get("canonical_export_sha256", "")) is None:
        raise CreativeStyleModelCursorBoundaryError("report summary differs")
    expected_method_summary = {
        "count": len(METHODS),
        "roles": [item["role"] for item in METHODS],
        "owners": [item["owner"] for item in METHODS],
    }
    expected_boundary_summary = {
        "field_access_count": expected_summary["field_access_count"],
        "field_access_digest": MODEL_CURSOR_BOUNDARY["field_access_digest"],
        "virtual_call_count": expected_summary["virtual_call_count"],
        "virtual_call_digest": MODEL_CURSOR_BOUNDARY["virtual_call_digest"],
        "named_lookup_sites": [item["site"] for item in NAMED_LOOKUP_CALLS],
        "local_terminal_calls": LOCAL_TERMINAL_CALLS,
        "local_terminal_semantics_resolved": False,
        "local_terminal_classification": "contains-widget-display-state-updates-with-unresolved-virtual-effects",
        "belt_widget_update_binding": {
            key: BELT_WIDGET_UPDATE[key]
            for key in ("site", "plt", "symbol", "symbol_index", "defined_owner", "defined_size")
        },
        "creative_style_specific_binding_found": False,
        "final_model_setter_or_commit_found": False,
        "commit_or_persistence_found": False,
    }
    if report["method_summary"] != expected_method_summary or report["boundary_summary"] != expected_boundary_summary or report["claims"] != CLAIMS:
        raise CreativeStyleModelCursorBoundaryError("report evidence differs")
    if report["readiness"] != READINESS or report["conclusion"] != CONCLUSION:
        raise CreativeStyleModelCursorBoundaryError("report promotes unresolved behavior")
    return copy.deepcopy(report)
