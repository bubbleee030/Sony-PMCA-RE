"""Fail-closed target-native Creative Style view/model binding evidence."""
from __future__ import annotations

import copy
import hashlib
import json
import re


SOURCE = {
    "module": "lib/viewUnified2.so",
    "size": 11_530_552,
    "sha256": "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2",
}

CASE_TARGETS = [
    0x5CF398, 0x5CF7D0, 0x5CD8C4, 0x5CD944, 0x5CD9C0,
    0x5D02A4, 0x5CFFE8, 0x5CE908, 0x5CE65C, 0x5CD9C6,
    0x5CD9CC, 0x5CE3E8, 0x5CE180, 0x5CFD14, 0x5CD9D4,
    0x5CD9EC, 0x5CE0A8, 0x5CDA14, 0x5CD8C4, 0x5CD944,
]

VIEW = {
    "type_name": "ViewCreativeStyle",
    "type_name_encoding": "17ViewCreativeStyle",
    "rtti": 0x93EC9C,
    "abi_type_info": "__si_class_type_info",
    "base_rtti_symbol": "_ZTI13ViewBaseForMR",
    "primary_vtable": {
        "header": 0x93ECB8,
        "address_point": 0x93ECC0,
        "end": 0x93EE38,
        "slot_count": 94,
    },
    "primary_relocation_shape": {"dynamic_symbol": 69, "local_relative": 25},
    "secondary_vtable": {
        "header": 0x93EE38,
        "offset_to_top": -0x28,
        "typeinfo_cell": 0x93EE3C,
        "address_point": 0x93EE40,
        "verified_slot_count": 2,
    },
    "factory_entry": {
        "symbol_index": 3418,
        "symbol": "ViewCreativeStyleToInstance",
        "range": {"start": 0x5CD88E, "end": 0x5CD8B2},
        "defined_function": True,
    },
    "constructor": {
        "factory_allocation_size_site": 0x5CD890,
        "object_size": 0x194,
        "helper": {"start": 0x5CD664, "end": 0x5CD6A0, "complete": True},
        "base_constructor_call": {"site": 0x5CD66C, "symbol": "_ZN13ViewBaseForMRC2EP11ViewManager"},
        "set_model_request_call": {"site": 0x5CD686, "symbol": "_ZN4View15setModelRequestEb", "value": False},
        "vtable_got_cell": 0x94D494,
        "vtable_got_relocation_index": 60820,
        "vtable_got_load": {
            "base_literal_load_site": 0x5CD668,
            "base_literal_site": 0x5CD698,
            "index_literal_load_site": 0x5CD670,
            "index_literal_site": 0x5CD69C,
            "base_add_site": 0x5CD672,
            "load_site": 0x5CD678,
        },
        "primary_vptr_store": {"site": 0x5CD682, "object_offset": 0, "address_point": 0x93ECC0},
        "secondary_vptr_store": {"site": 0x5CD684, "object_offset": 0x28, "address_point": 0x93EE40},
    },
    "initializer": {
        "slot": 54,
        "cell": 0x93ED98,
        "target": 0x5CCFA4,
        "owner": {"start": 0x5CCFA4, "end": 0x5CD100, "complete": True},
        "event_attachments": [
            {"site": 0x5CD024, "name": "@M00B", "literal_site": 0x5CD0F8, "vptr_load_site": 0x5CD014, "name_load_site": 0x5CD016, "receiver_site": 0x5CD018, "count_site": 0x5CD01A, "slot_load_site": 0x5CD01C, "name_add_site": 0x5CD020, "event_id_site": 0x5CD022, "count": 1, "event_id": 9},
            {"site": 0x5CD036, "name": "@M096", "literal_site": 0x5CD0FC, "vptr_load_site": 0x5CD026, "name_load_site": 0x5CD028, "receiver_site": 0x5CD02C, "count_site": 0x5CD02A, "slot_load_site": 0x5CD030, "name_add_site": 0x5CD02E, "event_id_site": 0x5CD034, "count": 1, "event_id": 8},
        ],
        "event_attachment_vtable_slot": 91,
        "event_attachment_cell": 0x93EE2C,
        "event_attachment_symbol": "_ZN13ViewBaseForMR13attachEventIdEPKcii",
        "model_request": {
            "site": 0x5CD04E,
            "vtable_slot": 87,
            "method": "ViewBaseForMR::requestModelExecute",
            "model_id_source": "CmnModelAndTreeId::getCurrentStillRecModelId",
            "request_code": 75,
            "param_list": None,
        },
    },
    "dispatcher": {
        "slot": 64,
        "cell": 0x93EDC0,
        "relocation_index": 51805,
        "target": 0x5D058C,
        "owner": {"start": 0x5D058C, "end": 0x5D0660, "complete": True},
        "selector_register": "r1",
        "selector_min": 0,
        "selector_max": 19,
        "guard": {"compare_site": 0x5D0592, "branch_site": 0x5D0594, "out_of_range_target": 0x5D065E},
        "table_branch_site": 0x5D0596,
        "table_start": 0x5D059A,
        "case_count": 20,
        "case_targets": CASE_TARGETS,
        "case_semantics_resolved": False,
    },
}

PROCESS_BINDING = {
    "view_helper_process_id": 42,
    "view_dispatch_join": {
        "case_index": 16,
        "case_target": 0x5CE0A8,
        "owner": {"start": 0x5CE0A8, "end": 0x5CE180, "complete": True},
        "read_helper_call_site": 0x5CE0FA,
        "write_helper_call_site": 0x5CE114,
    },
    "read_helper": {
        "target": 0x2D7C84,
        "owner": {"start": 0x2D7C84, "end": 0x2D7CF8, "complete": True},
        "manager_accessor_call_site": 0x2D7C94,
        "manager_result_capture_site": 0x2D7CA8,
        "manager_vptr_load_site": 0x2D7CB2,
        "manager_receiver_site": 0x2D7CB6,
        "process_id_site": 0x2D7CB8,
        "manager_slot_load_site": 0x2D7CCE,
        "manager_call_site": 0x2D7CD2,
        "manager_vtable_slot": 6,
        "manager_target": 0x43926A,
        "typed_element_slot": 10,
        "classification": "getValue-seven-argument-boundary",
    },
    "write_helper": {
        "target": 0x2D7CF8,
        "owner": {"start": 0x2D7CF8, "end": 0x2D7D54, "complete": True},
        "manager_accessor_call_site": 0x2D7D08,
        "manager_result_capture_site": 0x2D7D18,
        "manager_receiver_site": 0x2D7D24,
        "manager_vptr_load_site": 0x2D7D26,
        "process_id_site": 0x2D7D28,
        "manager_slot_load_site": 0x2D7D36,
        "manager_call_site": 0x2D7D3A,
        "manager_vtable_slot": 16,
        "manager_target": 0x43911E,
        "typed_element_slot": 21,
    },
    "manager": {
        "type_name": "CmnViewProcessDataMgr",
        "rtti": 0x905990,
        "vtable_header": 0x905928,
        "vtable_address_point": 0x905930,
        "instance_accessor": {
            "start": 0x158350,
            "end": 0x1583AC,
            "constructor_receiver_site": 0x158370,
            "constructor_call_site": 0x158372,
            "constructor_symbol": "_ZN21CmnViewProcessDataMgrC1Ev",
            "return_site": 0x15838A,
        },
        "lookup": {"start": 0x439088, "end": 0x4390BC, "complete": True},
    },
    "manager_mapping": {
        "table": 0x7AF2C4,
        "index": 42,
        "entry_site": 0x7AF36C,
        "value": 45,
    },
    "factory_dispatch": {
        "owner": {"start": 0x437AA0, "end": 0x438C94, "complete": True},
        "selector_min": 0,
        "selector_max": 377,
        "table": 0x437AB8,
        "selector_index": 45,
        "entry_site": 0x437B6C,
        "entry_offset": 0x751,
        "stub": 0x438208,
        "branch_site": 0x43820C,
        "accessor": 0x42ECA8,
    },
    "join_proof": {
        "lookup_input_register": "r1",
        "lookup_parameter_capture_site": 0x439090,
        "lookup_table_base_load_site": 0x439096,
        "lookup_table_base_literal_site": 0x4390B8,
        "lookup_table_base_add_site": 0x43909A,
        "lookup_table_load_site": 0x43909C,
        "lookup_factory_call_site": 0x4390A0,
        "lookup_result_vptr_load_site": 0x4390A6,
        "lookup_result_capture_site": 0x4390A8,
        "lookup_result_slot_load_site": 0x4390AA,
        "lookup_result_virtual_call_site": 0x4390AC,
        "lookup_return_site": 0x4390B2,
        "read_receiver": {
            "manager_entry": 0x43926A,
            "lookup_call_site": 0x439274,
            "vptr_load_site": 0x43927E,
            "slot_load_site": 0x439290,
            "virtual_call_site": 0x439294,
            "typed_element_slot": 10,
        },
        "write_receiver": {
            "manager_entry": 0x43911E,
            "lookup_call_site": 0x439128,
            "vptr_load_site": 0x439132,
            "slot_load_site": 0x43913C,
            "virtual_call_site": 0x439140,
            "typed_element_slot": 21,
        },
        "typed_accessor": {
            "initialized_branch_site": 0x42ECBE,
            "guard_failure_branch_site": 0x42ECC6,
            "constructor_call_site": 0x42ECCA,
            "constructor": 0x48B7E8,
            "constructor_receiver_site": 0x42ECC8,
            "accessor_return_site": 0x42ECE2,
            "constructor_object_capture_site": 0x48B7EE,
            "vtable_got_load_site": 0x48B7FA,
            "vtable_address_point_add_site": 0x48B7FC,
            "vptr_store_site": 0x48B7FE,
            "constructor_return_site": 0x48B80C,
        },
    },
    "typed_element": {
        "type_name": "CmnViewProcessDataElementCustomCreativeStyle",
        "type_name_encoding": "44CmnViewProcessDataElementCustomCreativeStyle",
        "rtti": 0x90EDF0,
        "vtable_header": 0x90ED80,
        "vtable_address_point": 0x90ED88,
        "vtable_got_cell": 0x9490C4,
        "vtable_got_relocation_index": 56691,
        "accessor": {"start": 0x42ECA8, "end": 0x42ED04, "complete": True},
        "constructor_factory": {"start": 0x48B7E8, "end": 0x48B82C, "complete": True},
        "value_getter_slot": 10,
        "value_getter_cell": 0x90EDB0,
        "value_getter_signature": "getValue(int&,int&,int&,int&,int&,int,int)",
        "value_getter": 0x48B8AC,
        "value_setter_slot": 21,
        "value_setter_cell": 0x90EDDC,
        "value_setter_signature": "setValue(int,int,int,int,int)",
        "value_setter": 0x4893AC,
    },
}

VALUE_COMMIT = {
    "owner": {"start": 0x4893AC, "end": 0x489644, "complete": True},
    "input_integer_count": 5,
    "backup_write_symbol": "_ZN21CmnViewModelIfWrapper11backupWriteEiPKv",
    "backup_write_call_sites": [0x489540, 0x48955A, 0x489574, 0x489588, 0x489598],
    "first_backup_id": 0x01070762,
    "model_request": {
        "site": 0x4895FA,
        "model": "@M00B",
        "request_code": 38,
        "param_list_add_count": 5,
    },
    "five_argument_semantics_resolved": False,
    "selected_style_argument_identified": False,
    "renderer_or_output_sink_found": False,
}

CONTROLLER_MODE = {
    "field_offset": 0x15C,
    "storage_width_bytes": 4,
    "backup_storage_width_bytes": 1,
    "observed_write_sites": [
        {"site": 0x5CFE5C, "value": 0, "value_source_site": 0x5CFE4C},
        {"site": 0x5D0120, "value": 3, "value_source_site": 0x5D011A},
        {"site": 0x5D0166, "value": 2, "value_source_site": 0x5D0162},
        {"site": 0x5D019E, "value": 1, "value_source_site": 0x5D019A},
        {"site": 0x5D01E2, "value": 4, "value_source_site": 0x5D01DE},
        {"site": 0x5D0224, "value": 0, "value_source_site": 0x5D021C},
    ],
    "observed_values": [0, 1, 2, 3, 4],
    "backup_id": 0x01070763,
    "backup_read_helper": {"start": 0x5CEE20, "end": 0x5CEE48, "complete": True},
    "backup_write_helper": {"start": 0x5CEFC0, "end": 0x5CEFE4, "complete": True},
    "reset_to_zero_on_slot_57": True,
    "reset_site": 0x5CF032,
    "reset_value_source_site": 0x5CF02A,
    "selected_creative_style_value_proven": False,
    "classification": "controller-mode-word-with-one-byte-backup-not-selected-style",
}

LOADER_REGISTRATION = {
    "module_string": "viewCreativeStyle.so",
    "module_string_address": 0x7AC326,
    "factory_string": "ViewCreativeStyleToInstance",
    "factory_string_address": 0x7AC33B,
    "factory_rel_dyn_relocation_count": 0,
    "factory_rel_plt_relocation_count": 0,
    "factory_direct_call_count": 0,
    "factory_direct_call_scan_complete": False,
    "factory_init_array_target_count": 0,
    "registration_or_loader_edge_found": False,
}

CLAIMS = {
    "creative_style_view_owner_found": True,
    "view_factory_function_found": True,
    "view_model_request_found": True,
    "typed_custom_process_element_binding_found": True,
    "creative_style_value_read_boundary_found": True,
    "creative_style_value_write_boundary_found": True,
    "backup_write_boundary_found": True,
    "model_request_boundary_found": True,
    "factory_registration_route_found": False,
    "selected_creative_style_field_identified": False,
    "five_argument_semantics_resolved": False,
    "eight_axis_creative_look_model_found": False,
    "renderer_or_output_sink_found": False,
    "touch_routing_found": False,
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
        "thumb_control_flow": True,
        "typed_itanium_rtti_and_vtable": True,
        "source_unchanged": True,
    },
    "source": SOURCE,
    "view": VIEW,
    "process_binding": PROCESS_BINDING,
    "value_commit": VALUE_COMMIT,
    "controller_mode": CONTROLLER_MODE,
    "loader_registration": LOADER_REGISTRATION,
    "claims": CLAIMS,
    "evidence_digest": canonical_digest({
        "view": VIEW,
        "process_binding": PROCESS_BINDING,
        "value_commit": VALUE_COMMIT,
        "controller_mode": CONTROLLER_MODE,
        "loader_registration": LOADER_REGISTRATION,
    }),
    "truncated": False,
}

READINESS = "TARGET_NATIVE_CREATIVE_STYLE_UI_MODEL_COMMIT_BOUNDARY"
CONCLUSION = (
    "The target-native ViewCreativeStyle screen is bound through process-data ID 42 to the typed "
    "CmnViewProcessDataElementCustomCreativeStyle singleton. Its manager path reaches exact "
    "getValue slot 10 and the five-integer setValue override at slot 21; that setter contains five bounded "
    "backupWrite call sites, five ParamList-add call sites, and an @M00B operation-38 request call site. A separate word at view "
    "offset 0x15c is a resettable controller mode persisted through a one-byte backup representation, not "
    "a proven selected-style field. Factory "
    "registration, five-argument semantics, an eight-axis Creative Look model, renderer/output "
    "binding, touch routing, runtime behavior, and installability remain unproven."
)

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FORBIDDEN_KEYS = (
    "payload", "key_material", "device_write", "usb_write", "flash_image", "package_bytes",
)


class CreativeStyleViewModelBindingError(ValueError):
    """Raised when the Creative Style view/model boundary is malformed or promoted."""


def _forbid(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if any(token in str(key).casefold() for token in _FORBIDDEN_KEYS):
                raise CreativeStyleViewModelBindingError("unsafe or reconstructive evidence field")
            _forbid(child)
    elif isinstance(value, list):
        for child in value:
            _forbid(child)


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise CreativeStyleViewModelBindingError(label + " fields differ")
    return value


def normalize_creative_style_view_model_binding_export(document):
    _forbid(document)
    export = _exact(document, set(EXPECTED_EXPORT), "Creative Style view/model export")
    if export != EXPECTED_EXPORT:
        differing = sorted(key for key in EXPECTED_EXPORT if export.get(key) != EXPECTED_EXPORT[key])
        raise CreativeStyleViewModelBindingError("Creative Style view/model export differs in: " + ",".join(differing))
    if export["evidence_digest"] != canonical_digest({
        "view": export["view"],
        "process_binding": export["process_binding"],
        "value_commit": export["value_commit"],
        "controller_mode": export["controller_mode"],
        "loader_registration": export["loader_registration"],
    }):
        raise CreativeStyleViewModelBindingError("evidence digest differs")
    if export["view"]["primary_vtable"]["slot_count"] != 94:
        raise CreativeStyleViewModelBindingError("ViewCreativeStyle primary slot count differs")
    if export["process_binding"]["manager_mapping"]["value"] != export["process_binding"]["factory_dispatch"]["selector_index"]:
        raise CreativeStyleViewModelBindingError("process manager/factory selector join differs")
    if export["process_binding"]["typed_element"]["value_setter_slot"] != 21:
        raise CreativeStyleViewModelBindingError("typed Creative Style setter slot differs")
    binding = export["process_binding"]
    if (
        binding["view_dispatch_join"]["case_target"]
        != export["view"]["dispatcher"]["case_targets"][binding["view_dispatch_join"]["case_index"]]
        or binding["read_helper"]["typed_element_slot"] != binding["typed_element"]["value_getter_slot"]
        or binding["write_helper"]["typed_element_slot"] != binding["typed_element"]["value_setter_slot"]
        or binding["join_proof"]["read_receiver"]["typed_element_slot"] != binding["typed_element"]["value_getter_slot"]
        or binding["join_proof"]["write_receiver"]["typed_element_slot"] != binding["typed_element"]["value_setter_slot"]
    ):
        raise CreativeStyleViewModelBindingError("view/helper/typed process-element join differs")
    if export["controller_mode"]["storage_width_bytes"] != 4 or export["controller_mode"]["backup_storage_width_bytes"] != 1:
        raise CreativeStyleViewModelBindingError("controller storage or backup width differs")
    if export["controller_mode"]["selected_creative_style_value_proven"]:
        raise CreativeStyleViewModelBindingError("controller mode was promoted to selected style")
    forbidden_positive = (
        "factory_registration_route_found", "selected_creative_style_field_identified",
        "five_argument_semantics_resolved", "eight_axis_creative_look_model_found",
        "renderer_or_output_sink_found", "touch_routing_found", "creative_look_equivalence_found",
        "runtime_execution_proven",
    )
    if any(export["claims"][key] for key in forbidden_positive):
        raise CreativeStyleViewModelBindingError("unproven Creative Style or Creative Look claim was promoted")
    return copy.deepcopy(export)


def summarize_creative_style_view_model_binding_export(document):
    export = normalize_creative_style_view_model_binding_export(document)
    return {
        "canonical_export_sha256": canonical_digest(export),
        "view_primary_slot_count": export["view"]["primary_vtable"]["slot_count"],
        "view_dispatch_case_count": export["view"]["dispatcher"]["case_count"],
        "typed_process_element_count": 1,
        "value_setter_argument_count": export["value_commit"]["input_integer_count"],
        "backup_write_call_count": len(export["value_commit"]["backup_write_call_sites"]),
        "model_param_count": export["value_commit"]["model_request"]["param_list_add_count"],
    }


def validate_creative_style_view_model_binding_report(document):
    _forbid(document)
    fields = {
        "schema_version", "analysis_scope", "camera_policy", "camera_executed", "installable",
        "camera_test_eligible", "source", "summary", "evidence_digest", "claims", "readiness",
        "conclusion",
    }
    report = _exact(document, fields, "Creative Style view/model report")
    if report["schema_version"] != 1 or report["analysis_scope"] != "offline-static-creative-style-view-model-binding" or report["camera_policy"] != "physically-disconnected":
        raise CreativeStyleViewModelBindingError("report scope differs")
    if any(report[key] is not False for key in ("camera_executed", "installable", "camera_test_eligible")):
        raise CreativeStyleViewModelBindingError("report promotes camera activity")
    if report["source"] != SOURCE or report["summary"] != summarize_creative_style_view_model_binding_export(EXPECTED_EXPORT):
        raise CreativeStyleViewModelBindingError("report source or summary differs")
    if _SHA.fullmatch(report["summary"].get("canonical_export_sha256", "")) is None:
        raise CreativeStyleViewModelBindingError("report digest shape differs")
    if report["evidence_digest"] != EXPECTED_EXPORT["evidence_digest"] or report["claims"] != CLAIMS:
        raise CreativeStyleViewModelBindingError("report evidence differs")
    if report["readiness"] != READINESS or report["conclusion"] != CONCLUSION:
        raise CreativeStyleViewModelBindingError("report conclusion differs")
    return copy.deepcopy(report)
