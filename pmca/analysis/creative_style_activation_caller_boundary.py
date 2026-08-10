"""Fail-closed α6400 Creative Style activation-caller evidence contract."""

from __future__ import annotations

import copy
import hashlib
import json


class CreativeStyleActivationCallerBoundaryError(ValueError):
    """Raised when activation-caller evidence exceeds the static boundary."""


SOURCE = {
    "module": "lib/viewUnified2.so",
    "size": 11_530_552,
    "sha256": "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2",
}

SUPPORTING_SOURCE = {
    "module": "lib/CautionConfig.so",
    "size": 12_070_800,
    "sha256": "bfd1bd7bad0ab3478b894da5dbb51c15464b1bedc4201240ccb61cd743150ef7",
}

DEPENDENCY = {
    "report": "analysis/a6400-creative-style-view-lifecycle-boundary.json",
    "evidence_digest": "6d1f51bd05f0bd2ba203ddef1a807aa8e25f5b924f41319cb1ad1ebddb44a572",
    "typed_process_id_42_caller_proven": False,
    "runtime_factory_invocation_proven": False,
}

SUPPORTING_DEPENDENCY = {
    "report": "analysis/a6400-creative-style-definition-registration.json",
    "artifact_sha256": "febc2ce84490fcbf4072ce77b5323df8584a5c68dd41293a3bfa8e1a6587343a",
    "root_constructor_binding_found": True,
    "root_constructor_runtime_provider_proven": False,
}

MANAGER_IDENTITY = {
    "type_name": "CmnViewProcessDataMgr",
    "instance_object": 0xB06BB0,
    "vtable_header": 0x905928,
    "vtable_address_point": 0x905930,
    "accessor": {
        "owner": {"start": 0x158350, "end": 0x1583AC, "complete": True},
        "pic_literal_site": 0x158398,
        "pic_base": 0x9446A0,
        "guard_got_cell": 0x94D228,
        "guard_relocation_index": 60668,
        "guard_storage": 0xB06BAC,
        "instance_got_cell": 0x94D990,
        "instance_relocation_index": 61126,
        "constructor_receiver_site": 0x158370,
        "constructor_call_site": 0x158372,
        "constructor_symbol": "_ZN21CmnViewProcessDataMgrC1Ev",
        "return_site": 0x15838A,
    },
    "constructor": {
        "owner": {"start": 0x43905C, "end": 0x4390BC, "complete": True},
        "bounded_body_end": 0x43907E,
        "pic_literal_site": 0x439080,
        "pic_base": 0x9446A0,
        "vtable_offset_literal_site": 0x439084,
        "vtable_got_cell": 0x94B104,
        "vtable_relocation_index": 58661,
        "vtable_header_target": 0x905928,
        "vtable_load_site": 0x43906E,
        "address_point_add_site": 0x439070,
        "vptr_store_site": 0x439072,
        "return_site": 0x43907A,
    },
    "bridge_slot": 20,
    "bridge_cell": 0x905980,
    "bridge_relocation_index": 37093,
    "bridge_target": 0x4390BC,
    "bridge_owner": {"start": 0x4390BC, "end": 0x4390D4, "complete": True},
    "bridge": {
        "condition_capture_site": 0x4390C0,
        "lookup_call_site": 0x4390C2,
        "lookup_target": 0x439088,
        "condition_forward_site": 0x4390CA,
        "typed_slot_load_site": 0x4390CC,
        "typed_slot_offset": 0x64,
        "typed_slot_call_site": 0x4390CE,
    },
}

TYPED_ACTIVATION_DEPENDENCY = {
    "element_type": "CmnViewProcessDataElementCustomCreativeStyle",
    "vtable_address_point": 0x90ED88,
    "slot": 25,
    "cell": 0x90EDEC,
    "relocation_index": 40033,
    "wrapper_target": 0x489218,
    "manager_bridge_target": 0x4390BC,
    "process_id": 42,
    "typed_process_id_42_caller_proven": False,
}

VIEWSETTINGMENU_IDENTITY = {
    "type_name": "ViewSettingMenu",
    "rtti": 0x8E2434,
    "type_name_address": 0x677110,
    "vtable_header": 0x8E2268,
    "typeinfo_cell": 0x8E226C,
    "typeinfo_relocation_index": 17834,
    "vtable_address_point": 0x8E2270,
    "slot_54": {
        "slot": 54,
        "cell": 0x8E2348,
        "relocation_index": 17848,
        "target": 0x2108B0,
        "owner": {"start": 0x2108B0, "end": 0x210D20, "complete": True},
    },
    "slot_64": {
        "slot": 64,
        "cell": 0x8E2370,
        "relocation_index": 17858,
        "target": 0x21355E,
        "owner": {"start": 0x21355E, "end": 0x213B8C, "complete": True},
    },
    "slot_65": {
        "slot": 65,
        "cell": 0x8E2374,
        "relocation_index": 17859,
        "target": 0x213418,
        "owner": {"start": 0x213418, "end": 0x213548, "complete": True},
    },
    "manager_publication": {
        "receiver_capture_site": 0x2108BC,
        "manager_accessor_call_site": 0x2109AA,
        "manager_accessor_target": 0x158350,
        "field_offset": 0x16C,
        "store_site": 0x2109C4,
        "same_receiver_proven": True,
    },
}

ACTION_TO_MANAGER_ROUTE = {
    "dispatcher_owner": {"start": 0x21355E, "end": 0x213B8C, "complete": True},
    "selector_limit_site": 0x213564,
    "selector_limit": 0x8E,
    "table_branch_site": 0x21356A,
    "action_selector": 10,
    "action_table_entry_site": 0x213582,
    "action_table_entry_halfword": 0xB7,
    "action_landing": 0x2136DC,
    "action_tail_site": 0x2136E0,
    "action_target": 0x20C7C0,
    "action_owner": {"start": 0x20C7C0, "end": 0x20C8A4, "complete": True},
    "state_field_load_site": 0x20C7C0,
    "state_field_offset": 0x14C,
    "receiver_capture_site": 0x20C7CA,
    "state_1_selected_node_call_site": 0x20C7CE,
    "state_1_selected_node_target": 0x207C4A,
    "state_3_probe_call_site": 0x20C7D8,
    "state_3_probe_target": 0x20C39C,
    "state_3_nonzero_receiver_site": 0x20C7DE,
    "state_3_nonzero_selected_node_call_site": 0x20C7E0,
    "state_3_nonzero_selected_node_target": 0x20C020,
    "state_3_zero_receiver_site": 0x20C7E6,
    "state_3_zero_selected_node_call_site": 0x20C7E8,
    "state_3_zero_selected_node_target": 0x207F28,
    "selected_node_move_site": 0x20C7EC,
    "selected_node_property_call_site": 0x20C7F4,
    "selected_node_property_helper": 0x2078C8,
    "selected_node_property_helper_owner": {
        "start": 0x2078C8,
        "end": 0x2078EC,
        "complete": True,
    },
    "selected_node_property_key_site": 0x2078DC,
    "selected_node_property_key": 14,
    "selected_node_property_vptr_load_site": 0x2078D6,
    "selected_node_property_slot_load_site": 0x2078DE,
    "selected_node_property_slot_offset": 0x5C,
    "selected_node_property_call_transfer_site": 0x2078E0,
    "property_result_capture_site": 0x20C7FC,
    "manager_field_offset": 0x16C,
    "manager_slot_19_cell": 0x90597C,
    "manager_slot_19_relocation_index": 37092,
    "manager_slot_19_target": 0x4390D4,
    "manager_slot_19_receiver_site": 0x20C884,
    "manager_slot_19_id_site": 0x20C888,
    "manager_slot_19_vptr_site": 0x20C88A,
    "manager_slot_19_load_site": 0x20C88C,
    "manager_slot_19_call_site": 0x20C88E,
    "manager_slot_20_receiver_site": 0x20C892,
    "manager_slot_20_id_site": 0x20C896,
    "condition_field_offset": 0x174,
    "condition_load_site": 0x20C898,
    "manager_slot_20_vptr_site": 0x20C89C,
    "manager_slot_20_load_site": 0x20C89E,
    "manager_slot_20_call_site": 0x20C8A0,
    "manager_receiver_proven": True,
    "manager_vptr_proven": True,
    "selected_node_property_source_proven": True,
    "condition_r2_proven": True,
    "selected_node_is_creative_style_root_proven": False,
    "process_id_42_proven": False,
}

CREATIVE_STYLE_PROPERTY_14 = {
    "root_object": 0xC5AE38,
    "properties_object": 0xC10A38,
    "property_list": 0xA54050,
    "property_count": 8,
    "property_constructor_owner": {
        "start": 0x8251F8,
        "end": 0x93AFF4,
        "complete": True,
    },
    "property_pic_base": 0xB0C1C8,
    "property_object_load_site": 0x83CCD8,
    "property_list_load_site": 0x83CCDE,
    "property_count_site": 0x83CCD6,
    "property_constructor_call_site": 0x83CCE0,
    "property_constructor_symbol": "_ZN24CmnViewSettingPropertiesC1EPK16_settingPropertyi",
    "property_object_got_cell": 0xB3A864,
    "property_object_relocation_index": 170252,
    "property_object_symbol_index": 59076,
    "property_list_got_cell": 0xB3D498,
    "property_list_relocation_index": 175923,
    "property_list_symbol_index": 64985,
    "record_address": 0xA5408C,
    "record": {"key": 14, "type": 1, "value": 42},
    "root_constructor_owner": {
        "start": 0x93AFF4,
        "end": 0x940954,
        "complete": True,
    },
    "root_receiver_load_site": 0x93B338,
    "root_properties_load_site": 0x93B342,
    "root_constructor_call_site": 0x93B344,
    "root_constructor_symbol": "_ZN31CmnViewSettingNodeCreativeStyleC1EPP18CmnViewSettingNodeiPK24CmnViewSettingProperties",
    "root_got_cell": 0xB1111C,
    "root_relocation_index": 87604,
    "root_symbol_index": 31507,
    "derived_constructor_owner": {
        "start": 0x7DBA40,
        "end": 0x7DBA74,
        "complete": True,
    },
    "base_constructor_call_site": 0x7DBA48,
    "base_constructor_symbol": "_ZN18CmnViewSettingNodeC2EPPS_iPK24CmnViewSettingProperties",
    "base_constructor_candidate_owner": {
        "start": 0x7C7610,
        "end": 0x7C7634,
        "complete": True,
    },
    "base_constructor_properties_store_site": 0x7C7626,
    "derived_vtable_got_cell": 0xB28A90,
    "derived_vtable_relocation_index": 134297,
    "derived_vtable_symbol_index": 63566,
    "derived_vtable_header": 0xAC8900,
    "derived_vtable_address_point": 0xAC8908,
    "derived_vptr_store_site": 0x7DBA56,
    "get_int_property_slot": 23,
    "get_int_property_cell": 0xAC8964,
    "get_int_property_relocation_index": 31358,
    "get_int_property_symbol_index": 23818,
    "get_int_property_target": 0x7C7518,
    "static_root_constructor_call_proven": True,
    "root_constructor_runtime_provider_binding_proven": False,
    "static_creative_style_root_property_14_equals_42_proven": True,
}

SELECTED_NODE_IDENTITY_BOUNDARY = {
    "runtime_selected_node_source": "ViewSettingMenu",
    "runtime_selected_node_helpers": [0x207C4A, 0x20C020, 0x207F28],
    "constructed_creative_style_root": 0xC5AE38,
    "selected_node_producer_identity_resolved": False,
    "exact_pointer_match_found": False,
    "pointer_identity_proven": False,
    "process_id_42_proven": False,
}


def _call(
    owner_start,
    owner_end,
    vptr_load,
    slot_load,
    call_site,
    receiver,
    *,
    manager_receiver=False,
    manager_vptr=False,
    process_id_source=False,
    condition=False,
):
    return {
        "owner": {"start": owner_start, "end": owner_end, "complete": True},
        "vptr_load_site": vptr_load,
        "slot_load_site": slot_load,
        "call_site": call_site,
        "receiver_register": receiver,
        "manager_receiver_proven": manager_receiver,
        "manager_vptr_proven": manager_vptr,
        "process_id_source_proven": process_id_source,
        "process_id_42_proven": False,
        "condition_r2_proven": condition,
        "accepted": False,
    }


CANONICAL_SLOT_20_CALLS = [
    _call(
        0x20C7C0,
        0x20C8A4,
        0x20C89C,
        0x20C89E,
        0x20C8A0,
        "r0",
        manager_receiver=True,
        manager_vptr=True,
        process_id_source=True,
        condition=True,
    ),
    _call(0x2A524C, 0x2A5294, 0x2A5254, 0x2A5256, 0x2A5258, "r0"),
    _call(0x2ABF6C, 0x2ABFDC, 0x2ABFAC, 0x2ABFAE, 0x2ABFB0, "r0"),
    _call(0x2AC550, 0x2AC590, 0x2AC56E, 0x2AC570, 0x2AC572, "r0"),
    _call(0x2F1094, 0x2F10C8, 0x2F10BA, 0x2F10BC, 0x2F10BE, "r0"),
    _call(0x35F8FE, 0x35F93E, 0x35F926, 0x35F928, 0x35F92A, "r0"),
    _call(0x43914C, 0x439164, 0x439158, 0x43915C, 0x43915E, "r0"),
    _call(0x43A5D0, 0x43A5F0, 0x43A5D8, 0x43A5DA, 0x43A5DC, "r0"),
    _call(0x45E114, 0x45E128, 0x45E120, 0x45E122, 0x45E124, "r0"),
    _call(0x46ADFC, 0x46AE10, 0x46AE08, 0x46AE0A, 0x46AE0C, "r0"),
    _call(0x50FBAC, 0x50FBDC, 0x50FBB4, 0x50FBB8, 0x50FBBA, "r1"),
    _call(0x50FBAC, 0x50FBDC, 0x50FBC0, 0x50FBC4, 0x50FBC6, "r4"),
    _call(0x578106, 0x578136, 0x57810E, 0x578112, 0x578114, "r1"),
    _call(0x578106, 0x578136, 0x57811A, 0x57811E, 0x578120, "r4"),
    _call(0x581144, 0x58131C, 0x581306, 0x581308, 0x58130A, "r0"),
    _call(0x5BC530, 0x5BC574, 0x5BC554, 0x5BC556, 0x5BC558, "r1"),
]

CALLER_SCAN = {
    "exidx_owner_count": 30_463,
    "fully_decoded_owner_count": 28_869,
    "incomplete_or_terminal_owner_count": 1_594,
    "canonical_slot_offset": 0x50,
    "canonical_slot_20_calls": CANONICAL_SLOT_20_CALLS,
    "accepted_candidates": [],
    "manager_bridge_direct_inbound": [],
    "typed_wrapper_direct_inbound": [],
    "direct_inbound_scan_complete": False,
    "whole_program_absence_proven": False,
    "unresolved_universes": [
        "decode-incomplete-or-terminal-exidx-owners",
        "noncanonical-virtual-dispatch",
        "indirect-callback-or-runtime-initialized-receiver",
        "cross-module-or-loader-mediated-delivery",
    ],
}

CLAIMS = {
    "concrete_process_manager_singleton_and_vptr_proven": True,
    "typed_manager_slot_20_bridge_proven": True,
    "bounded_canonical_slot_20_inventory_proven": True,
    "viewsettingmenu_typed_identity_proven": True,
    "viewsettingmenu_manager_publication_proven": True,
    "viewsettingmenu_action_to_process_manager_proven": True,
    "static_creative_style_property_14_equals_42_proven": True,
    "selected_node_is_creative_style_root_proven": False,
    "process_id_42_activation_caller_proven": False,
    "menu_root_activation_join_proven": False,
    "runtime_open_view_delivery_proven": False,
    "runtime_factory_invocation_proven": False,
    "returned_viewcreative_style_identity_proven": False,
    "first_class_creative_look_equivalence_proven": False,
    "processing_or_output_behavior_proven": False,
    "recovery_validated": False,
    "installable": False,
    "camera_test_eligible": False,
}

READINESS = (
    "VIEWSETTINGMENU_ACTION_TO_PROCESS_MANAGER_PROVEN__"
    "CREATIVE_STYLE_SELECTED_NODE_IDENTITY_UNRESOLVED"
)
FIRST_UNRESOLVED_BOUNDARY = (
    "viewsettingmenu-selected-node-pointer-identity-to-constructed-creative-style-root"
)
CONCLUSION = (
    "The authenticated VU2 module constructs a concrete CmnViewProcessDataMgr "
    "singleton at 0xB06BB0 and installs vptr 0x905930. A typed ViewSettingMenu "
    "slot-54 owner stores that manager at receiver field +0x16C, and slot-64 "
    "selector 10 reaches a bounded action that obtains selected-node property 14 "
    "and sends the returned integer plus receiver field +0x174 through manager "
    "slots 19 and 20. Authenticated CautionConfig metadata proves that the "
    "static Creative Style root-construction path's property-14 record is "
    "{14,1,42}; runtime PLT-provider binding remains unproven. The "
    "runtime selected-node pointer is not joined to that root, so the canonical "
    "call remains unaccepted and does not prove process ID 42 activation. The "
    "function-aware scan still covers 28,869 fully decoded exception-index "
    "owners, retains 1,594 incomplete or terminal owners, and inventories 16 "
    "canonical slot-0x50 calls. This result does not prove menu-root activation, "
    "runtime openView delivery, factory invocation, returned ViewCreativeStyle "
    "identity, first-class Creative Look equivalence, processing/output behavior, "
    "installability, recovery, or camera-test eligibility."
)

EXPECTED_EXPORT = {
    "schema_version": 2,
    "analysis_mode": "offline-static-creative-style-activation-caller-boundary",
    "source": SOURCE,
    "supporting_source": SUPPORTING_SOURCE,
    "dependency": DEPENDENCY,
    "supporting_dependency": SUPPORTING_DEPENDENCY,
    "manager_identity": MANAGER_IDENTITY,
    "typed_activation_dependency": TYPED_ACTIVATION_DEPENDENCY,
    "viewsettingmenu_identity": VIEWSETTINGMENU_IDENTITY,
    "action_to_manager_route": ACTION_TO_MANAGER_ROUTE,
    "creative_style_property_14": CREATIVE_STYLE_PROPERTY_14,
    "selected_node_identity_boundary": SELECTED_NODE_IDENTITY_BOUNDARY,
    "caller_scan": CALLER_SCAN,
    "claims": CLAIMS,
    "readiness": READINESS,
    "first_unresolved_boundary": FIRST_UNRESOLVED_BOUNDARY,
}


def normalize_creative_style_activation_caller_boundary_export(raw):
    """Validate and copy the exact fail-closed static export."""
    if raw != EXPECTED_EXPORT:
        raise CreativeStyleActivationCallerBoundaryError(
            "Creative Style activation-caller export differs from the pinned boundary"
        )
    return copy.deepcopy(raw)


def canonical_digest(document):
    encoded = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def _report_from_export(export):
    scan = export["caller_scan"]
    report = {
        "schema_version": 2,
        "analysis_scope": "offline-static-creative-style-activation-caller-boundary",
        "camera_policy": "physically-disconnected",
        "camera_executed": False,
        "installable": False,
        "recovery_validated": False,
        "camera_test_eligible": False,
        "source": copy.deepcopy(export["source"]),
        "supporting_source": copy.deepcopy(export["supporting_source"]),
        "dependency": copy.deepcopy(export["dependency"]),
        "supporting_dependency": copy.deepcopy(export["supporting_dependency"]),
        "summary": {
            "canonical_export_sha256": canonical_digest(export),
            "manager_instance_object": export["manager_identity"]["instance_object"],
            "manager_vtable_address_point": export["manager_identity"][
                "vtable_address_point"
            ],
            "fully_decoded_owner_count": scan["fully_decoded_owner_count"],
            "incomplete_or_terminal_owner_count": scan[
                "incomplete_or_terminal_owner_count"
            ],
            "canonical_slot_20_call_count": len(scan["canonical_slot_20_calls"]),
            "accepted_candidate_count": len(scan["accepted_candidates"]),
            "whole_program_absence_proven": scan["whole_program_absence_proven"],
            "viewsettingmenu_action_to_process_manager_proven": export["claims"][
                "viewsettingmenu_action_to_process_manager_proven"
            ],
            "static_creative_style_property_14_equals_42_proven": export["claims"][
                "static_creative_style_property_14_equals_42_proven"
            ],
            "selected_node_is_creative_style_root_proven": export["claims"][
                "selected_node_is_creative_style_root_proven"
            ],
        },
        "evidence": {
            "manager_identity": copy.deepcopy(export["manager_identity"]),
            "typed_activation_dependency": copy.deepcopy(
                export["typed_activation_dependency"]
            ),
            "viewsettingmenu_identity": copy.deepcopy(
                export["viewsettingmenu_identity"]
            ),
            "action_to_manager_route": copy.deepcopy(
                export["action_to_manager_route"]
            ),
            "creative_style_property_14": copy.deepcopy(
                export["creative_style_property_14"]
            ),
            "selected_node_identity_boundary": copy.deepcopy(
                export["selected_node_identity_boundary"]
            ),
            "caller_scan": copy.deepcopy(scan),
        },
        "first_unresolved_boundary": export["first_unresolved_boundary"],
        "readiness": export["readiness"],
        "claims": copy.deepcopy(export["claims"]),
        "conclusion": CONCLUSION,
        "narrative_sha256": hashlib.sha256(CONCLUSION.encode("utf-8")).hexdigest(),
    }
    report["evidence_digest"] = canonical_digest(report["evidence"])
    return report


def build_creative_style_activation_caller_boundary_report(document):
    """Build the checked report from the exact validated raw export."""
    return _report_from_export(
        normalize_creative_style_activation_caller_boundary_export(document)
    )


def validate_creative_style_activation_caller_boundary_report(document):
    """Reject any report that promotes the bounded caller scan."""
    expected = _report_from_export(EXPECTED_EXPORT)
    if document != expected:
        raise CreativeStyleActivationCallerBoundaryError(
            "Creative Style activation-caller report differs from the pinned boundary"
        )
    return copy.deepcopy(document)
