"""Fail-closed α6400 Creative Style selected-node identity evidence contract."""

from __future__ import annotations

import copy
import hashlib
import json


class CreativeStyleSelectedNodeIdentityBoundaryError(ValueError):
    """Raised when selected-node evidence exceeds the static boundary."""


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

DEPENDENCIES = [
    {
        "report": "analysis/a6400-creative-style-activation-caller-boundary.json",
        "digest_field": "evidence_digest",
        "digest": "5ba9e6edacdf1d1bfa4472de2eaa88381359a7cbdc0ed62aac1f8493b59812a4",
    },
    {
        "report": "analysis/a6400-creative-style-definition-registration.json",
        "digest_field": "artifact_sha256",
        "digest": "febc2ce84490fcbf4072ce77b5323df8584a5c68dd41293a3bfa8e1a6587343a",
    },
    {
        "report": "analysis/a6400-creative-style-menu-list-construction.json",
        "digest_field": "summary.canonical_export_sha256",
        "digest": "43ce4740fe9d195505a35823722112543d2d2e29e7c1fc91b565ea7c85dd0e8d",
    },
]

PRODUCT_ROOT_SELECTION = {
    "selector_owner": {"start": 0x208648, "end": 0x2088F0, "complete": True},
    "backup_read_call_site": 0x20865A,
    "backup_record_id_literal_cell": 0x20882C,
    "backup_record_id": 0x01070316,
    "table_branch_site": 0x208668,
    "selector_value_count": 75,
    "unique_return_count": 49,
    "selector_return_map_digest": (
        "6bcc43b350783cf9e085c644f9e7ca6ece162c59408247bbe8033041bfce7aef"
    ),
    "unique_returns": [
        0x0,
        0xB09A3C,
        0xB09B5C,
        0xB09E04,
        0xB0B158,
        0xB0B900,
        0xB0BD60,
        0xB0C820,
        0xB0D260,
        0xB0D3C8,
        0xB0D470,
        0xB0D538,
        0xB0DA60,
        0xB0E564,
        0xB0F8DC,
        0xB0FA1C,
        0xB0FB84,
        0xB0FCEC,
        0xB102E4,
        0xB106AC,
        0xB10C14,
        0xB10EBC,
        0xB1156C,
        0xB115BC,
        0xB11724,
        0xB1183C,
        0xB131FC,
        0xB133DC,
        0xB134F4,
        0xB1351C,
        0xB1354C,
        0xB1432C,
        0xB14E48,
        0xB154D8,
        0xB15D2C,
        0xB15D54,
        0xB15FAC,
        0xB1668C,
        0xB16764,
        0xB168A4,
        0xB16A5C,
        0xB16EA4,
        0xB17214,
        0xB17714,
        0xB18878,
        0xB188F0,
        0xB18CF0,
        0xB195F0,
        0xB198C0,
    ],
    "null_selector_values": [32],
    "default_root": 0xB09B5C,
    "default_root_selector_values": [
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        11,
        12,
        13,
        14,
        15,
        22,
        33,
        34,
        35,
        36,
        37,
        38,
        39,
        40,
        41,
        50,
        54,
        66,
    ],
    "slot_54_owner": {"start": 0x2108B0, "end": 0x210D20, "complete": True},
    "slot_54_call_site": 0x210986,
    "slot_54_store_site": 0x21098C,
    "slot_54_receiver_register": "r5",
    "product_root_field_offset": 0x1A0,
    "same_receiver_and_return_value_proven": True,
}

CONSTRUCTOR_GRAPH = {
    "owner": {"start": 0x213B8C, "end": 0x228BA4, "complete": True},
    "reachable_instruction_count": 23_355,
    "generic_constructor_call_count": 1_748,
    "generic_constructor_plt": 0x154024,
    "generic_constructor_symbol": (
        "_ZN18CmnViewSettingNodeC1EPPS_iPK24CmnViewSettingProperties"
    ),
    "runtime_provider_binding_proven": False,
    "path_constructors": [
        {
            "call_site": 0x21EE7E,
            "node": 0xB09B5C,
            "child_list": 0x957C80,
            "child_count": 5,
            "properties": 0xB1A36C,
        },
        {
            "call_site": 0x21EDCA,
            "node": 0xB152A8,
            "child_list": 0x956B78,
            "child_count": 8,
            "properties": 0xB1A3D4,
        },
        {
            "call_site": 0x21EAFA,
            "node": 0xB12364,
            "child_list": 0x9548BC,
            "child_count": 6,
            "properties": 0xB1A394,
        },
    ],
}

STATIC_PATH = {
    "zero_based_indices": [0, 4, 1],
    "start_root": 0xB09B5C,
    "final_symbol": "cmnViewSettingNodeRootCreativeStyle",
    "final_symbol_runtime_provider_proven": False,
    "edges": [
        {
            "index": 0,
            "cell": 0x957C80,
            "relocation_index": 64_482,
            "relocation_type": 23,
            "symbol_index": 0,
            "target": 0xB152A8,
        },
        {
            "index": 4,
            "cell": 0x956B88,
            "relocation_index": 64_238,
            "relocation_type": 23,
            "symbol_index": 0,
            "target": 0xB12364,
        },
        {
            "index": 1,
            "cell": 0x9548C0,
            "relocation_index": 130_947,
            "relocation_type": 2,
            "symbol_index": 901,
            "target": 0,
        },
    ],
}

SELECTED_CHILD_MECHANISM = {
    "owner": {"start": 0x207C4A, "end": 0x207C8C, "complete": True},
    "root_field_offset": 0x1A0,
    "virtual_slot_offset": 0x28,
    "chained_call_count": 3,
    "same_result_to_next_receiver_proven": True,
    "final_child_returned_proven": True,
}

RUNTIME_SELECTION = {
    "required_one_based_ordinals": [1, 5, 2],
    "candidate_get_selected_item": {
        "symbol": "_ZN18CmnViewSettingNode15getSelectedItemEPPS_",
        "vtable_address_point": 0xAB9400,
        "slot": 10,
        "cell": 0xAB9428,
        "relocation_index": 15_680,
        "owner": {"start": 0x7C6BD2, "end": 0x7C6C16, "complete": True},
        "selected_ordinal_offset": 0x18,
        "positive_clamp_and_subtract_one_proven": True,
        "runtime_provider_binding_proven": False,
    },
    "candidate_get_sub_node": {
        "symbol": "_ZN18CmnViewSettingNode10getSubNodeEPPPS_Ri",
        "vtable_address_point": 0xAB9400,
        "slot": 60,
        "cell": 0xAB94F0,
        "relocation_index": 73_942,
        "symbol_range": {"start": 0x7C72CC, "end": 0x7C72EA},
        "child_list_offset": 4,
        "child_count_offset": 8,
        "runtime_provider_binding_proven": False,
    },
}

ROOT_INITIALIZATION = {
    "slot_54_owner": {"start": 0x2108B0, "end": 0x210D20, "complete": True},
    "root_field_offset": 0x1A0,
    "root_store_site": 0x21098C,
    "root_vptr_load_site": 0x210992,
    "init_slot_load_site": 0x210994,
    "init_slot_offset": 0x08,
    "list_helper_call_site": 0x210996,
    "list_helper_target": 0x2084EC,
    "list_helper_owner": {"start": 0x2084EC, "end": 0x208548, "complete": True},
    "count_load_site": 0x21099E,
    "root_receiver_restore_site": 0x2109A2,
    "init_call_site": 0x2109A4,
    "default_root_bindings": [
        {
            "role": "root-list",
            "got": 0x948AA0,
            "relocation_index": 130_801,
            "relocation_type": 21,
            "symbol_index": 392,
            "symbol": "cmnViewSettingNodesRootDefault",
        },
        {
            "role": "root-count",
            "got": 0x94B8E4,
            "relocation_index": 130_996,
            "relocation_type": 21,
            "symbol_index": 937,
            "symbol": "cmnViewSettingNodesNumOfRootDefault",
        },
    ],
    "pointer_width": 4,
    "list_argument_register": "r1",
    "count_argument_register": "r2",
    "root_argument_register": "r0",
    "virtual_target_register": "r4",
    "runtime_binding_proven": False,
}

CANDIDATE_LIFECYCLE = {
    "vtable_address_point": 0xAB9400,
    "init_setting_node": {
        "cell": 0xAB9408,
        "slot_offset": 0x08,
        "relocation_index": 6_168,
        "relocation_type": 2,
        "symbol_index": 3_892,
        "symbol": "_ZN18CmnViewSettingNode15initSettingNodeEPPS_i",
        "owner": {"start": 0x7C6AEA, "end": 0x7C6B20, "complete": True},
        "lifecycle_slots": [
            {"offset": 0xE8, "load_site": 0x7C6AF2, "call_site": 0x7C6AFC},
            {"offset": 0xF8, "load_site": 0x7C6B08, "call_site": 0x7C6B0E},
            {"offset": 0xEC, "load_site": 0x7C6B16, "call_site": 0x7C6B1A},
        ],
    },
    "recursive_init": {
        "cell": 0xAB94F8,
        "slot_offset": 0xF8,
        "relocation_index": 76_320,
        "relocation_type": 2,
        "symbol_index": 72_371,
        "symbol": "_ZN18CmnViewSettingNode4initEPPS_ii",
        "owner": {"start": 0x7C732C, "end": 0x7C744C, "complete": True},
        "parent_store_site": 0x7C73BE,
        "parent_field_offset": 0x10,
        "ordinal_increment_site": 0x7C73B8,
        "ordinal_store_site": 0x7C73C4,
        "one_based_ordinal_field_offset": 0x20,
        "selected_state_store_site": 0x7C73C8,
        "selected_state_field_offset": 0x24,
        "selected_ordinal_store_site": 0x7C73CE,
        "selected_ordinal_field_offset": 0x18,
        "recursive_slot_load_site": 0x7C73FA,
        "recursive_call_site": 0x7C7402,
        "selected_state_test_slot_offset": 0x94,
        "selected_state_test_call_site": 0x7C7410,
        "set_selected_slot_offset": 0xB8,
        "set_selected_call_site": 0x7C741E,
        "selected_child_slot_offset": 0x28,
        "selected_child_call_site": 0x7C7432,
        "fallback_slot_offset": 0xFC,
        "fallback_call_site": 0x7C743E,
    },
    "set_head_selected": {
        "cell": 0xAB94FC,
        "slot_offset": 0xFC,
        "relocation_index": 77_509,
        "relocation_type": 2,
        "symbol_index": 57_258,
        "symbol": "_ZN18CmnViewSettingNode19setHeadItemSelectedEv",
        "owner": {"start": 0x7C744C, "end": 0x7C747A, "complete": True},
        "requested_one_based_ordinal": 1,
        "child_lookup_slot_offset": 0x38,
        "child_lookup_call_site": 0x7C745C,
        "set_selected_slot_offset": 0xB8,
        "set_selected_call_site": 0x7C7468,
        "missing_child_selected_ordinal": -1,
    },
    "one_based_ordinal_field_offset": 0x20,
    "selected_ordinal_field_offset": 0x18,
    "runtime_provider_binding_proven": False,
    "live_selected_ordinal_triplet_1_5_2_proven": False,
}

SELECTED_ORDINAL_WRITERS = {
    "field_offset": 0x18,
    "writers": [
        {
            "site": 0x7C6C00,
            "owner": {"start": 0x7C6BD2, "end": 0x7C6C16, "complete": True},
            "destination_identity": "this",
            "destination_register": "r4",
            "source_identity": "positive-count-clamped-selected-ordinal",
            "source_register": "r3",
            "source_field_offset": None,
            "role": "selected-item-cache-clamp",
            "typed_lifecycle_path": True,
        },
        {
            "site": 0x7C70AA,
            "owner": {"start": 0x7C705A, "end": 0x7C70DA, "complete": True},
            "destination_identity": "resolved-super-item",
            "destination_register": "r3",
            "source_identity": "selected-child-one-based-ordinal",
            "source_register": "r2",
            "source_field_offset": 0x20,
            "role": "parent-selected-ordinal-from-child-one-based-field",
            "typed_lifecycle_path": True,
        },
        {
            "site": 0x7C7358,
            "owner": {"start": 0x7C732C, "end": 0x7C744C, "complete": True},
            "destination_identity": "this",
            "destination_register": "r0",
            "source_identity": "minus-one",
            "source_register": "r3",
            "source_field_offset": None,
            "role": "root-default-minus-one",
            "typed_lifecycle_path": True,
        },
        {
            "site": 0x7C73CE,
            "owner": {"start": 0x7C732C, "end": 0x7C744C, "complete": True},
            "destination_identity": "resolved-child",
            "destination_register": "r0",
            "source_identity": "minus-one",
            "source_register": "r3",
            "source_field_offset": None,
            "role": "child-default-minus-one",
            "typed_lifecycle_path": True,
        },
        {
            "site": 0x7C7470,
            "owner": {"start": 0x7C744C, "end": 0x7C747A, "complete": True},
            "destination_identity": "this",
            "destination_register": "r4",
            "source_identity": "minus-one",
            "source_register": "r3",
            "source_field_offset": None,
            "role": "fallback-missing-child-minus-one",
            "typed_lifecycle_path": True,
        },
    ],
    "typed_owner_inventory_complete": True,
    "parent_selected_ordinal_from_child_one_based_field_proven": True,
    "candidate_provider_conditional_ordinal_triplet_proven": False,
    "runtime_selected_ordinal_triplet_1_5_2_proven": False,
}

UNNAMED_PRODUCTACTION_CALLER_OWNER = {
    "kind": "unnamed-exidx-owner",
    "symbol_index": None,
    "symbol": None,
}
AF_PRODUCTACTION_CALLER_OWNER = {
    "kind": "defined-dynsym",
    "symbol_index": 1_718,
    "symbol": "_ZN27CmnWrpOrientationRegisterAF26getRecallRegisteredAfFrameEv",
}

CANONICAL_SLOT_37_CALLS = [
    {
        "owner": {"start": 0x310CD8, "end": 0x310E30, "complete": True},
        "vptr_load_site": 0x310CFE,
        "slot_load_site": 0x310D02,
        "call_site": 0x310D06,
        "receiver_register": "r4",
        "receiver_origin": "entry-r0-preserved-r4",
        "selector_origin": "call-clobbered",
        "owner_identity": UNNAMED_PRODUCTACTION_CALLER_OWNER,
        "address_taken_records": [],
        "rejection_reason": "receiver-untyped-and-selector-call-clobbered",
        "receiver_identity_proven": False,
        "selector_10_proven": False,
        "accepted": False,
    },
    {
        "owner": {"start": 0x310CD8, "end": 0x310E30, "complete": True},
        "vptr_load_site": 0x310D6C,
        "slot_load_site": 0x310D70,
        "call_site": 0x310D74,
        "receiver_register": "r4",
        "receiver_origin": "entry-r0-preserved-r4",
        "selector_origin": "call-clobbered",
        "owner_identity": UNNAMED_PRODUCTACTION_CALLER_OWNER,
        "address_taken_records": [],
        "rejection_reason": "receiver-untyped-and-selector-call-clobbered",
        "receiver_identity_proven": False,
        "selector_10_proven": False,
        "accepted": False,
    },
    {
        "owner": {"start": 0x310CD8, "end": 0x310E30, "complete": True},
        "vptr_load_site": 0x310D9A,
        "slot_load_site": 0x310D9E,
        "call_site": 0x310DA2,
        "receiver_register": "r4",
        "receiver_origin": "entry-r0-preserved-r4",
        "selector_origin": "call-clobbered",
        "owner_identity": UNNAMED_PRODUCTACTION_CALLER_OWNER,
        "address_taken_records": [],
        "rejection_reason": "receiver-untyped-and-selector-call-clobbered",
        "receiver_identity_proven": False,
        "selector_10_proven": False,
        "accepted": False,
    },
    {
        "owner": {"start": 0x310CD8, "end": 0x310E30, "complete": True},
        "vptr_load_site": 0x310DC8,
        "slot_load_site": 0x310DCC,
        "call_site": 0x310DD0,
        "receiver_register": "r4",
        "receiver_origin": "entry-r0-preserved-r4",
        "selector_origin": "call-clobbered",
        "owner_identity": UNNAMED_PRODUCTACTION_CALLER_OWNER,
        "address_taken_records": [],
        "rejection_reason": "receiver-untyped-and-selector-call-clobbered",
        "receiver_identity_proven": False,
        "selector_10_proven": False,
        "accepted": False,
    },
    {
        "owner": {"start": 0x35F66C, "end": 0x35F67E, "complete": True},
        "vptr_load_site": 0x35F674,
        "slot_load_site": 0x35F676,
        "call_site": 0x35F67A,
        "receiver_register": "r0",
        "receiver_origin": "helper-return-0x35f670",
        "selector_origin": "call-clobbered",
        "owner_identity": AF_PRODUCTACTION_CALLER_OWNER,
        "address_taken_records": [],
        "rejection_reason": (
            "af-helper-return-receiver-and-selector-call-clobbered"
        ),
        "receiver_identity_proven": False,
        "selector_10_proven": False,
        "accepted": False,
    },
    {
        "owner": {"start": 0x3E11D4, "end": 0x3E134C, "complete": True},
        "vptr_load_site": 0x3E1318,
        "slot_load_site": 0x3E1322,
        "call_site": 0x3E1328,
        "receiver_register": "r5",
        "receiver_origin": "entry-r2-preserved-r5",
        "selector_origin": "helper-return-0x3e12fc",
        "owner_identity": UNNAMED_PRODUCTACTION_CALLER_OWNER,
        "address_taken_records": [
            {
                "cell": 0x8EB458,
                "relocation_index": 23_651,
                "relocation_type": 23,
                "target": 0x3E11D4,
            }
        ],
        "rejection_reason": "entry-r2-receiver-and-helper-return-selector",
        "receiver_identity_proven": False,
        "selector_10_proven": False,
        "accepted": False,
    },
]


PRODUCTACTION_DELIVERY = {
    "viewsettingmenu_vtable_address_point": 0x8E2270,
    "slot_37": {
        "cell": 0x8E2304,
        "relocation_index": 86_865,
        "relocation_type": 2,
        "symbol_index": 2_323,
        "symbol": "_ZN15ViewBaseProduct13ProductActionEi",
    },
    "productaction": {
        "symbol_index": 2_323,
        "symbol_range": {"start": 0x2F1350, "end": 0x2F135E},
        "exidx_owner": {
            "start": 0x2F12EC,
            "end": 0x2F135E,
            "complete": True,
        },
        "instruction_count": 6,
        "receiver_vptr_load_site": 0x2F1350,
        "slot_64_load_site": 0x2F1356,
        "slot_64_offset": 0x100,
        "slot_64_call_site": 0x2F135A,
        "selector_register": "r1",
        "selector_register_preserved": True,
    },
    "slot_64": {
        "cell": 0x8E2370,
        "relocation_index": 17_858,
        "relocation_type": 23,
        "target": 0x21355E,
    },
    "fully_decoded_owner_count": 28_869,
    "incomplete_or_terminal_owner_count": 1_594,
    "canonical_slot_37_call_count": 6,
    "canonical_slot_37_calls": CANONICAL_SLOT_37_CALLS,
    "accepted_candidates": [],
    "receiver_identity_proven": False,
    "selector_10_proven": False,
    "unresolved_universes": [
        "decode-incomplete-or-terminal-exidx-owners",
        "noncanonical-virtual-dispatch",
        "indirect-callback-or-runtime-initialized-receiver",
        "cross-module-or-loader-mediated-delivery",
    ],
    "whole_program_absence_proven": False,
}

CLAIMS = {
    "product_root_selector_found": True,
    "default_product_root_constructor_found": True,
    "creative_style_static_selected_child_path_0_4_1_found": True,
    "candidate_get_selected_item_semantics_found": True,
    "viewsettingmenu_product_root_init_call_found": True,
    "candidate_recursive_one_based_ordinal_assignment_found": True,
    "selected_ordinal_writer_inventory_found": True,
    "parent_selected_ordinal_from_child_one_based_field_found": True,
    "candidate_provider_conditional_ordinal_triplet_proven": False,
    "productaction_forwards_selector_to_slot_64_found": True,
    "runtime_constructor_provider_binding_proven": False,
    "runtime_selected_ordinal_triplet_1_5_2_proven": False,
    "runtime_selected_node_is_creative_style_root_proven": False,
    "viewsettingmenu_productaction_10_delivery_proven": False,
    "process_id_42_activation_accepted": False,
    "viewcreative_style_factory_invocation_proven": False,
    "first_class_creative_look_proven": False,
    "processing_or_output_binding_proven": False,
    "installable": False,
    "recovery_validated": False,
    "camera_test_eligible": False,
}

READINESS = "STATIC_CREATIVE_STYLE_PATH_WITH_CANDIDATE_RUNTIME_INITIALIZATION"
FIRST_UNRESOLVED_BOUNDARY = (
    "caution-provider-bound-creative-style-selected-ordinal-chain-and-"
    "viewsettingmenu-productaction-10-delivery"
)
CONCLUSION = (
    "The authenticated viewUnified2 source proves a default product-root "
    "constructor graph whose relocation-backed child indices 0, 4, and 1 end "
    "at the Creative Style root symbol. ViewSettingMenu passes the selected product "
    "root through the typed initialization slot, and candidate CautionConfig base "
    "semantics recursively assign one-based child ordinals and restore or choose "
    "generic selection. Five bounded selected-ordinal writes are source-derived; "
    "setItemSelected copies a selected child's one-based ordinal into its resolved "
    "parent cache. ProductAction preserves its selector into slot 64, but all six "
    "canonical callers are source-classified and rejected. The exact three-level "
    "1, 5, and 2 selection chain, receiver-proven ProductAction selector 10 delivery, "
    "provider bindings, selected-node identity, process-ID 42 activation, "
    "ViewCreativeStyle factory invocation, first-class Creative Look, "
    "processing/output binding, installation, recovery, and camera eligibility "
    "remain unproven."
)

EXPECTED_EXPORT = {
    "schema_version": 3,
    "analysis_mode": "offline-static-creative-style-selected-node-identity-boundary",
    "source": SOURCE,
    "supporting_source": SUPPORTING_SOURCE,
    "dependencies": DEPENDENCIES,
    "product_root_selection": PRODUCT_ROOT_SELECTION,
    "constructor_graph": CONSTRUCTOR_GRAPH,
    "static_path": STATIC_PATH,
    "selected_child_mechanism": SELECTED_CHILD_MECHANISM,
    "runtime_selection": RUNTIME_SELECTION,
    "root_initialization": ROOT_INITIALIZATION,
    "candidate_lifecycle": CANDIDATE_LIFECYCLE,
    "selected_ordinal_writers": SELECTED_ORDINAL_WRITERS,
    "productaction_delivery": PRODUCTACTION_DELIVERY,
    "claims": CLAIMS,
    "readiness": READINESS,
    "first_unresolved_boundary": FIRST_UNRESOLVED_BOUNDARY,
}


def canonical_digest(document):
    encoded = (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def normalize_creative_style_selected_node_identity_boundary_export(document):
    """Accept only the exact bounded static export."""
    if document != EXPECTED_EXPORT:
        raise CreativeStyleSelectedNodeIdentityBoundaryError(
            "Creative Style selected-node export differs from the pinned boundary"
        )
    return copy.deepcopy(document)


def _report_from_export(export):
    return {
        "schema_version": 3,
        "analysis_scope": "offline-static-creative-style-selected-node-identity-boundary",
        "camera_policy": "physically-disconnected",
        "camera_executed": False,
        "installable": False,
        "recovery_validated": False,
        "camera_test_eligible": False,
        "source": copy.deepcopy(export["source"]),
        "supporting_source": copy.deepcopy(export["supporting_source"]),
        "dependencies": copy.deepcopy(export["dependencies"]),
        "summary": {"canonical_export_sha256": canonical_digest(export)},
        "product_root_selection": copy.deepcopy(export["product_root_selection"]),
        "constructor_graph": copy.deepcopy(export["constructor_graph"]),
        "static_path": copy.deepcopy(export["static_path"]),
        "selected_child_mechanism": copy.deepcopy(
            export["selected_child_mechanism"]
        ),
        "runtime_selection": copy.deepcopy(export["runtime_selection"]),
        "root_initialization": copy.deepcopy(export["root_initialization"]),
        "candidate_lifecycle": copy.deepcopy(export["candidate_lifecycle"]),
        "selected_ordinal_writers": copy.deepcopy(
            export["selected_ordinal_writers"]
        ),
        "productaction_delivery": copy.deepcopy(export["productaction_delivery"]),
        "claims": copy.deepcopy(export["claims"]),
        "readiness": export["readiness"],
        "first_unresolved_boundary": export["first_unresolved_boundary"],
        "conclusion": CONCLUSION,
        "narrative_sha256": hashlib.sha256(CONCLUSION.encode("utf-8")).hexdigest(),
    }


def build_creative_style_selected_node_identity_boundary_report(document):
    """Build a report from the exact validated static export."""
    return _report_from_export(
        normalize_creative_style_selected_node_identity_boundary_export(document)
    )


def validate_creative_style_selected_node_identity_boundary_report(document):
    """Reject any report that promotes runtime or product behavior."""
    expected = _report_from_export(EXPECTED_EXPORT)
    if document != expected:
        raise CreativeStyleSelectedNodeIdentityBoundaryError(
            "Creative Style selected-node report differs from the pinned boundary"
        )
    return copy.deepcopy(document)
