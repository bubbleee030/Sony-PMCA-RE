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
    "slot_54_receiver_register": "r4",
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
        "owner": {"start": 0x7C72CC, "end": 0x7C72EA, "complete": True},
        "child_list_offset": 4,
        "child_count_offset": 8,
        "runtime_provider_binding_proven": False,
    },
}

CLAIMS = {
    "product_root_selector_found": True,
    "default_product_root_constructor_found": True,
    "creative_style_static_selected_child_path_0_4_1_found": True,
    "candidate_get_selected_item_semantics_found": True,
    "runtime_constructor_provider_binding_proven": False,
    "runtime_selected_ordinal_triplet_1_5_2_proven": False,
    "runtime_selected_node_is_creative_style_root_proven": False,
    "process_id_42_activation_accepted": False,
    "viewcreative_style_factory_invocation_proven": False,
    "first_class_creative_look_proven": False,
    "processing_or_output_binding_proven": False,
    "installable": False,
    "recovery_validated": False,
    "camera_test_eligible": False,
}

READINESS = "STATIC_CREATIVE_STYLE_SELECTED_CHILD_PATH_ONLY"
FIRST_UNRESOLVED_BOUNDARY = (
    "viewsettingmenu-runtime-selected-ordinal-triplet-1-5-2-and-action-provenance"
)
CONCLUSION = (
    "The authenticated viewUnified2 source proves a default product-root "
    "constructor graph whose relocation-backed child indices 0, 4, and 1 end "
    "at the Creative Style root symbol. Candidate CautionConfig base semantics "
    "would select those entries with one-based ordinals 1, 5, and 2, but the "
    "runtime ordinals, provider bindings, selected-node identity, process-ID 42 "
    "activation, ViewCreativeStyle factory invocation, first-class Creative Look, "
    "processing/output binding, installation, recovery, and camera eligibility "
    "remain unproven."
)

EXPECTED_EXPORT = {
    "schema_version": 1,
    "analysis_mode": "offline-static-creative-style-selected-node-identity-boundary",
    "source": SOURCE,
    "supporting_source": SUPPORTING_SOURCE,
    "dependencies": DEPENDENCIES,
    "product_root_selection": PRODUCT_ROOT_SELECTION,
    "constructor_graph": CONSTRUCTOR_GRAPH,
    "static_path": STATIC_PATH,
    "selected_child_mechanism": SELECTED_CHILD_MECHANISM,
    "runtime_selection": RUNTIME_SELECTION,
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
        "schema_version": 1,
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
