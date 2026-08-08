"""Fail-closed α6400 Creative Style view-lifecycle evidence contract."""

from __future__ import annotations

import copy
import hashlib
import json


class CreativeStyleViewLifecycleBoundaryError(ValueError):
    """Raised when lifecycle evidence exceeds the pinned static boundary."""


SOURCES = {
    "view": {
        "module": "lib/viewUnified2.so",
        "size": 11_530_552,
        "sha256": "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2",
    },
    "object": {
        "module": "lib/libObj.so",
        "size": 20_860_436,
        "sha256": "60ffd2b0f31f4bc139a7c13a4f62c25cdeb6a531ad5ef35df48471e6e36e88b1",
    },
}

DEPENDENCIES = {
    "view_model_binding": {
        "report": "analysis/a6400-creative-style-view-model-binding.json",
        "canonical_export_sha256": "7a1a92c3da8c597032d241e0f24fb2a1b0e77a4a55d7471be0862c54f00cb977",
        "local_factory_found": True,
        "runtime_factory_invocation_proven": False,
    },
    "runtime_binding": {
        "report": "analysis/a6400-creative-style-runtime-binding.json",
        "canonical_export_sha256": "80ec7ea1160acc4362d2b5e869f885733003016727a878fd0091f88c02b2d459",
        "generic_dynamic_loader_chain_proven": True,
        "runtime_route_selection_proven": False,
    },
    "model_request_transport": {
        "report": "analysis/a6400-creative-style-model-request-transport.json",
        "canonical_export_sha256": "e03c61b1d71ebe628fb97f5ea93efdf8e925b6c61022b541e595bc232b66c1a7",
        "runtime_config_selector_resolved": False,
        "same_event_manager_instance_proven": False,
    },
}

TYPED_ACTIVATION = {
    "element": {
        "type_name": "CmnViewProcessDataElementCustomCreativeStyle",
        "type_name_encoding": "44CmnViewProcessDataElementCustomCreativeStyle",
        "rtti": 0x90EDF0,
        "vtable_header": 0x90ED80,
        "vtable_address_point": 0x90ED88,
    },
    "slot": 25,
    "cell": 0x90EDEC,
    "relocation": {
        "section": ".rel.dyn",
        "index": 40033,
        "type": 23,
        "symbol_index": 0,
        "target": 0x489218,
        "thumb_value": 0x489219,
    },
    "base_abi": {
        "vtable_address_point": 0x906F38,
        "cell": 0x906F9C,
        "relocation_index": 130362,
        "relocation_type": 2,
        "symbol_index": 2775,
        "symbol": "_ZN31CmnViewProcessDataElementNormal21execProcWithConditionEi",
        "signature": "execProcWithCondition(int)",
    },
    "wrapper": {
        "owner": {"start": 0x4891D4, "end": 0x489238, "complete": True},
        "entry": 0x489218,
        "literal_load_site": 0x489218,
        "literal_cell": 0x489228,
        "literal_word": 0x003230F2,
        "alias_add_site": 0x48921C,
        "alias_address": 0x7AC312,
        "alias": "view/CREATIVE_STYLE",
        "open_view_call": {
            "site": 0x489220,
            "plt": 0x1531A0,
            "symbol": "_ZN13viewManagerIf8openViewEPKci",
        },
        "condition_register": "r1",
        "condition_forwarded_unchanged": True,
        "success_return_site": 0x489224,
        "success_return_value": 1,
    },
    "manager_bridge": {
        "manager_rtti": 0x905990,
        "manager_vtable_address_point": 0x905930,
        "manager_slot": 20,
        "manager_cell": 0x905980,
        "manager_relocation_index": 37093,
        "manager_target": 0x4390BC,
        "owner": {"start": 0x4390BC, "end": 0x4390D4, "complete": True},
        "condition_capture_site": 0x4390C0,
        "condition_source_register": "r2",
        "condition_saved_register": "r4",
        "lookup_call": {"site": 0x4390C2, "target": 0x439088},
        "condition_forward_site": 0x4390CA,
        "typed_slot_load_site": 0x4390CC,
        "typed_slot_offset": 0x64,
        "typed_slot_call_site": 0x4390CE,
        "typed_process_id_42_caller_proven": False,
    },
    "menu_root_or_process_activation_caller_proven": False,
}

REGISTRATION = {
    "caller": {
        "owner": {"start": 0x2DC1E4, "end": 0x2DC228, "complete": True},
        "get_instance_call": {
            "site": 0x2DC1EC,
            "plt": 0x15095C,
            "symbol": "_ZN13ViewIdSoTable11getInstanceEv",
        },
        "receiver_capture_site": 0x2DC1FA,
        "registration_call": {"site": 0x2DC216, "target": 0x40B9D4},
        "receiver_return_site": 0x2DC21A,
    },
    "branch_source": {
        "backup_read_call_site": 0x2DC1FE,
        "backup_read_symbol": "_ZN13BackupManager9Bkup_ReadEiPv",
        "backup_id_literal_cell": 0x2DC224,
        "backup_id": 0x003E000B,
        "compare_site": 0x2DC204,
        "branch_site": 0x2DC206,
        "branch_value_one_site": 0x2DC20C,
        "branch_value_two_site": 0x2DC214,
        "runtime_value_resolved": False,
    },
    "owner": {"start": 0x40B9D4, "end": 0x40F1EC, "complete": True},
    "table_receiver": {
        "entry_source_register": "r1",
        "retained_register": "r4",
        "capture_site": 0x40B9DC,
        "same_receiver_for_all_rows": True,
    },
    "rows": [
        {
            "branch_value": 1,
            "branch_gate_site": 0x40B9D4,
            "alias_load_site": 0x40BD5C,
            "alias_add_site": 0x40BD60,
            "alias_address": 0x7AC312,
            "alias": "view/CREATIVE_STYLE",
            "get_call_site": 0x40BD62,
            "component_load_site": 0x40BD66,
            "component_add_site": 0x40BD6E,
            "component_address": 0x7AC326,
            "component": "viewCreativeStyle.so",
            "factory_load_site": 0x40BD6A,
            "factory_add_site": 0x40BD70,
            "factory_address": 0x7AC33B,
            "factory": "ViewCreativeStyleToInstance",
            "id_to_key_site": 0x40BD72,
            "receiver_site": 0x40BD74,
            "add_call_site": 0x40BD76,
        },
        {
            "branch_value": 2,
            "branch_gate_site": 0x40B9E0,
            "component_seed_load_site": 0x40D8C4,
            "component_seed_add_site": 0x40D8CE,
            "alias_load_site": 0x40DBC0,
            "alias_add_site": 0x40DBC4,
            "alias_address": 0x7AC312,
            "alias": "view/CREATIVE_STYLE",
            "get_call_site": 0x40DBC6,
            "component_source_register": "sl",
            "component_address": 0x79C295,
            "component": "viewUnified2.so",
            "factory_load_site": 0x40DBCA,
            "factory_add_site": 0x40DBD0,
            "factory_address": 0x7AC33B,
            "factory": "ViewCreativeStyleToInstance",
            "component_forward_site": 0x40DBCE,
            "id_to_key_site": 0x40DBD2,
            "receiver_site": 0x40DBD4,
            "add_call_site": 0x40DBD6,
        },
    ],
    "active_row_resolved": False,
    "registration_runtime_invocation_proven": False,
}

PROVIDER_BINDING = {
    "view_dt_needed": ["CautionConfig.so", "libgcc_s.so.1", "libc.so.6"],
    "libobj_direct_dependency_found": False,
    "symbols": [
        {
            "role": "view-id-table-singleton",
            "symbol": "_ZN13ViewIdSoTable11getInstanceEv",
            "view_dynsym_index": 540,
            "view_defined": False,
            "object_dynsym_index": 2118,
            "object_entry": 0x847269,
            "object_size": 88,
        },
        {
            "role": "id-generator-get",
            "symbol": "_ZN11IdGenerator3GetEPKc",
            "view_dynsym_index": 1063,
            "view_defined": False,
            "object_dynsym_index": 2156,
            "object_entry": 0x402DB5,
            "object_size": 272,
        },
        {
            "role": "id-so-table-add",
            "symbol": "_ZN9IdSoTable3addEiPKcS1_",
            "view_dynsym_index": 922,
            "view_defined": False,
            "object_dynsym_index": 1980,
            "object_entry": 0x842EAD,
            "object_size": 118,
        },
        {
            "role": "open-view",
            "symbol": "_ZN13viewManagerIf8openViewEPKci",
            "view_dynsym_index": 1030,
            "view_defined": False,
            "object_dynsym_index": 2250,
            "object_entry": 0x3F2BE5,
            "object_size": 16,
        },
    ],
    "pinned_pair_provider_candidates_found": True,
    "runtime_binding_proven": False,
}

CONDITIONAL_TABLE_IDENTITY = {
    "conditions": [
        "runtime-selector-equals-AppConfig.so",
        "appconfig-loader-resolves-authenticated-viewUnified2-exports",
        "viewUnified2-ViewIdSoTable-getInstance-binds-pinned-libObj-provider",
        "viewUnified2-openView-and-registration-imports-bind-pinned-libObj-providers",
    ],
    "app_config_selector": {
        "buffer_address": 0x1424D78,
        "storage_section": ".bss",
        "literal": "AppConfig.so",
        "literal_address": 0x10027D7,
        "compare_call_sites": [0x843C9A, 0x843CB2],
        "runtime_contents_resolved": False,
        "runtime_match_proven": False,
    },
    "app_config": {
        "vtable_address_point": 0x133E3E8,
        "view_config_field_offset": 4,
        "view_config_store_site": 0x3FD7E8,
        "forwarding_slot_offset": 0x14,
        "forwarding_cell": 0x133E3FC,
        "forwarding_target": 0x3FD43A,
        "forwarding_field_load_site": 0x3FD43A,
        "forwarding_vptr_load_site": 0x3FD440,
        "forwarding_slot_load_site": 0x3FD442,
        "forwarding_call_site": 0x3FD444,
    },
    "view_config": {
        "type_name": "ViewConfig",
        "rtti": 0x8F746C,
        "vtable_header": 0x8FC728,
        "vtable_address_point": 0x8FC730,
        "constructor": {"start": 0x3E9644, "end": 0x3E96A0},
        "vptr_store_site": 0x3E965E,
        "forwarding_slot_offset": 0x14,
        "forwarding_cell": 0x8FC744,
        "forwarding_target": 0x2DC1E4,
    },
    "libobj_get_instance_candidate": {
        "owner": {"start": 0x847268, "end": 0x8472C0, "complete": True},
        "return_literal_site": 0x8472A2,
        "return_literal_cell": 0x8472BC,
        "return_add_site": 0x8472A4,
        "singleton_storage": 0x14250D4,
    },
    "wrapper_table": {
        "constructor": {"start": 0x845CA0, "end": 0x845E00},
        "config_argument_source": "stacked-argument-5",
        "config_capture_site": 0x845CAC,
        "config_slot_load_site": 0x845CEA,
        "config_slot_call_site": 0x845CEC,
        "table_store_site": 0x845CF0,
        "table_field_offset": 8,
    },
    "singleton_storage": 0x14250D4,
    "registration_receiver_equals_loader_table_if_conditions_hold": True,
    "unconditional_identity_proven": False,
}

GENERIC_LOADER = {
    "open_view_candidate": {
        "entry": 0x3F2BE4,
        "owner": {"start": 0x3F2BE4, "end": 0x3F2C18, "complete": True},
        "helper_call": {"site": 0x3F2BE8, "target": 0x3F2B0C},
        "helper_owner": {"start": 0x3F2B0C, "end": 0x3F2BE4, "complete": True},
    },
    "event": {
        "id_generator_call_site": 0x3F2B6C,
        "allocation_size": 0x10,
        "event_id_literal_load_site": 0x3F2B78,
        "event_id_literal_cell": 0x3F2BD4,
        "event_id": 0x11012001,
        "destination_site": 0x3F2B7A,
        "destination": 4,
        "tag_site": 0x3F2B7C,
        "tag": 0,
        "constructor_call_site": 0x3F2B80,
        "resolved_id_key": 6,
        "resolved_id_add_call_site": 0x3F2B98,
        "condition_key": 26,
        "condition_add_call_site": 0x3F2BB0,
        "push_call": {"site": 0x3F2BBC, "target": 0x8447F0},
    },
    "destination_4_handler": {
        "owner": {"start": 0x846710, "end": 0x846B44, "complete": True},
        "literal_site": 0x846748,
        "compare_site": 0x84674A,
        "match_branch": {"site": 0x84674C, "target": 0x846812},
        "loader_call": {"site": 0x846816, "target": 0x845FE8},
    },
    "record_loader": {
        "owner": {"start": 0x845E00, "end": 0x845FE8, "complete": True},
        "table_field_offset": 8,
        "component_lookup_call": {"site": 0x845E50, "target": 0x842BDE},
        "dlopen_flags_site": 0x845E94,
        "dlopen_flags": 0x101,
        "dlopen_call_site": 0x845EA0,
        "factory_lookup_call": {"site": 0x845F18, "target": 0x842BAE},
        "dlsym_call_site": 0x845F28,
        "factory_call_site": 0x845F4C,
        "factory_call_register": "sb",
        "factory_result_store_site": 0x845F50,
        "factory_result_record_offset": 4,
    },
    "selected_row_to_loader_record_join_proven": False,
    "event_delivery_at_runtime_proven": False,
    "factory_invocation_proven": False,
    "returned_viewcreative_style_identity_proven": False,
}

FACTORY_DEPENDENCY = {
    "symbol": "ViewCreativeStyleToInstance",
    "symbol_index": 3418,
    "range": {"start": 0x5CD88E, "end": 0x5CD8B2},
    "allocation_size": 0x194,
    "local_factory_available": True,
    "runtime_factory_invocation_proven": False,
}

FIRST_UNRESOLVED_BOUNDARY = (
    "menu-or-process-activation-and-runtime-binding-to-selected-registration-and-factory-invocation"
)
READINESS = (
    "TYPED_CREATIVE_STYLE_VIEW_LIFECYCLE_SUBSTRATE_PROVEN__"
    "RUNTIME_SELECTION_AND_FACTORY_INVOCATION_UNRESOLVED"
)
CLAIMS = {
    "typed_creative_style_open_view_bridge_proven": True,
    "typed_process_manager_slot25_bridge_proven": True,
    "alternative_registration_rows_proven": True,
    "generic_open_view_event_loader_abi_found": True,
    "conditional_registration_loader_table_identity_proven": True,
    "runtime_provider_binding_proven": False,
    "runtime_config_route_selected": False,
    "runtime_registration_row_selected": False,
    "runtime_event_delivery_proven": False,
    "runtime_factory_invocation_proven": False,
    "returned_viewcreative_style_identity_proven": False,
    "menu_root_to_typed_activation_join_proven": False,
    "first_class_creative_look_equivalence_proven": False,
    "renderer_or_output_sink_found": False,
    "runtime_execution_proven": False,
    "installable": False,
    "recovery_validated": False,
    "camera_test_eligible": False,
}
CONCLUSION = (
    "The authenticated target publishes a typed Creative Style process-element slot 25 "
    "override for execProcWithCondition(int). The override replaces only the alias with "
    "view/CREATIVE_STYLE and forwards the caller's condition to viewManagerIf::openView. "
    "The VU2 registration owner publishes two alternative rows for the same alias and "
    "factory, using viewCreativeStyle.so on branch 1 and viewUnified2.so on branch 2; the "
    "runtime backup value does not select a row statically. The registration receiver and "
    "generic loader table are the same pointer only if the runtime selector equals "
    "AppConfig.so, the authenticated VU2 exports load successfully, and VU2's imported "
    "ViewIdSoTable/openView/IdGenerator/IdSoTable symbols bind to the pinned libObj "
    "providers. Under those conditions the corrected singleton storage is 0x14250D4. "
    "The candidate openView provider builds Event 0x11012001 with destination 4 and "
    "forwards the alias ID and condition into a generic record loader that contains "
    "dlopen, dlsym, and an indirect factory ABI. This establishes lifecycle substrate and "
    "conditional table identity, but does not prove runtime factory invocation, a returned "
    "ViewCreativeStyle instance, menu-root activation, first-class Creative Look "
    "equivalence, renderer/output behavior, installability, recovery, or camera-test "
    "eligibility."
)

EXPECTED_EXPORT = {
    "schema_version": 1,
    "analysis_mode": {
        "read_only": True,
        "static_elf_metadata": True,
        "source_unchanged": True,
        "camera_access": False,
        "binary_execution": False,
    },
    "sources": SOURCES,
    "dependencies": DEPENDENCIES,
    "typed_activation": TYPED_ACTIVATION,
    "registration": REGISTRATION,
    "provider_binding": PROVIDER_BINDING,
    "conditional_table_identity": CONDITIONAL_TABLE_IDENTITY,
    "generic_loader": GENERIC_LOADER,
    "factory_dependency": FACTORY_DEPENDENCY,
    "first_unresolved_boundary": FIRST_UNRESOLVED_BOUNDARY,
    "readiness": READINESS,
    "claims": CLAIMS,
    "truncated": False,
}

_EXPORT_FIELDS = {
    "schema_version",
    "analysis_mode",
    "sources",
    "dependencies",
    "typed_activation",
    "registration",
    "provider_binding",
    "conditional_table_identity",
    "generic_loader",
    "factory_dependency",
    "first_unresolved_boundary",
    "readiness",
    "claims",
    "truncated",
}
_FORBIDDEN_KEYS = {
    "bytes",
    "disassembly",
    "instructions",
    "key_material",
    "private_key",
    "device_path",
    "flash_image",
    "package_bytes",
}


def _forbid_reconstructive_fields(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or key.casefold().replace("-", "_") in _FORBIDDEN_KEYS:
                raise CreativeStyleViewLifecycleBoundaryError(
                    "forbidden reconstructive or unsafe lifecycle field"
                )
            _forbid_reconstructive_fields(child)
    elif isinstance(value, list):
        for child in value:
            _forbid_reconstructive_fields(child)


def normalize_creative_style_view_lifecycle_boundary_export(document: dict) -> dict:
    """Accept only the exact source-pinned, fail-closed lifecycle result."""

    _forbid_reconstructive_fields(document)
    if not isinstance(document, dict) or set(document) != _EXPORT_FIELDS:
        raise CreativeStyleViewLifecycleBoundaryError("lifecycle export fields differ")
    if document != EXPECTED_EXPORT:
        raise CreativeStyleViewLifecycleBoundaryError(
            "lifecycle export differs from the pinned static result"
        )
    return copy.deepcopy(document)


def canonical_digest(document: dict) -> str:
    encoded = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def _report_from_export(export: dict) -> dict:
    typed = export["typed_activation"]
    registration = export["registration"]
    identity = export["conditional_table_identity"]
    loader = export["generic_loader"]
    report = {
        "schema_version": 1,
        "analysis_scope": "offline-static-creative-style-view-lifecycle-boundary",
        "camera_policy": "physically-disconnected",
        "camera_executed": False,
        "installable": False,
        "recovery_validated": False,
        "camera_test_eligible": False,
        "sources": copy.deepcopy(export["sources"]),
        "dependencies": copy.deepcopy(export["dependencies"]),
        "summary": {
            "canonical_export_sha256": canonical_digest(export),
            "typed_open_view_slot": typed["slot"],
            "registration_row_count": len(registration["rows"]),
            "conditional_table_identity_proven": identity[
                "registration_receiver_equals_loader_table_if_conditions_hold"
            ],
            "unconditional_table_identity_proven": identity[
                "unconditional_identity_proven"
            ],
            "generic_event_id": loader["event"]["event_id"],
            "generic_loader_abi_found": True,
            "local_factory_available": export["factory_dependency"][
                "local_factory_available"
            ],
            "runtime_factory_invocation_proven": loader["factory_invocation_proven"],
        },
        "evidence": {
            "typed_activation": {
                "type_name": typed["element"]["type_name"],
                "slot": typed["slot"],
                "base_signature": typed["base_abi"]["signature"],
                "alias": typed["wrapper"]["alias"],
                "condition_forwarded_unchanged": typed["wrapper"][
                    "condition_forwarded_unchanged"
                ],
                "typed_process_id_42_caller_proven": typed["manager_bridge"][
                    "typed_process_id_42_caller_proven"
                ],
            },
            "registration_rows": [
                {
                    "branch_value": row["branch_value"],
                    "alias": row["alias"],
                    "component": row["component"],
                    "factory": row["factory"],
                }
                for row in registration["rows"]
            ],
            "active_registration_row_resolved": registration["active_row_resolved"],
            "conditional_table_identity": {
                "conditions": copy.deepcopy(identity["conditions"]),
                "singleton_storage": identity["singleton_storage"],
                "conditional_identity_proven": identity[
                    "registration_receiver_equals_loader_table_if_conditions_hold"
                ],
                "unconditional_identity_proven": identity[
                    "unconditional_identity_proven"
                ],
            },
            "generic_loader": {
                "event_id": loader["event"]["event_id"],
                "destination": loader["event"]["destination"],
                "condition_key": loader["event"]["condition_key"],
                "dlopen_flags": loader["record_loader"]["dlopen_flags"],
                "selected_row_to_loader_record_join_proven": loader[
                    "selected_row_to_loader_record_join_proven"
                ],
                "factory_invocation_proven": loader["factory_invocation_proven"],
                "returned_viewcreative_style_identity_proven": loader[
                    "returned_viewcreative_style_identity_proven"
                ],
            },
        },
        "first_unresolved_boundary": export["first_unresolved_boundary"],
        "readiness": export["readiness"],
        "claims": copy.deepcopy(export["claims"]),
        "conclusion": CONCLUSION,
    }
    report["evidence_digest"] = canonical_digest(report["evidence"])
    return report


def build_creative_style_view_lifecycle_boundary_report(document: dict) -> dict:
    """Build the checked report from the exact validated raw export."""

    return _report_from_export(
        normalize_creative_style_view_lifecycle_boundary_export(document)
    )


_REPORT_FIELDS = {
    "schema_version",
    "analysis_scope",
    "camera_policy",
    "camera_executed",
    "installable",
    "recovery_validated",
    "camera_test_eligible",
    "sources",
    "dependencies",
    "summary",
    "evidence",
    "first_unresolved_boundary",
    "readiness",
    "claims",
    "conclusion",
    "evidence_digest",
}


def validate_creative_style_view_lifecycle_boundary_report(document: dict) -> dict:
    """Reject any report that broadens the conditional static result."""

    _forbid_reconstructive_fields(document)
    if not isinstance(document, dict) or set(document) != _REPORT_FIELDS:
        raise CreativeStyleViewLifecycleBoundaryError("lifecycle report fields differ")
    expected = _report_from_export(EXPECTED_EXPORT)
    if document != expected:
        raise CreativeStyleViewLifecycleBoundaryError(
            "lifecycle report differs from the pinned fail-closed result"
        )
    return copy.deepcopy(document)
