"""Fail-closed generic runtime-binding evidence for α6400 Creative Style."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import re


class CreativeStyleRuntimeBindingError(ValueError):
    """Raised when runtime-binding evidence exceeds the pinned static boundary."""


ROOT = Path(__file__).resolve().parents[2]
UPSTREAM_REPORT = "analysis/a6400-creative-style-model-request-transport.json"
UPSTREAM_EVIDENCE_DIGEST = (
    "3303e96ac7f7f6bd237c4bf043056874aafde56b4ceb3ef3b2b4d38989619f0d"
)
SOURCES = {
    "object": {
        "module": "lib/libObj.so",
        "size": 20_860_436,
        "sha256": "60ffd2b0f31f4bc139a7c13a4f62c25cdeb6a531ad5ef35df48471e6e36e88b1",
    },
    "view": {
        "module": "lib/viewUnified2.so",
        "size": 11_530_552,
        "sha256": "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2",
    },
}

ID_GENERATOR = {
    "get_owner": {"start": 0x402DB4, "end": 0x402EC4},
    "splitter_owner": {"start": 0x402424, "end": 0x4024A0},
    "splitter_call": {"site": 0x402DEE, "target": 0x402424},
    "input_alias": "model/CAMERA",
    "splitter_delimiter_semantics_resolved": False,
    "model_table_key_resolved": False,
    "camera_row_key_resolved": False,
    "map_argument": {"site": 0x402E0A, "base_offset": 4},
    "map_lookup_call": {
        "site": 0x402E10,
        "target": 0x402BEC,
        "owner": {"start": 0x402BEC, "end": 0x402C66},
    },
    "find_id_call": {
        "site": 0x402E34,
        "owner": {"start": 0x4002AE, "end": 0x4002E4},
        "symbol": "_ZN7IdTable6findIdESs",
    },
    "set_table": {
        "owner": {"start": 0x402C66, "end": 0x402C7E},
        "entry_store_site": 0x402C7A,
        "entry_store_offset": 0,
    },
    "validated_static_set_table_call": {
        "module": "lib/viewUnified2.so",
        "site": 0x37FD10,
        "symbol": "_ZN11IdGenerator8SetTableESsP7IdTable",
        "table_key_resolved": False,
    },
    "model_table_static_registration_found": False,
    "camera_row_numeric_value_resolved": False,
}

MODEL_MANAGER_RECORDS = {
    "manager_constructor_owner": {"start": 0x84986A, "end": 0x849932},
    "map_offset": 0x88,
    "map_constructor": {
        "add_site": 0x84988A,
        "receiver_site": 0x84988E,
        "site": 0x849890,
        "target": 0x848DAA,
        "target_owner": {"start": 0x848DAA, "end": 0x848DB8},
    },
    "lookup_owner": {"start": 0x84903E, "end": 0x849088},
    "lookup_call": {
        "map_add_site": 0x849048,
        "receiver_site": 0x84904C,
        "site": 0x849054,
        "target": 0x849034,
        "target_owner": {"start": 0x849034, "end": 0x84903E},
    },
    "lookup_result_node_offset": 4,
    "lookup_result_site": 0x84907C,
    "registration_owner": {"start": 0x849D88, "end": 0x849E58},
    "registration_map": {
        "add_site": 0x849D9E,
        "receiver_site": 0x849DA4,
        "call_site": 0x849DA6,
        "target": 0x848C16,
    },
    "record_allocation": {
        "size_site": 0x849DEC,
        "size": 0x24,
        "call_site": 0x849DEE,
        "symbol": "_Znwj",
        "constructor_call_site": 0x849E00,
        "constructor_target": 0x8410B0,
    },
    "record_constructor_owner": {"start": 0x8410B0, "end": 0x8410D4},
    "executor_initialization": {
        "value_site": 0x8410C4,
        "site": 0x8410CE,
        "record_offset": 0x1C,
        "value": 0,
    },
    "activation_owner": {"start": 0x841124, "end": 0x8411A4},
    "record_executor_offset": 0x1C,
    "runtime_descriptor_provider_resolved": False,
    "key7_to_record_lookup_join_found": False,
}

DYNAMIC_LOADER = {
    "mode_argument": {"site": 0x84112C, "value": 0x101},
    "component_path_load": {"site": 0x841130, "record_offset": 0x10},
    "dlopen_call": {"site": 0x841132, "symbol": "dlopen"},
    "handle_store": {"site": 0x841136, "record_offset": 0x18},
    "symbol_name_load": {"site": 0x84113C, "record_offset": 0x14},
    "dlsym_call": {"site": 0x841140, "symbol": "dlsym"},
    "factory_symbol_capture": {"site": 0x841144, "register": "r3"},
    "factory_call": {
        "site": 0x84114C,
        "target_register": "r3",
        "key_load_site": 0x841148,
        "key_record_offset": 0,
        "manager_load_site": 0x84114A,
        "manager_record_offset": 0x20,
        "result_store_site": 0x84114E,
        "result_record_offset": 0x1C,
    },
    "guard_sites": [0x84113A, 0x84113E, 0x841146, 0x841150],
    "descriptor_population_dataflow_resolved": False,
    "exact_modelcamera_descriptor_join_found": False,
}

MODELCAMERA_CANDIDATE = {
    "manifest": {
        "alias": {"address": 0xF03447, "value": "@M00B"},
        "component": {"address": 0xF0344D, "value": "modelCamera.so"},
        "factory": {"address": 0xF0345C, "value": "ModelCameraToInstance"},
    },
    "factory": {
        "owner": {"start": 0x4D32E0, "end": 0x4D3304},
        "dynsym_index": 2198,
        "symbol": "ModelCameraToInstance",
        "size_site": 0x4D32E2,
        "instance_size": 0x6434,
        "allocation_call_site": 0x4D32EA,
        "allocation_symbol": "_Znwj",
        "manager_capture_site": 0x4D32E8,
        "instance_capture_site": 0x4D32EE,
        "constructor_call_site": 0x4D32F0,
        "constructor_target": 0x4D30F8,
    },
    "constructor_owner": {"start": 0x4D30F8, "end": 0x4D32E0},
    "manager_store": {"site": 0x4D32F4, "instance_offset": 0x20},
    "default_scheduler_event": {
        "modelbase_constructor_call": {"site": 0x4D3104, "target": 0x3FE58C},
        "setter_call": {"site": 0x3FE5E0, "target": 0x3FDF44},
        "literal_address": 0x3FDF50,
        "value": 0x11004001,
        "store_site": 0x3FDF4A,
        "instance_offset": 0x60,
    },
    "rtti": {
        "address": 0x1341AD8,
        "name": "11ModelCamera",
        "name_address": 0xF68740,
        "name_relocation_index": 39127,
        "vtable_header": 0x1341AE8,
        "vtable_rtti_relocation_index": 39129,
        "vptr_address_point": 0x1341AF0,
    },
    "slot_cell": {"address": 0x1341B08, "offset": 0x18, "relocation_index": 39136},
    "slot_target_owner": {"start": 0x3FE6B4, "end": 0x3FE6DC},
    "slot_target_classification": "shared-generic-slot-target",
    "manifest_to_operation38_model_alias_join_found": False,
    "manifest_to_runtime_descriptor_join_found": False,
}

GENERIC_EXECUTOR = {
    "model_manager_dispatch_owner": {"start": 0x84A830, "end": 0x84AC94},
    "candidate_branch_range": {"start": 0x84A95C, "end": 0x84A9E4},
    "request_event_id": 0x11004003,
    "scalar_event_parameters": {
        "request_context": {"key_load_site": 0x84A95C, "key": 6, "get_call_site": 0x84A960, "get_target": 0x848190},
        "model_id": {"key_load_site": 0x84A966, "key": 7, "get_call_site": 0x84A968, "get_target": 0x848190},
        "mapped_operation": {"key_load_site": 0x84A97C, "key": 8, "get_call_site": 0x84A97E, "get_target": 0x848190},
    },
    "secondary_event": {
        "destination_argument_site": 0x84A9B6,
        "destination": 0,
        "id_argument_site": 0x84A9B8,
        "queue_tag_argument_site": 0x84A9BA,
        "queue_tag": 0,
        "capture_site": 0x84A9BC,
        "constructor_call_site": 0x84A9BE,
        "get_param_list_call_site": 0x84A9C4,
        "allocation_size_site": 0x84A9CA,
        "allocation_size": 0x14,
        "allocation_call_site": 0x84A9CC,
        "clone_helper_call_site": 0x84A9D4,
        "clone_helper_owner": {"start": 0x841294, "end": 0x8412B4},
        "set_param_list_call_site": 0x84A9DC,
    },
    "param_list_clone_forwarded_to_secondary_event": True,
    "dispatcher_owner": {"start": 0x843014, "end": 0x843032},
    "incoming_event_store": {"site": 0x843018, "executor_offset": 0x14},
    "virtual_call": {"slot_offset": 0x18, "load_site": 0x843028, "site": 0x84302A},
    "scheduler_owner": {"start": 0x3FE62C, "end": 0x3FE6B4},
    "scheduled_event_id_accessor": {
        "call_site": 0x3FE634,
        "target": 0x3FDF3C,
        "load_site": 0x3FDF40,
    },
    "scheduled_event_id_resolved_generically": False,
    "scheduled_event_id_instance_offset": 0x60,
    "scheduled_event_constructor_call_site": 0x3FE648,
    "scheduled_destination": 4,
    "scheduled_queue_tag": 0,
    "scheduler_direct_incoming_event_read_found": False,
    "scheduler_direct_creative_style_field_read_found": False,
    "operation38_to_candidate_branch_join_found": False,
    "candidate_branch_to_modelcamera_executor_join_found": False,
    "operation38_to_modelcamera_executor_join_found": False,
}

DESTINATION_4 = {
    "model_manager_push_owner": {"start": 0x848188, "end": 0x848308},
    "model_manager_push_function": {"start": 0x84826C, "end": 0x84827C},
    "queue_boolean": True,
    "manager_event_manager_offset": 0,
    "central_dispatch_owner": {"start": 0x843A84, "end": 0x843C48},
    "destination_bit_test": {"site": 0x843B0E, "mask": 4, "zero_skip_site": 0x843B14, "zero_skip_target": 0x843B28},
    "receiver_call_site": 0x843B24,
    "receiver": 0x846710,
    "receiver_owner": {"start": 0x846710, "end": 0x846B44},
    "validated_event_id_comparisons": [
        {"literal_site": 0x846748, "compare_site": 0x84674A, "value": 0x11012001},
        {"literal_site": 0x846750, "compare_site": 0x846752, "value": 0x11001001},
        {"literal_site": 0x846756, "compare_site": 0x846758, "value": 0x11004004},
        {"literal_site": 0x846760, "compare_site": 0x846762, "value": 0x11012008},
    ],
    "modelcamera_candidate_default_event_matches_validated_comparisons": False,
    "default_predicate_owner": {"start": 0x8454D4, "end": 0x845524},
    "default_predicate_call": 0x8468D2,
    "downstream_concrete_receiver_resolved": False,
    "operation38_to_default_path_join_found": False,
}

UNPROVEN_CLAIMS = (
    "model_camera_name_split_proven",
    "model_camera_numeric_id_resolved",
    "model_table_registration_proven",
    "runtime_descriptor_provider_proven",
    "key7_to_record_join_proven",
    "record_is_modelcamera_proven",
    "executor_is_modelcamera_proven",
    "manifest_to_operation38_model_alias_join_proven",
    "operation38_to_candidate_branch_join_proven",
    "candidate_branch_to_modelcamera_executor_join_proven",
    "operation38_to_modelcamera_executor_join_proven",
    "operation38_to_destination_4_default_path_join_proven",
    "concrete_operation_38_handler_proven",
    "five_field_consumption_proven",
    "live_view_binding_proven",
    "still_jpeg_binding_proven",
    "movie_binding_proven",
    "native_creative_look_pipeline_proven",
    "runtime_execution_proven",
    "installable",
)

CLAIMS = {
    "model_camera_alias_reaches_id_generator_get_proven": True,
    "id_generator_runtime_lookup_boundary_reached": True,
    "generic_model_manager_record_lifecycle_layout_proven": True,
    "generic_dynamic_loader_chain_proven": True,
    "modelcamera_candidate_manifest_and_factory_found": True,
    "modelbase_scheduler_slot_proven": True,
    "destination_4_receiver_route_and_default_predicate_found": True,
    **{claim: False for claim in UNPROVEN_CLAIMS},
}

_FORBIDDEN_KEYS = {
    "bytes",
    "disassembly",
    "hex_dump",
    "key_material",
    "payload",
    "private_key",
    "raw",
}
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def canonical_digest(value: object) -> str:
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def _reject_forbidden(value: object) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str) or key.casefold() in _FORBIDDEN_KEYS:
                raise CreativeStyleRuntimeBindingError("runtime binding contains a forbidden field")
            _reject_forbidden(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_forbidden(nested)


def _validate_committed_upstream() -> None:
    try:
        document = json.loads((ROOT / UPSTREAM_REPORT).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CreativeStyleRuntimeBindingError("upstream transport report is unavailable") from error
    if (
        not isinstance(document, dict)
        or document.get("evidence_digest") != UPSTREAM_EVIDENCE_DIGEST
        or document.get("sources") != SOURCES
    ):
        raise CreativeStyleRuntimeBindingError("upstream transport report identity differs")


_EVIDENCE = {
    "schema_version": 1,
    "analysis_scope": "offline-static-creative-style-runtime-binding-export",
    "sources": SOURCES,
    "upstream": {"report": UPSTREAM_REPORT, "evidence_digest": UPSTREAM_EVIDENCE_DIGEST},
    "id_generator": ID_GENERATOR,
    "model_manager_records": MODEL_MANAGER_RECORDS,
    "dynamic_loader": DYNAMIC_LOADER,
    "modelcamera_candidate": MODELCAMERA_CANDIDATE,
    "generic_executor": GENERIC_EXECUTOR,
    "destination_4": DESTINATION_4,
    "claims": CLAIMS,
    "truncated": False,
}
EXPECTED_EXPORT = {**copy.deepcopy(_EVIDENCE), "evidence_digest": canonical_digest(_EVIDENCE)}


def normalize_creative_style_runtime_binding_export(document: dict) -> dict:
    """Validate exact generic machinery without promoting runtime model identity."""

    _reject_forbidden(document)
    if not isinstance(document, dict) or set(document) != set(EXPECTED_EXPORT):
        raise CreativeStyleRuntimeBindingError("runtime-binding export fields are not exact")
    _validate_committed_upstream()
    evidence = {key: value for key, value in document.items() if key != "evidence_digest"}
    if document["evidence_digest"] != canonical_digest(evidence):
        raise CreativeStyleRuntimeBindingError("runtime-binding evidence digest differs")
    if document != EXPECTED_EXPORT:
        raise CreativeStyleRuntimeBindingError("runtime-binding evidence differs")
    if any(document["claims"][claim] is not False for claim in UNPROVEN_CLAIMS):
        raise CreativeStyleRuntimeBindingError("runtime or pipeline identity was over-promoted")
    return copy.deepcopy(document)


def summarize_creative_style_runtime_binding_export(document: dict) -> dict:
    normalized = normalize_creative_style_runtime_binding_export(document)
    return {
        "canonical_export_sha256": canonical_digest(normalized),
        "proven_static_claim_count": sum(
            value is True for value in normalized["claims"].values()
        ),
        "resolved_model_identity_count": 0,
        "resolved_runtime_descriptor_count": 0,
        "resolved_pipeline_sink_count": 0,
    }


READINESS = "GENERIC_RUNTIME_BINDING_NO_MODELCAMERA_RECORD_OR_PIPELINE"
CONCLUSION = (
    "The model/CAMERA alias reaches IdGenerator::Get, and the generic ID lookup, ModelManager "
    "record lifecycle, dynamic loader, generic ModelBase scheduler slot, and conditional "
    "destination-4 receiver route plus its structural default predicate are statically bounded. "
    "The splitter delimiter and exact "
    "table/row semantics are not resolved, and no operation-38 join to the candidate path is "
    "proven. The numeric model ID, runtime descriptor provider, ModelCamera record/executor "
    "identity, operation-38 field consumption, rendering pipelines, runtime behavior, and "
    "installability remain unproven."
)


def build_creative_style_runtime_binding_report(export_document: dict) -> dict:
    export = normalize_creative_style_runtime_binding_export(export_document)
    return {
        "schema_version": 1,
        "analysis_scope": "offline-static-creative-style-runtime-binding",
        "camera_policy": "physically-disconnected",
        "camera_executed": False,
        "camera_test_eligible": False,
        "installable": False,
        "sources": copy.deepcopy(export["sources"]),
        "upstream": copy.deepcopy(export["upstream"]),
        "summary": summarize_creative_style_runtime_binding_export(export),
        "evidence_digest": export["evidence_digest"],
        "id_generator": copy.deepcopy(export["id_generator"]),
        "model_manager_records": copy.deepcopy(export["model_manager_records"]),
        "dynamic_loader": copy.deepcopy(export["dynamic_loader"]),
        "modelcamera_candidate": copy.deepcopy(export["modelcamera_candidate"]),
        "generic_executor": copy.deepcopy(export["generic_executor"]),
        "destination_4": copy.deepcopy(export["destination_4"]),
        "claims": copy.deepcopy(export["claims"]),
        "readiness": READINESS,
        "conclusion": CONCLUSION,
    }


def validate_creative_style_runtime_binding_report(document: object) -> dict:
    """Validate the deterministic checked-in runtime-binding report."""

    _reject_forbidden(document)
    expected = build_creative_style_runtime_binding_report(EXPECTED_EXPORT)
    if not isinstance(document, dict) or document != expected:
        raise CreativeStyleRuntimeBindingError("runtime-binding report differs")
    if not _DIGEST.fullmatch(document["summary"]["canonical_export_sha256"]):
        raise CreativeStyleRuntimeBindingError("runtime-binding summary digest is invalid")
    return copy.deepcopy(document)
