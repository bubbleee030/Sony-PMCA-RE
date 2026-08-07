"""Fail-closed Creative Style model-request transport evidence."""
from __future__ import annotations

import copy
import hashlib
import json
import re


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

TYPED_REQUEST = {
    "owner": {"start": 0x4893AC, "end": 0x489644, "complete": True},
    "site": 0x4895FA,
    "symbol": "_ZN21CmnViewModelIfWrapper19requestModelExecuteEPKcmP9ParamList",
    "model": "@M00B",
    "request_code": 38,
    "param_list_add_count": 5,
    "classification": "typed-custom-creative-style-request-boundary",
}

VIEW_WRAPPER_TRANSPORT = {
    "wrapper_symbol": "_ZN21CmnViewModelIfWrapper19requestModelExecuteEPKcmP9ParamList",
    "wrapper_owner": {"start": 0x2F11E4, "end": 0x2F1202, "complete": True},
    "mr_util_call_site": 0x2F11F0,
    "mr_util_symbol": "_ZN9CmnMRUtil11getInstanceEv",
    "tail_branch": {"site": 0x2F11FE, "target": 0x33A450},
    "helper_owner": {"start": 0x33A450, "end": 0x33A46A, "complete": True},
    "helper_call": {"site": 0x33A462, "target": 0x339CBC},
    "dispatcher_owner": {"start": 0x339CBC, "end": 0x33A450, "complete": True},
    "operation_38_dispatch_branch_resolved": True,
}

CANDIDATE_CROSS_MODULE_BOUNDARY = {
    "site": 0x339EA0,
    "symbol": "_ZN13viewManagerIf19requestModelExecuteEPKcmP9ParamList",
    "inside_dispatcher_owner": True,
    "only_named_request_edge_in_dispatcher": True,
    "operation_38_branch_proven": True,
    "classification": "proven-operation-38-shared-request-edge-not-model-handler",
}

OPERATION_38_DISPATCH_PATH = {
    "wrapper_argument_capture_sites": {
        "model": 0x2F11EE,
        "request_code": 0x2F11EA,
        "param_list": 0x2F11EC,
    },
    "wrapper_argument_forward_sites": [0x2F11F4, 0x2F11F6, 0x2F11F8],
    "helper_model_capture_site": 0x33A454,
    "helper_code_capture_site": 0x33A456,
    "helper_param_list_stack_store_site": 0x33A45A,
    "helper_model_forward_site": 0x33A45E,
    "helper_code_forward_site": 0x33A460,
    "dispatcher_stack_param_offset": 0x130,
    "dispatcher_model_capture_site": 0x339CCC,
    "dispatcher_code_capture_site": 0x339CCE,
    "dispatcher_param_list_capture_site": 0x339CD0,
    "model_mapping_call_site": 0x339CF8,
    "model_mapping_target": 0x3391D8,
    "model_mapping_owner": {"start": 0x3391D8, "end": 0x339234, "complete": True},
    "model_mapping_result_capture_site": 0x339D00,
    "gate_subtract_site": 0x339CFC,
    "gate_subtract_value": 40,
    "gate_compare_site": 0x339D02,
    "gate_compare_value": 1,
    "gate_branch": {"site": 0x339D04, "target": 0x339E9A, "condition": "unsigned-higher"},
    "input_request_code": 38,
    "normalized_gate_value": 0xFFFFFFFE,
    "shared_call_argument_sites": {
        "model_mapping_result": 0x339E9A,
        "request_code": 0x339E9C,
        "param_list": 0x339E9E,
    },
    "shared_call_site": 0x339EA0,
    "normal_return_from_model_mapping_required": True,
    "original_model_identity_preserved": False,
    "literal_operation_38_event_field_proven": False,
    "classification": "operation-38-normal-return-path-to-shared-request-api",
}

SHARED_LIBOBJ_TRANSPORT = {
    "request_symbol": "_ZN13viewManagerIf19requestModelExecuteEPKcmP9ParamList",
    "request_owner": {"start": 0x3F2AA8, "end": 0x3F2AEC, "complete": True},
    "id_generator_call_site": 0x3F2AC0,
    "id_generator_symbol": "_ZN11IdGenerator3GetEPKc",
    "event_builder_call_site": 0x3F2AD6,
    "event_builder_symbol": "_ZN22AbstractUtilityManager30createRequestModelExecuteEventEimP9ParamList",
    "event_builder_owner": {"start": 0x8430AC, "end": 0x843118, "complete": True},
    "event_constructor_call_site": 0x8430C6,
    "event_constructor_symbol": "_ZN5EventC1Emhh",
    "param_list_attach_call_site": 0x8430D0,
    "param_list_attach_symbol": "_ZN5Event12setParamListEP9ParamList",
    "scalar_parameter_add_call_sites": [0x8430E8, 0x843100],
    "scalar_parameter_add_symbol": "_ZN5Event12addParameterEmP9ParamBase",
    "event_continuation_branch_site": 0x3F2ADE,
    "event_continuation": 0x3F2A6C,
    "shared_request_to_event_queue_join_found": True,
    "classification": "shared-request-event-construction-boundary",
}

OPERATION_38_EVENT_MAPPING = {
    "request_code_capture_site": 0x3F2AB8,
    "request_code_r9_preservation_segment": [0x3F2ABA, 0x3F2AC4],
    "r9_abi": {
        "attribute_section": ".ARM.attributes",
        "r9_tag": "TAG_ABI_PCS_R9_USE",
        "r9_tag_present": False,
        "tag_nodefaults_present": False,
        "effective_value": 0,
        "classification": "v6-callee-saved-register",
    },
    "mapper_code_argument_site": 0x3F2AC4,
    "mapper_model_argument_site": 0x3F2AC8,
    "mapper_call": {"site": 0x3F2ACA, "target": 0x402EC4},
    "mapper_owner": {"start": 0x402EC4, "end": 0x402FC0, "complete": True},
    "mapper_code_capture_site": 0x402ECC,
    "mapper_callback_code_argument_site": 0x402F4A,
    "mapper_alternate_code_argument_site": 0x402F82,
    "mapper_callback_object_load_site": 0x402F26,
    "mapper_callback_vptr_load_site": 0x402F32,
    "mapper_callback_target_load_site": 0x402F3E,
    "mapper_callback_receiver_site": 0x402F44,
    "mapper_callback_buffer_site": 0x402F46,
    "mapper_callback_buffer_offset": 116,
    "mapper_callback_call_site": 0x402F4C,
    "mapper_callback_is_indirect": True,
    "mapper_callback_result_capture_site": 0x402F4E,
    "mapper_return_site": 0x402F90,
    "mapper_sentinel_sites": [0x402F5A, 0x402F8C],
    "mapped_operation_builder_argument_site": 0x3F2AD2,
    "event_builder_call_site": 0x3F2AD6,
    "builder_operation_capture_site": 0x8430B6,
    "builder_operation_value_site": 0x8430F2,
    "builder_event_receiver_site": 0x8430FA,
    "builder_parameter_key_site": 0x8430FC,
    "builder_parameter_value_site": 0x8430FE,
    "event_parameter_key": 8,
    "event_parameter_add_site": 0x843100,
    "operation_38_origin_reaches_mapped_event_parameter": True,
    "literal_operation_38_event_field_proven": False,
    "classification": "operation-38-origin-to-opaque-event-key-8-mapping",
}

SHARED_REQUEST_TO_EVENT_QUEUE_JOIN = {
    "continuation_owner": {"start": 0x3F2A6C, "end": 0x3F2AA8, "complete": True},
    "event_result_capture_site": 0x3F2A70,
    "parameter_receiver_site": 0x3F2A86,
    "parameter_key_site": 0x3F2A88,
    "parameter_key": 6,
    "parameter_value_site": 0x3F2A8A,
    "parameter_add_call_site": 0x3F2A8C,
    "parameter_add_symbol": "_ZN5Event12addParameterEmP9ParamBase",
    "event_argument_site": 0x3F2A92,
    "queue_manager_literal_load_site": 0x3F2A90,
    "queue_manager_got_load_site": 0x3F2A94,
    "queue_manager_instance_load_site": 0x3F2A96,
    "continuation_tail_branch": {"site": 0x3F2A9C, "target": 0x8447F0},
    "queue_helper_owner": {"start": 0x8447F0, "end": 0x844800, "complete": True},
    "queue_boolean_true_site": 0x8447F2,
    "queue_receiver_load_site": 0x8447F6,
    "queue_receiver_offset": 0x10,
    "queue_helper_tail_branch": {"site": 0x8447FC, "target": 0x100D5C},
    "thumb_to_arm_gate": 0x100D5C,
    "arm_plt_veneer": 0x100D60,
    "got_cell": 0x136B818,
    "relocation": {"section": ".rel.plt", "index": 1339, "type": 22, "symbol_index": 2860},
    "push_symbol": "_ZN12EventManager4pushEP5Eventb",
    "queue_boolean": True,
    "classification": "shared-request-event-to-event-manager-push",
}

EVENT_QUEUE_BOUNDARY = {
    "push_symbol": "_ZN12EventManager4pushEP5Eventb",
    "push_owner": {"start": 0x842598, "end": 0x84264C, "complete": True},
    "indirect_call_sites": [0x8425C6, 0x8425D6, 0x842620],
    "indirect_call_count": 3,
    "consumer_dispatch_resolved": False,
    "model_id_or_operation_38_target_resolved": False,
    "classification": "event-queue-indirect-dispatch-terminal",
}

CLAIMS = {
    "typed_custom_creative_style_request_found": True,
    "view_wrapper_transport_found": True,
    "candidate_cross_module_request_edge_found": True,
    "shared_event_construction_boundary_found": True,
    "event_queue_indirect_boundary_found": True,
    "operation_38_candidate_branch_proven": True,
    "end_to_end_operation_38_event_queue_join_found": True,
    "shared_request_to_event_queue_join_found": True,
    "operation_38_origin_reaches_mapped_event_parameter": True,
    "original_model_identity_preserved": False,
    "literal_operation_38_event_field_proven": False,
    "named_model_handler_found": False,
    "renderer_or_live_view_sink_found": False,
    "still_jpeg_sink_found": False,
    "movie_sink_found": False,
    "creative_look_equivalence_found": False,
    "runtime_execution_proven": False,
}


def canonical_digest(value):
    return hashlib.sha256((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()).hexdigest()


EXPECTED_EXPORT = {
    "schema_version": 1,
    "analysis_mode": {
        "read_only": True,
        "static_elf_metadata": True,
        "thumb_control_flow": True,
        "source_unchanged": True,
    },
    "sources": SOURCES,
    "typed_request": TYPED_REQUEST,
    "view_wrapper_transport": VIEW_WRAPPER_TRANSPORT,
    "candidate_cross_module_boundary": CANDIDATE_CROSS_MODULE_BOUNDARY,
    "operation_38_dispatch_path": OPERATION_38_DISPATCH_PATH,
    "shared_libobj_transport": SHARED_LIBOBJ_TRANSPORT,
    "operation_38_event_mapping": OPERATION_38_EVENT_MAPPING,
    "shared_request_to_event_queue_join": SHARED_REQUEST_TO_EVENT_QUEUE_JOIN,
    "event_queue_boundary": EVENT_QUEUE_BOUNDARY,
    "claims": CLAIMS,
    "evidence_digest": canonical_digest({
        "typed_request": TYPED_REQUEST,
        "view_wrapper_transport": VIEW_WRAPPER_TRANSPORT,
        "candidate_cross_module_boundary": CANDIDATE_CROSS_MODULE_BOUNDARY,
        "operation_38_dispatch_path": OPERATION_38_DISPATCH_PATH,
        "shared_libobj_transport": SHARED_LIBOBJ_TRANSPORT,
        "operation_38_event_mapping": OPERATION_38_EVENT_MAPPING,
        "shared_request_to_event_queue_join": SHARED_REQUEST_TO_EVENT_QUEUE_JOIN,
        "event_queue_boundary": EVENT_QUEUE_BOUNDARY,
    }),
    "truncated": False,
}

READINESS = "OPERATION_38_EVENT_QUEUE_TRANSPORT_NO_HANDLER"
CONCLUSION = (
    "The typed CustomCreativeStyle setter emits an exact @M00B operation-38 request with five parameters. "
    "Its local wrapper preserves code 38 and the ParamList through a bounded dispatcher; unsigned gate "
    "arithmetic proves that code 38 takes the named cross-module request edge on the model-mapping helper's "
    "normal-return path. The shared libObj request API constructs an Event and provably forwards it to "
    "EventManager::push with boolean true. The operation code passes through an opaque mapper before Event "
    "parameter key 8, so neither literal 38 nor original @M00B identity is proven in the queued Event. The "
    "queue's three indirect calls leave consumer dispatch unresolved. No named model handler, "
    "renderer/live-view, still-JPEG, movie, Creative Look equivalence, runtime behavior, or installability "
    "is proven."
)

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FORBIDDEN_KEYS = ("payload", "key_material", "device_write", "usb_write", "flash_image", "package_bytes")


class CreativeStyleModelRequestTransportError(ValueError):
    """Raised when request-transport evidence is malformed or promoted."""


def _forbid(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if any(token in str(key).casefold() for token in _FORBIDDEN_KEYS):
                raise CreativeStyleModelRequestTransportError("unsafe or reconstructive evidence field")
            _forbid(child)
    elif isinstance(value, list):
        for child in value:
            _forbid(child)


def normalize_creative_style_model_request_transport_export(document):
    _forbid(document)
    if not isinstance(document, dict) or set(document) != set(EXPECTED_EXPORT):
        raise CreativeStyleModelRequestTransportError("request-transport export fields differ")
    if document != EXPECTED_EXPORT:
        raise CreativeStyleModelRequestTransportError("request-transport export differs")
    if document["evidence_digest"] != canonical_digest({
        "typed_request": document["typed_request"],
        "view_wrapper_transport": document["view_wrapper_transport"],
        "candidate_cross_module_boundary": document["candidate_cross_module_boundary"],
        "operation_38_dispatch_path": document["operation_38_dispatch_path"],
        "shared_libobj_transport": document["shared_libobj_transport"],
        "operation_38_event_mapping": document["operation_38_event_mapping"],
        "shared_request_to_event_queue_join": document["shared_request_to_event_queue_join"],
        "event_queue_boundary": document["event_queue_boundary"],
    }):
        raise CreativeStyleModelRequestTransportError("request-transport digest differs")
    forbidden_positive = (
        "original_model_identity_preserved",
        "literal_operation_38_event_field_proven",
        "named_model_handler_found", "renderer_or_live_view_sink_found", "still_jpeg_sink_found",
        "movie_sink_found", "creative_look_equivalence_found", "runtime_execution_proven",
    )
    if any(document["claims"][key] for key in forbidden_positive):
        raise CreativeStyleModelRequestTransportError("unproven request handler or sink promoted")
    return copy.deepcopy(document)


def summarize_creative_style_model_request_transport_export(document):
    export = normalize_creative_style_model_request_transport_export(document)
    return {
        "canonical_export_sha256": canonical_digest(export),
        "typed_request_count": 1,
        "operation_38_shared_request_edge_count": 1,
        "shared_event_builder_count": 1,
        "mapped_operation_event_parameter_count": 1,
        "shared_request_queue_join_count": 1,
        "indirect_queue_call_count": export["event_queue_boundary"]["indirect_call_count"],
        "resolved_model_handler_count": 0,
        "resolved_pipeline_sink_count": 0,
    }


def validate_creative_style_model_request_transport_report(document):
    _forbid(document)
    fields = {
        "schema_version", "analysis_scope", "camera_policy", "camera_executed", "installable",
        "camera_test_eligible", "sources", "summary", "evidence_digest", "claims", "readiness",
        "conclusion",
    }
    if not isinstance(document, dict) or set(document) != fields:
        raise CreativeStyleModelRequestTransportError("request-transport report fields differ")
    if document["schema_version"] != 1 or document["analysis_scope"] != "offline-static-creative-style-model-request-transport":
        raise CreativeStyleModelRequestTransportError("request-transport report scope differs")
    if document["camera_policy"] != "physically-disconnected" or any(
        document[key] is not False for key in ("camera_executed", "installable", "camera_test_eligible")
    ):
        raise CreativeStyleModelRequestTransportError("request-transport report promotes camera activity")
    if document["sources"] != SOURCES or document["summary"] != summarize_creative_style_model_request_transport_export(EXPECTED_EXPORT):
        raise CreativeStyleModelRequestTransportError("request-transport report source or summary differs")
    if _SHA.fullmatch(document["summary"].get("canonical_export_sha256", "")) is None:
        raise CreativeStyleModelRequestTransportError("request-transport report digest shape differs")
    if document["evidence_digest"] != EXPECTED_EXPORT["evidence_digest"] or document["claims"] != CLAIMS:
        raise CreativeStyleModelRequestTransportError("request-transport report evidence differs")
    if document["readiness"] != READINESS or document["conclusion"] != CONCLUSION:
        raise CreativeStyleModelRequestTransportError("request-transport report conclusion differs")
    return copy.deepcopy(document)
