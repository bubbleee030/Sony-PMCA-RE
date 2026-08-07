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
    "operation_38_dispatch_branch_resolved": False,
}

CANDIDATE_CROSS_MODULE_BOUNDARY = {
    "site": 0x339EA0,
    "symbol": "_ZN13viewManagerIf19requestModelExecuteEPKcmP9ParamList",
    "inside_dispatcher_owner": True,
    "only_named_request_edge_in_dispatcher": True,
    "operation_38_branch_proven": False,
    "classification": "candidate-shared-request-transport-edge-not-operation-38-handler",
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
    "shared_request_to_event_queue_join_found": False,
    "classification": "shared-request-event-construction-boundary",
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
    "operation_38_candidate_branch_proven": False,
    "end_to_end_operation_38_event_queue_join_found": False,
    "shared_request_to_event_queue_join_found": False,
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
    "shared_libobj_transport": SHARED_LIBOBJ_TRANSPORT,
    "event_queue_boundary": EVENT_QUEUE_BOUNDARY,
    "claims": CLAIMS,
    "evidence_digest": canonical_digest({
        "typed_request": TYPED_REQUEST,
        "view_wrapper_transport": VIEW_WRAPPER_TRANSPORT,
        "candidate_cross_module_boundary": CANDIDATE_CROSS_MODULE_BOUNDARY,
        "shared_libobj_transport": SHARED_LIBOBJ_TRANSPORT,
        "event_queue_boundary": EVENT_QUEUE_BOUNDARY,
    }),
    "truncated": False,
}

READINESS = "REQUEST_WRAPPER_AND_CANDIDATE_EVENT_TRANSPORT_ONLY"
CONCLUSION = (
    "The typed CustomCreativeStyle setter emits an exact @M00B operation-38 request with five parameters. "
    "Its local wrapper reaches a bounded branchy dispatcher that contains one named cross-module request "
    "edge, but no static path proves that the @M00B/38 input takes that edge. Independently, the shared "
    "libObj request API constructs an Event; a separate EventManager queue boundary has three indirect "
    "calls, but the shared request-to-queue join and consumer dispatch remain unresolved. No end-to-end "
    "operation-38 queue join, named model handler, "
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
        "shared_libobj_transport": document["shared_libobj_transport"],
        "event_queue_boundary": document["event_queue_boundary"],
    }):
        raise CreativeStyleModelRequestTransportError("request-transport digest differs")
    forbidden_positive = (
        "operation_38_candidate_branch_proven", "end_to_end_operation_38_event_queue_join_found",
        "shared_request_to_event_queue_join_found",
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
        "candidate_cross_module_edge_count": 1,
        "shared_event_builder_count": 1,
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
