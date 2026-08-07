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
    "model_mapping_input_site": 0x339CF6,
    "dispatcher_model_preservation_segment": [0x339CCE, 0x339CF6],
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

OPERATION_38_MODEL_ALIAS = {
    "mapper_owner": {"start": 0x3391D8, "end": 0x339234, "complete": True},
    "input_model": "@M00B",
    "resolved_model_alias": "model/CAMERA",
    "model_capture_site": 0x3391DC,
    "utility_constructor_call_site": 0x3391E2,
    "utility_constructor_symbol": "_ZN18WrapperSettingUtilC1Ev",
    "utility_destructor_call_site": 0x339220,
    "utility_destructor_symbol": "_ZN18WrapperSettingUtilD1Ev",
    "first_byte_load": {"site": 0x3391E6, "offset": 0},
    "first_byte_compare_site": 0x3391E8,
    "first_byte_value": 0x40,
    "non_alias_branch": {"site": 0x3391EA, "target": 0x33921E},
    "input_byte_loads": [
        {"site": 0x3391EC, "offset": 2, "register": "r5"},
        {"site": 0x339200, "offset": 3, "register": "lr"},
        {"site": 0x33920A, "offset": 4, "register": "r6"},
    ],
    "candidate_pointer_load_site": 0x3391F6,
    "candidate_byte_loads": [
        {"site": 0x3391FA, "offset": 2, "register": "r6"},
        {"site": 0x339204, "offset": 3, "register": "r6"},
        {"site": 0x33920C, "offset": 4, "register": "r1"},
    ],
    "byte_compare_sites": [0x3391FC, 0x339206, 0x33920E],
    "counter_initialization_site": 0x3391EE,
    "counter_increment_site": 0x339218,
    "counter_compare_site": 0x33921A,
    "counter_loop_bound": 23,
    "counter_loop_branch": {"site": 0x33921C, "target": 0x3391F0},
    "match_result_address_site": 0x339212,
    "match_result_load": {"site": 0x339214, "offset": 4},
    "return_site": 0x339224,
    "table": {
        "literal_load_site": 0x3391F0,
        "literal_address": 0x339230,
        "pc_add_site": 0x3391F4,
        "base": 0x8D760C,
        "entry_stride": 8,
        "entry_count": 23,
    },
    "entry_zero": {
        "key_cell": 0x8D760C,
        "key_relocation": {"section": ".rel.dyn", "index": 13096, "type": 23, "symbol_index": 0},
        "key_address": 0x667129,
        "key": "@M00B",
        "result_cell": 0x8D7610,
        "result_relocation": {"section": ".rel.dyn", "index": 13097, "type": 23, "symbol_index": 0},
        "result_address": 0x6671FB,
        "result": "model/CAMERA",
    },
    "id_generator_call_site": 0x3F2AC0,
    "id_generator_symbol": "_ZN11IdGenerator3GetEPKc",
    "id_generator_owner": {"start": 0x402DB4, "end": 0x402EC4, "complete": True},
    "id_generator_model_preservation_segment": [0x3F2AB8, 0x3F2AC0],
    "id_generator_result_capture_site": 0x3F2AC6,
    "event_builder_id_argument_site": 0x3F2ACE,
    "id_generator_result_preservation_segment": [0x3F2AC8, 0x3F2ACE],
    "builder_id_capture_site": 0x8430B4,
    "builder_id_value_site": 0x8430DA,
    "builder_id_preservation_segment": [0x8430B6, 0x8430DA],
    "builder_id_holder_site": 0x8430DC,
    "builder_parameter_value_site": 0x8430E2,
    "builder_parameter_key_site": 0x8430E4,
    "builder_event_receiver_site": 0x8430E6,
    "event_parameter_key": 7,
    "event_parameter_add_site": 0x8430E8,
    "id_generator_first_byte_load": {"site": 0x402DBC, "offset": 0},
    "id_generator_first_byte_compare_site": 0x402DBE,
    "id_generator_special_at_branch": {"site": 0x402DC0, "target": 0x402E52},
    "id_table_find_call_site": 0x402E34,
    "id_table_find_symbol": "_ZN7IdTable6findIdESs",
    "id_table_result_capture_site": 0x402E38,
    "id_generator_missing_sentinel_site": 0x402E44,
    "semantic_model_alias_resolved": True,
    "original_model_literal_preserved": False,
    "numeric_model_id_resolved": False,
    "classification": "m00b-to-model-camera-alias-with-runtime-key-7-id",
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

OPERATION_38_EVENT_HEADER = {
    "builder_owner": {"start": 0x8430AC, "end": 0x843118, "complete": True},
    "event_id_literal_load_site": 0x8430BE,
    "event_id_literal_address": 0x843114,
    "event_id": 0x11004003,
    "destination_argument_site": 0x8430C0,
    "destination": 2,
    "queue_tag_argument_site": 0x8430C2,
    "queue_tag": 0,
    "header_argument_preservation_segments": {
        "event_id": [0x8430C0, 0x8430C6],
        "destination": [0x8430C2, 0x8430C6],
        "queue_tag": [0x8430C4, 0x8430C6],
    },
    "constructor_call_site": 0x8430C6,
    "constructor_symbol": "_ZN5EventC1Emhh",
    "constructor_owner": {"start": 0x840FEC, "end": 0x841022, "complete": True},
    "event_id_store": {"site": 0x840FF0, "offset": 4, "width": 4},
    "destination_store": {"site": 0x840FF4, "offset": 8, "width": 1},
    "queue_tag_store": {"site": 0x840FF6, "offset": 9, "width": 1},
    "get_id_owner": {"start": 0x3478D0, "end": 0x3478D8, "complete": True},
    "get_id_load": {"site": 0x3478D4, "offset": 4, "width": 4},
    "get_destination_owner": {"start": 0x842458, "end": 0x84248C, "complete": True},
    "get_destination_function": {"start": 0x84247C, "end": 0x842484},
    "get_destination_load": {"site": 0x842480, "offset": 8, "width": 1},
    "get_queue_tag_owner": {"start": 0x842458, "end": 0x84248C, "complete": True},
    "get_queue_tag_function": {"start": 0x842484, "end": 0x84248C},
    "get_queue_tag_load": {"site": 0x842488, "offset": 9, "width": 1},
    "set_param_list_owner": {"start": 0x84106C, "end": 0x84108E, "complete": True},
    "set_param_list_store": {"site": 0x84108A, "offset": 12, "width": 4},
    "add_parameter_owner": {"start": 0x34793C, "end": 0x34794C, "complete": True},
    "add_parameter_param_list_load": {"site": 0x347940, "offset": 12, "width": 4},
    "parameter_method_direct_header_store_found": False,
    "classification": "fixed-request-event-header-with-opaque-key-8-operation",
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

OPERATION_38_QUEUE_DISPATCH = {
    "push_owner": {"start": 0x842598, "end": 0x84264C, "complete": True},
    "queue_tag_reader_owner": {"start": 0x842458, "end": 0x84248C, "complete": True},
    "queue_tag_reader_function": {"start": 0x842484, "end": 0x84248C},
    "queue_tag_read_call": {"site": 0x8425A8, "target": 0x842484},
    "tag_one_compare_site": 0x8425AC,
    "tag_one_branch": {"site": 0x8425B0, "target": 0x8425B6},
    "tag_three_compare_site": 0x8425B2,
    "other_tag_branch": {"site": 0x8425B4, "target": 0x842624},
    "tag_zero_fallthrough_site": 0x842624,
    "tag_zero_guard_target": 0x84263C,
    "event_argument_capture_site": 0x8425A4,
    "event_argument_forward_site": 0x84262E,
    "event_argument_preservation_segments": [
        [0x8425A6, 0x8425B4],
        [0x842624, 0x84262E],
    ],
    "queue_zero_receiver_sites": [0x84262C, 0x842630],
    "queue_zero_call": {"site": 0x842632, "target": 0x840CE2},
    "queue_zero_helper_owner": {"start": 0x840CE2, "end": 0x840D02, "complete": True},
    "bypassed_indirect_call_sites": [0x8425C6, 0x8425D6, 0x842620],
    "operation_38_indirect_reachability": [],
    "consumer_loop_join_proven": False,
    "classification": "operation-38-tag-zero-direct-queue-path",
}

OPERATION_38_QUEUE_CONSUMER_IDENTITY = {
    "producer_initialization_caller_owner": {
        "start": 0x3FD8E8, "end": 0x3FD9D4, "complete": True,
    },
    "utility_manager_load": {"site": 0x3FD93A, "offset": 0x10},
    "producer_initializer_call": {"site": 0x3FD93C, "target": 0x3F29D4},
    "producer_initializer_owner": {"start": 0x3F29D4, "end": 0x3F2A10, "complete": True},
    "wrapper_load": {"site": 0x3F29DE, "offset": 0x0C},
    "initializer_got_base_literal_site": 0x3F29D8,
    "initializer_got_base_add_site": 0x3F29DC,
    "initializer_got_offset_literal_site": 0x3F29E4,
    "initializer_got_load_site": 0x3F29E8,
    "producer_global_store_site": 0x3F29EA,
    "producer_global": {
        "got_cell": 0x136EC90,
        "relocation": {
            "section": ".rel.dyn", "index": 65700, "type": 23,
            "symbol_index": 0, "target": 0x13EF0C0,
        },
    },
    "continuation_owner": {"start": 0x3F2A6C, "end": 0x3F2AA8, "complete": True},
    "continuation_got_base_literal_site": 0x3F2A7C,
    "continuation_got_base_add_site": 0x3F2A7E,
    "continuation_got_offset_literal_site": 0x3F2A90,
    "continuation_got_load_site": 0x3F2A94,
    "continuation_global_value_load_site": 0x3F2A96,
    "queue_helper_owner": {"start": 0x8447F0, "end": 0x844800, "complete": True},
    "producer_receiver_load": {"site": 0x8447F6, "offset": 0x10},
    "producer_receiver_steps": [
        "utility_manager=load(app_config+0x10)",
        "wrapper=load(utility_manager+0x0c)",
        "producer_event_manager=load(wrapper+0x10)",
    ],
    "thread_owner": {"start": 0x84319C, "end": 0x84320C, "complete": True},
    "outer_constructor_argument_site": 0x8431A8,
    "outer_constructor_call": {"site": 0x8431AE, "target": 0x843CD8},
    "outer_loop_argument_site": 0x8431DC,
    "outer_loop_call": {"site": 0x8431DE, "target": 0x843EFC},
    "outer_constructor_owner": {"start": 0x843CD8, "end": 0x843E34, "complete": True},
    "event_manager_constructor_call": {"site": 0x843D4E, "target": 0x84248C},
    "outer_event_manager_store": {"site": 0x843D58, "offset": 0x10},
    "outer_event_manager_global": {
        "got_cell": 0x1371044,
        "got_base_literal_site": 0x843CF0,
        "got_base_add_site": 0x843CF2,
        "got_offset_literal_site": 0x843D52,
        "got_load_site": 0x843D56,
        "relocation": {
            "section": ".rel.dyn", "index": 74865, "type": 21,
            "symbol_index": 2361, "symbol": "g_pEvtMgr",
        },
        "store_site": 0x843D5A,
    },
    "consumer_loop_owner": {"start": 0x843EFC, "end": 0x844340, "complete": True},
    "consumer_outer_capture_site": 0x843F04,
    "consumer_receiver_steps": [
        "outer=thread_stack_frame+4",
        "consumer_event_manager=load(outer+0x10)",
    ],
    "consumer_pop": {
        "queue_index_site": 0x84409C,
        "queue_index": 0,
        "receiver_load_site": 0x84409E,
        "call": {"site": 0x8440A6, "target": 0x842574},
    },
    "consumer_dispatch": {
        "event_argument_site": 0x8440AA,
        "receiver_site": 0x8440AC,
        "call": {"site": 0x8440AE, "target": 0x843A84},
        "event_preservation_segment": [0x8440AC, 0x8440AE],
    },
    "producer_receiver_expression_proven": True,
    "consumer_receiver_expression_proven": True,
    "utility_manager_outer_backref_proven": False,
    "same_event_manager_instance_proven": False,
    "operation_38_queue_to_consumer_identity_proven": False,
    "classification": "distinct-producer-consumer-receiver-expressions-no-equality-join",
}

MODEL_MANAGER_REQUEST_EVENT_CANDIDATE = {
    "event_id": 0x11004003,
    "destination": 2,
    "central_dispatch_owner": {"start": 0x843A84, "end": 0x843C48, "complete": True},
    "event_argument_capture_site": 0x843A8C,
    "get_destination_call_site": 0x843AF2,
    "get_destination_symbol": "_ZN5Event7getDestEv",
    "destination_result_capture_site": 0x843B00,
    "destination_two_mask_site": 0x843B54,
    "destination_two_skip": {"site": 0x843B5A, "target": 0x843B6E},
    "model_manager_receiver_load": {"site": 0x843B66, "offset": 4},
    "event_argument_forward_site": 0x843B68,
    "central_event_preservation_segment": [0x843A8E, 0x843B68],
    "destination_two_call": {"site": 0x843B6A, "target": 0x84A830},
    "model_manager_constructor_owner": {"start": 0x84986A, "end": 0x849932, "complete": True},
    "model_manager_constructor_call": {"site": 0x843D86, "target": 0x84986A},
    "model_manager_outer_store": {"site": 0x843D8A, "offset": 4},
    "event_manager_field_store": {"site": 0x84989E, "offset": 0},
    "model_manager_dispatch_owner": {"start": 0x84A830, "end": 0x84AC94, "complete": True},
    "get_id_call_site": 0x84A83E,
    "get_id_symbol": "_ZNK5Event5getIdEv",
    "event_id_capture_site": 0x84A842,
    "request_gate_literal_load_site": 0x84A87E,
    "request_gate_literal_address": 0x84AAE4,
    "request_gate_literal_value": 0x11004005,
    "request_gate_initial_compare_site": 0x84A880,
    "request_gate_higher_branch": {"site": 0x84A886, "target": 0x84A898},
    "request_gate_subtract_site": 0x84A888,
    "request_gate_subtract_value": 3,
    "request_gate_lower_compare_site": 0x84A88A,
    "request_gate_lower_equal_branch": {"site": 0x84A88C, "target": 0x84AA42},
    "request_gate_add_site": 0x84A890,
    "request_gate_add_value": 1,
    "request_gate_event_compare_site": 0x84A892,
    "request_gate_mismatch_branch": {"site": 0x84A894, "target": 0x84A8E6},
    "request_event_branch": {"site": 0x84A896, "target": 0x84A95C},
    "parameter_get_helper": 0x848190,
    "parameter_keys": {
        "request_context": {"site": 0x84A95C, "key": 6},
        "model_id": {"site": 0x84A966, "key": 7},
        "mapped_operation": {"site": 0x84A97C, "key": 8},
    },
    "parameter_get_calls": {
        "request_context": 0x84A960,
        "model_id": 0x84A968,
        "mapped_operation": 0x84A97E,
    },
    "scalar_value_target": 0x3490E6,
    "model_id_scalar_call_site": 0x84A96E,
    "model_id_value_flow": {
        "event_capture_site": 0x84A83C,
        "event_preservation_segment": [0x84A83E, 0x84A964],
        "parameter_receiver_site": 0x84A964,
        "missing_branch": {"site": 0x84A96C, "target": 0x84A976},
        "scalar_result_capture_site": 0x84A972,
        "scalar_join_branch": {"site": 0x84A974, "target": 0x84A97A},
        "missing_sentinel_site": 0x84A976,
        "missing_sentinel": -1,
        "lookup_argument_site": 0x84A98E,
        "preservation_segment": [0x84A97A, 0x84A98E],
    },
    "mapped_operation_scalar_call_site": 0x84A986,
    "mapped_operation_scalar_result_capture_site": 0x84A98A,
    "mapped_operation_value_flow": {
        "parameter_receiver_site": 0x84A97A,
        "event_preservation_segment": [0x84A83E, 0x84A97A],
        "pointer_or_null_capture_site": 0x84A982,
        "missing_branch": {"site": 0x84A984, "target": 0x84A98C},
        "scalar_result_capture_site": 0x84A98A,
        "joined_preservation_segment": [0x84A98C, 0x84A9B8],
        "secondary_event_id_site": 0x84A9B8,
    },
    "model_record_lookup_call": {"site": 0x84A990, "target": 0x84903E},
    "model_record_lookup_owner": {"start": 0x84903E, "end": 0x849088, "complete": True},
    "model_record_result_capture_site": 0x84A994,
    "model_record_validity": {
        "compare_site": 0x84A996,
        "missing_branch": {"site": 0x84A998, "target": 0x84A9FE},
        "executor_argument_site": 0x84A9E0,
        "record_preservation_segment": [0x84A996, 0x84A9E0],
    },
    "secondary_event_constructor_call_site": 0x84A9BE,
    "secondary_event_id_site": 0x84A9B8,
    "secondary_event_destination_site": 0x84A9B6,
    "secondary_event_queue_tag_site": 0x84A9BA,
    "model_executor_inputs": {
        "secondary_event_capture_site": 0x84A9BC,
        "secondary_event_preservation_segment": [0x84A9BE, 0x84A9E2],
        "record_argument_site": 0x84A9E0,
        "event_argument_site": 0x84A9E2,
    },
    "model_executor_call": {"site": 0x84A9E4, "target": 0x8411A4},
    "model_executor_helper_owner": {"start": 0x8411A4, "end": 0x8411BA, "complete": True},
    "record_executor_load": {"site": 0x8411A4, "offset": 0x1C},
    "executor_dispatch_call": {"site": 0x8411AC, "target": 0x843014},
    "executor_validity": {
        "presence_branch": {"site": 0x8411AA, "target": 0x8411B4},
        "missing_sentinel_site": 0x8411B4,
        "missing_sentinel": -1,
        "event_preservation_segment": [0x8411A4, 0x8411AC],
    },
    "executor_dispatch_owner": {"start": 0x843014, "end": 0x843032, "complete": True},
    "executor_event_store": {"site": 0x843018, "offset": 0x14},
    "executor_state_value_site": 0x84301A,
    "executor_state_store": {"site": 0x84301E, "offset": 8, "value": 1},
    "executor_virtual_target_load": {"site": 0x843028, "offset": 0x18},
    "executor_virtual_call_site": 0x84302A,
    "executor_virtual_slot": 0x18,
    "model_manager_request_event_branch_found": True,
    "operation_38_queue_join_proven": False,
    "concrete_model_record_found": False,
    "concrete_model_executor_handler_found": False,
    "classification": "bounded-model-manager-request-event-candidate-no-queue-identity",
}

CLAIMS = {
    "typed_custom_creative_style_request_found": True,
    "view_wrapper_transport_found": True,
    "candidate_cross_module_request_edge_found": True,
    "shared_event_construction_boundary_found": True,
    "event_queue_indirect_boundary_found": True,
    "operation_38_candidate_branch_proven": True,
    "creative_style_request_model_alias_resolved": True,
    "operation_38_model_id_reaches_event_key_7": True,
    "operation_38_key_7_numeric_model_id_resolved": False,
    "end_to_end_operation_38_event_queue_join_found": True,
    "shared_request_to_event_queue_join_found": True,
    "operation_38_origin_reaches_mapped_event_parameter": True,
    "operation_38_event_header_proven": True,
    "operation_38_tag_zero_queue_path_proven": True,
    "operation_38_indirect_queue_callbacks_bypassed": True,
    "producer_receiver_expression_proven": True,
    "consumer_receiver_expression_proven": True,
    "operation_38_queue_to_consumer_identity_proven": False,
    "model_manager_request_event_branch_found": True,
    "operation_38_reaches_model_manager_dispatch": False,
    "concrete_model_record_found": False,
    "concrete_model_executor_handler_found": False,
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
    "operation_38_model_alias": OPERATION_38_MODEL_ALIAS,
    "shared_libobj_transport": SHARED_LIBOBJ_TRANSPORT,
    "operation_38_event_mapping": OPERATION_38_EVENT_MAPPING,
    "operation_38_event_header": OPERATION_38_EVENT_HEADER,
    "shared_request_to_event_queue_join": SHARED_REQUEST_TO_EVENT_QUEUE_JOIN,
    "event_queue_boundary": EVENT_QUEUE_BOUNDARY,
    "operation_38_queue_dispatch": OPERATION_38_QUEUE_DISPATCH,
    "operation_38_queue_consumer_identity": OPERATION_38_QUEUE_CONSUMER_IDENTITY,
    "model_manager_request_event_candidate": MODEL_MANAGER_REQUEST_EVENT_CANDIDATE,
    "claims": CLAIMS,
    "evidence_digest": canonical_digest({
        "typed_request": TYPED_REQUEST,
        "view_wrapper_transport": VIEW_WRAPPER_TRANSPORT,
        "candidate_cross_module_boundary": CANDIDATE_CROSS_MODULE_BOUNDARY,
        "operation_38_dispatch_path": OPERATION_38_DISPATCH_PATH,
        "operation_38_model_alias": OPERATION_38_MODEL_ALIAS,
        "shared_libobj_transport": SHARED_LIBOBJ_TRANSPORT,
        "operation_38_event_mapping": OPERATION_38_EVENT_MAPPING,
        "operation_38_event_header": OPERATION_38_EVENT_HEADER,
        "shared_request_to_event_queue_join": SHARED_REQUEST_TO_EVENT_QUEUE_JOIN,
        "event_queue_boundary": EVENT_QUEUE_BOUNDARY,
        "operation_38_queue_dispatch": OPERATION_38_QUEUE_DISPATCH,
        "operation_38_queue_consumer_identity": OPERATION_38_QUEUE_CONSUMER_IDENTITY,
        "model_manager_request_event_candidate": MODEL_MANAGER_REQUEST_EVENT_CANDIDATE,
    }),
    "truncated": False,
}

READINESS = "OPERATION_38_TAG_ZERO_QUEUE_NO_CONSUMER_IDENTITY"
CONCLUSION = (
    "The typed CustomCreativeStyle setter emits an exact @M00B operation-38 request with five parameters. "
    "Its local wrapper preserves code 38 and the ParamList through a bounded dispatcher; unsigned gate "
    "arithmetic proves that code 38 takes the named cross-module request edge on the model-mapping helper's "
    "normal-return path. The view mapper resolves @M00B to model/CAMERA; IdGenerator's runtime-dependent "
    "numeric result reaches Event key 7, while the operation code passes through a separate opaque mapper "
    "before key 8. The builder fixes Event ID 0x11004003, destination 2, and queue tag 0, then forwards the "
    "Event to EventManager::push with boolean true. Tag 0 bypasses all three indirect push callbacks and "
    "takes the direct queue-zero path. The producer receiver is derived through a UtilityManager wrapper, "
    "whereas the consumer loop uses the thread-local outer object's EventManager; no static equality join "
    "between them is proven. A matching ModelManager request-Event branch, key-7 lookup, and generic executor "
    "virtual boundary are bounded candidates only. Literal 38 in key 8, the numeric key-7 ID, operation-38 "
    "delivery to that consumer, a concrete model record or handler, renderer/live-view, still-JPEG, movie, "
    "Creative Look equivalence, runtime behavior, and installability remain unproven."
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
        "operation_38_model_alias": document["operation_38_model_alias"],
        "shared_libobj_transport": document["shared_libobj_transport"],
        "operation_38_event_mapping": document["operation_38_event_mapping"],
        "operation_38_event_header": document["operation_38_event_header"],
        "shared_request_to_event_queue_join": document["shared_request_to_event_queue_join"],
        "event_queue_boundary": document["event_queue_boundary"],
        "operation_38_queue_dispatch": document["operation_38_queue_dispatch"],
        "operation_38_queue_consumer_identity": document["operation_38_queue_consumer_identity"],
        "model_manager_request_event_candidate": document["model_manager_request_event_candidate"],
    }):
        raise CreativeStyleModelRequestTransportError("request-transport digest differs")
    forbidden_positive = (
        "original_model_identity_preserved",
        "literal_operation_38_event_field_proven",
        "operation_38_queue_to_consumer_identity_proven",
        "operation_38_reaches_model_manager_dispatch",
        "concrete_model_record_found",
        "concrete_model_executor_handler_found",
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
        "resolved_model_alias_count": 1,
        "fixed_event_header_count": 1,
        "tag_zero_queue_path_count": 1,
        "shared_request_queue_join_count": 1,
        "queue_to_consumer_identity_join_count": 0,
        "model_manager_request_event_candidate_count": 1,
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
