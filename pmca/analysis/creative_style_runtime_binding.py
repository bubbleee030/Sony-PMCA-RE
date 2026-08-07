"""Fail-closed generic runtime-binding evidence for α6400 Creative Style."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import re

from pmca.analysis.creative_style_model_request_transport import (
    validate_creative_style_model_request_transport_report,
)


class CreativeStyleRuntimeBindingError(ValueError):
    """Raised when runtime-binding evidence exceeds the pinned static boundary."""


ROOT = Path(__file__).resolve().parents[2]
UPSTREAM_REPORT = "analysis/a6400-creative-style-model-request-transport.json"
UPSTREAM_EVIDENCE_DIGEST = (
    "7575751cc125bef4d26df426d6558166f501209ce6d918bee0af11639ca56e6a"
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

DEFAULT_ROUTE_DESCRIPTOR_PROVIDER = {
    "condition": {
        "selector": "AppConfig.so",
        "runtime_selector_resolved": False,
    },
    "app_config_constructor": {
        "owner": {"start": 0x3FD794, "end": 0x3FD8C0},
        "model_config_store": {
            "resolver_call_site": 0x3FD7CC,
            "site": 0x3FD7D0,
            "offset": 8,
        },
        "vtable": {
            "header_got_cell": 0x136DFB0,
            "header_got_sites": {
                "base_literal_site": 0x3FD798,
                "base_add_site": 0x3FD7A2,
                "offset_literal_site": 0x3FD7A0,
                "load_site": 0x3FD7A8,
                "address_point_add_site": 0x3FD7AE,
                "store_site": 0x3FD7B0,
            },
            "header_relocation_index": 64884,
            "header": 0x133E3E0,
            "address_point": 0x133E3E8,
        },
    },
    "app_config_to_manager": {
        "app_config_vslot": {
            "offset": 0x1C,
            "cell": 0x133E404,
            "relocation_index": 37833,
            "target": 0x3FD456,
            "model_config_load": {"site": 0x3FD456, "offset": 8},
            "model_config_vptr_load": {"site": 0x3FD45C},
            "model_config_slot_load": {"site": 0x3FD45E, "offset": 8},
            "model_config_slot_call": {"site": 0x3FD460, "target_register": "r3"},
        },
        "manager_constructor": {
            "owner": {"start": 0x84986A, "end": 0x849932},
            "app_config_receiver": {"site": 0x84989A, "source": "r5", "destination": "r0"},
            "vptr_load": {"site": 0x84989C, "receiver": "r5"},
            "vslot_load": {"site": 0x8498A4, "offset": 0x1C},
            "vslot_call": {"site": 0x8498A6, "target_register": "r3"},
            "result_store": {"site": 0x8498AA, "manager_offset": 8},
        },
    },
    "model_config_resolver": {
        "owner": {"start": 0x3FD6A0, "end": 0x3FD724},
        "module": "libObj.so",
        "symbols": ["initializeModelConfig", "getModelConfig"],
        "dlopen_call": {"site": 0x3FD6B0, "symbol": "dlopen"},
        "dlopen_success_branch": {"site": 0x3FD6BA, "register": "r0", "target": 0x3FD6CC},
        "dlsym_calls": [0x3FD6CE, 0x3FD6F4],
        "constructor_calls": [0x3FD7CC, 0x3FD7E4, 0x3FD7FC, 0x3FD816],
        "model_config_call": {
            "site": 0x3FD7CC,
            "arguments": {
                "module": {"load_site": 0x3FD7B8, "add_site": 0x3FD7BE, "address": 0xF05632, "register": "r0"},
                "initialize": {"load_site": 0x3FD7BA, "add_site": 0x3FD7C2, "address": 0xF24CDF, "register": "r1"},
                "get": {"load_site": 0x3FD7C8, "add_site": 0x3FD7CA, "address": 0xF24CF5, "register": "r2"},
                "handle_slot": {"load_site": 0x3FD7C0, "add_site": 0x3FD7C4, "address": 0x13EF1BC, "register": "r3"},
            },
            "argument_preservation": {
                "module": {"start": 0x3FD7C0, "end": 0x3FD7CC, "register": "r0"},
                "initialize": {"start": 0x3FD7C4, "end": 0x3FD7CC, "register": "r1"},
                "handle_slot": {"start": 0x3FD7C6, "end": 0x3FD7CC, "register": "r3"},
            },
            "pic_argument_preservation": {
                "module": {"start": 0x3FD7BA, "end": 0x3FD7BE, "register": "r0"},
                "initialize": {"start": 0x3FD7BC, "end": 0x3FD7C2, "register": "r1"},
                "handle_slot": {"start": 0x3FD7C2, "end": 0x3FD7C4, "register": "r3"},
            },
            "pic_adjacent_argument": "get",
        },
        "entry_argument_preservation": {
            "module": {"start": 0x3FD6A0, "end": 0x3FD6B0, "register": "r0"},
            "initialize": {"start": 0x3FD6A0, "end": 0x3FD6A4, "register": "r1"},
            "get": {"start": 0x3FD6A0, "end": 0x3FD6AE, "register": "r2"},
            "handle_slot": {"start": 0x3FD6A0, "end": 0x3FD6AC, "register": "r3"},
        },
        "dlopen_flags": {
            "site": 0x3FD6A8,
            "register": "r1",
            "value": 257,
            "preservation": {"start": 0x3FD6AC, "end": 0x3FD6B0, "register": "r1"},
        },
        "handle_flow": {
            "slot_capture": {"site": 0x3FD6AC, "source": "r3", "destination": "r8"},
            "slot_base_to_store_preservation": {"start": 0x3FD6AE, "end": 0x3FD6B6, "register": "r8"},
            "dlopen_result_capture": {"site": 0x3FD6B4, "source": "r0", "destination": "r5"},
            "dlopen_result_preservation": {"start": 0x3FD6B4, "end": 0x3FD6BA, "register": "r0"},
            "slot_store": {"site": 0x3FD6B6, "source": "r0", "base": "r8", "offset": 0},
            "success_path_slot_base_preservation": [
                {"start": 0x3FD6CC, "end": 0x3FD6D4, "register": "r8"},
                {"start": 0x3FD6EC, "end": 0x3FD6EE, "register": "r8"},
            ],
            "slot_reload": {"site": 0x3FD6EE, "destination": "r0", "base": "r8", "offset": 0},
        },
        "initialize_callable": {
            "symbol_capture": {"site": 0x3FD6A4, "source": "r1", "destination": "r4"},
            "dlsym_argument": {"site": 0x3FD6CC, "source": "r4", "destination": "r1"},
            "dlsym_call": {"site": 0x3FD6CE, "symbol": "dlsym"},
            "result_preservation": {"start": 0x3FD6D2, "end": 0x3FD6D4, "register": "r0"},
            "success_branch": {"site": 0x3FD6D4, "register": "r0", "target": 0x3FD6EC},
            "call": {"site": 0x3FD6EC, "target_register": "r0"},
        },
        "get_callable": {
            "symbol_capture": {"site": 0x3FD6AE, "source": "r2", "destination": "r6"},
            "dlsym_argument": {"site": 0x3FD6F2, "source": "r6", "destination": "r1"},
            "dlsym_call": {"site": 0x3FD6F4, "symbol": "dlsym"},
            "result_preservation": {"start": 0x3FD6F8, "end": 0x3FD6FA, "register": "r0"},
            "success_branch": {"site": 0x3FD6FA, "register": "r0", "target": 0x3FD712},
            "call": {"site": 0x3FD712, "target_register": "r0"},
            "return": {"site": 0x3FD714, "register": "r0", "control": "pop-pc"},
        },
    },
    "factory_to_manager_provenance": {
        "config_factory_owner": {"start": 0x843C68, "end": 0x843CD8},
        "outer_constructor_owner": {"start": 0x843CD8, "end": 0x843E34},
        "factory_call": {"site": 0x843CEC, "target": 0x843C68},
        "factory_result_store": {"site": 0x843CF4, "outer_offset": 0x14},
        "manager_config_argument": {"site": 0x843D82, "outer_offset": 0x14},
        "manager_config_argument_preservation": {"start": 0x843D84, "end": 0x843D86, "register": "r2"},
        "manager_constructor_call": {"site": 0x843D86, "target": 0x84986A},
        "manager_config_capture": {"site": 0x84987E, "source": "r2", "destination": "r5"},
        "manager_config_receiver_preservation": {"start": 0x849880, "end": 0x84989A, "register": "r5"},
    },
    "model_config_symbols": {
        "initialize": {
            "name": "initializeModelConfig",
            "dynsym_index": 2633,
            "address": 0x38E609,
        },
        "get": {
            "name": "getModelConfig",
            "dynsym_index": 2362,
            "address": 0x38E63D,
        },
    },
    "model_config_singleton": 0x13EE49C,
    "model_config_singleton_lifecycle": {
        "initialize": {
            "owner": {"start": 0x38E608, "end": 0x38E624},
            "allocation_result_capture": {"site": 0x38E612, "source": "r0", "destination": "r4"},
            "constructor_call": {"site": 0x38E614, "target": 0x38E5E4},
            "singleton_address": {"load_site": 0x38E618, "add_site": 0x38E61A, "address": 0x13EE49C, "register": "r3"},
            "singleton_store": {"site": 0x38E61C, "source": "r4", "base": "r3"},
        },
        "constructor": {
            "owner": {"start": 0x38E5E4, "end": 0x38E608},
            "instance_capture": {"site": 0x38E5EA, "source": "r0", "destination": "r5"},
            "instance_preservation": {"start": 0x38E5EC, "end": 0x38E5FA, "register": "r5"},
            "vtable_header_got_cell": 0x137241C,
            "vtable_header_got_sites": {
                "base_literal_site": 0x38E5E8,
                "base_add_site": 0x38E5F2,
                "offset_literal_site": 0x38E5F0,
                "load_site": 0x38E5F6,
                "address_point_add_site": 0x38E5F8,
                "store_site": 0x38E5FA,
            },
            "vtable_header_relocation_index": 69234,
            "vtable_header": 0x13394C8,
            "vtable_address_point": 0x13394D0,
        },
        "get": {
            "owner": {"start": 0x38E624, "end": 0x38E64C},
            "singleton_address": {"load_site": 0x38E63C, "add_site": 0x38E640, "address": 0x13EE49C, "register": "r0"},
            "singleton_load": {"site": 0x38E642, "destination": "r0", "base": "r0"},
            "return_preservation": {"start": 0x38E644, "end": 0x38E646, "register": "r0"},
            "return_control": {"site": 0x38E646, "control": "pop-pc"},
        },
    },
    "model_config_vtable": {
        "address_point": 0x13394D0,
        "descriptor_slot": {
            "offset": 8,
            "cell": 0x13394D8,
            "relocation_index": 35733,
            "target": 0x340710,
            "owner": {"start": 0x340710, "end": 0x345554},
        },
    },
    "modelcamera_table_entry": {
        "id_generator_get": {
            "site": 0x340828,
            "symbol": "_ZN11IdGenerator3GetEPKc",
        },
        "id_so_table_add": {
            "site": 0x340838,
            "symbol": "_ZN9IdSoTable3addEiPKcS1_",
        },
        "manifest": {
            "alias": {"address": 0xF03447, "value": "@M00B"},
            "component": {"address": 0xF0344D, "value": "modelCamera.so"},
            "factory": {"address": 0xF0345C, "value": "ModelCameraToInstance"},
        },
        "argument_abi": {
            "get_alias": {"load_site": 0x340824, "add_site": 0x340826, "address": 0xF03447, "register": "r0"},
            "get_result_to_table_key": {"site": 0x340834, "source": "r0", "destination": "r1"},
            "component": {"load_site": 0x34082C, "add_site": 0x340830, "address": 0xF0344D, "register": "r2"},
            "factory": {"load_site": 0x34082E, "add_site": 0x340832, "address": 0xF0345C, "register": "r3"},
            "table_receiver": {"site": 0x340836, "source": "r4", "destination": "r0"},
        },
    },
    "model_manager_descriptor_lookup": {
        "registration_owner": {"start": 0x849D88, "end": 0x849E58},
        "lookup_owner": {"start": 0x848350, "end": 0x84837A},
        "provider_field": {"site": 0x848354, "offset": 8},
        "default_lookup_branch": {"site": 0x84835A, "target": 0x842BDE},
        "alternate_lookup_call": {"site": 0x848368, "target": 0x842BAE},
        "provider_lookup_owners": {
            "alternate": {"start": 0x842BAE, "end": 0x842BDE},
            "default": {"start": 0x842BDE, "end": 0x842C0E},
        },
        "provider_record_result_loads": [
            {"site": 0x842BD4, "offset": 12},
            {"site": 0x842C04, "offset": 8},
        ],
        "registration_lookup_calls": [
            {"site": 0x849DCC, "target": 0x848350},
            {"site": 0x849DD6, "target": 0x84835E},
        ],
        "record_descriptor_fields": {"component_offset": 0x10, "factory_offset": 0x14},
        "record_construction_dataflow": {
            "lookup_key_load_sites": [0x849DC8, 0x849DD0],
            "component_result_capture": {"site": 0x849DD2, "source": "r0", "destination": "r8"},
            "factory_result_capture": {"site": 0x849DDA, "source": "r0", "destination": "r10"},
            "component_constructor_argument": {"site": 0x849DF6, "source": "r8", "destination": "r3"},
            "factory_stack_argument": {"site": 0x849DF8, "source": "r10", "stack_offset": 0},
            "component_store": {"site": 0x8410B4, "record_offset": 0x10},
            "factory_stack_load": {"site": 0x8410B8, "stack_offset": 0xC},
            "factory_store": {"site": 0x8410C6, "record_offset": 0x14},
        },
    },
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
    "appconfig_default_route_manifest_descriptor_table_proven": True,
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
        validate_creative_style_model_request_transport_report(document)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
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
    "default_route_descriptor_provider": DEFAULT_ROUTE_DESCRIPTOR_PROVIDER,
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
        "resolved_runtime_descriptor_count": 1,
        "resolved_pipeline_sink_count": 0,
    }


READINESS = "CONDITIONAL_DEFAULT_ROUTE_DESCRIPTOR_NO_OPERATION38_RECORD_OR_PIPELINE"
CONCLUSION = (
    "The model/CAMERA alias reaches IdGenerator::Get, and the generic ID lookup, ModelManager "
    "record lifecycle, dynamic loader, generic ModelBase scheduler slot, and conditional "
    "destination-4 receiver route plus its structural default predicate are statically bounded. "
    "On the statically identified AppConfig.so default route only, the AppConfig constructor "
    "obtains ModelConfig and its descriptor-table slot registers the @M00B ModelCamera manifest. "
    "The splitter delimiter and exact "
    "table/row semantics are not resolved, and no operation-38 join to the candidate path is "
    "proven. The numeric model ID, runtime route selection, operation-38 key-7 equality, "
    "ModelCamera record/executor "
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
        "default_route_descriptor_provider": copy.deepcopy(
            export["default_route_descriptor_provider"]
        ),
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
