import copy
import importlib.util
import io
import json
import unittest
from pathlib import Path
from unittest import mock

from pmca.analysis.creative_style_runtime_binding import (
    CLAIMS,
    EXPECTED_EXPORT,
    UNPROVEN_CLAIMS,
    CreativeStyleRuntimeBindingError,
    build_creative_style_runtime_binding_report,
    normalize_creative_style_runtime_binding_export,
    summarize_creative_style_runtime_binding_export,
    validate_creative_style_runtime_binding_report,
)


ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = ROOT / "analysis" / "a6400-creative-style-runtime-binding.json"
EXPORTER = ROOT / "tools" / "static" / "export_a6400_creative_style_runtime_binding.py"


class _MemoryProxy:
    def __init__(self, memory, *, base=None, index=None, displacement=None):
        self.base = memory.base if base is None else base
        self.index = memory.index if index is None else index
        self.disp = memory.disp if displacement is None else displacement


class _OperandProxy:
    def __init__(self, operand, *, register=None, immediate=None, memory=None):
        self.type = operand.type
        self.reg = operand.reg if register is None else register
        self.imm = operand.imm if immediate is None else immediate
        self.mem = operand.mem if memory is None else memory


class _InstructionProxy:
    def __init__(self, instruction, operands, *, written_register=None):
        self.address = instruction.address
        self.size = instruction.size
        self.id = instruction.id
        self.cc = instruction.cc
        self.writeback = instruction.writeback
        self.operands = operands
        self._instruction = instruction
        self._written_register = written_register

    def group(self, group):
        return self._instruction.group(group)

    def regs_access(self):
        reads, writes = self._instruction.regs_access()
        if self._written_register is not None and self._written_register not in writes:
            writes = [*writes, self._written_register]
        return reads, writes


class CreativeStyleRuntimeBindingTests(unittest.TestCase):
    def test_generic_loader_and_executor_are_proven_without_modelcamera_identity(self):
        self.assertTrue(CLAIMS["model_camera_alias_reaches_id_generator_get_proven"])
        self.assertTrue(CLAIMS["generic_dynamic_loader_chain_proven"])
        self.assertTrue(CLAIMS["modelbase_scheduler_slot_proven"])
        self.assertTrue(CLAIMS["destination_4_receiver_route_and_default_predicate_found"])
        self.assertTrue(CLAIMS["appconfig_default_route_manifest_descriptor_table_proven"])
        self.assertFalse(CLAIMS["model_camera_numeric_id_resolved"])
        self.assertTrue(CLAIMS["model_camera_name_split_proven"])
        self.assertFalse(CLAIMS["key7_to_record_join_proven"])
        self.assertFalse(CLAIMS["record_is_modelcamera_proven"])
        self.assertFalse(CLAIMS["executor_is_modelcamera_proven"])
        self.assertFalse(CLAIMS["operation38_to_candidate_branch_join_proven"])
        self.assertFalse(CLAIMS["operation38_to_modelcamera_executor_join_proven"])
        self.assertFalse(CLAIMS["operation38_to_destination_4_default_path_join_proven"])
        self.assertFalse(CLAIMS["five_field_consumption_proven"])
        self.assertFalse(CLAIMS["native_creative_look_pipeline_proven"])

    def test_exact_static_boundaries_are_pinned(self):
        normalized = normalize_creative_style_runtime_binding_export(EXPECTED_EXPORT)

        self.assertEqual(normalized["id_generator"]["input_alias"], "model/CAMERA")
        self.assertTrue(normalized["id_generator"]["splitter_delimiter_semantics_resolved"])
        self.assertEqual(
            normalized["id_generator"]["splitter_delimiter"],
            {
                "load_site": 0x40242A,
                "add_site": 0x402434,
                "consumer_argument_site": 0x40243C,
                "consumer_call": {
                    "site": 0x402444,
                    "symbol": "_ZNKSs13find_first_ofEPKcjj",
                },
                "address": 0xEE4911,
                "value": "/",
            },
        )
        self.assertTrue(normalized["id_generator"]["model_table_key_resolved"])
        self.assertEqual(normalized["id_generator"]["model_table_key"], "model")
        self.assertTrue(normalized["id_generator"]["camera_row_key_resolved"])
        self.assertEqual(normalized["id_generator"]["camera_row_key"], "CAMERA")
        self.assertEqual(
            normalized["id_generator"]["validated_static_set_table_call"],
            {
                "module": "lib/viewUnified2.so",
                "owner": {"start": 0x37FCB0, "end": 0x37FD3C},
                "site": 0x37FD10,
                "symbol": "_ZN11IdGenerator8SetTableESsP7IdTable",
                "key_constructor": {
                    "destination_site": 0x37FCFE,
                    "call_site": 0x37FD04,
                    "symbol": "_ZNSsC1EPKcRKSaIcE",
                },
                "key_argument_site": 0x37FD0E,
                "table_argument_site": 0x37FD0C,
                "table_key_resolved": True,
                "table_key": "view",
            },
        )
        self.assertEqual(
            normalized["id_generator"]["validated_static_view_table"],
            {
                "table_key_literal": {
                    "load_site": 0x37FCFC,
                    "add_site": 0x37FD02,
                    "address": 0x79C21A,
                    "value": "view",
                },
                "lazy_getter_owner": {"start": 0x3F4B1C, "end": 0x3F4B8C},
                "constructor_owner": {"start": 0x3F4AE4, "end": 0x3F4B1C},
                "initializer_owner": {"start": 0x318720, "end": 0x31B128},
                "initializer_chain": {
                    "getter_constructor_call_site": 0x3F4B3A,
                    "constructor_initializer_call_site": 0x3F4B02,
                    "initializer_thunk_owner": {"start": 0x4015A4, "end": 0x4015E0},
                    "initializer_thunk_entry": 0x4015C8,
                    "initializer_thunk_branch_site": 0x4015D0,
                },
                "table_instance": 0xB2F644,
                "row_count": 191,
                "row_id_range": [0, 190],
                "id_11": {
                    "name": "AUTO_SELECTION",
                    "name_load_site": 0x3188F0,
                    "name_add_site": 0x3188FC,
                    "name_address": 0x7ABE4B,
                    "store_site": 0x31890E,
                },
                "exact_camera_row_found": False,
            },
        )
        self.assertFalse(
            normalized["id_generator"][
                "operation38_key7_equals_descriptor_id_11_proven"
            ]
        )
        self.assertEqual(normalized["model_manager_records"]["map_offset"], 0x88)
        self.assertEqual(
            normalized["dynamic_loader"]["factory_call"],
            {
                "site": 0x84114C,
                "target_register": "r3",
                "key_load_site": 0x841148,
                "key_record_offset": 0,
                "manager_load_site": 0x84114A,
                "manager_record_offset": 0x20,
                "result_store_site": 0x84114E,
                "result_record_offset": 0x1C,
            },
        )
        self.assertEqual(
            normalized["modelcamera_candidate"]["manifest"],
            {
                "alias": {"address": 0xF03447, "value": "@M00B"},
                "component": {"address": 0xF0344D, "value": "modelCamera.so"},
                "factory": {"address": 0xF0345C, "value": "ModelCameraToInstance"},
            },
        )
        self.assertEqual(
            normalized["default_route_descriptor_provider"],
            {
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
                        "app_config_receiver": {
                            "site": 0x84989A,
                            "source": "r5",
                            "destination": "r0",
                        },
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
                    "record_descriptor_fields": {
                        "component_offset": 0x10,
                        "factory_offset": 0x14,
                    },
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
            },
        )
        default_route = normalized["default_route_descriptor_provider"]
        self.assertEqual(
            default_route["app_config_to_manager"],
            {
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
        )
        self.assertEqual(
            default_route["modelcamera_table_entry"]["argument_abi"],
            {
                "get_alias": {"load_site": 0x340824, "add_site": 0x340826, "address": 0xF03447, "register": "r0"},
                "get_result_to_table_key": {"site": 0x340834, "source": "r0", "destination": "r1"},
                "component": {"load_site": 0x34082C, "add_site": 0x340830, "address": 0xF0344D, "register": "r2"},
                "factory": {"load_site": 0x34082E, "add_site": 0x340832, "address": 0xF0345C, "register": "r3"},
                "table_receiver": {"site": 0x340836, "source": "r4", "destination": "r0"},
            },
        )
        self.assertEqual(
            default_route["model_manager_descriptor_lookup"]["record_construction_dataflow"],
            {
                "lookup_key_load_sites": [0x849DC8, 0x849DD0],
                "component_result_capture": {"site": 0x849DD2, "source": "r0", "destination": "r8"},
                "factory_result_capture": {"site": 0x849DDA, "source": "r0", "destination": "r10"},
                "component_constructor_argument": {"site": 0x849DF6, "source": "r8", "destination": "r3"},
                "factory_stack_argument": {"site": 0x849DF8, "source": "r10", "stack_offset": 0},
                "component_store": {"site": 0x8410B4, "record_offset": 0x10},
                "factory_stack_load": {"site": 0x8410B8, "stack_offset": 0xC},
                "factory_store": {"site": 0x8410C6, "record_offset": 0x14},
            },
        )
        self.assertFalse(normalized["generic_executor"]["scheduled_event_id_resolved_generically"])
        self.assertEqual(
            normalized["modelcamera_candidate"]["default_scheduler_event"]["value"],
            0x11004001,
        )
        self.assertEqual(
            normalized["generic_executor"]["model_manager_dispatch_owner"],
            {"start": 0x84A830, "end": 0x84AC94},
        )
        self.assertEqual(
            normalized["generic_executor"]["candidate_branch_range"],
            {"start": 0x84A95C, "end": 0x84A9E4},
        )
        self.assertTrue(
            normalized["generic_executor"]["param_list_clone_forwarded_to_secondary_event"]
        )
        self.assertEqual(normalized["destination_4"]["receiver"], 0x846710)
        self.assertEqual(normalized["destination_4"]["default_predicate_call"], 0x8468D2)

    def test_unproven_claims_cannot_be_promoted(self):
        for claim in UNPROVEN_CLAIMS:
            mutated = copy.deepcopy(EXPECTED_EXPORT)
            mutated["claims"][claim] = True
            with self.subTest(claim=claim), self.assertRaises(
                CreativeStyleRuntimeBindingError
            ):
                normalize_creative_style_runtime_binding_export(mutated)

    def test_every_evidence_section_and_nested_field_is_exact(self):
        mutations = (
            ("id_generator", "get_owner", "end", 0x402EC2),
            ("id_generator", "splitter_owner", "start", 0x402426),
            ("id_generator", "find_id_call", "site", 0x402E36),
            ("model_manager_records", "lookup_owner", "end", 0x849086),
            ("model_manager_records", "map_offset", None, 0x8C),
            ("model_manager_records", "map_constructor", "site", 0x849892),
            ("model_manager_records", "record_allocation", "size", 0x28),
            ("model_manager_records", "activation_owner", "end", 0x8411A2),
            ("dynamic_loader", "dlopen_call", "site", 0x841134),
            ("dynamic_loader", "mode_argument", "value", 0x102),
            ("dynamic_loader", "dlsym_call", "symbol", "wrong"),
            ("dynamic_loader", "handle_store", "record_offset", 0x14),
            ("dynamic_loader", "factory_call", "target_register", "r4"),
            ("modelcamera_candidate", "factory", "instance_size", 0x6438),
            ("modelcamera_candidate", "rtti", "name", "wrong"),
            ("modelcamera_candidate", "slot_cell", "address", 0x1341B0C),
            ("modelcamera_candidate", "slot_target_owner", "end", 0x3FE6DA),
            ("generic_executor", "virtual_call", "site", 0x84302C),
            ("generic_executor", "scalar_event_parameters", "request_context", {}),
            ("generic_executor", "secondary_event", "constructor_call_site", 0x84A9BC),
            ("generic_executor", "scheduled_event_id_instance_offset", None, 0x64),
            ("destination_4", "destination_bit_test", "mask", 2),
            ("destination_4", "validated_event_id_comparisons", None, []),
            ("destination_4", "default_predicate_call", None, 0x8468D4),
        )
        for section, field, nested, value in mutations:
            mutated = copy.deepcopy(EXPECTED_EXPORT)
            if nested is None:
                mutated[section][field] = value
            else:
                mutated[section][field][nested] = value
            with self.subTest(section=section, field=field), self.assertRaises(
                CreativeStyleRuntimeBindingError
            ):
                normalize_creative_style_runtime_binding_export(mutated)

    def test_identity_digest_scope_and_reconstructive_fields_are_strict(self):
        candidates = []

        mutated = copy.deepcopy(EXPECTED_EXPORT)
        mutated["sources"]["object"]["sha256"] = "0" * 64
        candidates.append(mutated)

        mutated = copy.deepcopy(EXPECTED_EXPORT)
        mutated["upstream"]["evidence_digest"] = "0" * 64
        candidates.append(mutated)

        mutated = copy.deepcopy(EXPECTED_EXPORT)
        mutated["analysis_scope"] = "runtime-tested"
        candidates.append(mutated)

        mutated = copy.deepcopy(EXPECTED_EXPORT)
        mutated["evidence_digest"] = "0" * 64
        candidates.append(mutated)

        mutated = copy.deepcopy(EXPECTED_EXPORT)
        mutated["raw_bytes"] = [1, 2, 3]
        candidates.append(mutated)

        mutated = copy.deepcopy(EXPECTED_EXPORT)
        del mutated["dynamic_loader"]
        candidates.append(mutated)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                CreativeStyleRuntimeBindingError
            ):
                normalize_creative_style_runtime_binding_export(candidate)

    def test_full_upstream_report_contract_is_validated(self):
        upstream_path = ROOT / "analysis" / "a6400-creative-style-model-request-transport.json"
        upstream = json.loads(upstream_path.read_text(encoding="utf-8"))
        mutations = (
            ("claim", lambda document: document["claims"].__setitem__("runtime_execution_proven", True)),
            ("readiness", lambda document: document.__setitem__("readiness", "WRONG")),
            ("camera_flag", lambda document: document.__setitem__("camera_executed", True)),
        )
        original_read_text = Path.read_text

        for label, mutate in mutations:
            changed = copy.deepcopy(upstream)
            mutate(changed)

            def read_text(path, *args, **kwargs):
                if Path(path) == upstream_path:
                    return json.dumps(changed)
                return original_read_text(path, *args, **kwargs)

            with self.subTest(label=label), mock.patch.object(
                Path, "read_text", autospec=True, side_effect=read_text
            ), self.assertRaises(CreativeStyleRuntimeBindingError):
                normalize_creative_style_runtime_binding_export(EXPECTED_EXPORT)

    def test_summary_and_report_remain_offline_noninstallable(self):
        summary = summarize_creative_style_runtime_binding_export(EXPECTED_EXPORT)
        report = build_creative_style_runtime_binding_report(EXPECTED_EXPORT)

        self.assertRegex(summary["canonical_export_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(summary["proven_static_claim_count"], 9)
        self.assertEqual(summary["resolved_model_identity_count"], 0)
        self.assertEqual(summary["resolved_runtime_descriptor_count"], 1)
        self.assertFalse(report["camera_executed"])
        self.assertFalse(report["camera_test_eligible"])
        self.assertFalse(report["installable"])
        self.assertEqual(
            report["readiness"],
            "CONDITIONAL_DEFAULT_ROUTE_DESCRIPTOR_NO_OPERATION38_RECORD_OR_PIPELINE",
        )
        self.assertEqual(validate_creative_style_runtime_binding_report(report), report)

    def test_every_internal_runtime_join_remains_explicitly_unproven(self):
        false_fields = (
            ("id_generator", "model_table_static_registration_found"),
            ("id_generator", "camera_row_numeric_value_resolved"),
            (
                "id_generator",
                "operation38_key7_equals_descriptor_id_11_proven",
            ),
            ("model_manager_records", "runtime_descriptor_provider_resolved"),
            ("model_manager_records", "key7_to_record_lookup_join_found"),
            ("dynamic_loader", "exact_modelcamera_descriptor_join_found"),
            ("dynamic_loader", "descriptor_population_dataflow_resolved"),
            ("modelcamera_candidate", "manifest_to_operation38_model_alias_join_found"),
            ("modelcamera_candidate", "manifest_to_runtime_descriptor_join_found"),
            ("generic_executor", "scheduled_event_id_resolved_generically"),
            ("generic_executor", "scheduler_direct_incoming_event_read_found"),
            ("generic_executor", "scheduler_direct_creative_style_field_read_found"),
            ("generic_executor", "operation38_to_candidate_branch_join_found"),
            ("generic_executor", "candidate_branch_to_modelcamera_executor_join_found"),
            ("generic_executor", "operation38_to_modelcamera_executor_join_found"),
            (
                "destination_4",
                "modelcamera_candidate_default_event_matches_validated_comparisons",
            ),
            ("destination_4", "downstream_concrete_receiver_resolved"),
            ("destination_4", "operation38_to_default_path_join_found"),
        )
        for section, field in false_fields:
            mutated = copy.deepcopy(EXPECTED_EXPORT)
            self.assertIs(mutated[section][field], False)
            mutated[section][field] = True
            with self.subTest(section=section, field=field), self.assertRaises(
                CreativeStyleRuntimeBindingError
            ):
                normalize_creative_style_runtime_binding_export(mutated)

    def test_committed_report_is_exact(self):
        document = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        validated = validate_creative_style_runtime_binding_report(document)

        self.assertEqual(validated, build_creative_style_runtime_binding_report(EXPECTED_EXPORT))
        self.assertEqual(
            validated["upstream"],
            {
                "report": "analysis/a6400-creative-style-model-request-transport.json",
                "evidence_digest": "7575751cc125bef4d26df426d6558166f501209ce6d918bee0af11639ca56e6a",
            },
        )


class CreativeStyleRuntimeBindingExporterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("runtime_binding_exporter", EXPORTER)
        cls.exporter = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(cls.exporter)
        cls.deps = cls.exporter._dependencies()
        cls.contexts = {}
        for role, path in cls.exporter.SOURCES.items():
            blob = path.read_bytes()
            stream = io.BytesIO(blob)
            elf = cls.deps["ELFFile"](stream)
            mappings = cls.exporter._mappings(elf)
            plt = cls.exporter._plt_symbols(elf, blob, mappings)
            cls.contexts[role] = {
                "blob": blob,
                "stream": stream,
                "elf": elf,
                "mappings": mappings,
                "exidx": cls.exporter._exidx_ranges(elf, blob),
                "plt": plt,
                "plt_symbols": plt,
                "dynsym": elf.get_section_by_name(".dynsym"),
            }

    @classmethod
    def tearDownClass(cls):
        for context in cls.contexts.values():
            context["stream"].close()

    def test_adapter_is_normalized(self):
        class FakeAdapter:
            def metadata(self):
                return copy.deepcopy(EXPECTED_EXPORT)

        self.assertEqual(self.exporter.build_raw_export(FakeAdapter()), EXPECTED_EXPORT)

    def test_source_identity_is_pinned_for_both_modules(self):
        self.assertEqual(
            self.exporter.SOURCES["object"],
            self.exporter.FIRMWARE_LIB / "libObj.so",
        )
        self.assertEqual(
            self.exporter.SOURCES["view"],
            self.exporter.FIRMWARE_LIB / "viewUnified2.so",
        )
        self.assertTrue(self.exporter.dependencies_available())

    def test_metadata_rejects_schema_mutation_after_static_validation(self):
        class MutatedAdapter:
            def metadata(self):
                document = copy.deepcopy(EXPECTED_EXPORT)
                document["dynamic_loader"]["dlopen_call"]["symbol"] = "wrong"
                return document

        with self.assertRaises(RuntimeError):
            self.exporter.build_raw_export(MutatedAdapter())

    def test_real_export_matches_exact_static_contract_when_available(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned sources or parser dependencies are unavailable")
        self.assertEqual(self.exporter.build_raw_export(), EXPECTED_EXPORT)

    def test_id_generator_static_mutations_fail_closed(self):
        original_target = self.exporter._direct_target
        for changed_site in (
            0x402444,
            0x402DEE,
            0x402E10,
            0x402E34,
            0x37FD04,
            0x37FD10,
        ):
            def changed_target(item, deps, *, changed_site=changed_site):
                if item.address == changed_site:
                    return 0
                return original_target(item, deps)

            with self.subTest(site=changed_site), mock.patch.object(
                self.exporter, "_direct_target", side_effect=changed_target
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_id_generator(
                        self.contexts["object"], self.contexts["view"], self.deps
                    )

        original_decode_range = self.exporter._decode_range

        def changed_delimiter_preservation(blob, mappings, deps, start, end):
            items = original_decode_range(blob, mappings, deps, start, end)
            return [
                _InstructionProxy(
                    item,
                    list(item.operands),
                    written_register=deps["r1"],
                )
                if item.address == 0x40243E
                else item
                for item in items
            ]

        with mock.patch.object(
            self.exporter,
            "_decode_range",
            side_effect=changed_delimiter_preservation,
        ):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_id_generator(
                    self.contexts["object"], self.contexts["view"], self.deps
                )

        original_instruction = self.exporter._instruction

        def changed_store(blob, mappings, deps, site):
            item = original_instruction(blob, mappings, deps, site)
            if site != 0x402C7A:
                return item
            operands = list(item.operands)
            operands[0] = _OperandProxy(operands[0], register=deps["r3"])
            return _InstructionProxy(item, operands)

        with mock.patch.object(self.exporter, "_instruction", side_effect=changed_store):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_id_generator(
                    self.contexts["object"], self.contexts["view"], self.deps
                )

        def changed_id_11_store(blob, mappings, deps, site):
            if site == 0x31890E:
                return original_instruction(blob, mappings, deps, 0x318910)
            return original_instruction(blob, mappings, deps, site)

        with mock.patch.object(
            self.exporter, "_instruction", side_effect=changed_id_11_store
        ):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_id_generator(
                    self.contexts["object"], self.contexts["view"], self.deps
                )

        original_word = self.exporter._word

        def changed_delimiter_pointer(blob, mappings, address):
            value = original_word(blob, mappings, address)
            return value + 1 if address == 0x40249C else value

        with mock.patch.object(
            self.exporter, "_word", side_effect=changed_delimiter_pointer
        ):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_id_generator(
                    self.contexts["object"], self.contexts["view"], self.deps
                )

        def changed_move_destination(blob, mappings, deps, site, *, changed_site):
            item = original_instruction(blob, mappings, deps, site)
            if site != changed_site:
                return item
            operands = list(item.operands)
            operands[0] = _OperandProxy(operands[0], register=deps["r2"])
            return _InstructionProxy(item, operands)

        for changed_site in (0x40243C, 0x37FCFE, 0x37FD0C, 0x37FD0E):
            with self.subTest(move_site=changed_site), mock.patch.object(
                self.exporter,
                "_instruction",
                side_effect=lambda blob, mappings, deps, site, changed_site=changed_site: changed_move_destination(
                    blob, mappings, deps, site, changed_site=changed_site
                ),
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_id_generator(
                        self.contexts["object"], self.contexts["view"], self.deps
                    )

    def test_record_and_loader_static_mutations_fail_closed(self):
        original_instruction = self.exporter._instruction

        original_target = self.exporter._direct_target
        for changed_site in (
            0x849890,
            0x849054,
            0x849DA6,
            0x849DEE,
            0x849E00,
            0x841132,
            0x841140,
        ):
            def changed_target(item, deps, *, changed_site=changed_site):
                if item.address == changed_site:
                    return 0
                return original_target(item, deps)

            with self.subTest(site=changed_site), mock.patch.object(
                self.exporter, "_direct_target", side_effect=changed_target
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_records_and_loader(
                        self.contexts["object"], self.deps
                    )

        def changed_map_offset(blob, mappings, deps, site):
            item = original_instruction(blob, mappings, deps, site)
            if site != 0x84988A:
                return item
            operands = list(item.operands)
            operands[2] = _OperandProxy(operands[2], immediate=0x8C)
            return _InstructionProxy(item, operands)

        with mock.patch.object(self.exporter, "_instruction", side_effect=changed_map_offset):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_records_and_loader(self.contexts["object"], self.deps)

        def changed_mode(blob, mappings, deps, site):
            item = original_instruction(blob, mappings, deps, site)
            if site != 0x84112C:
                return item
            operands = list(item.operands)
            operands[1] = _OperandProxy(operands[1], immediate=0x102)
            return _InstructionProxy(item, operands)

        with mock.patch.object(self.exporter, "_instruction", side_effect=changed_mode):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_records_and_loader(self.contexts["object"], self.deps)

        def changed_component_base(blob, mappings, deps, site):
            item = original_instruction(blob, mappings, deps, site)
            if site != 0x841130:
                return item
            operands = list(item.operands)
            operands[1] = _OperandProxy(
                operands[1], memory=_MemoryProxy(operands[1].mem, base=deps["r4"])
            )
            return _InstructionProxy(item, operands)

        with mock.patch.object(
            self.exporter, "_instruction", side_effect=changed_component_base
        ):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_records_and_loader(self.contexts["object"], self.deps)

        def changed_factory_register(blob, mappings, deps, site):
            item = original_instruction(blob, mappings, deps, site)
            if site != 0x84114C:
                return item
            operands = list(item.operands)
            operands[0] = _OperandProxy(operands[0], register=deps["r4"])
            return _InstructionProxy(item, operands)

        with mock.patch.object(
            self.exporter, "_instruction", side_effect=changed_factory_register
        ):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_records_and_loader(self.contexts["object"], self.deps)

        def changed_factory_result(blob, mappings, deps, site):
            item = original_instruction(blob, mappings, deps, site)
            if site != 0x84114E:
                return item
            operands = list(item.operands)
            operands[1] = _OperandProxy(
                operands[1], memory=_MemoryProxy(operands[1].mem, displacement=0x18)
            )
            return _InstructionProxy(item, operands)

        with mock.patch.object(
            self.exporter, "_instruction", side_effect=changed_factory_result
        ):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_records_and_loader(self.contexts["object"], self.deps)

    def test_modelcamera_static_mutations_fail_closed(self):
        original_at = self.exporter._at
        for changed_address in (0xF03447, 0xF0344D, 0xF0345C, 0xF68740):
            def changed_string(blob, mappings, address, length, *, changed_address=changed_address):
                value = original_at(blob, mappings, address, length)
                if address == changed_address:
                    return b"X" + value[1:]
                return value

            with self.subTest(address=changed_address), mock.patch.object(
                self.exporter, "_at", side_effect=changed_string
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_modelcamera(
                        self.contexts["object"], self.deps
                    )

        original_target = self.exporter._direct_target
        for changed_site in (0x4D32EA, 0x4D32F0, 0x4D3104, 0x3FE5E0):
            def changed_target(item, deps, *, changed_site=changed_site):
                if item.address == changed_site:
                    return 0
                return original_target(item, deps)

            with self.subTest(site=changed_site), mock.patch.object(
                self.exporter, "_direct_target", side_effect=changed_target
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_modelcamera(
                        self.contexts["object"], self.deps
                    )

        original_instruction = self.exporter._instruction

        def changed_allocation_size(blob, mappings, deps, site):
            item = original_instruction(blob, mappings, deps, site)
            if site != 0x4D32E2:
                return item
            operands = list(item.operands)
            operands[1] = _OperandProxy(operands[1], immediate=0x6438)
            return _InstructionProxy(item, operands)

        with mock.patch.object(
            self.exporter, "_instruction", side_effect=changed_allocation_size
        ):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_modelcamera(self.contexts["object"], self.deps)

        for changed_site, operand_index in (
            (0x4D3102, 0),
            (0x3FE58E, 0),
            (0x3FE5DE, 1),
        ):
            def changed_this_flow(
                blob, mappings, deps, site, *, changed_site=changed_site,
                operand_index=operand_index,
            ):
                item = original_instruction(blob, mappings, deps, site)
                if site != changed_site:
                    return item
                operands = list(item.operands)
                operands[operand_index] = _OperandProxy(
                    operands[operand_index], register=deps["r4"]
                )
                return _InstructionProxy(item, operands)

            with self.subTest(this_flow=changed_site), mock.patch.object(
                self.exporter, "_instruction", side_effect=changed_this_flow
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_modelcamera(
                        self.contexts["object"], self.deps
                    )

        original_word = self.exporter._word

        for changed_address in (0x1341ADC, 0x1341AEC, 0x1341B08):
            def changed_relocation(blob, mappings, address, *, changed_address=changed_address):
                if address == changed_address:
                    return 0
                return original_word(blob, mappings, address)

            with self.subTest(address=changed_address), mock.patch.object(
                self.exporter, "_word", side_effect=changed_relocation
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_modelcamera(
                        self.contexts["object"], self.deps
                    )

    def test_default_route_descriptor_provider_static_mutations_fail_closed(self):
        original_target = self.exporter._direct_target
        for changed_site in (0x84835A, 0x848368, 0x849DCC, 0x849DD6):
            def changed_target(item, deps, *, changed_site=changed_site):
                if item.address == changed_site:
                    return 0
                return original_target(item, deps)

            with self.subTest(site=changed_site), mock.patch.object(
                self.exporter, "_direct_target", side_effect=changed_target
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_default_route_descriptor_provider(
                        self.contexts["object"], self.deps
                    )

        original_instruction = self.exporter._instruction

        def changed_model_config_store(blob, mappings, deps, site):
            item = original_instruction(blob, mappings, deps, site)
            if site != 0x3FD7D0:
                return item
            operands = list(item.operands)
            operands[1] = _OperandProxy(
                operands[1], memory=_MemoryProxy(operands[1].mem, displacement=0x0C)
            )
            return _InstructionProxy(item, operands)

        with mock.patch.object(
            self.exporter, "_instruction", side_effect=changed_model_config_store
        ):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_default_route_descriptor_provider(
                    self.contexts["object"], self.deps
                )

        original_word = self.exporter._word

        def changed_slot_relocation(blob, mappings, address):
            if address == 0x13394D8:
                return 0
            return original_word(blob, mappings, address)

        with mock.patch.object(self.exporter, "_word", side_effect=changed_slot_relocation):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_default_route_descriptor_provider(
                    self.contexts["object"], self.deps
                )

        def changed_dataflow_memory(blob, mappings, deps, site):
            item = original_instruction(blob, mappings, deps, site)
            changed_offsets = {0x3FD456: 0x0C, 0x8498A4: 0x18, 0x8498AA: 0x0C, 0x8410C6: 0x18}
            if site not in changed_offsets:
                return item
            operands = list(item.operands)
            operands[1] = _OperandProxy(
                operands[1],
                memory=_MemoryProxy(operands[1].mem, displacement=changed_offsets[site]),
            )
            return _InstructionProxy(item, operands)

        for changed_site in (0x3FD456, 0x8498A4, 0x8498AA, 0x8410C6):
            with self.subTest(dataflow_memory=changed_site), mock.patch.object(
                self.exporter, "_instruction", side_effect=changed_dataflow_memory
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_default_route_descriptor_provider(
                        self.contexts["object"], self.deps
                    )

        def changed_dataflow_move(blob, mappings, deps, site):
            item = original_instruction(blob, mappings, deps, site)
            changed_registers = {0x340834: deps["r2"], 0x849DD2: deps["r7"], 0x849DF6: deps["r9"]}
            if site not in changed_registers:
                return item
            operands = list(item.operands)
            operands[0] = _OperandProxy(operands[0], register=changed_registers[site])
            return _InstructionProxy(item, operands)

        for changed_site in (0x340834, 0x849DD2, 0x849DF6):
            with self.subTest(dataflow_move=changed_site), mock.patch.object(
                self.exporter, "_instruction", side_effect=changed_dataflow_move
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_default_route_descriptor_provider(
                        self.contexts["object"], self.deps
                    )

        original_word = self.exporter._word

        def changed_pic_literal(blob, mappings, address):
            if address in (0x340A78, 0x340A7C, 0x340A80):
                return 0
            return original_word(blob, mappings, address)

        with mock.patch.object(self.exporter, "_word", side_effect=changed_pic_literal):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_default_route_descriptor_provider(
                    self.contexts["object"], self.deps
                )

    def test_default_route_provenance_byte_mutations_fail_closed(self):
        original_instruction = self.exporter._instruction

        def changed_handoff(blob, mappings, deps, site, *, changed_site):
            item = original_instruction(blob, mappings, deps, site)
            if site != changed_site:
                return item
            operands = list(item.operands)
            if site in (0x3FD7B0, 0x3FD7D0, 0x843CF4):
                operands[0] = _OperandProxy(operands[0], register=deps["r1"])
            elif site == 0x3FD7A8:
                operands[1] = _OperandProxy(
                    operands[1], memory=_MemoryProxy(operands[1].mem, index=deps["r2"])
                )
            elif site == 0x3FD7AE:
                operands[1] = _OperandProxy(operands[1], immediate=0x0C)
            elif site == 0x3FD7B8:
                operands[0] = _OperandProxy(operands[0], register=deps["r1"])
            elif site == 0x843D82:
                operands[0] = _OperandProxy(operands[0], register=deps["r1"])
            elif site == 0x84987E:
                operands[1] = _OperandProxy(operands[1], register=deps["r3"])
            elif site == 0x84989A:
                operands[1] = _OperandProxy(operands[1], register=deps["r2"])
            return _InstructionProxy(item, operands)

        for changed_site in (
            0x3FD7A8, 0x3FD7AE, 0x3FD7B0, 0x3FD7B8, 0x3FD7D0,
            0x843CF4, 0x843D82, 0x84987E, 0x84989A,
        ):
            with self.subTest(site=changed_site), mock.patch.object(
                self.exporter,
                "_instruction",
                side_effect=lambda blob, mappings, deps, site, changed_site=changed_site: changed_handoff(
                    blob, mappings, deps, site, changed_site=changed_site
                ),
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_default_route_descriptor_provider(
                        self.contexts["object"], self.deps
                    )

        original_target = self.exporter._direct_target
        for changed_site in (0x3FD7CC, 0x843CEC, 0x843D86):
            def changed_target(item, deps, *, changed_site=changed_site):
                if item.address == changed_site:
                    return 0
                return original_target(item, deps)

            with self.subTest(edge=changed_site), mock.patch.object(
                self.exporter, "_direct_target", side_effect=changed_target
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_default_route_descriptor_provider(
                        self.contexts["object"], self.deps
                    )

        original_word = self.exporter._word

        def changed_provenance_word(blob, mappings, address):
            if address in (0x136DFB0, 0x3FD868, 0x3FD86C, 0x3FD874):
                return 0
            return original_word(blob, mappings, address)

        with mock.patch.object(
            self.exporter, "_word", side_effect=changed_provenance_word
        ):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_default_route_descriptor_provider(
                    self.contexts["object"], self.deps
                )

    def test_model_config_callable_and_vtable_join_mutations_fail_closed(self):
        original_instruction = self.exporter._instruction

        def changed_model_config_join(blob, mappings, deps, site, *, changed_site):
            item = original_instruction(blob, mappings, deps, site)
            if site != changed_site:
                return item
            operands = list(item.operands)
            if site == 0x3FD6F2:
                operands[1] = _OperandProxy(operands[1], register=deps["r5"])
            elif site in (0x3FD712, 0x38E642, 0x38E61C, 0x38E5FA):
                operands[0] = _OperandProxy(operands[0], register=deps["r1"])
            elif site == 0x3FD6FA:
                operands[0] = _OperandProxy(operands[0], register=deps["r1"])
            return _InstructionProxy(item, operands)

        for changed_site in (0x3FD6F2, 0x3FD6FA, 0x3FD712, 0x38E5FA, 0x38E61C, 0x38E642):
            with self.subTest(site=changed_site), mock.patch.object(
                self.exporter,
                "_instruction",
                side_effect=lambda blob, mappings, deps, site, changed_site=changed_site: changed_model_config_join(
                    blob, mappings, deps, site, changed_site=changed_site
                ),
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_default_route_descriptor_provider(
                        self.contexts["object"], self.deps
                    )

        original_word = self.exporter._word

        def changed_model_config_vtable(blob, mappings, address):
            if address == 0x137241C:
                return 0
            return original_word(blob, mappings, address)

        with mock.patch.object(
            self.exporter, "_word", side_effect=changed_model_config_vtable
        ):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_default_route_descriptor_provider(
                    self.contexts["object"], self.deps
                )

    def test_config_receiver_preservation_mutations_fail_closed(self):
        original_decode_range = self.exporter._decode_range

        def changed_preserved_register(blob, mappings, deps, start, end, *, changed_site):
            items = original_decode_range(blob, mappings, deps, start, end)
            changed_register = deps["r2"] if changed_site == 0x843D84 else deps["r5"]
            return [
                _InstructionProxy(
                    item,
                    list(item.operands),
                    written_register=changed_register,
                )
                if item.address == changed_site
                else item
                for item in items
            ]

        for changed_site in (0x843D84, 0x849884):
            with self.subTest(site=changed_site), mock.patch.object(
                self.exporter,
                "_decode_range",
                side_effect=lambda blob, mappings, deps, start, end, changed_site=changed_site: changed_preserved_register(
                    blob, mappings, deps, start, end, changed_site=changed_site
                ),
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_default_route_descriptor_provider(
                        self.contexts["object"], self.deps
                    )

    def test_dlsym_result_preservation_mutations_fail_closed(self):
        original_decode_range = self.exporter._decode_range

        def changed_dlsym_result(blob, mappings, deps, start, end, *, changed_site):
            items = original_decode_range(blob, mappings, deps, start, end)
            return [
                _InstructionProxy(
                    item,
                    list(item.operands),
                    written_register=deps["r0"],
                )
                if item.address == changed_site
                else item
                for item in items
            ]

        for changed_site in (0x3FD6D2, 0x3FD6F8):
            with self.subTest(site=changed_site), mock.patch.object(
                self.exporter,
                "_decode_range",
                side_effect=lambda blob, mappings, deps, start, end, changed_site=changed_site: changed_dlsym_result(
                    blob, mappings, deps, start, end, changed_site=changed_site
                ),
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_default_route_descriptor_provider(
                        self.contexts["object"], self.deps
                    )

    def test_resolver_and_getter_return_control_mutations_fail_closed(self):
        original_instruction = self.exporter._instruction

        def changed_return_control(blob, mappings, deps, site, *, changed_site):
            item = original_instruction(blob, mappings, deps, site)
            if site != changed_site:
                return item
            operands = [
                _OperandProxy(operand, register=deps["r1"])
                if operand.type == deps["reg"] and operand.reg == deps["pc"]
                else operand
                for operand in item.operands
            ]
            return _InstructionProxy(item, operands)

        for changed_site in (0x3FD714, 0x38E646):
            with self.subTest(site=changed_site), mock.patch.object(
                self.exporter,
                "_instruction",
                side_effect=lambda blob, mappings, deps, site, changed_site=changed_site: changed_return_control(
                    blob, mappings, deps, site, changed_site=changed_site
                ),
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_default_route_descriptor_provider(
                        self.contexts["object"], self.deps
                    )

    def test_model_config_instance_preservation_mutation_fails_closed(self):
        original_decode_range = self.exporter._decode_range

        def changed_constructor_instance(blob, mappings, deps, start, end):
            items = original_decode_range(blob, mappings, deps, start, end)
            return [
                _InstructionProxy(
                    item,
                    list(item.operands),
                    written_register=deps["r5"],
                )
                if item.address == 0x38E5F2
                else item
                for item in items
            ]

        with mock.patch.object(
            self.exporter,
            "_decode_range",
            side_effect=changed_constructor_instance,
        ):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_default_route_descriptor_provider(
                    self.contexts["object"], self.deps
                )

    def test_resolver_handle_provenance_mutations_fail_closed(self):
        original_instruction = self.exporter._instruction

        def changed_handle_access(blob, mappings, deps, site, *, changed_site, mutation):
            item = original_instruction(blob, mappings, deps, site)
            if site != changed_site:
                return item
            operands = list(item.operands)
            if mutation == "capture_source":
                operands[1] = _OperandProxy(operands[1], register=deps["r1"])
            elif mutation == "store_source":
                operands[0] = _OperandProxy(operands[0], register=deps["r1"])
            elif mutation == "reload_destination":
                operands[0] = _OperandProxy(operands[0], register=deps["r1"])
            else:
                operands[1] = _OperandProxy(
                    operands[1],
                    memory=_MemoryProxy(operands[1].mem, base=deps["r7"]),
                )
            return _InstructionProxy(item, operands)

        for changed_site, mutation in (
            (0x3FD6B4, "capture_source"),
            (0x3FD6B6, "store_source"),
            (0x3FD6B6, "store_base"),
            (0x3FD6EE, "reload_destination"),
            (0x3FD6EE, "reload_base"),
        ):
            with self.subTest(site=changed_site, mutation=mutation), mock.patch.object(
                self.exporter,
                "_instruction",
                side_effect=lambda blob, mappings, deps, site, changed_site=changed_site, mutation=mutation: changed_handle_access(
                    blob,
                    mappings,
                    deps,
                    site,
                    changed_site=changed_site,
                    mutation=mutation,
                ),
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_default_route_descriptor_provider(
                        self.contexts["object"], self.deps
                    )

        original_decode_range = self.exporter._decode_range

        def changed_handle_register(blob, mappings, deps, start, end, *, changed_site, register):
            items = original_decode_range(blob, mappings, deps, start, end)
            return [
                _InstructionProxy(
                    item,
                    list(item.operands),
                    written_register=deps[register],
                )
                if item.address == changed_site
                else item
                for item in items
            ]

        for changed_site, register in (
            (0x3FD7C8, "r3"),
            (0x3FD6A8, "r3"),
            (0x3FD6AE, "r8"),
            (0x3FD6B4, "r0"),
            (0x3FD6D2, "r8"),
            (0x3FD6EC, "r8"),
        ):
            with self.subTest(site=changed_site, register=register), mock.patch.object(
                self.exporter,
                "_decode_range",
                side_effect=lambda blob, mappings, deps, start, end, changed_site=changed_site, register=register: changed_handle_register(
                    blob,
                    mappings,
                    deps,
                    start,
                    end,
                    changed_site=changed_site,
                    register=register,
                ),
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_default_route_descriptor_provider(
                        self.contexts["object"], self.deps
                    )

    def test_resolver_argument_preservation_mutations_fail_closed(self):
        original_decode_range = self.exporter._decode_range

        def changed_argument(blob, mappings, deps, start, end, *, changed_site, register):
            items = original_decode_range(blob, mappings, deps, start, end)
            return [
                _InstructionProxy(
                    item,
                    list(item.operands),
                    written_register=deps[register],
                )
                if item.address == changed_site
                else item
                for item in items
            ]

        for changed_site, register in (
            (0x3FD7C8, "r0"),
            (0x3FD7C8, "r1"),
            (0x3FD6A4, "r0"),
            (0x3FD6A0, "r1"),
            (0x3FD6A6, "r2"),
            (0x3FD6AC, "r1"),
        ):
            with self.subTest(site=changed_site, register=register), mock.patch.object(
                self.exporter,
                "_decode_range",
                side_effect=lambda blob, mappings, deps, start, end, changed_site=changed_site, register=register: changed_argument(
                    blob,
                    mappings,
                    deps,
                    start,
                    end,
                    changed_site=changed_site,
                    register=register,
                ),
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_default_route_descriptor_provider(
                        self.contexts["object"], self.deps
                    )

    def test_resolver_pic_argument_preservation_mutations_fail_closed(self):
        original_decode_range = self.exporter._decode_range

        def changed_pic_argument(blob, mappings, deps, start, end, *, changed_site, register):
            items = original_decode_range(blob, mappings, deps, start, end)
            return [
                _InstructionProxy(
                    item,
                    list(item.operands),
                    written_register=deps[register],
                )
                if item.address == changed_site
                else item
                for item in items
            ]

        for changed_site, register in (
            (0x3FD7BA, "r0"),
            (0x3FD7BE, "r1"),
            (0x3FD7C2, "r3"),
        ):
            with self.subTest(site=changed_site, register=register), mock.patch.object(
                self.exporter,
                "_decode_range",
                side_effect=lambda blob, mappings, deps, start, end, changed_site=changed_site, register=register: changed_pic_argument(
                    blob,
                    mappings,
                    deps,
                    start,
                    end,
                    changed_site=changed_site,
                    register=register,
                ),
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_default_route_descriptor_provider(
                        self.contexts["object"], self.deps
                    )

    def test_executor_and_destination_static_mutations_fail_closed(self):
        original_target = self.exporter._direct_target

        for changed_site in (
            0x84A960,
            0x84A968,
            0x84A97E,
            0x84A9BE,
            0x84A9C4,
            0x84A9CC,
            0x84A9D4,
            0x84A9DC,
            0x3FE634,
            0x3FE648,
            0x848278,
            0x843B24,
            0x8468D2,
        ):
            def changed_target(item, deps, *, changed_site=changed_site):
                if item.address == changed_site:
                    return 0
                return original_target(item, deps)

            with self.subTest(site=changed_site), mock.patch.object(
                self.exporter, "_direct_target", side_effect=changed_target
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_executor_and_destination(
                        self.contexts["object"], self.deps
                    )

        original_instruction = self.exporter._instruction

        def changed_mask(blob, mappings, deps, site):
            item = original_instruction(blob, mappings, deps, site)
            if site != 0x843B0E:
                return item
            operands = list(item.operands)
            operands[2] = _OperandProxy(operands[2], immediate=2)
            return _InstructionProxy(item, operands)

        with mock.patch.object(self.exporter, "_instruction", side_effect=changed_mask):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_executor_and_destination(
                    self.contexts["object"], self.deps
                )

        def changed_secondary_header(blob, mappings, deps, site):
            item = original_instruction(blob, mappings, deps, site)
            if site != 0x84A9B6:
                return item
            operands = list(item.operands)
            operands[1] = _OperandProxy(operands[1], immediate=1)
            return _InstructionProxy(item, operands)

        with mock.patch.object(
            self.exporter, "_instruction", side_effect=changed_secondary_header
        ):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_executor_and_destination(
                    self.contexts["object"], self.deps
                )

        def changed_virtual_slot(blob, mappings, deps, site):
            item = original_instruction(blob, mappings, deps, site)
            if site != 0x843028:
                return item
            operands = list(item.operands)
            operands[1] = _OperandProxy(
                operands[1], memory=_MemoryProxy(operands[1].mem, displacement=0x1C)
            )
            return _InstructionProxy(item, operands)

        with mock.patch.object(
            self.exporter, "_instruction", side_effect=changed_virtual_slot
        ):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_executor_and_destination(
                    self.contexts["object"], self.deps
                )

        original_word = self.exporter._word
        literal_addresses = []
        for record in EXPECTED_EXPORT["destination_4"]["validated_event_id_comparisons"]:
            load = original_instruction(
                self.contexts["object"]["blob"],
                self.contexts["object"]["mappings"],
                self.deps,
                record["literal_site"],
            )
            literal_addresses.append(
                self.exporter._transport._thumb_literal_address(
                    load, self.deps, self.deps["r3"], "test Event-ID literal"
                )
            )
        for changed_address in literal_addresses:
            def changed_literal(blob, mappings, address, *, changed_address=changed_address):
                if address == changed_address:
                    return 0
                return original_word(blob, mappings, address)

            with self.subTest(literal=changed_address), mock.patch.object(
                self.exporter, "_word", side_effect=changed_literal
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_executor_and_destination(
                        self.contexts["object"], self.deps
                    )

    def test_report_rejects_safety_or_pipeline_promotion(self):
        report = build_creative_style_runtime_binding_report(EXPECTED_EXPORT)
        candidates = []
        for field in ("camera_executed", "camera_test_eligible", "installable"):
            mutated = copy.deepcopy(report)
            mutated[field] = True
            candidates.append(mutated)
        for field in (
            "record_is_modelcamera_proven",
            "five_field_consumption_proven",
            "native_creative_look_pipeline_proven",
            "runtime_execution_proven",
        ):
            mutated = copy.deepcopy(report)
            mutated["claims"][field] = True
            candidates.append(mutated)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                CreativeStyleRuntimeBindingError
            ):
                validate_creative_style_runtime_binding_report(candidate)


if __name__ == "__main__":
    unittest.main()
