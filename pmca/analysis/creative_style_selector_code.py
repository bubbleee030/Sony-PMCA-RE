"""Fail-closed typed Creative Style selector-to-persisted-code evidence."""
from __future__ import annotations

import copy
import hashlib
import json
import re


SOURCE = {
    "module": "lib/viewUnified2.so",
    "size": 11_530_552,
    "sha256": "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2",
}

TYPED_ELEMENT = {
    "type_name": "CmnViewProcessDataElementCustomCreativeStyle",
    "type_name_encoding": "44CmnViewProcessDataElementCustomCreativeStyle",
    "rtti": 0x90EDF0,
    "vtable_header": 0x90ED80,
    "vtable_address_point": 0x90ED88,
    "setter_slot": 21,
    "setter_cell": 0x90EDDC,
    "setter_relocation_index": 40031,
    "setter": 0x4893AC,
    "setter_owner": {"start": 0x4893AC, "end": 0x489644, "complete": True},
    "getter_slot": 10,
    "getter_cell": 0x90EDB0,
    "getter_relocation_index": 40025,
    "getter": 0x48B8AC,
    "getter_signature": "getValue(int&,int&,int&,int&,int&,int,int)",
    "getter_base_cell": 0x906F60,
    "getter_base_symbol": "_ZN31CmnViewProcessDataElementNormal8getValueERiS0_S0_S0_S0_ii",
    "getter_owner": {"start": 0x48B8AC, "end": 0x48BC88, "complete": True},
    "base_vtable_address_point": 0x906F38,
    "setter_signature": "setValue(int,int,int,int,int)",
    "setter_base_cell": 0x906F8C,
    "setter_base_symbol": "_ZN31CmnViewProcessDataElementNormal8setValueEiiiii",
}

SELECTOR_CASES = [
    {"selector": 0, "landing": 0x489428, "allocation_site": 0x48942A, "capture_site": 0x48942E, "code_site": 0x489430, "persisted_code": 1, "join_branch_site": 0x489432, "constructor_call_site": 0x4894AA},
    {"selector": 1, "landing": 0x489434, "allocation_site": 0x489436, "capture_site": 0x48943A, "code_site": 0x48943C, "persisted_code": 2, "join_branch_site": 0x48943E, "constructor_call_site": 0x4894AA},
    {"selector": 2, "landing": 0x489440, "allocation_site": 0x489442, "capture_site": 0x489446, "code_site": 0x489448, "persisted_code": 3, "join_branch_site": 0x48944A, "constructor_call_site": 0x4894AA},
    {"selector": 3, "landing": 0x48944C, "allocation_site": 0x48944E, "capture_site": 0x489452, "code_site": 0x489454, "persisted_code": 7, "join_branch_site": 0x489456, "constructor_call_site": 0x4894AA},
    {"selector": 4, "landing": 0x489458, "allocation_site": 0x48945A, "capture_site": 0x48945E, "code_site": 0x489460, "persisted_code": 8, "join_branch_site": 0x489462, "constructor_call_site": 0x4894AA},
    {"selector": 5, "landing": 0x489464, "allocation_site": 0x489466, "capture_site": 0x48946A, "code_site": 0x48946C, "persisted_code": 9, "join_branch_site": 0x48946E, "constructor_call_site": 0x4894AA},
    {"selector": 6, "landing": 0x489470, "allocation_site": 0x489472, "capture_site": 0x489476, "code_site": 0x489478, "persisted_code": 4, "join_branch_site": 0x48947A, "constructor_call_site": 0x4894AA},
    {"selector": 7, "landing": 0x48947C, "allocation_site": 0x48947E, "capture_site": 0x489482, "code_site": 0x489484, "persisted_code": 5, "join_branch_site": 0x489486, "constructor_call_site": 0x4894AA},
    {"selector": 8, "landing": 0x489488, "allocation_site": 0x48948A, "capture_site": 0x48948E, "code_site": 0x489490, "persisted_code": 10, "join_branch_site": 0x489492, "constructor_call_site": 0x4894AA},
    {"selector": 9, "landing": 0x489494, "allocation_site": 0x489496, "capture_site": 0x48949A, "code_site": 0x48949C, "persisted_code": 11, "join_branch_site": 0x48949E, "constructor_call_site": 0x4894AA},
    {"selector": 10, "landing": 0x4894A0, "allocation_site": 0x4894A2, "capture_site": 0x4894A6, "code_site": 0x4894A8, "persisted_code": 12, "join_branch_site": None, "constructor_call_site": 0x4894AA},
    {"selector": 11, "landing": 0x4894CA, "allocation_site": 0x4894CC, "capture_site": 0x4894D0, "code_site": 0x4894D2, "persisted_code": 6, "join_branch_site": 0x4894D4, "constructor_call_site": 0x4894E0},
    {"selector": 12, "landing": 0x489602, "rejected": True},
    {"selector": 13, "landing": 0x4894D6, "allocation_site": 0x4894D8, "capture_site": 0x4894DC, "code_site": 0x4894DE, "persisted_code": 14, "join_branch_site": None, "constructor_call_site": 0x4894E0},
]

SETTER_SELECTOR = {
    "argument_position": 1,
    "capture_site": 0x4893B6,
    "input_min": 0,
    "input_max": 13,
    "guard_compare_site": 0x489400,
    "guard_branch_site": 0x489404,
    "out_of_range_target": 0x489602,
    "table_branch_site": 0x489408,
    "table_start": 0x48940C,
    "entry_count": 14,
    "rejected_indices": [12],
    "selector_to_persisted_code": {
        "0": 1, "1": 2, "2": 3, "3": 7, "4": 8, "5": 9,
        "6": 4, "7": 5, "8": 10, "9": 11, "10": 12,
        "11": 6, "13": 14,
    },
    "cases": SELECTOR_CASES,
    "classification": "typed-element-bounded-selector-to-persisted-code-map",
}

SELECTOR_RECORD = {
    "holder_constructor": 0x1581CC,
    "holder_constructor_owner": {"start": 0x1581CC, "end": 0x1581F4, "complete": True},
    "holder_input_capture_site": 0x1581CE,
    "param_base_constructor_call_site": 0x1581D8,
    "param_base_constructor_symbol": "_ZN9ParamBaseC2Em",
    "holder_value_store_site": 0x1581E4,
    "holder_value_offset": 0x10,
    "holder_accessor": 0x15820C,
    "holder_accessor_owner": {"start": 0x15820C, "end": 0x158224, "complete": True},
    "holder_value_load_site": 0x158210,
    "setter_holder_receiver_site": 0x489516,
    "setter_holder_accessor_call_site": 0x489530,
    "holder_preservation_paths": [
        {
            "constructor_call_site": 0x4894AA,
            "segments": [[0x4894AE, 0x4894C8], [0x4894FC, 0x4895EC]],
            "join_branch_site": 0x4894C8,
            "join_target": 0x4894FC,
        },
        {
            "constructor_call_site": 0x4894E0,
            "segments": [[0x4894E4, 0x4895EC]],
            "join_branch_site": None,
            "join_target": None,
        },
    ],
    "setter_argument_position": 1,
    "code_byte_store_site": 0x48953A,
    "code_byte_local_offset": 0x11E,
    "argument_2_nonzero_compare_site": 0x489544,
    "argument_2_zero_skip_branch_site": 0x489548,
    "argument_2_zero_skip_target": 0x489562,
    "code_byte_pointer_site": 0x48954E,
    "storage_width_bytes": 1,
    "dynamic_record_id_table_base_site": 0x48954A,
    "dynamic_record_id_index_site": 0x489552,
    "dynamic_record_id_load_site": 0x489556,
    "backup_write_call_site": 0x48955A,
    "backup_write_symbol": "_ZN21CmnViewModelIfWrapper11backupWriteEiPKv",
    "persistence_condition": "argument-2-nonzero-path",
    "record_id_semantics_resolved": False,
}

ARGUMENT_2_RECORD = {
    "setter_argument_position": 2,
    "argument_capture_site": 0x4893BA,
    "default_minus_one_site": 0x489510,
    "encode_compare_site": 0x48951E,
    "default_byte_store_site": 0x489522,
    "positive_it_site": 0x489526,
    "positive_decrement_site": 0x489528,
    "positive_byte_store_site": 0x48952C,
    "byte_local_offset": 0x11F,
    "byte_pointer_sites": [0x489534, 0x489538],
    "storage_width_bytes": 1,
    "backup_id_load_site": 0x48953E,
    "backup_id_literal_site": 0x48962C,
    "backup_id": 0x01070762,
    "backup_write_call_site": 0x489540,
    "backup_write_symbol": "_ZN21CmnViewModelIfWrapper11backupWriteEiPKv",
    "encode": "nonpositive-to-0xff-positive-n-to-low-byte-of-n-minus-one",
    "getter_decode": "preinitialized-zero-signed-minus-one-skips-write-otherwise-signed-byte-plus-one",
}

REQUEST_BOUNDARY = {
    "param_add_symbol": "_ZN9ParamList3addEmP9ParamBase",
    "param_add_call_sites": [0x4895B4, 0x4895C2, 0x4895D0, 0x4895E2, 0x4895EE],
    "param_receiver_sites": [0x4895AC, 0x4895BA, 0x4895C8, 0x4895DA, 0x4895E6],
    "param_key_sites": [0x4895AE, 0x4895BC, 0x4895CA, 0x4895DC, 0x4895E8],
    "param_keys": [383, 386, 389, 392, 383],
    "param_holder_registers": ["r4", "r5", "r6", "r8", "r4"],
    "param_value_roles": [
        "selector-code", "argument-3", "argument-4-or-branch-default",
        "argument-5", "selector-code",
    ],
    "argument_3_capture_site": 0x4893BC,
    "argument_3_local_offset": 4,
    "argument_3_value_load_sites": [0x4894B4, 0x4894EA],
    "argument_3_constructor_call_sites": [0x4894B8, 0x4894EE],
    "argument_4_stack_offset": 0x140,
    "argument_4_value_sources": {
        "normal_stack_load_site": 0x4894C4,
        "special_default_zero_site": 0x4894FA,
    },
    "argument_4_normal_join_branch_site": 0x4894C8,
    "argument_4_constructor_call_site": 0x4894FC,
    "argument_5_stack_offset": 0x144,
    "argument_5_value_load_site": 0x489506,
    "argument_5_constructor_call_site": 0x48950C,
    "holder_constructions": [
        {
            "role": "argument-3-normal",
            "allocation_size_site": 0x4894AE,
            "allocation_call_site": 0x4894B0,
            "value_source_site": 0x4894B4,
            "holder_capture_site": 0x4894B6,
            "holder_register": "r5",
            "constructor_call_site": 0x4894B8,
            "receiver_preservation_segments": [[0x4894B4, 0x4894B8]],
            "value_preservation_segments": [[0x4894B6, 0x4894B8]],
            "preservation_segments": [[0x4894BC, 0x4894C8], [0x4894FC, 0x4895C0]],
        },
        {
            "role": "argument-3-special",
            "allocation_size_site": 0x4894E4,
            "allocation_call_site": 0x4894E6,
            "value_source_site": 0x4894EA,
            "holder_capture_site": 0x4894EC,
            "holder_register": "r5",
            "constructor_call_site": 0x4894EE,
            "receiver_preservation_segments": [[0x4894EA, 0x4894EE]],
            "value_preservation_segments": [[0x4894EC, 0x4894EE]],
            "preservation_segments": [[0x4894F2, 0x4895C0]],
        },
        {
            "role": "argument-4-normal",
            "allocation_size_site": 0x4894BC,
            "allocation_call_site": 0x4894BE,
            "value_source_site": 0x4894C4,
            "holder_capture_site": 0x4894C2,
            "holder_register": "r6",
            "constructor_call_site": 0x4894FC,
            "receiver_preservation_segments": [[0x4894C2, 0x4894CA]],
            "value_preservation_segments": [[0x4894C8, 0x4894CA]],
            "preservation_segments": [[0x4894C4, 0x4894C8], [0x4894FC, 0x4895CE]],
        },
        {
            "role": "argument-4-special-default",
            "allocation_size_site": 0x4894F2,
            "allocation_call_site": 0x4894F4,
            "value_source_site": 0x4894FA,
            "holder_capture_site": 0x4894F8,
            "holder_register": "r6",
            "constructor_call_site": 0x4894FC,
            "receiver_preservation_segments": [[0x4894F8, 0x4894FC]],
            "value_preservation_segments": [],
            "preservation_segments": [[0x4894FA, 0x4895CE]],
        },
        {
            "role": "argument-5",
            "allocation_size_site": 0x489500,
            "allocation_call_site": 0x489502,
            "value_source_site": 0x489506,
            "holder_capture_site": 0x48950A,
            "holder_register": "r8",
            "constructor_call_site": 0x48950C,
            "receiver_preservation_segments": [[0x489506, 0x48950C]],
            "value_preservation_segments": [[0x48950A, 0x48950C]],
            "preservation_segments": [[0x48950C, 0x4895E0]],
        },
    ],
    "param_list": {
        "allocation_size_site": 0x48959C,
        "allocation_call_site": 0x48959E,
        "constructor_argument_site": 0x4895A2,
        "capture_site": 0x4895A4,
        "capture_register": "sb",
        "constructor_call_site": 0x4895A6,
        "constructor_symbol": "_ZN9ParamListC1Ej",
    },
    "request_model_literal_load_site": 0x4895F2,
    "request_model_literal_site": 0x489640,
    "request_code_site": 0x4895F4,
    "request_param_list_site": 0x4895F6,
    "request_model_add_site": 0x4895F8,
    "request_call_site": 0x4895FA,
    "request_symbol": "_ZN21CmnViewModelIfWrapper19requestModelExecuteEPKcmP9ParamList",
    "request_model": "@M00B",
    "request_code": 38,
    "human_field_semantics_resolved": False,
}

GETTER_BOUNDARY = {
    "direct_output_reference_position": 2,
    "direct_output_capture_site": 0x48B8C4,
    "fixed_backup_id_load_site": 0x48BA64,
    "fixed_backup_id_literal_site": 0x48BC70,
    "fixed_backup_read_call_site": 0x48BA6A,
    "backup_read_symbol": "_ZN21CmnViewModelIfWrapper10backupReadEiPv",
    "signed_byte_load_site": 0x48BA6E,
    "read_buffer_base_site": 0x48BA5E,
    "read_buffer_initial_value_site": 0x48BA62,
    "read_buffer_pointer_adjust_site": 0x48BA66,
    "read_buffer_local_offset": 0x135,
    "output_zero_source_site": 0x48B910,
    "output_zero_initialization_site": 0x48B95C,
    "post_read_transform": "preinitialized-zero-minus-one-skips-write-otherwise-plus-one",
    "decode_compare_site": 0x48BA72,
    "minus_one_skip_branch_site": 0x48BA76,
    "minus_one_skip_target": 0x48BA82,
    "positive_increment_site": 0x48BA78,
    "decode_join_branch_site": 0x48BA7A,
    "output_store_site": 0x48BA7E,
    "branch_dependent_backup_read_sites": [
        0x48BADA, 0x48BAEC, 0x48BAFE, 0x48BB34, 0x48BB9E,
        0x48BBB2, 0x48BBC2, 0x48BBFC, 0x48BC10, 0x48BC20,
    ],
    "branch_dependent_reads": [
        {"call_site": 0x48BADA, "buffer_base_site": 0x48BAC8, "buffer_base_offset": 0x134, "buffer_adjust_site": 0x48BAD2, "buffer_adjustment": 1, "buffer_local_offset": 0x135},
        {"call_site": 0x48BAEC, "buffer_base_site": 0x48BAE2, "buffer_base_offset": 0x134, "buffer_adjust_site": None, "buffer_adjustment": 0, "buffer_local_offset": 0x134},
        {"call_site": 0x48BAFE, "buffer_base_site": 0x48BAF4, "buffer_base_offset": 0x134, "buffer_adjust_site": 0x48BAF8, "buffer_adjustment": 3, "buffer_local_offset": 0x137},
        {"call_site": 0x48BB34, "buffer_base_site": 0x48BB2A, "buffer_base_offset": 0x134, "buffer_adjust_site": 0x48BB32, "buffer_adjustment": 3, "buffer_local_offset": 0x137},
        {"call_site": 0x48BB9E, "buffer_base_site": 0x48BB92, "buffer_base_offset": 0x134, "buffer_adjust_site": None, "buffer_adjustment": 0, "buffer_local_offset": 0x134},
        {"call_site": 0x48BBB2, "buffer_base_site": 0x48BBA6, "buffer_base_offset": 0x134, "buffer_adjust_site": 0x48BBAC, "buffer_adjustment": 1, "buffer_local_offset": 0x135},
        {"call_site": 0x48BBC2, "buffer_base_site": 0x48BBBA, "buffer_base_offset": 0x136, "buffer_adjust_site": None, "buffer_adjustment": 0, "buffer_local_offset": 0x136},
        {"call_site": 0x48BBFC, "buffer_base_site": 0x48BBF0, "buffer_base_offset": 0x136, "buffer_adjust_site": None, "buffer_adjustment": 0, "buffer_local_offset": 0x136},
        {"call_site": 0x48BC10, "buffer_base_site": 0x48BC04, "buffer_base_offset": 0x134, "buffer_adjust_site": 0x48BC0A, "buffer_adjustment": 1, "buffer_local_offset": 0x135},
        {"call_site": 0x48BC20, "buffer_base_site": 0x48BC18, "buffer_base_offset": 0x134, "buffer_adjust_site": None, "buffer_adjustment": 0, "buffer_local_offset": 0x134},
    ],
    "branch_dependent_backup_read_count": 10,
    "branch_dependent_record_ids_resolved": False,
    "branch_dependent_setter_record_join_found": False,
    "manager_or_view_output_position_proven": False,
}

DYNAMIC_RECORDS = {
    "other_backup_write_call_sites": [0x489574, 0x489588, 0x489598],
    "other_backup_write_count": 3,
    "argument_2_plus_13_site": 0x48955E,
    "argument_2_plus_13_scaled_site": 0x489562,
    "incoming_argument_2_preservation_segment": [0x4893BC, 0x48955E],
    "scaled_argument_2_preservation_segments": [
        [0x489566, 0x48956A],
        [0x48956E, 0x489580],
    ],
    "argument_2_plus_13_preservation_segment": [0x489562, 0x489594],
    "writes": [
        {
            "role": "selector-code",
            "condition": "argument-2-nonzero",
            "id_base_site": 0x48954A,
            "id_base_offset": 0x120,
            "id_index_site": 0x489552,
            "id_index_semantics": "four-times-original-argument-2",
            "id_load_site": 0x489556,
            "id_load_displacement": -0x28,
            "record_id_effective_byte_offset": 0xF8,
            "record_id_argument_2_scale": 4,
            "value_pointer_site": 0x48954E,
            "value_local_offset": 0x11E,
            "backup_write_call_site": 0x48955A,
        },
        {
            "role": "argument-3",
            "condition": "always-after-selector-branch",
            "id_base_site": 0x489566,
            "id_base_offset": 0x120,
            "id_index_site": 0x48956A,
            "id_index_semantics": "four-times-(argument-2-plus-13)",
            "id_load_site": 0x489570,
            "id_load_displacement": -0x78,
            "record_id_effective_byte_offset": 0xDC,
            "record_id_argument_2_scale": 4,
            "value_pointer_site": 0x48956E,
            "value_local_offset": 0x4,
            "backup_write_call_site": 0x489574,
        },
        {
            "role": "argument-4",
            "condition": "always-after-selector-branch",
            "id_base_site": 0x489578,
            "id_base_offset": 0x120,
            "id_index_site": 0x489580,
            "id_index_semantics": "four-times-(argument-2-plus-13)",
            "id_load_site": 0x489584,
            "id_load_displacement": -0xC8,
            "record_id_effective_byte_offset": 0x8C,
            "record_id_argument_2_scale": 4,
            "value_pointer_site": 0x48957C,
            "value_local_offset": 0x140,
            "backup_write_call_site": 0x489588,
        },
        {
            "role": "argument-5",
            "condition": "always-after-selector-branch",
            "id_base_site": 0x48958C,
            "id_base_offset": 0x8,
            "id_index_site": 0x489594,
            "id_index_semantics": "four-times-(argument-2-plus-13)",
            "id_load_site": 0x489594,
            "id_load_displacement": 0,
            "record_id_effective_byte_offset": 0x3C,
            "record_id_argument_2_scale": 4,
            "value_pointer_site": 0x489590,
            "value_local_offset": 0x144,
            "backup_write_call_site": 0x489598,
        },
    ],
    "numeric_record_ids_resolved": False,
    "record_id_source_initialization_resolved": False,
    "record_id_human_semantics_resolved": False,
    "record_id_semantics_resolved": False,
    "human_field_semantics_resolved": False,
}

CLAIMS = {
    "typed_element_selector_code_mapping_found": True,
    "selector_code_dynamic_record_boundary_found": True,
    "dynamic_record_geometry_found": True,
    "branch_dependent_getter_buffer_geometry_found": True,
    "argument_2_fixed_record_encode_decode_found": True,
    "getter_argument_2_record_boundary_found": True,
    "request_parameter_keys_found": True,
    "selector_code_fixed_record_found": False,
    "dynamic_record_ids_resolved": False,
    "dynamic_setter_getter_record_join_found": False,
    "human_style_labels_mapped": False,
    "menu_selected_state_join_found": False,
    "caution_config_selected_state_join_found": False,
    "five_argument_semantics_resolved": False,
    "renderer_or_output_sink_found": False,
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
        "typed_itanium_rtti_and_vtable": True,
        "source_unchanged": True,
    },
    "source": SOURCE,
    "typed_element": TYPED_ELEMENT,
    "setter_selector": SETTER_SELECTOR,
    "selector_record": SELECTOR_RECORD,
    "argument_2_record": ARGUMENT_2_RECORD,
    "request_boundary": REQUEST_BOUNDARY,
    "getter_boundary": GETTER_BOUNDARY,
    "dynamic_records": DYNAMIC_RECORDS,
    "claims": CLAIMS,
    "evidence_digest": canonical_digest({
        "typed_element": TYPED_ELEMENT,
        "setter_selector": SETTER_SELECTOR,
        "selector_record": SELECTOR_RECORD,
        "argument_2_record": ARGUMENT_2_RECORD,
        "request_boundary": REQUEST_BOUNDARY,
        "getter_boundary": GETTER_BOUNDARY,
        "dynamic_records": DYNAMIC_RECORDS,
    }),
    "truncated": False,
}

READINESS = "TYPED_ELEMENT_SELECTOR_AND_DYNAMIC_RECORD_GEOMETRY"
CONCLUSION = (
    "The typed CustomCreativeStyle setter has a bounded selector-to-persisted-code table: inputs "
    "0..13 reject 12 and map the other thirteen values to exact codes. That code reaches an adjacent "
    "dynamic backup-record boundary on the argument-2-nonzero path; its record-ID semantics remain "
    "unresolved. Fixed backup item 0x01070762 instead carries a low-byte argument-2 encoding into the "
    "getter's second direct output reference: nonpositive input writes 0xff, positive n writes the low "
    "byte of n-1, signed -1 leaves the preinitialized output zero, and other signed bytes are incremented. "
    "No admissible input range is proven, so a universal round trip is not claimed. The four dynamic "
    "setter writes now have exact frame-relative record-source and value-pointer formulas, and the ten "
    "branch-dependent getter reads have exact scratch-buffer pointers. Their numeric record IDs and any "
    "setter/getter dynamic-record join remain unresolved. Five ParamList "
    "keys are exact, but named preset labels, menu-selected-state identity, full five-field semantics, "
    "renderer/output effects, Creative Look equivalence, runtime behavior, and installability remain unproven."
)

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FORBIDDEN_KEYS = ("payload", "key_material", "device_write", "usb_write", "flash_image", "package_bytes")


class CreativeStyleSelectorCodeError(ValueError):
    """Raised when selector-code evidence is malformed or promoted."""


def _forbid(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if any(token in str(key).casefold() for token in _FORBIDDEN_KEYS):
                raise CreativeStyleSelectorCodeError("unsafe or reconstructive evidence field")
            _forbid(child)
    elif isinstance(value, list):
        for child in value:
            _forbid(child)


def normalize_creative_style_selector_code_export(document):
    _forbid(document)
    if not isinstance(document, dict) or set(document) != set(EXPECTED_EXPORT):
        raise CreativeStyleSelectorCodeError("selector-code export fields differ")
    if document != EXPECTED_EXPORT:
        raise CreativeStyleSelectorCodeError("selector-code export differs")
    if document["evidence_digest"] != canonical_digest({
        "typed_element": document["typed_element"],
        "setter_selector": document["setter_selector"],
        "selector_record": document["selector_record"],
        "argument_2_record": document["argument_2_record"],
        "request_boundary": document["request_boundary"],
        "getter_boundary": document["getter_boundary"],
        "dynamic_records": document["dynamic_records"],
    }):
        raise CreativeStyleSelectorCodeError("selector-code digest differs")
    if len(document["setter_selector"]["selector_to_persisted_code"]) != 13:
        raise CreativeStyleSelectorCodeError("selector-code cardinality differs")
    forbidden_positive = (
        "human_style_labels_mapped", "menu_selected_state_join_found",
        "caution_config_selected_state_join_found", "five_argument_semantics_resolved",
        "selector_code_fixed_record_found",
        "dynamic_record_ids_resolved", "dynamic_setter_getter_record_join_found",
        "renderer_or_output_sink_found", "creative_look_equivalence_found",
        "runtime_execution_proven",
    )
    if any(document["claims"][key] for key in forbidden_positive):
        raise CreativeStyleSelectorCodeError("unproven selector semantics promoted")
    return copy.deepcopy(document)


def summarize_creative_style_selector_code_export(document):
    export = normalize_creative_style_selector_code_export(document)
    return {
        "canonical_export_sha256": canonical_digest(export),
        "selector_entry_count": export["setter_selector"]["entry_count"],
        "accepted_selector_count": len(export["setter_selector"]["selector_to_persisted_code"]),
        "rejected_selector_count": len(export["setter_selector"]["rejected_indices"]),
        "fixed_argument_2_record_count": 1,
        "dynamic_setter_write_count": len(export["dynamic_records"]["writes"]),
        "request_param_count": len(export["request_boundary"]["param_keys"]),
        "branch_dependent_getter_read_count": export["getter_boundary"]["branch_dependent_backup_read_count"],
        "branch_dependent_getter_buffer_count": len(export["getter_boundary"]["branch_dependent_reads"]),
    }


def validate_creative_style_selector_code_report(document):
    _forbid(document)
    fields = {
        "schema_version", "analysis_scope", "camera_policy", "camera_executed",
        "installable", "camera_test_eligible", "source", "summary", "evidence_digest",
        "claims", "readiness", "conclusion",
    }
    if not isinstance(document, dict) or set(document) != fields:
        raise CreativeStyleSelectorCodeError("selector-code report fields differ")
    if document["schema_version"] != 1 or document["analysis_scope"] != "offline-static-creative-style-selector-code":
        raise CreativeStyleSelectorCodeError("selector-code report scope differs")
    if document["camera_policy"] != "physically-disconnected" or any(document[key] is not False for key in ("camera_executed", "installable", "camera_test_eligible")):
        raise CreativeStyleSelectorCodeError("selector-code report promotes camera activity")
    if document["source"] != SOURCE or document["summary"] != summarize_creative_style_selector_code_export(EXPECTED_EXPORT):
        raise CreativeStyleSelectorCodeError("selector-code report source or summary differs")
    if _SHA.fullmatch(document["summary"].get("canonical_export_sha256", "")) is None:
        raise CreativeStyleSelectorCodeError("selector-code report digest shape differs")
    if document["evidence_digest"] != EXPECTED_EXPORT["evidence_digest"] or document["claims"] != CLAIMS:
        raise CreativeStyleSelectorCodeError("selector-code report evidence differs")
    if document["readiness"] != READINESS or document["conclusion"] != CONCLUSION:
        raise CreativeStyleSelectorCodeError("selector-code report conclusion differs")
    return copy.deepcopy(document)
