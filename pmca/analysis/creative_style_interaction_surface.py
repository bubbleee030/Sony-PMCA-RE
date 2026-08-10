"""Fail-closed target-native Creative Style interaction-surface evidence."""
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

VIEW_DISPATCHER = {
    "view_type": "ViewCreativeStyle",
    "rtti": 0x93EC9C,
    "vtable_address_point": 0x93ECC0,
    "slot": 64,
    "cell": 0x93EDC0,
    "relocation_index": 51805,
    "target": 0x5D058C,
    "owner": {"start": 0x5D058C, "end": 0x5D0660, "complete": True},
    "compare_site": 0x5D0592,
    "branch_site": 0x5D0594,
    "out_of_range_target": 0x5D065E,
    "table_branch_site": 0x5D0596,
    "table_start": 0x5D059A,
    "case_count": 20,
    "selected_cases": {"0": 0x5CF398, "13": 0x5CFD14, "16": 0x5CE0A8},
}

CREATIVE_STYLE_LAYOUT = {
    "view_type": "ViewCreativeStyle",
    "initializer_slot": 54,
    "initializer_cell": 0x93ED98,
    "initializer_relocation_index": 51795,
    "initializer_owner": {"start": 0x5CCFA4, "end": 0x5CD100, "complete": True},
    "layout_call_site": 0x5CCFB8,
    "layout_call_symbol": "_ZN8ViewBase30setLayoutManagementInformationEjPFPN2ux6wgtlay20LayoutGroupConverterEvE",
    "layout_key_load_site": 0x5CCFB4,
    "layout_key_literal_site": 0x5CD0DC,
    "layout_key": 0x1FA14683,
    "callback_got": {
        "base_literal_load_site": 0x5CCFA4,
        "base_literal_site": 0x5CD0F0,
        "index_literal_load_site": 0x5CCFB0,
        "index_literal_site": 0x5CD0F4,
        "base_add_site": 0x5CCFAA,
        "load_site": 0x5CCFB6,
        "got_cell": 0x94BB24,
        "relocation_index": 59269,
    },
    "layout_callback": 0x5CD730,
    "layout_callback_owner": {"start": 0x5CD730, "end": 0x5CD748, "complete": True},
    "layout_callback_symbol_found": False,
    "helpers": [
        {
            "type": "CmnViewMenuData", "size": 0x50, "object_offset": 0x144,
            "size_site": 0x5CCFBC, "allocation_site": 0x5CCFBE,
            "result_capture_site": 0x5CCFC2,
            "constructor_site": 0x5CCFC4, "constructor_symbol": "_ZN15CmnViewMenuDataC1Ev",
            "store_site": 0x5CCFC8,
        },
        {
            "type": "CmnMenuTableUtil", "size": 0x14, "object_offset": 0x148,
            "size_site": 0x5CCFCC, "allocation_site": 0x5CCFCE,
            "result_capture_site": 0x5CCFD2,
            "constructor_site": 0x5CCFD4, "constructor_symbol": "_ZN16CmnMenuTableUtilC1Ev",
            "store_site": 0x5CCFDA,
        },
        {
            "type": "CmnZakoMenuUtil", "size": 0x3C, "object_offset": 0x150,
            "size_site": 0x5CCFE2, "allocation_site": 0x5CCFFC,
            "result_capture_site": 0x5CD000,
            "constructor_site": 0x5CD002, "constructor_symbol": "_ZN15CmnZakoMenuUtilC1Ev",
            "store_site": 0x5CD006,
        },
    ],
}

MENU_TABLE = {
    "case_index": 0,
    "target": 0x5CF398,
    "owner": {"start": 0x5CF398, "end": 0x5CF7A0, "complete": True},
    "init_call_site": 0x5CF3AC,
    "init_symbol": "_ZN16CmnMenuTableUtil12initMenuDataEPP15CmnViewMenuDataP21CmnViewMenuItemStruct",
    "receiver_load_site": 0x5CF3A2,
    "receiver_offset": 0x148,
    "menu_data_address_site": 0x5CF3A6,
    "menu_data_offset": 0x144,
    "table_literal_load_site": 0x5CF398,
    "table_literal_site": 0x5CF79C,
    "table_address_add_site": 0x5CF3AA,
    "table_semantics_resolved": False,
    "index_loop": {
        "init_site": 0x5CF3B0,
        "body_start": 0x5CF3B2,
        "helper_call_site": 0x5CF3BA,
        "helper": 0x5CF360,
        "compare_site": 0x5CF3BE,
        "backedge_site": 0x5CF3C0,
        "first": 0,
        "last": 18,
        "iteration_count": 19,
    },
    "set_greyout_symbol": "_ZN16CmnMenuTableUtil10setGreyoutEib",
    "set_greyout_call_sites": [
        0x5CF644, 0x5CF660, 0x5CF67C, 0x5CF698,
        0x5CF6B4, 0x5CF6D0, 0x5CF6EC, 0x5CF708,
        0x5CF724, 0x5CF740, 0x5CF75C, 0x5CF778,
    ],
}

BELT_CURSOR = {
    "case_index": 16,
    "target": 0x5CE0A8,
    "owner": {"start": 0x5CE0A8, "end": 0x5CE180, "complete": True},
    "belt_load_site": 0x5CE0B0,
    "belt_object_offset": 0x14C,
    "null_test_site": 0x5CE0B4,
    "null_branch_site": 0x5CE0B6,
    "update_call_site": 0x5CE0C0,
    "update_symbol": "_ZN16CmnMenuTableUtil26_updateCursorForBeltWidgetEP22PAS_MenuDataSelectBeltbb",
    "menu_util_load_site": 0x5CE0BC,
    "menu_util_offset": 0x148,
    "flag_1_site": 0x5CE0BA,
    "flag_1": True,
    "flag_2_site": 0x5CE0B8,
    "flag_2": False,
    "get_menu_id_call_site": 0x5CE0C8,
    "get_menu_id_symbol": "_ZN16CmnMenuTableUtil9getMenuIdEv",
    "widget_lookup_call_site": 0x5CE124,
    "widget_lookup_symbol": "_ZN8ViewBase9getWidgetEj",
    "positive_widget_id": {"load_site": 0x5CE120, "literal_site": 0x5CE178, "value": 0xCE1DDAAF},
    "nonpositive_widget_id": {"load_site": 0x5CE122, "literal_site": 0x5CE17C, "value": 0xBF331BAA},
    "widget_selector": {"value_load_site": 0x5CE118, "value_offset": 0x10, "compare_site": 0x5CE11C, "it_site": 0x5CE11E},
    "post_lookup_local_call_site": 0x5CE128,
    "post_lookup_local_target": 0x599C54,
    "concrete_belt_type_proven": False,
    "belt_creation_or_store_proven": False,
}

# This is deliberately a widget-interface boundary.  It does not type the belt
# member at ViewCreativeStyle+0x14c and does not establish a touch route.
POST_LOOKUP_WIDGET_CAST = {
    "call": {"site": 0x5CE128, "target": 0x599C54},
    "thunk_owner": {"start": 0x599C54, "end": 0x599C60},
    "tail": {"site": 0x599C5C, "target": 0x1501AC},
    "interworking_gate": 0x1501AC,
    "interworking_veneer": 0x1501B0,
    "got": 0x944F48,
    "rel_plt_index": 551,
    "symbol": "_ZN12PAS_BtnCombo4castEPN2ux6wgtsys6WidgetE",
    "cast_owner": {"start": 0x599510, "end": 0x59953C},
    "virtual_type_slot": 0x190,
    "null_input_branch_site": 0x59951A,
    "vptr_load_site": 0x59951C,
    "virtual_type_slot_load_site": 0x59951E,
    "virtual_type_call_site": 0x599522,
    "type_compare_site": 0x599528,
    "result_select_site": 0x59952A,
    "original_widget_capture_site": 0x599512,
    "original_widget_return_site": 0x59952C,
    "null_result_site": 0x59952E,
    "null_input_return_site": 0x599532,
    "generic_widget_type_filter_proven": True,
    "returns_original_widget_or_null": True,
}

FIELD_0X14C_CONSTRUCTOR_BOUNDARY = {
    "derived_constructor_owner": {"start": 0x5CD664, "end": 0x5CD6A0},
    "derived_base_constructor_call": {
        "site": 0x5CD66C,
        "symbol": "_ZN13ViewBaseForMRC2EP11ViewManager",
    },
    "default_base_constructor_owner": {"start": 0x2FC788, "end": 0x2FC7B4},
    "default_product_constructor_owner": {"start": 0x2F29F4, "end": 0x2F2A88},
    "direct_view_creative_style_0x14c_store_found": False,
    "external_viewbase_constructor_boundary": {
        "site": 0x2F29FC,
        "symbol": "_ZN8ViewBaseC2EP11ViewManager",
        "resolved": False,
    },
    "viewbase_constructor_import": {
        "module": "lib/viewUnified2.so",
        "call_site": 0x2F29FC,
        "symbol": "_ZN8ViewBaseC2EP11ViewManager",
        "dynsym_index": 1112,
        "symbol_undefined": True,
        "rel_plt_index": 1573,
        "got": 0x945F40,
        "relocation_type": 22,
        "branch_target": 0x153810,
        "declared_dependencies": ["CautionConfig.so", "libgcc_s.so.1", "libc.so.6"],
        "candidate_module_declared_dependency": False,
        "binding_proven": False,
    },
    "libobj_candidate": {
        "source": {
            "module": "lib/libObj.so",
            "size": 20_860_436,
            "sha256": "60ffd2b0f31f4bc139a7c13a4f62c25cdeb6a531ad5ef35df48471e6e36e88b1",
        },
        "symbol": "_ZN8ViewBaseC2EP11ViewManager",
        "dynsym_index": 3758,
        "symbol_entry": 0x3EDBAD,
        "owner": {"start": 0x3EDBAC, "end": 0x3EDC7C, "instruction_count": 73},
        "receiver_transfer_site": 0x3EDBB0,
        "receiver_store_offsets": {
            "0x3edbd6": 0x0,
            "0x3edbd8": 0x28,
            "0x3edbf8": 0x74,
            "0x3edbfc": 0x78,
            "0x3edc08": 0xD8,
            "0x3edc2a": 0x100,
            "0x3edc2e": 0x64,
            "0x3edc3a": 0x11C,
        },
        "direct_0x14c_store_found": False,
        "first_plt_boundary": {
            "call_site": 0x3EDBBA,
            "plt_target": 0x1004F4,
            "rel_plt_index": 1231,
            "got": 0x136B668,
            "relocation_type": 22,
            "symbol": "_ZN8ViewBase18getViewBootElementEv",
            "dynsym_index": 2501,
            "same_module_definition": {"entry": 0x3EBFE7, "size": 0x46},
            "binding_proven": False,
        },
    },
    "field_0x14c_concrete_type_resolved": False,
}

NAVIGATION = {
    "case_index": 13,
    "target": 0x5CFD14,
    "owner": {"start": 0x5CFD14, "end": 0x5CFFE8, "complete": True},
    "field_load_site": 0x5CFF84,
    "field_offset": 0x190,
    "compare_3_site": 0x5CFF88,
    "branch_not_3_site": 0x5CFF8A,
    "branch_not_3_target": 0x5CFF94,
    "route_3_join_site": 0x5CFF92,
    "route_3_join_target": 0x5CFF9E,
    "compare_2_site": 0x5CFF94,
    "branch_not_2_site": 0x5CFF96,
    "branch_not_2_target": 0x5CFFA8,
    "open_call_site": 0x5CFFA2,
    "open_argument_sites": {"r2": 0x5CFF9E, "r3": 0x5CFFA0},
    "open_symbol": "_ZN8ViewBase8openViewEPKcib",
    "close_call_site": 0x5CFFAE,
    "close_symbol": "_ZN8ViewBase9closeViewEPKc",
    "route_evidence": {
        "3": {"load_site": 0x5CFF8C, "receiver_site": 0x5CFF8E, "add_site": 0x5CFF90, "literal_site": 0x5CFFDC},
        "2": {"load_site": 0x5CFF98, "receiver_site": 0x5CFF9A, "add_site": 0x5CFF9C, "literal_site": 0x5CFFE0},
        "other": {"load_site": 0x5CFFA8, "receiver_site": 0x5CFFAA, "add_site": 0x5CFFAC, "literal_site": 0x5CFFE4},
    },
    "routes": {
        "3": {"operation": "openView", "name": "view/FNMENU"},
        "2": {"operation": "openView", "name": "view/QUICK_NAVI"},
        "other": {"operation": "closeView", "name": "@V01D"},
    },
    "creative_style_selection_proven": False,
}

TOUCHABILITY_CANDIDATE = {
    "movie_view": {
        "type_name": "ViewMovieRecPatch",
        "rtti": 0x94182C,
        "vtable_address_point": 0x941870,
        "slot": 65,
        "cell": 0x941974,
        "relocation_index": 53119,
        "slot_target": 0x627E50,
        "slot_owner": {"start": 0x627E50, "end": 0x627F48, "complete": True},
        "branch_site": 0x627EFC,
        "branch_target": 0x6275E8,
        "branch_target_owner": {"start": 0x6275E8, "end": 0x62773C, "complete": True},
        "get_widget_call_site": 0x62762C,
        "check_widget_call_site": 0x627630,
        "check_widget_symbol": "_Z21Check_PAS_BarCtrlDialPN2ux6wgtsys6WidgetE",
        "set_touchable_value_site": 0x627638,
        "set_touchable_call_site": 0x62763A,
        "set_touchable_symbol": "_ZN15PAS_BarCtrlDial12setTouchableEb",
        "set_touchable_value": False,
        "data_domain": "movie-iris-control",
    },
    "converter": {
        "type_name": "PAS_BarCtrlDialConverter",
        "rtti": 0x8EB6B8,
        "vtable_address_point": 0x8EB698,
        "slot": 6,
        "cell": 0x8EB6B0,
        "relocation_index": 23755,
        "target": 0x3E16C0,
        "owner": {"start": 0x3E16C0, "end": 0x3E18E8, "complete": True},
        "forward_to_boolean_site": 0x3E1866,
        "widget_receiver_site": 0x3E1868,
        "set_touchable_call_site": 0x3E186A,
        "forwarded_value_semantics_resolved": False,
    },
}

# This chain is intentionally generic and conditional.  It describes what a
# PAS_MenuDataSelectBelt can do after a candidate GEN_GridList provider is
# bound, its registration method has run, and the callback-enable state has
# become nonzero.  None of those facts identifies ViewCreativeStyle+0x14c or
# proves delivery of a camera touch event to that member.
GENERIC_BELT_INPUT_CHAIN = {
    "status": "CONDITIONAL_STATIC_PATH",
    "pas_belt": {
        "type_name": "PAS_MenuDataSelectBelt",
        "rtti": 0x92EF90,
        "vtable_address_point": 0x92EFA8,
        "vtable_type_relocation_index": 47852,
        "vtable_got_cell": 0x94D5EC,
        "vtable_got_relocation_index": 60904,
        "constructor_owner": {"start": 0x56E860, "end": 0x56E97C},
        "vptr_store_site": 0x56E87E,
        "embedded_base_offset": 0x410,
        "embedded_base_constructor_call_site": 0x56E8A4,
        "embedded_base_constructor_target": 0x59DD1C,
        "embedded_base_parent_call_site": 0x56E8EC,
    },
    "embedded_grid": {
        "base_type_name": "PAS_MenuDataSelectBeltBase",
        "base_rtti": 0x9375A0,
        "base_vtable_address_point": 0x9373E8,
        "base_vtable_type_relocation_index": 49950,
        "object_offset": 0x3F8,
        "constructor_call_site": 0x59DD48,
        "constructor_symbol": "_ZN12GEN_GridListC1Ev",
        "constructor_dynsym_index": 1029,
        "constructor_rel_plt_index": 1448,
        "constructor_got": 0x945D4C,
        "candidate_module": "lib/libObj.so",
        "candidate_type_name": "GEN_GridList",
        "candidate_constructor_dynsym_index": 3316,
        "candidate_constructor_entry": 0x3EA611,
        "candidate_constructor_size": 0x218,
        "candidate_rtti": 0x133CB20,
        "candidate_vtable_address_point": 0x133C908,
        "candidate_vtable_type_relocation_index": 37133,
        "candidate_vtable_got_cell": 0x1371BE0,
        "candidate_vtable_got_relocation_index": 68710,
        "candidate_constructor_owner": {"start": 0x3EA610, "end": 0x3EA828},
        "candidate_vptr_store_site": 0x3EA62C,
        "candidate_slots": {
            "mouse_wrapper": {"slot": 26, "relocation_index": 37135, "target": 0x3E850C},
            "mouse_handler": {"slot": 27, "relocation_index": 37136, "target": 0x3E9BCC},
            "action_callback": {"slot": 88, "relocation_index": 37156, "target": 0x3EA35A},
            "selection_update": {"slot": 121, "relocation_index": 37173, "target": 0x3EAF0C},
            "custom_region_test": {"slot": 126, "relocation_index": 37178, "target": 0x3E86D6},
        },
        "parent_call_site": 0x59DE46,
        "mouse_hook_call_site": 0x59DE56,
        "registration_slot": 107,
        "registration_relocation_index": 49972,
        "registration_target": 0x59DCB8,
        "registration_call_site": 0x59DCFA,
        "registration_callback_got_cell": 0x94DF34,
        "registration_callback_relocation_index": 61470,
        "callback": 0x59EDE0,
        "callback_callee_offset": 0x17C,
        "callback_function_offset": 0x180,
        "runtime_provider_binding_proven": False,
    },
    "path": {
        "event_type": 4,
        "mouse_handler_owner": {"start": 0x3E9BCC, "end": 0x3EA098},
        "event_type_call_site": 0x3E9BF8,
        "event_type_call_plt": 0x102C08,
        "event_type_symbol": "_ZNK2ux6wgtsys10MouseEvent12getEventTypeEv",
        "event_type_bias_site": 0x3E9BFC,
        "event_type_bias": 4,
        "event_type_guard_site": 0x3E9BFE,
        "event_type_guard_max_index": 7,
        "event_type_guard_branch_site": 0x3E9C00,
        "event_type_guard_target": 0x3EA038,
        "event_type_table_branch_site": 0x3E9C04,
        "event_type_table_start": 0x3E9C08,
        "event_type_case_landing": 0x3E9E22,
        "custom_region_call_site": 0x3E9F3E,
        "custom_region_zero_branch_site": 0x3E9F42,
        "custom_region_zero_target": 0x3E9F60,
        "custom_region_zero_tail_call_site": 0x3E9F78,
        "custom_region_zero_path_join": 0x3E9F7A,
        "selection_update_call_site": 0x3EA00A,
        "callback_enable_offset": 0x314,
        "callback_enable_initialization_site": 0x3EA6B2,
        "callback_enable_zero_source_site": 0x3EA644,
        "callback_enable_initial_value": 0,
        "callback_enable_test_site": 0x3EB06A,
        "enabled_callback_entry_call_site": 0x3EB074,
        "action_callback_call_site": 0x3E9800,
        "action_dispatch_call_site": 0x3EA420,
        "action_dispatch_target": 0x3E8C18,
        "registered_callback_call_site": 0x3E8C70,
        "callback_tail_site": 0x59EDEE,
        "callback_tail_target": 0x59E87C,
        "selection_helper_call_site": 0x59E95A,
        "selection_helper_target": 0x59E6F4,
        "selection_grid_address_site": 0x59E6FC,
        "set_item_select_call_site": 0x59E844,
        "set_item_select_plt": 0x154180,
        "set_item_select_symbol": "_ZN12GEN_GridList13setItemSelectEib",
        "belt_check_call_site": 0x59E7B6,
        "belt_check_plt": 0x155D00,
        "belt_check_symbol": "_Z28Check_PAS_MenuDataSelectBeltPN2ux6wgtsys6WidgetE",
        "event_helper_call_site": 0x59E7BC,
        "event_helper_target": 0x56EDEE,
        "event_id_base_site": 0x56EDEE,
        "event_id_base_offset": 0x2500,
        "event_id_load_site": 0x56EDF8,
        "event_id_offset": 0x4C,
        "event_push_tail_site": 0x56EDFE,
        "event_push_gate": 0x154EDC,
        "event_push_veneer": 0x154EE0,
        "event_push_got": 0x946600,
        "event_push_rel_plt_index": 2005,
        "event_push_symbol": "_ZN13AppWidgetBase9pushEventEmP9ParamList",
    },
    "candidate_widget_system_delivery": {
        "status": "CONDITIONAL_ON_LIBOBJ_PROVIDER_BINDINGS",
        "view_constructor_chain": {
            "pas_base_call_site": 0x56E86C,
            "pas_base_call_target": 0x401268,
            "layoutable_base_import_call_site": 0x401270,
            "layoutable_base_import_plt": 0x1563FC,
            "layoutable_base_symbol": "_ZN20LayoutableWidgetBaseC2Ev",
            "layoutable_base_dynsym_index": 1625,
            "layoutable_base_rel_plt_index": 2403,
            "layoutable_base_got": 0x946C38,
            "view_needed_libobj": False,
        },
        "candidate_provider": {
            "module": "lib/libObj.so",
            "layoutable_constructor_dynsym_index": 2788,
            "layoutable_constructor_entry": 0x413281,
            "layoutable_constructor_size": 0xB8,
            "layoutable_constructor_owner": {"start": 0x413280, "end": 0x413338},
            "layoutable_to_abstract_call_site": 0x41328C,
            "layoutable_to_abstract_target": 0x3FECC8,
            "abstract_constructor_owner": {"start": 0x3FECC8, "end": 0x3FED20},
            "abstract_to_widget_bridge_call_site": 0x3FECD0,
            "abstract_to_widget_bridge_target": 0x842434,
            "widget_bridge_owner": {"start": 0x842410, "end": 0x842458},
            "widget_bridge_receiver_capture_site": 0x84243A,
            "widget_constructor_call_site": 0x84243C,
            "widget_constructor_target": 0x5ED6D0,
            "widget_constructor_owner": {"start": 0x5ED624, "end": 0x5ED77C},
            "same_receiver_preserved": True,
        },
        "layer_attachment": {
            "default_layer_got_cell": 0x13725C8,
            "default_layer_relocation_index": 69341,
            "default_layer_object": 0x13EF6DC,
            "default_layer_load_site": 0x5ED762,
            "set_layer_call_site": 0x5ED766,
            "set_layer_plt": 0x10293C,
            "set_layer_symbol": "_ZN2ux6wgtsys6Widget10setLayerIDERKNS_4core2IDE",
            "set_layer_dynsym_index": 2787,
            "set_layer_rel_plt_index": 1903,
            "set_layer_got": 0x136C0E8,
            "set_layer_owner": {"start": 0x5ED584, "end": 0x5ED5E0},
            "get_layer_call_site": 0x5ED598,
            "get_layer_plt": 0x103DAC,
            "get_layer_symbol": "_ZNK2ux6wgtsys12WidgetSystem8getLayerERKNS_4core2IDE",
            "widget_node_address_site": 0x5ED59C,
            "widget_node_offset": 4,
            "layer_widget_list_address_site": 0x5ED5A0,
            "layer_widget_list_offset": 0x18,
            "insert_call_site": 0x5ED5A4,
            "insert_target": 0x7AEBE4,
        },
        "parent_chain": {
            "set_parent_dynsym_index": 3506,
            "set_parent_entry": 0x5ED7FB,
            "set_parent_size": 0x2C,
            "set_parent_owner": {"start": 0x5ED7FA, "end": 0x5ED826},
            "child_node_address_site": 0x5ED80C,
            "parent_node_address_site": 0x5ED80E,
            "node_offset": 4,
            "insert_call_site": 0x5ED810,
            "insert_target": 0x7AEBE4,
            "pas_to_base_call_site": 0x56E8EC,
            "base_to_grid_call_site": 0x59DE46,
            "child_slot": 5,
            "pas_child_slot_relocation_index": 90590,
            "base_child_slot_relocation_index": 90662,
            "view_child_symbol": "_ZNK2ux6wgtsys6Widget22getLastChildWidgetBaseEv",
            "candidate_grid_child_slot_relocation_index": 92832,
            "candidate_child_symbol_dynsym_index": 3671,
            "candidate_child_entry": 0x5ED899,
            "candidate_child_size": 0xC,
            "candidate_child_tail_site": 0x5ED8A0,
            "candidate_child_tail_target": 0x5ED882,
            "candidate_child_container_address_site": 0x5ED884,
            "candidate_child_container_offset": 4,
        },
        "hit_delivery": {
            "layer_hit_owner": {"start": 0x5F1B44, "end": 0x5F1BB0},
            "layer_first_widget_call_site": 0x5F1B76,
            "layer_first_widget_target": 0x601192,
            "layer_widget_list_offset_site": 0x601194,
            "layer_widget_list_offset": 0x18,
            "recursive_hit_call_site": 0x5F1B80,
            "recursive_hit_target": 0x5F1120,
            "recursive_hit_owner": {"start": 0x5F1120, "end": 0x5F1190},
            "recursive_child_slot_load_site": 0x5F1180,
            "recursive_child_slot_call_site": 0x5F1182,
            "recursive_next_child_call_site": 0x5F114A,
            "recursive_next_child_target": 0x60684E,
            "per_mouse_owner": {"start": 0x5F1BB0, "end": 0x5F1C7E},
            "hit_walk_call_site": 0x5F1BFA,
            "hit_walk_target": 0x5F1B44,
            "old_receiver_dispatch_call_site": 0x5F1C42,
            "new_receiver_dispatch_call_site": 0x5F1C70,
            "mouse_dispatch_target": 0x5F1190,
            "mouse_dispatch_owner": {"start": 0x5F1190, "end": 0x5F11F0},
            "hook_dispatch_slot": 27,
            "hook_dispatch_offset": 0x6C,
            "hook_dispatch_load_site": 0x5F11C8,
            "hook_dispatch_call_site": 0x5F11CA,
            "fallback_dispatch_slot": 26,
            "fallback_dispatch_offset": 0x68,
            "fallback_dispatch_load_site": 0x5F11E8,
            "fallback_dispatch_call_site": 0x5F11EA,
        },
        "static_mouse_post_pipeline": {
            "status": "STATIC_POST_API_TO_WIDGET_DELIVERY_PROVEN__UPSTREAM_PRODUCER_UNRESOLVED",
            "public_entries": [
                {
                    "role": "move",
                    "symbol": "_ZN2ux6wgtsys12WidgetSystem13postMouseMoveEhssNS_4core8MsecTimeE",
                    "dynsym_index": 2976,
                    "entry": 0x5F2151,
                    "size": 0x90,
                    "symbol_range": {"start": 0x5F2150, "end": 0x5F21E0},
                    "allocation_size_site": 0x5F217E,
                    "allocation_call_site": 0x5F218C,
                    "record_capture_site": 0x5F2192,
                    "event_type": 0,
                    "event_type_source_site": 0x5F2190,
                    "event_type_store_site": 0x5F2194,
                    "enqueue_receiver_site": 0x5F21C8,
                    "enqueue_call_site": 0x5F21CE,
                },
                {
                    "role": "press",
                    "symbol": "_ZN2ux6wgtsys12WidgetSystem14postMousePressEhhNS_4core8MsecTimeE",
                    "dynsym_index": 2773,
                    "entry": 0x5F21E1,
                    "size": 0x68,
                    "symbol_range": {"start": 0x5F21E0, "end": 0x5F2248},
                    "allocation_size_site": 0x5F21EC,
                    "allocation_call_site": 0x5F21F6,
                    "record_capture_site": 0x5F21FC,
                    "event_type": 1,
                    "event_type_source_site": 0x5F21FA,
                    "event_type_store_site": 0x5F21FE,
                    "enqueue_receiver_site": 0x5F2232,
                    "enqueue_call_site": 0x5F2234,
                },
                {
                    "role": "release",
                    "symbol": "_ZN2ux6wgtsys12WidgetSystem16postMouseReleaseEhhNS_4core8MsecTimeE",
                    "dynsym_index": 3785,
                    "entry": 0x5F2249,
                    "size": 0x68,
                    "symbol_range": {"start": 0x5F2248, "end": 0x5F22B0},
                    "allocation_size_site": 0x5F2254,
                    "allocation_call_site": 0x5F225E,
                    "record_capture_site": 0x5F2264,
                    "event_type": 2,
                    "event_type_source_site": 0x5F2262,
                    "event_type_store_site": 0x5F2266,
                    "enqueue_receiver_site": 0x5F229A,
                    "enqueue_call_site": 0x5F229C,
                },
            ],
            "record_allocation_size": 0x20,
            "record_allocation_target": 0x63DC5A,
            "event_type_offset": 0x10,
            "enqueue_target": 0x5F2124,
            "posted_queue": {
                "helper_owner": {"start": 0x5F2116, "end": 0x5F2150},
                "base_literal_load_site": 0x5F2124,
                "base_literal_site": 0x5F2144,
                "base_add_site": 0x5F212A,
                "offset_literal_load_site": 0x5F2128,
                "offset_literal_site": 0x5F2148,
                "indexed_load_site": 0x5F2130,
                "got_cell": 0x1373468,
                "relocation_index": 70274,
                "queue_object": 0x13EF6F4,
                "record_forward_site": 0x5F2126,
                "append_call_site": 0x5F2132,
                "append_target": 0x5F2116,
                "append_tail_site": 0x5F211E,
                "append_tail_target": 0x5F20E8,
            },
            "transfer": {
                "source_pop_owner": {"start": 0x5F275C, "end": 0x5F2788},
                "source_base_literal_load_site": 0x5F275C,
                "source_base_literal_site": 0x5F277C,
                "source_base_add_site": 0x5F2760,
                "source_offset_literal_load_site": 0x5F275E,
                "source_offset_literal_site": 0x5F2780,
                "source_indexed_load_site": 0x5F2766,
                "source_pop_call_site": 0x5F2768,
                "source_pop_target": 0x5F2712,
                "source_pop_tail_site": 0x5F271A,
                "source_pop_tail_target": 0x5F26E6,
                "owner": {"start": 0x5F2904, "end": 0x5F2964},
                "posted_queue_pop_call_site": 0x5F290C,
                "posted_queue_pop_target": 0x5F275C,
                "posted_record_capture_site": 0x5F2914,
                "initial_record_null_branch_site": 0x5F291C,
                "initial_record_null_branch_target": 0x5F2952,
                "initial_record_eligibility_load_site": 0x5F291E,
                "initial_record_eligibility_offset": 0x10,
                "initial_record_eligible_branch_site": 0x5F2920,
                "initial_record_eligible_branch_target": 0x5F2926,
                "initial_record_reject_branch_site": 0x5F2922,
                "initial_record_reject_branch_target": 0x5F2952,
                "loop_record_capture_site": 0x5F2924,
                "secondary_base_literal_load_site": 0x5F2910,
                "secondary_base_literal_site": 0x5F2958,
                "secondary_base_add_site": 0x5F2912,
                "secondary_offset_literal_load_site": 0x5F2926,
                "secondary_offset_literal_site": 0x5F295C,
                "secondary_indexed_load_site": 0x5F292A,
                "secondary_queue_got_cell": 0x13734A0,
                "secondary_queue_relocation_index": 70287,
                "secondary_queue_object": 0x13EF700,
                "secondary_append_record_site": 0x5F2928,
                "secondary_append_receiver_site": 0x5F292C,
                "secondary_append_call_site": 0x5F292E,
                "secondary_append_target": 0x5F2116,
                "loop_pop_call_site": 0x5F2932,
                "loop_pop_target": 0x5F275C,
                "loop_record_forward_site": 0x5F2936,
                "loop_record_null_branch_site": 0x5F2938,
                "loop_record_null_branch_target": 0x5F2948,
                "loop_record_eligibility_load_site": 0x5F293A,
                "loop_record_eligibility_compare_site": 0x5F293C,
                "loop_record_eligible_branch_site": 0x5F293E,
                "loop_record_eligible_branch_target": 0x5F2924,
                "secondary_pop_receiver_site": 0x5F2948,
                "secondary_pop_tail_site": 0x5F294E,
                "secondary_pop_target": 0x5F28D6,
            },
            "member_dispatch": {
                "processor_owner": {"start": 0x5F2964, "end": 0x5F2A38},
                "transfer_call_site": 0x5F2A1A,
                "transfer_target": 0x5F2904,
                "record_capture_site": 0x5F2A1E,
                "record_nonzero_branch_site": 0x5F2A22,
                "record_nonzero_branch_target": 0x5F29C6,
                "dispatch_receiver_site": 0x5F29C8,
                "dispatch_record_site": 0x5F29C6,
                "dispatch_call_site": 0x5F29CA,
                "dispatch_target": 0x5F10EC,
                "owner": {"start": 0x5F10EC, "end": 0x5F1120},
                "event_type_load_site": 0x5F10F0,
                "table_literal_load_site": 0x5F10F2,
                "table_literal_site": 0x5F111C,
                "table_add_site": 0x5F10F4,
                "table_address": 0x134A480,
                "entry_stride": 8,
                "function_pointer_load_site": 0x5F110E,
                "indirect_call_site": 0x5F1116,
                "entries": [
                    {"event_type": 0, "cell": 0x134A480, "relocation_index": 45771, "target": 0x5F1F88, "hit_update_call_site": 0x5F1FB2},
                    {"event_type": 1, "cell": 0x134A488, "relocation_index": 45772, "target": 0x5F1ECC, "hit_update_call_site": 0x5F1F02},
                    {"event_type": 2, "cell": 0x134A490, "relocation_index": 45773, "target": 0x5F1DC0, "hit_update_call_site": 0x5F1DF8},
                ],
                "hit_update_target": 0x5F1BB0,
            },
        },
    },
    "findings": {
        "slot27_to_custom_region_test_proven": True,
        "slot27_to_selection_update_proven": True,
        "slot27_to_registered_callback_proven": False,
        "selection_callback_enable_state_proven": False,
        "selection_callback_constructor_initial_value": 0,
        "enabled_callback_to_grid_selection_proven": True,
        "enabled_callback_to_typed_pas_belt_event_push_boundary_proven": True,
        "widget_is_hit_used_by_this_path": False,
        "candidate_provider_layer_attachment_path_proven": True,
        "candidate_provider_parent_chain_to_embedded_grid_proven": True,
        "candidate_provider_widget_system_hit_delivery_path_proven": True,
        "static_public_mouse_post_to_hit_delivery_pipeline_proven": True,
        "bounded_absent_vtable_offsets": [0x8C, 0x90],
        "bounded_absent_direct_targets": [0x606676, 0x5ED0F8],
        "bounded_absent_plt_symbols": [
            "_ZN2ux6wgtsys10WidgetBase9sys_isHitERKNS_4core7Vector2E",
            "_ZN2ux6wgtsys6Widget5isHitERKNS_4core7Vector2E",
        ],
    },
    "preconditions": {
        "runtime_provider_binding_proven": False,
        "registration_method_invocation_proven": False,
        "runtime_widget_system_delivery_to_embedded_grid_proven": False,
        "runtime_registered_root_attachment_proven": False,
        "raw_mouse_input_producer_proven": False,
        "viewcreative_style_field_0x14c_instance_join_proven": False,
        "viewcreative_style_case16_selector_proven": False,
    },
}

CLAIMS = {
    "native_creative_style_layout_found": True,
    "native_menu_table_scaffold_found": True,
    "native_belt_cursor_boundary_found": True,
    "native_navigation_boundary_found": True,
    "concrete_touchability_flag_boundary_found": True,
    "generic_widget_type_filter_proven": True,
    "conditional_generic_pas_belt_input_chain_found": True,
    "concrete_creative_style_belt_type_found": False,
    "creative_style_touch_route_found": False,
    "coordinate_input_found": False,
    "hit_test_found": False,
    "gesture_found": False,
    "selection_dispatch_found": False,
    "menu_selection_dispatch_found": False,
    "field_0x14c_concrete_type_resolved": False,
    "reusable_touch_adjustment_implementation_found": False,
    "creative_look_layout_equivalence_found": False,
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
    "source": SOURCE,
    "view_dispatcher": VIEW_DISPATCHER,
    "creative_style_layout": CREATIVE_STYLE_LAYOUT,
    "menu_table": MENU_TABLE,
    "belt_cursor": BELT_CURSOR,
    "post_lookup_widget_cast": POST_LOOKUP_WIDGET_CAST,
    "field_0x14c_constructor_boundary": FIELD_0X14C_CONSTRUCTOR_BOUNDARY,
    "navigation": NAVIGATION,
    "touchability_candidate": TOUCHABILITY_CANDIDATE,
    "generic_belt_input_chain": GENERIC_BELT_INPUT_CHAIN,
    "claims": CLAIMS,
    "evidence_digest": canonical_digest({
        "creative_style_layout": CREATIVE_STYLE_LAYOUT,
        "view_dispatcher": VIEW_DISPATCHER,
        "menu_table": MENU_TABLE,
        "belt_cursor": BELT_CURSOR,
        "post_lookup_widget_cast": POST_LOOKUP_WIDGET_CAST,
        "field_0x14c_constructor_boundary": FIELD_0X14C_CONSTRUCTOR_BOUNDARY,
        "navigation": NAVIGATION,
        "touchability_candidate": TOUCHABILITY_CANDIDATE,
        "generic_belt_input_chain": GENERIC_BELT_INPUT_CHAIN,
    }),
    "truncated": False,
}

READINESS = "NATIVE_CREATIVE_STYLE_LAYOUT_AND_BELT_TOUCH_UNPROVEN"
CONCLUSION = (
    "ViewCreativeStyle owns a target-native layout key, three menu helpers, a bounded 19-index "
    "initialization loop, twelve greyout call sites, a pre-existing belt-cursor update boundary, "
    "and exact navigation routes. The post-lookup call reaches the generic PAS_BtnCombo::cast "
    "Widget type filter, which returns the original widget or null; it does not type the belt member "
    "at +0x14c. The bounded derived/default-base constructors contain no direct +0x14c store. A "
    "candidate ViewBase constructor in libObj is not a declared viewUnified2 dependency, has no direct "
    "+0x14c store, and reaches a PLT/GOT boundary without a proved binding. The belt object's concrete type, creation, "
    "and touch route remain unproven. A separate Movie Rec path acquires a checked PAS_BarCtrlDial "
    "but explicitly calls "
    "setTouchable(false); its converter only forwards an unresolved value. This proves reusable UI "
    "scaffolding and a touchability flag boundary. Separately, a conditional generic "
    "PAS_MenuDataSelectBelt path reaches a custom grid-region test and selection-update method. Its "
    "provider-candidate constructor path inserts the PAS root into the same WidgetSystem layer list "
    "traversed by hit testing, and the PAS-to-base-to-grid parent chain reaches the hook dispatcher. "
    "Separately, the three exported postMouse APIs statically feed fixed records through two queues "
    "and a member-dispatch table into that hit/delivery path. The upstream raw-input producer, runtime "
    "provider binding, actual input occurrence, registration invocation, callback enablement, "
    "ViewCreativeStyle+0x14c identity, and case-16 selector provenance remain unproved. The enabled "
    "callback continuation can select a grid item and reaches a typed PAS belt event-push boundary, "
    "but this is not Creative Style touch, hit "
    "testing, or selection, "
    "Creative Look layout equivalence, runtime behavior, or installability."
)

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FORBIDDEN_KEYS = ("payload", "key_material", "device_write", "usb_write", "flash_image", "package_bytes")


class CreativeStyleInteractionSurfaceError(ValueError):
    """Raised when interaction-surface evidence is malformed or promoted."""


def _forbid(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if any(token in str(key).casefold() for token in _FORBIDDEN_KEYS):
                raise CreativeStyleInteractionSurfaceError("unsafe or reconstructive evidence field")
            _forbid(child)
    elif isinstance(value, list):
        for child in value:
            _forbid(child)


def normalize_creative_style_interaction_surface_export(document):
    _forbid(document)
    if not isinstance(document, dict) or set(document) != set(EXPECTED_EXPORT):
        raise CreativeStyleInteractionSurfaceError("interaction-surface export fields differ")
    if document != EXPECTED_EXPORT:
        raise CreativeStyleInteractionSurfaceError("interaction-surface export differs")
    if document["evidence_digest"] != canonical_digest({
        "creative_style_layout": document["creative_style_layout"],
        "view_dispatcher": document["view_dispatcher"],
        "menu_table": document["menu_table"],
        "belt_cursor": document["belt_cursor"],
        "post_lookup_widget_cast": document["post_lookup_widget_cast"],
        "field_0x14c_constructor_boundary": document["field_0x14c_constructor_boundary"],
        "navigation": document["navigation"],
        "touchability_candidate": document["touchability_candidate"],
        "generic_belt_input_chain": document["generic_belt_input_chain"],
    }):
        raise CreativeStyleInteractionSurfaceError("interaction-surface digest differs")
    forbidden_positive = (
        "concrete_creative_style_belt_type_found", "creative_style_touch_route_found",
        "coordinate_input_found", "hit_test_found", "gesture_found",
        "selection_dispatch_found", "reusable_touch_adjustment_implementation_found",
        "menu_selection_dispatch_found", "field_0x14c_concrete_type_resolved",
        "creative_look_layout_equivalence_found", "runtime_execution_proven",
    )
    if any(document["claims"][key] for key in forbidden_positive):
        raise CreativeStyleInteractionSurfaceError("unproven interaction claim promoted")
    return copy.deepcopy(document)


def summarize_creative_style_interaction_surface_export(document):
    export = normalize_creative_style_interaction_surface_export(document)
    return {
        "canonical_export_sha256": canonical_digest(export),
        "layout_helper_count": len(export["creative_style_layout"]["helpers"]),
        "menu_index_count": export["menu_table"]["index_loop"]["iteration_count"],
        "greyout_call_count": len(export["menu_table"]["set_greyout_call_sites"]),
        "navigation_route_count": len(export["navigation"]["routes"]),
        "touchable_true_call_count": int(export["touchability_candidate"]["movie_view"]["set_touchable_value"] is True),
        "conditional_generic_belt_input_chain_found": export["claims"]["conditional_generic_pas_belt_input_chain_found"],
    }


def build_creative_style_interaction_surface_report(export_document):
    """Build the only checked interaction report from exact static evidence."""
    export = normalize_creative_style_interaction_surface_export(export_document)
    return {
        "schema_version": 1,
        "analysis_scope": "offline-static-creative-style-interaction-surface",
        "camera_policy": "physically-disconnected",
        "camera_executed": False,
        "installable": False,
        "camera_test_eligible": False,
        "source": copy.deepcopy(export["source"]),
        "summary": summarize_creative_style_interaction_surface_export(export),
        "evidence_digest": export["evidence_digest"],
        "claims": copy.deepcopy(export["claims"]),
        "readiness": READINESS,
        "conclusion": CONCLUSION,
    }


def validate_creative_style_interaction_surface_report(document):
    _forbid(document)
    fields = {
        "schema_version", "analysis_scope", "camera_policy", "camera_executed",
        "installable", "camera_test_eligible", "source", "summary", "evidence_digest",
        "claims", "readiness", "conclusion",
    }
    if not isinstance(document, dict) or set(document) != fields:
        raise CreativeStyleInteractionSurfaceError("interaction-surface report fields differ")
    expected = build_creative_style_interaction_surface_report(EXPECTED_EXPORT)
    if document != expected:
        raise CreativeStyleInteractionSurfaceError("interaction-surface report differs")
    if _SHA.fullmatch(document["summary"].get("canonical_export_sha256", "")) is None:
        raise CreativeStyleInteractionSurfaceError("interaction-surface report digest shape differs")
    return copy.deepcopy(document)
