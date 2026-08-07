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

CLAIMS = {
    "native_creative_style_layout_found": True,
    "native_menu_table_scaffold_found": True,
    "native_belt_cursor_boundary_found": True,
    "native_navigation_boundary_found": True,
    "concrete_touchability_flag_boundary_found": True,
    "generic_widget_type_filter_proven": True,
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
    "scaffolding and a touchability flag boundary, not Creative Style touch, hit testing, selection, "
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
