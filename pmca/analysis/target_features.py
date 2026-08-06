"""Fail-closed validation for offline ILCE-6400 target feature evidence."""

import copy
import re


class TargetFeatureError(ValueError):
    """Raised when target evidence is malformed or promotes an unsupported claim."""


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_TOP_FIELDS = {
    "schema_version",
    "subject",
    "camera_policy",
    "camera_connected",
    "camera_executed",
    "bypass_established",
    "installable",
    "target",
    "module_inventory",
    "backup_images",
    "vertical_ui",
    "touch_ui",
    "ui_static_trace",
    "creative_rendering",
    "observations",
    "inferences",
    "unresolved",
    "conclusion",
}
_TARGET_FIELDS = {
    "outer_updater_sha256",
    "firmware_dat_sha256",
    "firmware_dat_offset",
    "fdat_size",
    "architecture",
    "model_id",
    "region",
    "version",
    "filesystem_count",
    "offline_unpack_succeeded",
}
_MODULE_FIELDS = {"name", "size", "sha256"}
_BACKUP_FIELDS = {
    "source_directory",
    "main_destination",
    "regional_image_count",
    "image_size",
    "backup_revision",
    "property_count",
    "all_regions_agree",
    "image_fingerprints",
    "properties",
}
_BACKUP_IMAGE_FIELDS = {"name", "sha256"}
_BACKUP_PROPERTY_FIELDS = {
    "id",
    "value_hex",
    "size",
    "attribute",
    "read_only",
}
_VERTICAL_FIELDS = {
    "classification",
    "view",
    "orientation_module",
    "orientation_api",
    "orientation_start_offset",
    "orientation_stop_offset",
    "orientation_consumer",
    "orientation_owner_vtable_offset",
    "orientation_owner_rtti_name",
    "layout_mode_attach_offset",
    "layout_mode_set_call_found",
    "af_orientation_dispatch_offset",
    "af_orientation_read_offsets",
    "layout_factory_module",
    "layout_factory_offset",
    "layout_group_id",
    "factory_model_predicate_absent",
    "orientation_layout_selector_established",
    "vertical_named_layouts",
    "uxc_resources",
    "vertical_name_device_rotation_semantics_established",
    "modern_vertical_menu_established",
    "vertical_input_transform_established",
}
_LAYOUT_FIELDS = {"name", "class_id"}
_TOUCH_FIELDS = {
    "view_module",
    "input_module",
    "root_resource_call_offset",
    "configuration_backup_id",
    "configuration_default_value",
    "configuration_backup_attribute",
    "configuration_read_only",
    "sample_view_resource_setup_offset",
    "sample_view_owner_rtti_name",
    "sample_view_rtti_name_offset",
    "sample_view_vtable_function_pointer_offset",
    "sample_view_production_menu_link_established",
    "root_setup_gate_backup_id",
    "root_setup_gate_read_offset",
    "root_setup_gate_default_value",
    "root_setup_gate_backup_attribute",
    "root_setup_gate_read_only",
    "root_setup_gate_nonzero_skips_resource_setup",
    "root_setup_gate_label_established",
    "device_capability_backup_id",
    "device_capability_backup_label",
    "device_capability_read_offsets",
    "device_capability_default_value",
    "device_capability_backup_attribute",
    "device_capability_read_only",
    "device_capability_linked_to_root_gate",
    "restore_modes",
    "view_specific_mode",
    "low_level_resource_routing_present",
    "select_widget_touch_mode_present",
    "setting_menu_instance_offset",
    "setting_menu_resource_hooks_found",
    "full_setting_menu_touch_established",
}
_CREATIVE_FIELDS = {
    "module",
    "compiled_default_graph_offset",
    "compiled_default_graph_nodes",
    "compiled_default_top_level_nodes",
    "compiled_graph_variants",
    "graph_selector_backup_id",
    "graph_selector_function_offset",
    "type07_selector_value",
    "documented_visible_graph_shape",
    "target_selector_value_confirmed",
    "target_selector_value",
    "target_selector_graph",
    "selector_backup_attribute",
    "selector_read_only",
    "selector_mutation_tested",
    "compiled_extra_fixed_style",
    "documented_visible_fixed_styles",
    "creative_boxes",
    "base_styles_per_box",
    "enum_range",
    "compiled_fixed_styles",
    "creative_box_names",
    "target_adjustment_axes",
    "donor_adjustment_axes",
    "creative_look_symbol_found",
    "native_creative_look_established",
    "label_reuse_is_concept_only",
}
_UI_STATIC_TRACE_FIELDS = {
    "analysis_scope",
    "module",
    "candidate_paths",
    "negative_searches",
    "coordinate_consumer_found",
    "menu_selection_dispatch_found",
}
_UI_STATIC_PATH_FIELDS = {
    "entry_name",
    "entry_offset",
    "target_name",
    "target_offset",
    "path_offsets",
    "semantic_boundary",
}
_UI_STATIC_NEGATIVE_FIELDS = {
    "root_set",
    "requested_roots",
    "resolved_roots",
    "target_name",
    "target_requested_offset",
    "target_function_offset",
    "search_method",
    "path_found",
}
_CLAIM_FIELDS = {"classification", "source", "claim"}
_FORBIDDEN_KEYS = {
    "raw",
    "raw_payload",
    "bytes",
    "payload",
    "base64",
    "hex_dump",
    "private_key",
}
_MODULES = {
    "lib/CautionConfig.so": (
        12070800,
        "bfd1bd7bad0ab3478b894da5dbb51c15464b1bedc4201240ccb61cd743150ef7",
    ),
    "lib/libObj.so": (
        20860436,
        "60ffd2b0f31f4bc139a7c13a4f62c25cdeb6a531ad5ef35df48471e6e36e88b1",
    ),
    "lib/viewUnified2.so": (
        11530552,
        "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2",
    ),
    "lib/viewUnified7.so": (
        541024,
        "c48cde43ff22d808ad23c42019ddae516fff7da060004eb81ed2bb85012aa538",
    ),
    "share/app/master_camera.uxc": (
        101720,
        "5a0370408dff25dab43ed677c3b8e6c9be3b8bb8630d7ea15273d4f996cca7ec",
    ),
    "share/app/viewStlrec.uxc": (
        32104,
        "f5aaa2f70f9b262b515a529ee2d80bf21928f0898504643cc7f174efa405d4f5",
    ),
}
_BACKUP_IMAGES = [
    ("CX62600_ALLLANG.bin", "04ca34dfe47e205aae570abeaa3302338bc24d35010de17126fa40da24235720"),
    ("CX62600_E38.bin", "5171763b31386bf67e490a05a8c14da9ca03c9426c1b9dbc94f6ccfb43e22469"),
    ("CX62600_J1.bin", "e83b9d21641e2a4ba29f4ad93955ee0cba1be47189d9c3ed92de482af74827ab"),
    ("CX62600_KR2.bin", "161bab48d242a2e912f1b016f3a6f3eca55af1ed7efbc7946f2f9814c86fc714"),
    ("CX62600_UC2.bin", "241c8521035bc9ff1edbe66cf3d42d81879a4bef8ff9e21cbfb84530a1446154"),
    ("CX62601_ALLLANG.bin", "13e3f2600923f1289d79f1452d8d62e11f1715af1e4ca7364886011a0752cd5b"),
    ("CX62601_AP2.bin", "6109fa82e88b26097b8c4d3ee42909a1f131cf6e7bb9fe23e7156b793006417e"),
    ("CX62601_CEC.bin", "e4b2aef35169d0d5fe0f91f07944a8287796fd2fd3731581c9a1ed60b37ef4b3"),
    ("CX62601_CN2.bin", "abf17ac691c5aaf25486e20a0f7d771a60796cbcfd8aea3db24059dccc74e454"),
    ("CX62601_IN5.bin", "f8d997fcc608f814898f05c15b296cd310bd7bf073338b7f5eadff194b26e12a"),
    ("CX62601_JE3.bin", "9edc4aec8a5e90f8a52853e2988400957fc2dbee232dd44f95d9c2defadb57b1"),
]
_BACKUP_PROPERTIES = [
    ("0x01070316", "43", 1, "0x01", True),
    ("0x002a000a", "01", 1, "0x00", False),
    ("0x01050002", "01", 1, "0x00", False),
    ("0x010704cb", "28", 1, "0x01", True),
    ("0x010701cf", "00", 1, "0x58", False),
]
_VERTICAL_NAMED_LAYOUTS = [
    (
        "Layoutlayout_CMN_M_REC_VERTICAL_CLASSICAL_INFO_LR",
        "0x61dc811c",
    ),
    (
        "Layoutlayout_CMN_M_REC_FOOTER_VERTICAL_CLASSICAL_LR",
        "0x186c17f6",
    ),
    (
        "Layoutlayout_CMN_M_REC_VERTICAL_CLASSICAL_HEADER_MANUALINFO_LR",
        "0x8e7fdf88",
    ),
    (
        "Layoutlayout_CMN_M_REC_VERTICAL_CLASSICAL_MANUAL_LR",
        "0x7be1c309",
    ),
    (
        "Layoutlayout_CMN_M_REC_VERTICAL_CLASSICAL_ERROR_LR",
        "0xbdbc36bd",
    ),
]
_FIXED_STYLES = [
    "Standard",
    "Vivid",
    "Neutral",
    "Clear",
    "Deep",
    "Light",
    "Portrait",
    "Landscape",
    "Sunset",
    "NightScene",
    "Autumnleaves",
    "Black_White",
    "Real",
    "Sepia",
]
_DOCUMENTED_VISIBLE_STYLES = [
    style for style in _FIXED_STYLES if style != "Real"
]


def _require_fields(value: object, fields: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise TargetFeatureError(f"{label} fields are invalid")
    return value


def _bounded_text(value: object, label: str, maximum: int = 1000) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or "\r" in value
        or "\n" in value
        or not value.isprintable()
    ):
        raise TargetFeatureError(f"{label} is invalid")
    return value


def _reject_reconstructive_fields(value: object) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str) or key.casefold() in _FORBIDDEN_KEYS:
                raise TargetFeatureError("Target feature report contains a forbidden field")
            _reject_reconstructive_fields(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_reconstructive_fields(nested)


def _validate_claims(document: dict) -> None:
    for field, classification in (
        ("observations", "OBSERVATION"),
        ("inferences", "INFERENCE"),
        ("unresolved", "UNRESOLVED"),
    ):
        claims = document[field]
        if not isinstance(claims, list) or not 1 <= len(claims) <= 24:
            raise TargetFeatureError(f"{field} claims are invalid")
        for claim in claims:
            _require_fields(claim, _CLAIM_FIELDS, "Target feature claim")
            if claim["classification"] != classification:
                raise TargetFeatureError("Target feature claim classification is invalid")
            _bounded_text(claim["source"], "Target feature claim source", 300)
            _bounded_text(claim["claim"], "Target feature claim")


def validate_target_feature_report(document: object) -> dict:
    """Validate target-only metadata without claiming a portable or installable patch."""
    _require_fields(document, _TOP_FIELDS, "Target feature report")
    _reject_reconstructive_fields(document)
    if document["schema_version"] != 2:
        raise TargetFeatureError("Target feature schema is unsupported")
    if document["subject"] != "ILCE-6400 Taiwan 2.00 target feature boundaries":
        raise TargetFeatureError("Target feature subject is invalid")
    if document["camera_policy"] != "physically-disconnected":
        raise TargetFeatureError("Target camera policy is invalid")
    for field in (
        "camera_connected",
        "camera_executed",
        "bypass_established",
        "installable",
    ):
        if document[field] is not False:
            raise TargetFeatureError(f"{field} must remain false")

    target = _require_fields(document["target"], _TARGET_FIELDS, "Target")
    if target != {
        "outer_updater_sha256": "ea460cbec5f8b62119630f0a653eeca4f4ffad887670e60c0fd9c0345e6b30a6",
        "firmware_dat_sha256": "78a6881eddd16609758951c80d533ac82042858eac919bd94453941ba6b766f2",
        "firmware_dat_offset": 715220,
        "fdat_size": 304833808,
        "architecture": "CXD90045",
        "model_id": "0x81030011",
        "region": 0,
        "version": "2.00",
        "filesystem_count": 1079,
        "offline_unpack_succeeded": True,
    }:
        raise TargetFeatureError("Target identity or extraction evidence is invalid")

    modules = document["module_inventory"]
    if not isinstance(modules, list) or len(modules) != len(_MODULES):
        raise TargetFeatureError("Target module inventory is incomplete")
    seen = set()
    for module in modules:
        _require_fields(module, _MODULE_FIELDS, "Target module")
        name = module["name"]
        if name not in _MODULES or name in seen:
            raise TargetFeatureError("Target module name is invalid")
        size, digest = _MODULES[name]
        if module["size"] != size or module["sha256"] != digest:
            raise TargetFeatureError("Target module fingerprint is invalid")
        if not _DIGEST.fullmatch(module["sha256"]):
            raise TargetFeatureError("Target module digest is malformed")
        seen.add(name)

    backup = _require_fields(document["backup_images"], _BACKUP_FIELDS, "Backup images")
    if backup != {
        "source_directory": "0110_backup/SYSASTRA-DSLR/DX2",
        "main_destination": "CX62600_UC2.bin",
        "regional_image_count": 11,
        "image_size": 1148036,
        "backup_revision": 4,
        "property_count": 28900,
        "all_regions_agree": True,
        "image_fingerprints": [
            {"name": name, "sha256": digest}
            for name, digest in _BACKUP_IMAGES
        ],
        "properties": [
            {
                "id": property_id,
                "value_hex": value_hex,
                "size": size,
                "attribute": attribute,
                "read_only": read_only,
            }
            for property_id, value_hex, size, attribute, read_only
            in _BACKUP_PROPERTIES
        ],
    }:
        raise TargetFeatureError("Backup image evidence is invalid")
    for image in backup["image_fingerprints"]:
        _require_fields(image, _BACKUP_IMAGE_FIELDS, "Backup image")
        if not _DIGEST.fullmatch(image["sha256"]):
            raise TargetFeatureError("Backup image digest is malformed")
    for prop in backup["properties"]:
        _require_fields(prop, _BACKUP_PROPERTY_FIELDS, "Backup property")

    vertical = _require_fields(document["vertical_ui"], _VERTICAL_FIELDS, "Vertical UI")
    if vertical["classification"] != "target-shooting-components":
        raise TargetFeatureError("Vertical UI classification is invalid")
    if vertical["view"] != "ViewStlrec" or vertical["orientation_module"] != "lib/viewUnified2.so":
        raise TargetFeatureError("Vertical view ownership is invalid")
    if (
        vertical["orientation_api"] != "startOrientationRollNotify_new"
        or (vertical["orientation_start_offset"], vertical["orientation_stop_offset"])
        != ("0x1ab41c", "0x1ba780")
        or vertical["orientation_consumer"] != 2
        or vertical["orientation_owner_vtable_offset"] != "0x8ded88"
        or vertical["orientation_owner_rtti_name"] != "ViewStlrec"
    ):
        raise TargetFeatureError("Vertical orientation registration is invalid")
    if (
        vertical["layout_mode_attach_offset"] != "0x1ab2d2"
        or vertical["layout_mode_set_call_found"] is not False
        or vertical["af_orientation_dispatch_offset"] != "0x1b1e76"
        or vertical["af_orientation_read_offsets"]
        != ["0x1b1e7c", "0x1b1e90", "0x1b1ea4"]
    ):
        raise TargetFeatureError("Vertical orientation use evidence is invalid")
    if (
        vertical["layout_factory_module"] != "lib/viewUnified7.so"
        or vertical["layout_factory_offset"] != "0x52840"
        or vertical["layout_group_id"] != "0x1b906244"
        or vertical["factory_model_predicate_absent"] is not True
    ):
        raise TargetFeatureError("Vertical layout factory evidence is invalid")
    if vertical["orientation_layout_selector_established"] is not False:
        raise TargetFeatureError("Vertical orientation selector was overclaimed")
    layouts = vertical["vertical_named_layouts"]
    if not isinstance(layouts, list) or len(layouts) != len(_VERTICAL_NAMED_LAYOUTS):
        raise TargetFeatureError("Vertical-named layout inventory is incomplete")
    actual_layouts = []
    for layout in layouts:
        _require_fields(layout, _LAYOUT_FIELDS, "Vertical-named layout")
        actual_layouts.append((layout["name"], layout["class_id"]))
    if actual_layouts != _VERTICAL_NAMED_LAYOUTS:
        raise TargetFeatureError("Vertical-named layout inventory is invalid")
    if vertical["uxc_resources"] != [
        "share/app/master_camera.uxc",
        "share/app/viewStlrec.uxc",
    ]:
        raise TargetFeatureError("Vertical-named UXC evidence is invalid")
    if vertical["vertical_name_device_rotation_semantics_established"] is not False:
        raise TargetFeatureError("Vertical naming was overclaimed as device rotation")
    if vertical["modern_vertical_menu_established"] is not False:
        raise TargetFeatureError("Modern vertical menu was overclaimed")
    if vertical["vertical_input_transform_established"] is not False:
        raise TargetFeatureError("Vertical input transform was overclaimed")

    touch = _require_fields(document["touch_ui"], _TOUCH_FIELDS, "Touch UI")
    if touch != {
        "view_module": "lib/viewUnified2.so",
        "input_module": "lib/libObj.so",
        "root_resource_call_offset": "0x2307d0",
        "configuration_backup_id": "0x010704cb",
        "configuration_default_value": "0x28",
        "configuration_backup_attribute": "0x01",
        "configuration_read_only": True,
        "sample_view_resource_setup_offset": "0x6666a4",
        "sample_view_owner_rtti_name": "10SampleView",
        "sample_view_rtti_name_offset": "0xfafd26",
        "sample_view_vtable_function_pointer_offset": "0x134d9c4",
        "sample_view_production_menu_link_established": False,
        "root_setup_gate_backup_id": "0x01050002",
        "root_setup_gate_read_offset": "0x6666c0",
        "root_setup_gate_default_value": "0x01",
        "root_setup_gate_backup_attribute": "0x00",
        "root_setup_gate_read_only": False,
        "root_setup_gate_nonzero_skips_resource_setup": True,
        "root_setup_gate_label_established": False,
        "device_capability_backup_id": "0x002a000a",
        "device_capability_backup_label": "BKID_DISPLAY_TP_DEVICE",
        "device_capability_read_offsets": ["0xdc30b6", "0xdc597a"],
        "device_capability_default_value": "0x01",
        "device_capability_backup_attribute": "0x00",
        "device_capability_read_only": False,
        "device_capability_linked_to_root_gate": False,
        "restore_modes": [0, 40],
        "view_specific_mode": 20,
        "low_level_resource_routing_present": True,
        "select_widget_touch_mode_present": True,
        "setting_menu_instance_offset": "0x205575",
        "setting_menu_resource_hooks_found": False,
        "full_setting_menu_touch_established": False,
    }:
        raise TargetFeatureError("Touch UI evidence is invalid or overclaimed")

    trace = _require_fields(
        document["ui_static_trace"], _UI_STATIC_TRACE_FIELDS, "UI static trace"
    )
    candidate_paths = trace["candidate_paths"]
    if not isinstance(candidate_paths, list):
        raise TargetFeatureError("UI static candidate paths are invalid")
    for path in candidate_paths:
        _require_fields(path, _UI_STATIC_PATH_FIELDS, "UI static candidate path")
    negative_searches = trace["negative_searches"]
    if not isinstance(negative_searches, list):
        raise TargetFeatureError("UI static negative searches are invalid")
    for search in negative_searches:
        _require_fields(search, _UI_STATIC_NEGATIVE_FIELDS, "UI static negative search")
    if trace != {
        "analysis_scope": "offline-static-target-filesystem",
        "module": "lib/viewUnified2.so",
        "candidate_paths": [
            {
                "entry_name": "ViewSettingMenu",
                "entry_offset": "0x22355e",
                "target_name": "touch_detect_mode_status_read",
                "target_offset": "0x1613f0",
                "path_offsets": [
                    "0x22355e",
                    "0x222f68",
                    "0x43156c",
                    "0x1613f0",
                ],
                "semantic_boundary": "status-read-not-coordinate-dispatch",
            },
            {
                "entry_name": "ViewSettingMenu",
                "entry_offset": "0x22355e",
                "target_name": "display_transition_touchpad_area_reconfiguration",
                "target_offset": "0x41ae08",
                "path_offsets": [
                    "0x22355e",
                    "0x21c644",
                    "0x1626cc",
                    "0x41b244",
                    "0x41ae08",
                ],
                "semantic_boundary": "configuration-not-menu-selection",
            },
        ],
        "negative_searches": [
            {
                "root_set": "ViewSettingMenu-candidate-functions",
                "requested_roots": 21,
                "resolved_roots": 21,
                "target_name": "master_layout_factory",
                "target_requested_offset": "0x181f18",
                "target_function_offset": "0x181f18",
                "search_method": "static-direct-call-graph",
                "path_found": False,
            },
            {
                "root_set": "ViewSettingMenu-candidate-functions",
                "requested_roots": 21,
                "resolved_roots": 21,
                "target_name": "vertical_info_layout_factory",
                "target_requested_offset": "0x24222c",
                "target_function_offset": "0x24222c",
                "search_method": "static-direct-call-graph",
                "path_found": False,
            },
            {
                "root_set": "ViewSettingMenu-candidate-functions",
                "requested_roots": 21,
                "resolved_roots": 21,
                "target_name": "root_resource_call_owner",
                "target_requested_offset": "0x2307d0",
                "target_function_offset": "0x223b8c",
                "search_method": "static-direct-call-graph",
                "path_found": False,
            },
            {
                "root_set": "ViewSettingMenu-candidate-functions",
                "requested_roots": 21,
                "resolved_roots": 21,
                "target_name": "sample_view_resource_setup_owner",
                "target_requested_offset": "0x6666a4",
                "target_function_offset": "0x6695d8",
                "search_method": "static-direct-call-graph",
                "path_found": False,
            },
            {
                "root_set": "ViewStlrec-candidate-functions",
                "requested_roots": 25,
                "resolved_roots": 10,
                "target_name": "master_layout_factory",
                "target_requested_offset": "0x181f18",
                "target_function_offset": "0x181f18",
                "search_method": "static-direct-call-graph",
                "path_found": False,
            },
            {
                "root_set": "ViewStlrec-candidate-functions",
                "requested_roots": 25,
                "resolved_roots": 10,
                "target_name": "vertical_info_layout_factory",
                "target_requested_offset": "0x24222c",
                "target_function_offset": "0x24222c",
                "search_method": "static-direct-call-graph",
                "path_found": False,
            },
        ],
        "coordinate_consumer_found": False,
        "menu_selection_dispatch_found": False,
    }:
        raise TargetFeatureError("UI static trace is invalid or overclaimed")

    creative = _require_fields(
        document["creative_rendering"], _CREATIVE_FIELDS, "Creative rendering"
    )
    if creative != {
        "module": "lib/CautionConfig.so",
        "compiled_default_graph_offset": "0xb836cc",
        "compiled_default_graph_nodes": 98,
        "compiled_default_top_level_nodes": 20,
        "compiled_graph_variants": [
            {"name": "Default", "nodes": 98},
            {"name": "TypeEmnt", "nodes": 91},
            {"name": "TypeDSCEntry", "nodes": 6},
            {"name": "Type05", "nodes": 7},
            {"name": "Type06", "nodes": 13},
            {"name": "Type07", "nodes": 19},
        ],
        "graph_selector_backup_id": "0x01070316",
        "graph_selector_function_offset": "0x7db958",
        "type07_selector_value": "0x45",
        "documented_visible_graph_shape": "TypeEmnt",
        "target_selector_value_confirmed": True,
        "target_selector_value": "0x43",
        "target_selector_graph": "TypeEmnt",
        "selector_backup_attribute": "0x01",
        "selector_read_only": True,
        "selector_mutation_tested": False,
        "compiled_extra_fixed_style": "Real",
        "documented_visible_fixed_styles": _DOCUMENTED_VISIBLE_STYLES,
        "creative_boxes": 6,
        "base_styles_per_box": 13,
        "enum_range": [0, 97],
        "compiled_fixed_styles": _FIXED_STYLES,
        "creative_box_names": [
            "CreativeBox1",
            "CreativeBox2",
            "CreativeBox3",
            "CreativeBox4",
            "CreativeBox5",
            "CreativeBox6",
        ],
        "target_adjustment_axes": 3,
        "donor_adjustment_axes": 8,
        "creative_look_symbol_found": False,
        "native_creative_look_established": False,
        "label_reuse_is_concept_only": True,
    }:
        raise TargetFeatureError("Creative rendering evidence is invalid or overclaimed")

    _validate_claims(document)
    _bounded_text(document["conclusion"], "Target feature conclusion")
    return copy.deepcopy(document)
