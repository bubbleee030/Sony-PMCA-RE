import copy
import json
import unittest
from pathlib import Path

from pmca.analysis.target_features import (
    TargetFeatureError,
    validate_target_feature_report,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = REPOSITORY_ROOT / "analysis" / "a6400-target-features.json"
UI_TRACE_PATH = REPOSITORY_ROOT / "analysis" / "a6400-ui-dispatch-boundary.json"
MODERN_UI_CONTRACT_PATH = (
    REPOSITORY_ROOT / "analysis" / "a6400-modern-ui-contract.json"
)
CREATIVE_LOOK_STACK_PATH = (
    REPOSITORY_ROOT / "analysis" / "a6400-creative-look-stack.json"
)
CREATIVE_LOOK_SOURCES_PATH = (
    REPOSITORY_ROOT / "analysis" / "a6400-creative-look-sources.json"
)
CREATIVE_LOOK_BOUNDARY_PATH = (
    REPOSITORY_ROOT / "analysis" / "a6400-creative-look-boundary.json"
)


class TargetFeatureTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(REPORT_PATH.read_text(encoding="utf-8"))

    def test_committed_report_preserves_the_target_only_boundary(self):
        validated = validate_target_feature_report(self.document)

        self.assertEqual(validated, self.document)
        self.assertEqual(validated["schema_version"], 4)
        self.assertFalse(validated["camera_connected"])
        self.assertFalse(validated["camera_executed"])
        self.assertFalse(validated["bypass_established"])
        self.assertFalse(validated["installable"])
        self.assertEqual(validated["target"]["model_id"], "0x81030011")
        self.assertEqual(validated["target"]["version"], "2.00")
        self.assertEqual(validated["target"]["filesystem_count"], 1079)

    def test_indirect_trace_and_contract_match_standalone_reports(self):
        validated = validate_target_feature_report(self.document)
        standalone_trace = json.loads(UI_TRACE_PATH.read_text(encoding="utf-8"))
        standalone_contract = json.loads(
            MODERN_UI_CONTRACT_PATH.read_text(encoding="utf-8")
        )

        self.assertEqual(validated["ui_indirect_trace"], standalone_trace)
        self.assertEqual(validated["modern_ui_contract"], standalone_contract)

    def test_creative_look_evidence_matches_all_standalone_reports(self):
        validated = validate_target_feature_report(self.document)

        self.assertEqual(
            validated["creative_look_stack"],
            json.loads(CREATIVE_LOOK_STACK_PATH.read_text(encoding="utf-8")),
        )
        self.assertEqual(
            validated["creative_look_sources"],
            json.loads(CREATIVE_LOOK_SOURCES_PATH.read_text(encoding="utf-8")),
        )
        self.assertEqual(
            validated["creative_look_boundary"],
            json.loads(CREATIVE_LOOK_BOUNDARY_PATH.read_text(encoding="utf-8")),
        )
        self.assertFalse(
            validated["creative_rendering"]["native_creative_look_established"]
        )

    def test_nested_ui_evidence_is_fail_closed_and_digest_pinned(self):
        candidates = []

        candidate = copy.deepcopy(self.document)
        candidate["ui_indirect_trace"]["claims"][
            "orientation_layout_selector_found"
        ] = True
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["ui_indirect_trace"]["modules"][0]["sha256"] = "00" * 32
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["modern_ui_contract"]["behaviors"][3]["status"] = "TARGET_NATIVE"
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        behavior = candidate["modern_ui_contract"]["behaviors"][3]
        behavior["status"] = "TARGET_NATIVE"
        behavior["evidence"] = [
            {
                "source": "analysis/a6400-ui-dispatch-boundary.json",
                "module": "lib/viewUnified2.so",
                "path_id": "direct-status-read",
                "semantic": "orientation-layout-selection",
                "level": "CONFIRMED",
                "claim": "Pinned path identifier does not match this behavior.",
            }
        ]
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["ui_indirect_trace"]["behavior_support"][
            "menu-touch-selection"
        ] = True
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                TargetFeatureError
            ):
                validate_target_feature_report(candidate)

    def test_schema_four_requires_both_nested_ui_reports_exactly(self):
        for field in ("ui_indirect_trace", "modern_ui_contract"):
            candidate = copy.deepcopy(self.document)
            del candidate[field]
            with self.subTest(field=field), self.assertRaises(TargetFeatureError):
                validate_target_feature_report(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["ui_indirect_trace"]["unexpected"] = False
        with self.assertRaises(TargetFeatureError):
            validate_target_feature_report(candidate)

    def test_schema_four_requires_all_nested_creative_look_reports_exactly(self):
        for field in (
            "creative_look_stack",
            "creative_look_sources",
            "creative_look_boundary",
        ):
            candidate = copy.deepcopy(self.document)
            del candidate[field]
            with self.subTest(field=field), self.assertRaises(TargetFeatureError):
                validate_target_feature_report(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["creative_look_boundary"]["claims"][
            "base_look_processing_found"
        ] = True
        with self.assertRaises(TargetFeatureError):
            validate_target_feature_report(candidate)

    def test_shipped_backup_defaults_are_exact_and_region_consistent(self):
        backup = validate_target_feature_report(self.document)["backup_images"]

        self.assertEqual(backup["main_destination"], "CX62600_UC2.bin")
        self.assertEqual(backup["regional_image_count"], 11)
        self.assertEqual(backup["backup_revision"], 4)
        self.assertEqual(backup["property_count"], 28900)
        self.assertTrue(backup["all_regions_agree"])
        self.assertEqual(
            backup["properties"],
            [
                {
                    "id": "0x01070316",
                    "value_hex": "43",
                    "size": 1,
                    "attribute": "0x01",
                    "read_only": True,
                },
                {
                    "id": "0x002a000a",
                    "value_hex": "01",
                    "size": 1,
                    "attribute": "0x00",
                    "read_only": False,
                },
                {
                    "id": "0x01050002",
                    "value_hex": "01",
                    "size": 1,
                    "attribute": "0x00",
                    "read_only": False,
                },
                {
                    "id": "0x010704cb",
                    "value_hex": "28",
                    "size": 1,
                    "attribute": "0x01",
                    "read_only": True,
                },
                {
                    "id": "0x010701cf",
                    "value_hex": "00",
                    "size": 1,
                    "attribute": "0x58",
                    "read_only": False,
                },
            ],
        )

    def test_vertical_named_components_are_present_without_claiming_rotation(self):
        vertical = validate_target_feature_report(self.document)["vertical_ui"]

        self.assertEqual(vertical["classification"], "target-shooting-components")
        self.assertEqual(vertical["view"], "ViewStlrec")
        self.assertEqual(vertical["orientation_api"], "startOrientationRollNotify_new")
        self.assertEqual(vertical["orientation_start_offset"], "0x1ab41c")
        self.assertEqual(vertical["orientation_stop_offset"], "0x1ba780")
        self.assertEqual(vertical["orientation_consumer"], 2)
        self.assertEqual(vertical["orientation_owner_vtable_offset"], "0x8ded88")
        self.assertEqual(vertical["orientation_owner_rtti_name"], "ViewStlrec")
        self.assertEqual(vertical["layout_mode_attach_offset"], "0x1ab2d2")
        self.assertFalse(vertical["layout_mode_set_call_found"])
        self.assertEqual(vertical["af_orientation_dispatch_offset"], "0x1b1e76")
        self.assertEqual(
            vertical["af_orientation_read_offsets"],
            ["0x1b1e7c", "0x1b1e90", "0x1b1ea4"],
        )
        self.assertEqual(len(vertical["vertical_named_layouts"]), 5)
        self.assertEqual(
            {item["class_id"] for item in vertical["vertical_named_layouts"]},
            {
                "0x61dc811c",
                "0x186c17f6",
                "0x8e7fdf88",
                "0x7be1c309",
                "0xbdbc36bd",
            },
        )
        self.assertTrue(vertical["factory_model_predicate_absent"])
        self.assertFalse(vertical["orientation_layout_selector_established"])
        self.assertFalse(vertical["vertical_name_device_rotation_semantics_established"])
        self.assertFalse(vertical["modern_vertical_menu_established"])
        self.assertFalse(vertical["vertical_input_transform_established"])

    def test_creative_style_graph_is_exact_and_native_look_stays_false(self):
        creative = validate_target_feature_report(self.document)["creative_rendering"]

        self.assertEqual(creative["compiled_default_graph_nodes"], 98)
        self.assertEqual(creative["compiled_default_top_level_nodes"], 20)
        self.assertEqual(
            creative["compiled_graph_variants"],
            [
                {"name": "Default", "nodes": 98},
                {"name": "TypeEmnt", "nodes": 91},
                {"name": "TypeDSCEntry", "nodes": 6},
                {"name": "Type05", "nodes": 7},
                {"name": "Type06", "nodes": 13},
                {"name": "Type07", "nodes": 19},
            ],
        )
        self.assertEqual(creative["graph_selector_backup_id"], "0x01070316")
        self.assertEqual(creative["graph_selector_function_offset"], "0x7db958")
        self.assertEqual(creative["type07_selector_value"], "0x45")
        self.assertEqual(creative["documented_visible_graph_shape"], "TypeEmnt")
        self.assertTrue(creative["target_selector_value_confirmed"])
        self.assertEqual(creative["target_selector_value"], "0x43")
        self.assertEqual(creative["target_selector_graph"], "TypeEmnt")
        self.assertTrue(creative["selector_read_only"])
        self.assertEqual(creative["selector_backup_attribute"], "0x01")
        self.assertFalse(creative["selector_mutation_tested"])
        self.assertEqual(creative["compiled_extra_fixed_style"], "Real")
        self.assertEqual(len(creative["documented_visible_fixed_styles"]), 13)
        self.assertEqual(creative["creative_boxes"], 6)
        self.assertEqual(creative["base_styles_per_box"], 13)
        self.assertEqual(creative["enum_range"], [0, 97])
        self.assertEqual(creative["target_adjustment_axes"], 3)
        self.assertEqual(creative["donor_adjustment_axes"], 8)
        self.assertFalse(creative["creative_look_symbol_found"])
        self.assertFalse(creative["native_creative_look_established"])
        self.assertTrue(creative["label_reuse_is_concept_only"])

    def test_settings_menu_touch_is_not_inferred_from_low_level_capability(self):
        touch = validate_target_feature_report(self.document)["touch_ui"]

        self.assertEqual(touch["input_module"], "lib/libObj.so")
        self.assertEqual(touch["sample_view_resource_setup_offset"], "0x6666a4")
        self.assertEqual(touch["sample_view_owner_rtti_name"], "10SampleView")
        self.assertEqual(touch["sample_view_rtti_name_offset"], "0xfafd26")
        self.assertEqual(
            touch["sample_view_vtable_function_pointer_offset"], "0x134d9c4"
        )
        self.assertFalse(touch["sample_view_production_menu_link_established"])
        self.assertEqual(touch["root_setup_gate_backup_id"], "0x01050002")
        self.assertEqual(touch["root_setup_gate_read_offset"], "0x6666c0")
        self.assertEqual(touch["root_setup_gate_default_value"], "0x01")
        self.assertEqual(touch["root_setup_gate_backup_attribute"], "0x00")
        self.assertFalse(touch["root_setup_gate_read_only"])
        self.assertTrue(touch["root_setup_gate_nonzero_skips_resource_setup"])
        self.assertFalse(touch["root_setup_gate_label_established"])
        self.assertEqual(touch["device_capability_backup_id"], "0x002a000a")
        self.assertEqual(
            touch["device_capability_backup_label"], "BKID_DISPLAY_TP_DEVICE"
        )
        self.assertEqual(
            touch["device_capability_read_offsets"], ["0xdc30b6", "0xdc597a"]
        )
        self.assertEqual(touch["device_capability_default_value"], "0x01")
        self.assertEqual(touch["device_capability_backup_attribute"], "0x00")
        self.assertFalse(touch["device_capability_read_only"])
        self.assertEqual(touch["configuration_default_value"], "0x28")
        self.assertEqual(touch["configuration_backup_attribute"], "0x01")
        self.assertTrue(touch["configuration_read_only"])
        self.assertFalse(touch["device_capability_linked_to_root_gate"])
        self.assertTrue(touch["low_level_resource_routing_present"])
        self.assertTrue(touch["select_widget_touch_mode_present"])
        self.assertFalse(touch["setting_menu_resource_hooks_found"])
        self.assertFalse(touch["full_setting_menu_touch_established"])

    def test_static_ui_trace_separates_touch_status_from_coordinate_dispatch(self):
        validated = validate_target_feature_report(self.document)
        trace = validated["ui_static_trace"]

        self.assertEqual(validated["schema_version"], 4)
        self.assertEqual(trace["analysis_scope"], "offline-static-target-filesystem")
        self.assertEqual(trace["module"], "lib/viewUnified2.so")
        self.assertEqual(
            trace["candidate_paths"],
            [
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
        )
        self.assertEqual(
            trace["negative_searches"],
            [
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
        )
        self.assertFalse(trace["coordinate_consumer_found"])
        self.assertFalse(trace["menu_selection_dispatch_found"])

    def test_static_ui_trace_rejects_semantic_promotion(self):
        for field in ("coordinate_consumer_found", "menu_selection_dispatch_found"):
            candidate = copy.deepcopy(self.document)
            candidate["ui_static_trace"][field] = True
            with self.subTest(field=field), self.assertRaises(TargetFeatureError):
                validate_target_feature_report(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["ui_static_trace"]["candidate_paths"][0]["semantic_boundary"] = (
            "coordinate-dispatch"
        )
        with self.assertRaises(TargetFeatureError):
            validate_target_feature_report(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["ui_static_trace"]["negative_searches"][0]["path_found"] = True
        with self.assertRaises(TargetFeatureError):
            validate_target_feature_report(candidate)

    def test_report_rejects_any_runtime_or_capability_promotion(self):
        mutations = (
            ("camera_connected", True),
            ("camera_executed", True),
            ("bypass_established", True),
            ("installable", True),
        )
        for field, value in mutations:
            candidate = copy.deepcopy(self.document)
            candidate[field] = value
            with self.subTest(field=field), self.assertRaises(TargetFeatureError):
                validate_target_feature_report(candidate)

        candidates = []
        candidate = copy.deepcopy(self.document)
        candidate["vertical_ui"]["modern_vertical_menu_established"] = True
        candidates.append(candidate)
        candidate = copy.deepcopy(self.document)
        candidate["touch_ui"]["full_setting_menu_touch_established"] = True
        candidates.append(candidate)
        candidate = copy.deepcopy(self.document)
        candidate["creative_rendering"]["native_creative_look_established"] = True
        candidates.append(candidate)
        for candidate in candidates:
            with self.assertRaises(TargetFeatureError):
                validate_target_feature_report(candidate)

    def test_default_creative_style_graph_cannot_promote_native_creative_look(self):
        candidate = copy.deepcopy(self.document)
        candidate["creative_rendering"]["target_selector_graph"] = "Default"
        candidate["creative_rendering"]["native_creative_look_established"] = True

        with self.assertRaises(TargetFeatureError):
            validate_target_feature_report(candidate)

    def test_report_rejects_raw_or_reconstructive_fields(self):
        candidate = copy.deepcopy(self.document)
        candidate["raw_payload"] = "not-allowed"

        with self.assertRaises(TargetFeatureError):
            validate_target_feature_report(candidate)


if __name__ == "__main__":
    unittest.main()
