"""Fail-closed tests for the Creative Style model/cursor boundary."""
from __future__ import annotations

import copy
import importlib.util
import json
import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "analysis" / "a6400-creative-style-model-cursor-boundary.json"
EXPORTER = ROOT / "tools" / "static" / "export_a6400_creative_style_model_cursor_boundary.py"


class CreativeStyleModelCursorBoundaryContractTests(unittest.TestCase):
    def test_exact_generic_helper_surface_is_pinned(self):
        from pmca.analysis.creative_style_model_cursor_boundary import (
            EXPECTED_EXPORT,
            normalize_creative_style_model_cursor_boundary_export,
        )

        document = normalize_creative_style_model_cursor_boundary_export(
            copy.deepcopy(EXPECTED_EXPORT)
        )
        self.assertEqual(
            (document["program"], document["file_size"], document["sha256"]),
            (
                "viewUnified2.so",
                11_530_552,
                "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2",
            ),
        )
        methods = {item["role"]: item for item in document["methods"]}
        self.assertEqual(
            set(methods),
            {
                "move-cursor",
                "get-value",
                "get-process-value-id-for-item",
                "set-cursor",
                "update-belt-widget",
                "set-cursor-on-item-change",
                "set-value-to-model",
            },
        )
        self.assertEqual(
            (methods["set-value-to-model"]["owner"], methods["set-value-to-model"]["size"]),
            (0x2FF0CC, 112),
        )
        self.assertEqual(
            (methods["set-cursor-on-item-change"]["owner"], methods["set-cursor-on-item-change"]["size"]),
            (0x2FEF78, 340),
        )

    def test_model_helper_terminals_resolve_to_widget_state_not_model_commit(self):
        from pmca.analysis.creative_style_model_cursor_boundary import EXPECTED_EXPORT

        model = EXPECTED_EXPORT["model_cursor_boundary"]["set_value_to_model"]
        self.assertEqual(
            [(item["site"], item["symbol"]) for item in model["named_lookup_calls"]],
            [
                (0x2FF0FC, "_ZN18CmnSettingNodeUtil16getProcIdForItemEP18CmnViewSettingNode"),
                (0x2FF118, "_ZN18CmnSettingNodeUtil19getProcValIdForItemEP18CmnViewSettingNode"),
            ],
        )
        self.assertEqual(
            [(item["site"], item["target"]) for item in model["local_terminal_calls"]],
            [(0x2FF12A, 0x2FE74C), (0x2FF130, 0x2FE806)],
        )
        self.assertFalse(model["local_terminal_semantics_resolved"])
        self.assertEqual(
            model["local_terminal_classification"],
            "contains-widget-display-state-updates-with-unresolved-virtual-effects",
        )
        self.assertEqual(
            [item["named_callee"]["symbol"] for item in model["local_terminal_routines"]],
            [
                "_ZN20LayoutableWidgetBase12setDispStateEb",
                "_ZN20LayoutableWidgetBase12setDispStateEb",
            ],
        )
        self.assertFalse(EXPECTED_EXPORT["claims"]["final_model_setter_or_commit_found"])
        self.assertFalse(EXPECTED_EXPORT["claims"]["creative_style_specific_binding_found"])
        self.assertFalse(EXPECTED_EXPORT["claims"]["commit_or_persistence_found"])

    def test_belt_update_is_a_named_widget_content_path(self):
        from pmca.analysis.creative_style_model_cursor_boundary import EXPECTED_EXPORT

        belt = EXPECTED_EXPORT["model_cursor_boundary"]["update_belt_widget_call"]
        self.assertEqual((belt["site"], belt["plt"]), (0x2FEF0A, 0x1513B4))
        self.assertEqual(
            belt["symbol"],
            "_ZN22PAS_MenuSelectBeltZako12updateWidgetEP18CmnViewSettingNode",
        )
        self.assertEqual((belt["defined_owner"], belt["defined_size"]), (0x5CC38C, 372))
        self.assertTrue(EXPECTED_EXPORT["claims"]["ui_widget_state_update_found"])
        self.assertFalse(EXPECTED_EXPORT["claims"]["renderer_binding_found"])

    def test_selection_interface_cells_and_utility_fields_are_exact(self):
        from pmca.analysis.creative_style_model_cursor_boundary import EXPECTED_EXPORT

        boundary = EXPECTED_EXPORT["model_cursor_boundary"]
        calls = boundary["virtual_calls"]
        self.assertIn(
            {
                "method_role": "set-cursor",
                "site": 0x2FED50,
                "receiver": "this+0x0c",
                "interface_cell": 46,
                "interface_symbol": "_ZN18CmnViewSettingNode15setItemSelectedEv",
                "concrete_target_resolved": False,
            },
            calls,
        )
        self.assertIn(
            {
                "method_role": "set-value-to-model",
                "site": 0x2FF0E6,
                "receiver": "this+0x0c",
                "interface_cell": 10,
                "interface_symbol": "_ZN18CmnViewSettingNode15getSelectedItemEPPS_",
                "concrete_target_resolved": False,
            },
            calls,
        )
        fields = {item["method_role"]: item["accesses"] for item in boundary["field_accesses"]}
        self.assertIn({"site": 0x2FEEFE, "offset": 0x18, "width": 4, "access": "write"}, fields["update-belt-widget"])
        self.assertIn({"site": 0x2FF120, "offset": 0x10, "width": 4, "access": "read"}, fields["set-value-to-model"])
        self.assertTrue(boundary["reported_sites_structurally_present"])
        self.assertTrue(boundary["receiver_object_register_match_checked"])
        self.assertFalse(boundary["path_sensitive_cfg_proof"])

    def test_tampering_and_claim_promotion_fail_closed(self):
        from pmca.analysis.creative_style_model_cursor_boundary import (
            CreativeStyleModelCursorBoundaryError,
            EXPECTED_EXPORT,
            normalize_creative_style_model_cursor_boundary_export,
        )

        mutations = []
        changed = copy.deepcopy(EXPECTED_EXPORT)
        changed["methods"][0]["owner"] += 2
        mutations.append(changed)
        changed = copy.deepcopy(EXPECTED_EXPORT)
        changed["model_cursor_boundary"]["set_value_to_model"]["local_terminal_semantics_resolved"] = True
        mutations.append(changed)
        changed = copy.deepcopy(EXPECTED_EXPORT)
        changed["claims"]["creative_style_specific_binding_found"] = True
        mutations.append(changed)
        changed = copy.deepcopy(EXPECTED_EXPORT)
        changed["device_payload"] = "forbidden"
        mutations.append(changed)
        for document in mutations:
            with self.subTest(document=document):
                with self.assertRaises(CreativeStyleModelCursorBoundaryError):
                    normalize_creative_style_model_cursor_boundary_export(document)

    def test_checked_in_report_validates(self):
        from pmca.analysis.creative_style_model_cursor_boundary import (
            validate_creative_style_model_cursor_boundary_report,
        )

        report = json.loads(REPORT.read_text(encoding="utf-8"))
        validated = validate_creative_style_model_cursor_boundary_report(report)
        self.assertEqual(validated["readiness"], "GENERIC_MODEL_CURSOR_BOUNDARY_ONLY")
        self.assertFalse(validated["installable"])
        self.assertFalse(validated["camera_test_eligible"])
        self.assertFalse(validated["claims"]["touch_routing_found"])
        self.assertFalse(validated["claims"]["renderer_binding_found"])


class CreativeStyleModelCursorBoundaryExporterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("model_cursor_exporter", EXPORTER)
        cls.exporter = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(cls.exporter)

    def test_adapter_is_normalized_and_source_is_static(self):
        from pmca.analysis.creative_style_model_cursor_boundary import EXPECTED_EXPORT

        class FakeAdapter:
            def metadata(self):
                return copy.deepcopy(EXPECTED_EXPORT)

        exported = self.exporter.build_raw_export(FakeAdapter())
        self.assertEqual(exported, EXPECTED_EXPORT)
        self.assertTrue(exported["analysis_mode"]["read_only"])
        self.assertTrue(exported["analysis_mode"]["source_unchanged"])
        self.assertFalse(exported["claims"]["runtime_execution_proven"])

    def test_arm_immediate_rotation_and_plt_veneer_shape_are_checked(self):
        self.assertEqual(self.exporter._arm_immediate((4 << 8) | 0x80), 0x80000000)
        if not self.exporter.dependencies_available():
            self.skipTest("local Capstone/pyelftools dependencies are unavailable")

        class FakeElf:
            def __init__(self, size):
                self.section = {"sh_addr": 0, "sh_size": size}

            def get_section_by_name(self, name):
                return self.section if name == ".plt" else None

        valid = struct.pack("<III", 0xE28FC001, 0xE28CC002, 0xE59CF003)
        self.assertEqual(
            self.exporter._decoded_plt_addresses_exact(FakeElf(len(valid)), valid, [(0, len(valid), 0)]),
            {14: 0},
        )
        wrong_destination = struct.pack("<III", 0xE28F0001, 0xE28CC002, 0xE59CF003)
        self.assertEqual(
            self.exporter._decoded_plt_addresses_exact(
                FakeElf(len(wrong_destination)), wrong_destination, [(0, len(wrong_destination), 0)]
            ),
            {},
        )

    def test_real_export_matches_the_pinned_boundary_when_available(self):
        source = self.exporter.SOURCE
        if not source.is_file() or not self.exporter.dependencies_available():
            self.skipTest("pinned local source or parser dependencies are unavailable")
        self.assertEqual(self.exporter.build_raw_export(), self.exporter.EXPECTED_EXPORT)


if __name__ == "__main__":
    unittest.main()
