"""Fail-closed tests for the orientation object/table boundary."""
from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "analysis" / "a6400-orientation-object-table-boundary.json"
EXPORTER = ROOT / "tools" / "static" / "export_a6400_orientation_object_table_boundary.py"


class OrientationObjectTableBoundaryContractTests(unittest.TestCase):
    def test_contract_pins_initializer_stores_and_negative_widget_match(self):
        from pmca.analysis.orientation_object_table_boundary import (
            EXPECTED_RAW_EXPORT,
            normalize_orientation_object_table_boundary_export,
        )

        document = normalize_orientation_object_table_boundary_export(copy.deepcopy(EXPECTED_RAW_EXPORT))
        self.assertEqual(document["prior_orientation_helper"]["analysis_contract"], "orientation_af_helper")
        self.assertEqual(document["prior_slot37_dispatch"]["analysis_contract"], "generic_slot37_dispatch")
        self.assertEqual([item["owner"] for item in document["initializers"]], [0x30E9CC, 0x30E9E8])
        self.assertEqual([item["decoded_item_count"] for item in document["initializers"]], [14, 17])
        self.assertEqual(document["initializers"][0]["store_base_register"], "r0")
        self.assertEqual(document["initializers"][0]["store_receiver_provenance"], "entry-r0")
        self.assertEqual(document["initializers"][1]["direct_calls"], [{"site": 0x30E9F0, "target": 0x30E9CC}])
        self.assertEqual(document["initializers"][1]["base_call_receiver_provenance"], "entry-r0")
        self.assertEqual(document["initializers"][1]["store_base_register"], "r5")
        self.assertEqual(document["initializers"][1]["store_receiver_provenance"], "entry-r0")
        self.assertEqual([item["target"] for item in document["table_stores"]], [0x8E6118, 0x8E6228])
        self.assertTrue(all(item["widget_address_point_match_count"] == 0 for item in document["table_stores"]))
        self.assertEqual(document["type_tables"][0]["type_name"], "AfOrientImpl")
        self.assertEqual(document["type_tables"][1]["type_name"], "AfImplForOrientationRegisterAF")
        self.assertEqual(document["type_tables"][1]["base_typeinfo"], 0x8E6108)
        self.assertEqual(document["type_tables"][1]["base_link_relocation_index"], 20071)
        self.assertEqual(document["type_tables"][1]["base_link_relocation_type"], 23)
        self.assertEqual([item["slot_count"] for item in document["type_tables"]], [66, 66])
        self.assertEqual(document["type_tables"][0]["pure_virtual_reference_count"], 63)
        self.assertEqual(document["slot37_binding"]["cell"], 0x8E62BC)
        self.assertEqual(document["slot37_binding"]["target"], 0x30C578)
        self.assertEqual(document["slot37_binding"]["defined_dynsym_match_count"], 0)
        self.assertTrue(document["claims"]["concrete_af_type_found"])
        self.assertFalse(document["claims"]["widget_compatible_table_found"])
        self.assertFalse(document["claims"]["menu_touch_behavior_found"])

    def test_contract_pins_direct_storage_consumers_and_graph_limit(self):
        from pmca.analysis.orientation_object_table_boundary import (
            EXPECTED_RAW_EXPORT,
            normalize_orientation_object_table_boundary_export,
        )

        document = normalize_orientation_object_table_boundary_export(copy.deepcopy(EXPECTED_RAW_EXPORT))
        consumers = document["storage_consumers"]
        self.assertEqual(consumers["guard_materialization_sites"], [0x35F428, 0x35F448])
        self.assertEqual(consumers["object_materialization_sites"], [0x35F440, 0x35F454, 0x35F460])
        self.assertEqual(consumers["offset_zero_load_sites"], [0x35F42E])
        self.assertEqual(consumers["initializer_calls"], [{"site": 0x35F442, "target": 0x30E9E8}])
        self.assertEqual(consumers["canonical_digest"], "d45002a0c1e392f1958022bc6ee86e636d0a6d3c1646a1c35953910a1a762984")
        self.assertEqual(document["direct_graph_summary"]["scope"], "pinned-complete-helper-prefix-only")
        self.assertEqual(document["direct_graph_summary"]["owner"], 0x35F424)
        self.assertTrue(document["direct_graph_summary"]["prefix_complete"])
        self.assertFalse(document["direct_graph_summary"]["path_analysis_performed"])
        self.assertFalse(document["direct_graph_summary"]["cross_module_path_analysis_performed"])
        self.assertFalse(document["claims"]["transitive_graph_absence_established"])

    def test_contract_rejects_promoted_identity_and_committed_report_is_safe(self):
        from pmca.analysis.orientation_object_table_boundary import (
            EXPECTED_RAW_EXPORT,
            OrientationObjectTableBoundaryError,
            normalize_orientation_object_table_boundary_export,
            validate_orientation_object_table_boundary_report,
        )

        mutations = (
            lambda value: value["table_stores"][1].__setitem__("widget_address_point_match_count", 1),
            lambda value: value["type_tables"][1].__setitem__("type_name", "Widget"),
            lambda value: value["claims"].__setitem__("menu_touch_behavior_found", True),
            lambda value: value.__setitem__("instruction_text", []),
        )
        for mutate in mutations:
            candidate = copy.deepcopy(EXPECTED_RAW_EXPORT)
            mutate(candidate)
            with self.subTest(mutate=mutate), self.assertRaises(OrientationObjectTableBoundaryError):
                normalize_orientation_object_table_boundary_export(candidate)

        report = validate_orientation_object_table_boundary_report(json.loads(REPORT.read_text(encoding="utf-8")))
        self.assertFalse(report["installable"])
        self.assertFalse(report["camera_test_eligible"])
        self.assertIn("false lead", report["conclusion"])


class OrientationObjectTableBoundaryExporterTests(unittest.TestCase):
    def _load(self):
        spec = importlib.util.spec_from_file_location("orientation_object_table_boundary_exporter", EXPORTER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_exporter_accepts_only_pinned_static_result(self):
        exporter = self._load()

        class Adapter:
            def metadata(self):
                return copy.deepcopy(exporter.EXPECTED_RAW_EXPORT)

        self.assertEqual(len(exporter.build_raw_export(Adapter())["initializers"]), 2)

    def test_output_rejects_escape_and_symlinked_precreation_ancestor(self):
        exporter = self._load()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary) / "base"
            allowed = base / "allowed"
            base.mkdir(); allowed.mkdir()
            with self.assertRaises(RuntimeError):
                exporter.write_json_atomic(base / "other" / exporter.OUTPUT_NAME, {}, allowed, base)

            outside = Path(temporary) / "outside"
            outside.mkdir()
            linked = base / "linked"
            try:
                linked.symlink_to(outside, target_is_directory=True)
            except OSError:
                self.skipTest("directory symlinks are unavailable")
            with self.assertRaises(RuntimeError):
                exporter.prepare_output_root(linked / "new", base)


if __name__ == "__main__":
    unittest.main()
