"""Fail-closed tests for the bounded orientation/AF helper trace."""
from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "analysis" / "a6400-orientation-af-helper.json"
EXPORTER = ROOT / "tools" / "static" / "export_a6400_orientation_af_helper.py"


class OrientationAfHelperContractTests(unittest.TestCase):
    def test_contract_pins_bounded_wrapper_and_helper_result(self):
        from pmca.analysis.orientation_af_helper import (
            EXPECTED_RAW_EXPORT,
            HELPER,
            MEMBER_INVENTORY,
            normalize_orientation_af_helper_export,
        )

        document = normalize_orientation_af_helper_export(copy.deepcopy(EXPECTED_RAW_EXPORT))
        self.assertEqual(document["member_inventory"], MEMBER_INVENTORY)
        self.assertEqual(MEMBER_INVENTORY["method_count"], 42)
        self.assertEqual(MEMBER_INVENTORY["aggregate_size"], 780)
        self.assertEqual(document["helper"], HELPER)
        self.assertTrue(document["helper"]["executable_prefix_complete"])
        self.assertFalse(document["helper"]["linear_exidx_complete"])
        self.assertEqual(document["helper"]["literal_table_tail_size"], 36)
        self.assertEqual(document["helper_call_inventory"]["typed_member_count"], 42)
        self.assertEqual(document["helper_call_inventory"]["non_member_count"], 20)
        self.assertEqual(len(document["jump_slot_relocation_indices"]), 17)
        self.assertEqual(document["getter_binding"]["direct_site_count"], 15)
        self.assertEqual(document["setter_binding"]["direct_site_count"], 42)
        self.assertFalse(document["claims"]["concrete_widget_type_found"])
        self.assertFalse(document["claims"]["menu_touch_behavior_found"])

    def test_contract_rejects_promoted_type_or_unsafe_data(self):
        from pmca.analysis.orientation_af_helper import (
            EXPECTED_RAW_EXPORT,
            OrientationAfHelperError,
            normalize_orientation_af_helper_export,
        )

        mutations = (
            lambda value: value["helper"].__setitem__("return_storage", 0xB2EFF8),
            lambda value: value["helper"].__setitem__("linear_exidx_complete", True),
            lambda value: value["relocation_summary"].__setitem__("class_ctor_dtor_vtable_rtti_symbol_count", 1),
            lambda value: value["claims"].__setitem__("concrete_widget_type_found", True),
            lambda value: value.__setitem__("instruction_listing", []),
        )
        for mutate in mutations:
            candidate = copy.deepcopy(EXPECTED_RAW_EXPORT)
            mutate(candidate)
            with self.subTest(mutate=mutate), self.assertRaises(OrientationAfHelperError):
                normalize_orientation_af_helper_export(candidate)

    def test_committed_report_stays_noninstallable(self):
        from pmca.analysis.orientation_af_helper import validate_orientation_af_helper_report

        report = validate_orientation_af_helper_report(json.loads(REPORT.read_text(encoding="utf-8")))
        self.assertFalse(report["installable"])
        self.assertFalse(report["camera_test_eligible"])
        self.assertIn("unresolved", report["conclusion"])


class OrientationAfHelperExporterTests(unittest.TestCase):
    def _load(self):
        spec = importlib.util.spec_from_file_location("orientation_af_helper_exporter", EXPORTER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_exporter_accepts_only_pinned_static_result(self):
        exporter = self._load()

        class Adapter:
            def metadata(self):
                return copy.deepcopy(exporter.EXPECTED_RAW_EXPORT)

        self.assertEqual(exporter.build_raw_export(Adapter())["helper"]["address"], 0x35F424)

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
            dangling = base / "dangling"
            try:
                linked.symlink_to(outside, target_is_directory=True)
                dangling.symlink_to(base / "missing", target_is_directory=True)
            except OSError:
                self.skipTest("directory symlinks are unavailable")
            with self.assertRaises(RuntimeError):
                exporter.prepare_output_root(linked / "new", base)
            with self.assertRaises(RuntimeError):
                exporter.prepare_output_root(dangling / "new", base)


if __name__ == "__main__":
    unittest.main()
