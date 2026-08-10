"""Fail-closed tests for the α6400 generic widget hit-test vtable family."""
from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "analysis" / "a6400-widget-hit-test-vtables.json"
EXPORTER = ROOT / "tools" / "static" / "export_a6400_widget_hit_test_vtables.py"


class WidgetHitTestVtableTests(unittest.TestCase):
    def test_exact_generic_hit_test_family_normalizes_without_promoting_menu_behavior(self):
        from pmca.analysis.widget_hit_test_vtables import (
            EXPECTED_RAW_EXPORT,
            normalize_widget_hit_test_vtables_export,
        )

        summary = normalize_widget_hit_test_vtables_export(copy.deepcopy(EXPECTED_RAW_EXPORT))
        self.assertEqual(summary["family_count"], 407)
        self.assertEqual(summary["sys_is_hit_reference_count"], 407)
        self.assertEqual(summary["is_hit_reference_count"], 407)
        self.assertEqual(summary["typed_rtti_table_count"], 1)
        self.assertFalse(summary["claims"]["menu_touch_selection_found"])

    def test_normalizer_rejects_nonadjacent_families_identity_promotion_and_unsafe_evidence(self):
        from pmca.analysis.widget_hit_test_vtables import (
            EXPECTED_RAW_EXPORT,
            WidgetHitTestVtablesError,
            normalize_widget_hit_test_vtables_export,
        )

        mutations = (
            lambda value: value["families"][0].__setitem__("is_hit_address", value["families"][0]["is_hit_address"] + 4),
            lambda value: value["families"][0].__setitem__("rtti_type", "fabricated"),
            lambda value: value["typed_layoutable_widget_base"]["sys_is_hit_slot"].__setitem__("relocation_index", 1),
            lambda value: value["set_hit_margin_summary"].__setitem__("family_count", 398),
            lambda value: value["prior_touch_api_callers"].__setitem__("artifact_sha256", "0" * 64),
            lambda value: value["claims"].__setitem__("menu_touch_selection_found", True),
            lambda value: value.__setitem__("disassembly", []),
        )
        for mutate in mutations:
            candidate = copy.deepcopy(EXPECTED_RAW_EXPORT)
            mutate(candidate)
            with self.subTest(mutate=mutate), self.assertRaises(WidgetHitTestVtablesError):
                normalize_widget_hit_test_vtables_export(candidate)

    def test_committed_report_is_noninstallable_and_retains_empty_ordered_touch_roots(self):
        from pmca.analysis.widget_hit_test_vtables import validate_widget_hit_test_vtables_report

        report = validate_widget_hit_test_vtables_report(json.loads(REPORT.read_text(encoding="utf-8")))
        self.assertFalse(report["installable"])
        self.assertFalse(report["camera_test_eligible"])
        self.assertEqual(report["ordered_root_paths"], {"touchpad_terminal_paths": [], "touch_api_caller_paths": []})
        self.assertIn("unresolved", report["conclusion"])


class WidgetHitTestVtableExporterTests(unittest.TestCase):
    def _load(self):
        spec = importlib.util.spec_from_file_location("widget_hit_test_vtables_exporter", EXPORTER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_exporter_accepts_only_the_pinned_static_adapter_result(self):
        exporter = self._load()

        class Adapter:
            def metadata(self):
                return copy.deepcopy(exporter.EXPECTED_RAW_EXPORT)

        document = exporter.build_raw_export(Adapter())
        self.assertEqual(len(document["families"]), 407)
        self.assertEqual(document["typed_layoutable_widget_base"]["class_name"], "LayoutableWidgetBase")

    def test_output_rejects_escape_and_symlinked_precreation_ancestor(self):
        exporter = self._load()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base, allowed, denied = root / "base", root / "base" / "allowed", root / "base" / "denied"
            base.mkdir(); allowed.mkdir(); denied.mkdir()
            with self.assertRaises(RuntimeError):
                exporter.write_json_atomic(denied / exporter.OUTPUT_NAME, {}, allowed, base)
            link = base / "trace"
            try:
                link.symlink_to(root / "outside", target_is_directory=True)
            except OSError as exc:
                self.skipTest("Windows cannot create test symlinks: %s" % exc)
            with self.assertRaises(RuntimeError):
                exporter.prepare_output_root(link / "a6400-v2.00", base)


if __name__ == "__main__":
    unittest.main()
