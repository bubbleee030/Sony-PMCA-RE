"""Fail-closed tests for the bounded Widget::isHit dispatch trace."""
from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "analysis" / "a6400-widget-ishit-dispatch.json"
EXPORTER = ROOT / "tools" / "static" / "export_a6400_widget_ishit_dispatch.py"


class WidgetIsHitDispatchTests(unittest.TestCase):
    def test_contract_accepts_only_ten_generic_slot37_dispatches(self):
        from pmca.analysis.widget_ishit_dispatch import (
            ANALYSIS_LOAD_BIAS,
            DEFINED_PLT_BINDING,
            EXPECTED_RAW_EXPORT,
            ROOT_RECORDS,
            ROOT_PATHS,
            TOUCH_REVERSE_PATHS,
            TOUCH_OWNER_RECORDS,
            normalize_widget_ishit_dispatch_export,
        )

        document = normalize_widget_ishit_dispatch_export(copy.deepcopy(EXPECTED_RAW_EXPORT))
        self.assertEqual(len(document["dispatches"]), 10)
        self.assertEqual(document["slot_offset"], 0x94)
        self.assertEqual(document["coverage"]["total_exidx_entry_count"], 30463)
        self.assertEqual(document["defined_plt_binding"], DEFINED_PLT_BINDING)
        self.assertEqual(document["path_summary"]["root_paths"], list(ROOT_PATHS))
        self.assertEqual(len(document["path_summary"]["root_paths"]), 2)
        self.assertEqual(document["path_summary"]["touch_paths_forward"], [])
        self.assertEqual(document["path_summary"]["touch_paths_reverse"], list(TOUCH_REVERSE_PATHS))
        self.assertEqual(len(document["path_summary"]["touch_paths_reverse"]), 2)
        self.assertEqual(document["path_summary"]["analysis_load_bias"], ANALYSIS_LOAD_BIAS)
        self.assertEqual(document["path_summary"]["roots"], list(ROOT_RECORDS))
        self.assertEqual(document["path_summary"]["touch_api_caller_owners"], list(TOUCH_OWNER_RECORDS))
        self.assertTrue(all(item["analysis_address"] - item["elf_address"] == ANALYSIS_LOAD_BIAS for item in ROOT_RECORDS))
        self.assertTrue(all(item["analysis_address"] - item["elf_address"] == ANALYSIS_LOAD_BIAS for item in TOUCH_OWNER_RECORDS))
        self.assertFalse(document["claims"]["menu_touch_selection_found"])

    def test_contract_rejects_fabricated_widget_identity_paths_and_unsafe_fields(self):
        from pmca.analysis.widget_ishit_dispatch import (
            EXPECTED_RAW_EXPORT,
            WidgetIsHitDispatchError,
            normalize_widget_ishit_dispatch_export,
        )

        mutations = (
            lambda value: value["dispatches"][0].__setitem__("slot_load", 0x310D08),
            lambda value: value["path_summary"]["root_paths"][0]["edges"][0].__setitem__("site", 0x2138A2),
            lambda value: value["defined_plt_binding"].__setitem__("plt_address", 0x14F200),
            lambda value: value["claims"].__setitem__("concrete_widget_identity_found", True),
            lambda value: value.__setitem__("instruction_text", []),
        )
        for mutate in mutations:
            candidate = copy.deepcopy(EXPECTED_RAW_EXPORT)
            mutate(candidate)
            with self.subTest(mutate=mutate), self.assertRaises(WidgetIsHitDispatchError):
                normalize_widget_ishit_dispatch_export(candidate)

    def test_committed_report_is_generic_only_and_noninstallable(self):
        from pmca.analysis.widget_ishit_dispatch import validate_widget_ishit_dispatch_report

        report = validate_widget_ishit_dispatch_report(json.loads(REPORT.read_text(encoding="utf-8")))
        self.assertFalse(report["installable"])
        self.assertFalse(report["camera_test_eligible"])
        self.assertEqual(report["dispatch_summary"]["accepted_count"], 10)
        self.assertIn("unresolved", report["conclusion"])


class WidgetIsHitDispatchExporterTests(unittest.TestCase):
    def _load(self):
        spec = importlib.util.spec_from_file_location("widget_ishit_dispatch_exporter", EXPORTER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_exporter_accepts_only_the_pinned_static_result(self):
        exporter = self._load()

        class Adapter:
            def metadata(self):
                return copy.deepcopy(exporter.EXPECTED_RAW_EXPORT)

        self.assertEqual(len(exporter.build_raw_export(Adapter())["dispatches"]), 10)

    def test_prior_evidence_derives_both_address_domains_and_rejects_a_bad_mapping(self):
        exporter = self._load()
        ui_document = json.loads(exporter.UI_DISPATCH.read_text(encoding="utf-8"))
        touch_document = json.loads(exporter.TOUCH_CALLERS.read_text(encoding="utf-8"))

        roots, owners = exporter.path_records_from_prior(ui_document, touch_document)
        self.assertEqual(roots, exporter.ROOT_RECORDS)
        self.assertEqual(owners, exporter.TOUCH_OWNER_RECORDS)

        ui_document["roots"][0]["analysis_address"] += 2
        with self.assertRaises(RuntimeError):
            exporter.path_records_from_prior(ui_document, touch_document)

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
