"""Fail-closed tests for the α6400 bounded touch API caller inventory."""
from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from pmca.analysis.touch_api_callers import (
    API_BINDINGS, CALLERS, PRIOR_UI_GRAPH_SHA256, ROOTS, TouchApiCallersError,
    normalize_touch_api_callers_export, validate_touch_api_callers_report,
)

ROOT = Path(__file__).resolve().parents[2]
EXPORTER = ROOT / "tools" / "static" / "export_a6400_touch_api_callers.py"
REPORT = ROOT / "analysis" / "a6400-touch-api-callers.json"


def raw():
    return {
        "program": "viewUnified2.so", "sha256": "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2", "file_size": 11530552,
        "analysis_mode": {"read_only": True, "static_elf_metadata": True, "thumb_control_flow": True}, "program_changed": False,
        "prior_ui_graph_sha256": PRIOR_UI_GRAPH_SHA256, "api_bindings": copy.deepcopy(API_BINDINGS), "callers": copy.deepcopy(CALLERS),
        "owner_accounting": {"complete_owner_count": 28869, "incomplete_owner_count": 1593, "terminal_unbounded_owner_count": 1},
        "root_paths": [{"root": root, "depth_cap": 32, "known_caller_count": 23, "paths": []} for root in ROOTS],
        "prior_traversal": {"edge_count": 2046, "known_caller_owner_hits": []}, "truncated": False,
    }


def exporter_module():
    spec = importlib.util.spec_from_file_location("touch_api_callers_exporter", EXPORTER)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


class TouchApiCallerTests(unittest.TestCase):
    def test_normalizes_only_the_pinned_six_api_inventory(self):
        document = raw(); document["callers"] = []
        with self.assertRaises(TouchApiCallersError):
            normalize_touch_api_callers_export(document)

    def test_exact_inventory_normalizes_without_promoting_menu_touch(self):
        summary = normalize_touch_api_callers_export(raw())
        self.assertEqual((summary["api_count"], summary["caller_count"]), (6, 23))
        self.assertTrue(summary["claims"]["shooting_focus_coordinate_api_found"])
        self.assertFalse(summary["claims"]["menu_touch_coordinate_route_found"])

    def test_incomplete_and_terminal_owner_accounting_cannot_be_forged(self):
        for key in ("complete_owner_count", "incomplete_owner_count", "terminal_unbounded_owner_count"):
            document = raw(); document["owner_accounting"][key] += 1
            with self.subTest(key=key), self.assertRaises(TouchApiCallersError):
                normalize_touch_api_callers_export(document)

    def test_committed_report_is_pinned_and_keeps_selection_unresolved(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertEqual(validate_touch_api_callers_report(report), report)
        forged = copy.deepcopy(report); forged["claims"]["selection_dispatch_found"] = True
        with self.assertRaises(TouchApiCallersError): validate_touch_api_callers_report(forged)


class ExporterTests(unittest.TestCase):
    def test_output_rejects_precreation_symlink_escape(self):
        module = exporter_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); base = root / "base"; outside = root / "outside"; base.mkdir(); outside.mkdir(); linked = base / "trace"
            try: linked.symlink_to(outside, target_is_directory=True)
            except OSError as exc: self.skipTest("Windows cannot create test symlinks: %s" % exc)
            with self.assertRaises(RuntimeError): module.prepare_output_root(linked / "a6400-v2.00", base)
            self.assertFalse((outside / "a6400-v2.00").exists())

    def test_output_rejects_dangling_symlink_ancestor_before_creation(self):
        module = exporter_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); base = root / "base"; base.mkdir(); dangling = base / "dangling"
            try: dangling.symlink_to(root / "missing", target_is_directory=True)
            except OSError as exc: self.skipTest("Windows cannot create test symlinks: %s" % exc)
            with self.assertRaises(RuntimeError): module.prepare_output_root(dangling / "a6400-v2.00", base)

    @unittest.skipUnless(exporter_module().capstone_available(), "local Capstone decoder unavailable")
    def test_live_export_derives_exact_caller_inventory(self):
        document = exporter_module().build_raw_export()
        self.assertEqual(document["callers"], CALLERS)
        self.assertEqual(document["owner_accounting"], {"complete_owner_count": 28869, "incomplete_owner_count": 1593, "terminal_unbounded_owner_count": 1})


if __name__ == "__main__":
    unittest.main()
