"""Fail-closed tests for the α6400 touchpad terminal boundary."""
from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from pmca.analysis.touchpad_terminal_boundary import (
    TouchpadTerminalBoundaryError,
    normalize_touchpad_terminal_export,
    validate_touchpad_terminal_report,
)

ROOT = Path(__file__).resolve().parents[2]
EXPORTER = ROOT / "tools" / "static" / "export_a6400_touchpad_terminal_boundary.py"
REPORT = ROOT / "analysis" / "a6400-touchpad-terminal-boundary.json"


def raw():
    return {
        "program": "viewUnified2.so",
        "sha256": "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2",
        "file_size": 11530552,
        "analysis_mode": {"read_only": True, "static_elf_metadata": True, "thumb_control_flow": True},
        "program_changed": False,
        "prior_ui_graph_sha256": "d19fc94fd52583f3d321535fd8b6a01aa03f4efc0c4dadde52adce3a9d246f22",
        "verified_path_edges": [
            {"owner": "0x22355e", "site": "0x223b36", "target": "0x21c644"},
            {"owner": "0x21c644", "site": "0x21c770", "target": "0x1626cc"},
        ],
        "owners": [
            {"owner": "0x162608", "end": "0x162760"},
            {"owner": "0x41b244", "end": "0x41b290"},
            {"owner": "0x41add8", "end": "0x41ae68"},
            {"owner": "0x2b3f7c", "end": "0x2b3f98"},
        ],
        "owner_dynamic_relocations": [],
        "owner_dynamic_symbols": [],
        "internal_edges": [{"owner": "0x41b244", "site": "0x41b24e", "target": "0x2b3f7c"}],
        "callee_direct_call_count": 0,
        "reverse_reference_scan": {"rel_dyn_count": 137966, "matching_relative_addends": []},
        "plt_bindings": [
            {"relocation_index": 43, "got_address": "0x944758", "plt_address": "0x14e6c8", "symbol": "InputService::forceReleaseTp"},
            {"relocation_index": 154, "got_address": "0x944914", "plt_address": "0x14ecac", "symbol": "InputService::setTpEnableArea"},
            {"relocation_index": 1730, "got_address": "0x9461b4", "plt_address": "0x15404c", "symbol": "CmnViewTPAreaEnableUtil::setTouchPadEnableAreaToOff"},
            {"relocation_index": 2101, "got_address": "0x946780", "plt_address": "0x1553f4", "symbol": "CmnViewTPAreaEnableUtil::setTouchPadEnabAreaForEvfOn"},
        ],
        "owner_direct_plt_calls": [],
        "truncated": False,
    }


def exporter_module():
    spec = importlib.util.spec_from_file_location("touchpad_terminal_exporter", EXPORTER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TouchpadTerminalBoundaryTests(unittest.TestCase):
    def test_exact_boundary_normalizes_fail_closed(self):
        summary = normalize_touchpad_terminal_export(raw())
        self.assertEqual(summary["owner_count"], 4)
        self.assertEqual(summary["reverse_reference_count"], 0)
        self.assertFalse(summary["claims"]["touch_configuration_found"])

    def test_fabricated_path_or_behavior_is_rejected(self):
        for mutate in (
            lambda item: item["verified_path_edges"].append({"owner": "0x41b244", "site": "0x41b260", "target": "0x41ae08"}),
            lambda item: item["owner_dynamic_relocations"].append({"bad": True}),
            lambda item: item["reverse_reference_scan"].update(rel_dyn_count=1),
            lambda item: item["reverse_reference_scan"]["matching_relative_addends"].append("0x162608"),
            lambda item: item.update(callee_direct_call_count=1),
            lambda item: item["owner_direct_plt_calls"].append({"bad": True}),
            lambda item: item["plt_bindings"][0].update(plt_address="0x0"),
            lambda item: item.update(raw_bytes="forbidden"),
        ):
            candidate = raw(); mutate(candidate)
            with self.subTest(mutate=mutate), self.assertRaises(TouchpadTerminalBoundaryError):
                normalize_touchpad_terminal_export(candidate)

    def test_committed_report_is_pinned_and_does_not_promote_touch_behavior(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertEqual(validate_touchpad_terminal_report(report), report)
        forged = copy.deepcopy(report)
        forged["claims"]["touch_configuration_found"] = True
        with self.assertRaises(TouchpadTerminalBoundaryError):
            validate_touchpad_terminal_report(forged)


class ExporterTests(unittest.TestCase):
    def test_output_is_contained_and_rejects_symlink_root(self):
        module = exporter_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); base = root / "base"; allowed = base / "allowed"; denied = base / "denied"
            base.mkdir(); allowed.mkdir(); denied.mkdir()
            with self.assertRaises(RuntimeError):
                module.write_json_atomic(denied / "raw-touchpad-terminal-boundary.json", {}, allowed, base)
            dangling = base / "dangling"
            try:
                dangling.symlink_to(root / "missing", target_is_directory=True)
            except OSError as exc:
                self.skipTest("Windows cannot create test symlinks: %s" % exc)
            with self.assertRaises(RuntimeError):
                module.write_json_atomic(dangling / "raw-touchpad-terminal-boundary.json", {}, dangling, base)

    def test_output_rejects_symlinked_ancestor_even_when_leaf_is_directory(self):
        module = exporter_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); base = root / "base"; outside = root / "outside"
            base.mkdir(); outside.mkdir()
            linked = base / "link"
            try:
                linked.symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                self.skipTest("Windows cannot create test symlinks: %s" % exc)
            escaped_leaf = linked / "leaf"; escaped_leaf.mkdir()
            with self.assertRaises(RuntimeError):
                module.write_json_atomic(
                    escaped_leaf / "raw-touchpad-terminal-boundary.json", {}, escaped_leaf, base
                )

    def test_prepare_output_root_rejects_symlinked_or_dangling_parent_before_creation(self):
        module = exporter_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); base = root / "base"; outside = root / "outside"
            base.mkdir(); outside.mkdir()
            linked = base / "trace"
            try:
                linked.symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                self.skipTest("Windows cannot create test symlinks: %s" % exc)
            escaped_leaf = linked / "a6400-v2.00"
            with self.assertRaises(RuntimeError):
                module.prepare_output_root(escaped_leaf, base)
            self.assertFalse((outside / "a6400-v2.00").exists())

            dangling = base / "dangling"
            dangling.symlink_to(root / "missing", target_is_directory=True)
            with self.assertRaises(RuntimeError):
                module.prepare_output_root(dangling / "a6400-v2.00", base)

    @unittest.skipUnless(exporter_module().capstone_available(), "local Capstone decoder unavailable")
    def test_live_export_decodes_complete_owners_without_touch_api_call(self):
        document = exporter_module().build_raw_export()
        self.assertEqual(document["owner_direct_plt_calls"], [])
        self.assertEqual(document["reverse_reference_scan"]["rel_dyn_count"], 137966)


if __name__ == "__main__":
    unittest.main()
