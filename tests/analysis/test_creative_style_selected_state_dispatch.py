"""Fail-closed tests for Creative Style selected-state dispatch evidence."""
from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "analysis" / "a6400-creative-style-selected-state-dispatch.json"
EXPORTER = ROOT / "tools" / "static" / "export_a6400_creative_style_selected_state_dispatch.py"


class CreativeStyleSelectedStateDispatchContractTests(unittest.TestCase):
    def test_contract_separates_product_selector_from_user_selection(self):
        from pmca.analysis.creative_style_selected_state_dispatch import (
            EXPECTED_RAW_EXPORT,
            normalize_creative_style_selected_state_dispatch_export,
        )

        document = normalize_creative_style_selected_state_dispatch_export(
            copy.deepcopy(EXPECTED_RAW_EXPORT)
        )
        binding = document["product_graph_selector"]["backup_read_binding"]
        self.assertEqual(binding["symbol"], "_ZN13BackupManager9Bkup_ReadEiPv")
        self.assertEqual(binding["plt"], 0x7B81A0)
        self.assertEqual(binding["got"], 0xB0E5D4)
        self.assertEqual(binding["relocation_index"], 2304)

        selectors = document["product_graph_selector"]["selectors"]
        self.assertEqual([item["owner"] for item in selectors], [0x7DB958, 0x7DBC04])
        self.assertEqual([item["call_site"] for item in selectors], [0x7DB970, 0x7DBC1C])
        self.assertTrue(all(item["backup_id"] == 0x01070316 for item in selectors))
        self.assertEqual(
            [item["output"] for item in selectors],
            [
                {"kind": "stack-local", "width": 1, "zero_initialized": True, "zero_init_site": 0x7DB96C, "readback_site": 0x7DB978, "same_storage": True, "write_before_call": True, "read_after_call": True, "pre_call_straight_line": True},
                {"kind": "stack-local", "width": 1, "zero_initialized": True, "zero_init_site": 0x7DBC18, "readback_site": 0x7DBC24, "same_storage": True, "write_before_call": True, "read_after_call": True, "pre_call_straight_line": True},
            ],
        )
        self.assertEqual(
            document["product_graph_selector"]["classification"],
            "shared-product-menu-graph-selector",
        )
        self.assertFalse(document["product_graph_selector"]["is_current_user_selection"])

    def test_contract_pins_selected_state_virtual_dispatch(self):
        from pmca.analysis.creative_style_selected_state_dispatch import (
            EXPECTED_RAW_EXPORT,
            normalize_creative_style_selected_state_dispatch_export,
        )

        document = normalize_creative_style_selected_state_dispatch_export(
            copy.deepcopy(EXPECTED_RAW_EXPORT)
        )
        edges = document["selected_state_dispatch"]["edges"]
        self.assertEqual(len(edges), 22)
        grouped = {}
        for edge in edges:
            grouped.setdefault(edge["caller_table_word"], []).append(edge["target_table_word"])
            self.assertEqual(edge["dispatch"], "indirect-vtable")
        self.assertEqual(
            grouped,
            {
                12: [62],
                14: [12, 19],
                22: [15, 21],
                23: [16, 21],
                40: [15, 39],
                41: [16, 39],
                48: [9, 12, 63],
                49: [15, 48],
                50: [16, 48],
                51: [14, 16, 48],
                58: [64],
            },
        )
        self.assertEqual(document["selected_state_dispatch"]["local_leaf_table_words"], [13, 21, 39, 62, 63])
        self.assertTrue(document["selected_state_dispatch"]["method_decode_complete"])
        self.assertTrue(document["selected_state_dispatch"]["reported_sites_cfg_reachable"])
        self.assertTrue(document["selected_state_dispatch"]["receiver_identity_checked"])
        self.assertTrue(document["selected_state_dispatch"]["unhandled_register_writes_invalidated"])
        self.assertEqual(
            document["selected_state_dispatch"]["bounded_table_branch"],
            {"caller_table_word": 63, "site": 0x7C7304, "entry_count": 7, "data_start": 0x7C7308, "data_end": 0x7C730F, "resume": 0x7C7310, "targets": [0x7C7314, 0x7C731C, 0x7C7320, 0x7C7328]},
        )
        fields = document["selected_state_dispatch"]["field_accesses"]
        self.assertEqual([item["offset"] for item in fields], [0x18, 0x20, 0x24])
        self.assertTrue(all(item["width"] == 4 for item in fields))
        self.assertEqual(
            document["selected_state_dispatch"]["unresolved_callback_sites"],
            [0x7C6C44, 0x7C6D78, 0x7C6D9C, 0x7C6F60, 0x7C6F82, 0x7C7090, 0x7C709E, 0x7C70F2, 0x7C7114, 0x7C7152],
        )
        self.assertTrue(document["claims"]["generic_selected_state_dispatch_found"])
        self.assertTrue(document["claims"]["creative_style_vtable_binding_found"])
        self.assertTrue(document["claims"]["in_memory_selection_state_fields_found"])
        self.assertFalse(document["claims"]["selected_model_value_storage_found"])
        self.assertFalse(document["claims"]["resolved_object_callback_binding_found"])

    def test_contract_rejects_behavior_promotion_and_reconstructive_fields(self):
        from pmca.analysis.creative_style_selected_state_dispatch import (
            CreativeStyleSelectedStateDispatchError,
            EXPECTED_RAW_EXPORT,
            normalize_creative_style_selected_state_dispatch_export,
            validate_creative_style_selected_state_dispatch_report,
        )

        mutations = (
            lambda value: value["product_graph_selector"].__setitem__("is_current_user_selection", True),
            lambda value: value["selected_state_dispatch"]["edges"][0].__setitem__("dispatch", "direct"),
            lambda value: value["claims"].__setitem__("commit_or_persistence_found", True),
            lambda value: value.__setitem__("instruction_text", []),
        )
        for mutate in mutations:
            candidate = copy.deepcopy(EXPECTED_RAW_EXPORT)
            mutate(candidate)
            with self.subTest(mutate=mutate), self.assertRaises(CreativeStyleSelectedStateDispatchError):
                normalize_creative_style_selected_state_dispatch_export(candidate)

        report = validate_creative_style_selected_state_dispatch_report(
            json.loads(REPORT.read_text(encoding="utf-8"))
        )
        self.assertEqual(report["readiness"], "GENERIC_SELECTED_STATE_DISPATCH_ONLY")
        self.assertFalse(report["installable"])
        self.assertFalse(report["camera_test_eligible"])
        self.assertFalse(report["claims"]["model_value_path_found"])
        self.assertFalse(report["claims"]["renderer_binding_found"])


class CreativeStyleSelectedStateDispatchExporterTests(unittest.TestCase):
    def _load(self):
        spec = importlib.util.spec_from_file_location(
            "creative_style_selected_state_dispatch_exporter", EXPORTER
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_exporter_accepts_only_pinned_static_result(self):
        exporter = self._load()

        class Adapter:
            def metadata(self):
                return copy.deepcopy(exporter.EXPECTED_RAW_EXPORT)

        document = exporter.build_raw_export(Adapter())
        self.assertEqual(len(document["selected_state_dispatch"]["edges"]), 22)
        self.assertEqual(
            document["product_graph_selector"]["selectors"][0]["backup_id"],
            0x01070316,
        )

    def test_non_branch_pc_write_is_terminal(self):
        exporter = self._load()

        class Item:
            def __init__(self, groups, writes):
                self.groups = set(groups)
                self.writes = writes

            def group(self, group):
                return group in self.groups

            def regs_access(self):
                return [], self.writes

        call_group, jump_group, pc = 1, 2, 15
        self.assertTrue(exporter._non_branch_pc_write_is_terminal(Item([], [pc]), call_group, jump_group, pc))
        self.assertFalse(exporter._non_branch_pc_write_is_terminal(Item([call_group], [pc]), call_group, jump_group, pc))
        self.assertFalse(exporter._non_branch_pc_write_is_terminal(Item([jump_group], [pc]), call_group, jump_group, pc))

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
