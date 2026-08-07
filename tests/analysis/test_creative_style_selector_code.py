"""Fail-closed tests for the typed Creative Style selector-code mapping."""
from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "analysis" / "a6400-creative-style-selector-code.json"
EXPORTER = ROOT / "tools" / "static" / "export_a6400_creative_style_selector_code.py"


class CreativeStyleSelectorCodeContractTests(unittest.TestCase):
    def test_selector_map_is_exact_and_has_one_rejected_index(self):
        from pmca.analysis.creative_style_selector_code import EXPECTED_EXPORT

        element = EXPECTED_EXPORT["typed_element"]
        self.assertEqual(element["getter_cell"], element["vtable_address_point"] + element["getter_slot"] * 4)
        self.assertEqual(element["setter_cell"], element["vtable_address_point"] + element["setter_slot"] * 4)
        self.assertEqual(element["getter_signature"], "getValue(int&,int&,int&,int&,int&,int,int)")
        self.assertEqual(element["setter_signature"], "setValue(int,int,int,int,int)")
        selector = EXPECTED_EXPORT["setter_selector"]
        self.assertEqual(selector["argument_position"], 1)
        self.assertEqual(selector["input_min"], 0)
        self.assertEqual(selector["input_max"], 13)
        self.assertEqual(selector["rejected_indices"], [12])
        self.assertEqual(selector["selector_to_persisted_code"], {
            "0": 1, "1": 2, "2": 3, "3": 7, "4": 8, "5": 9,
            "6": 4, "7": 5, "8": 10, "9": 11, "10": 12,
            "11": 6, "13": 14,
        })

    def test_argument_2_encode_decode_uses_fixed_backup_record(self):
        from pmca.analysis.creative_style_selector_code import EXPECTED_EXPORT

        record = EXPECTED_EXPORT["argument_2_record"]
        self.assertEqual(record["backup_id"], 0x01070762)
        self.assertEqual(record["backup_write_call_site"], 0x489540)
        self.assertEqual(record["storage_width_bytes"], 1)
        self.assertEqual(record["setter_argument_position"], 2)
        self.assertEqual(record["encode"], "nonpositive-to-0xff-positive-n-to-low-byte-of-n-minus-one")
        self.assertEqual(record["getter_decode"], "preinitialized-zero-signed-minus-one-skips-write-otherwise-signed-byte-plus-one")
        self.assertTrue(EXPECTED_EXPORT["claims"]["argument_2_fixed_record_encode_decode_found"])

    def test_selector_code_uses_adjacent_dynamic_record_boundary(self):
        from pmca.analysis.creative_style_selector_code import EXPECTED_EXPORT

        record = EXPECTED_EXPORT["selector_record"]
        self.assertEqual(record["setter_argument_position"], 1)
        self.assertEqual(record["code_byte_store_site"], 0x48953A)
        self.assertEqual(record["backup_write_call_site"], 0x48955A)
        self.assertEqual(record["persistence_condition"], "argument-2-nonzero-path")
        self.assertFalse(record["record_id_semantics_resolved"])
        self.assertTrue(EXPECTED_EXPORT["claims"]["selector_code_dynamic_record_boundary_found"])

    def test_request_keys_are_positional_but_semantics_remain_open(self):
        from pmca.analysis.creative_style_selector_code import EXPECTED_EXPORT

        request = EXPECTED_EXPORT["request_boundary"]
        self.assertEqual(request["param_keys"], [383, 386, 389, 392, 383])
        self.assertEqual(request["param_value_roles"], [
            "selector-code", "argument-3", "argument-4-or-branch-default",
            "argument-5", "selector-code",
        ])
        self.assertEqual(request["argument_3_constructor_call_sites"], [0x4894B8, 0x4894EE])
        self.assertEqual(request["argument_4_value_sources"], {
            "normal_stack_load_site": 0x4894C4,
            "special_default_zero_site": 0x4894FA,
        })
        self.assertEqual(request["argument_4_normal_join_branch_site"], 0x4894C8)
        self.assertEqual(request["argument_5_value_load_site"], 0x489506)
        self.assertFalse(request["human_field_semantics_resolved"])

    def test_selector_dynamic_write_is_not_double_counted_as_an_other_record(self):
        from pmca.analysis.creative_style_selector_code import EXPECTED_EXPORT

        selector_site = EXPECTED_EXPORT["selector_record"]["backup_write_call_site"]
        other = EXPECTED_EXPORT["dynamic_records"]
        self.assertEqual(other["other_backup_write_call_sites"], [0x489574, 0x489588, 0x489598])
        self.assertEqual(other["other_backup_write_count"], 3)
        self.assertNotIn(selector_site, other["other_backup_write_call_sites"])

    def test_getter_fixed_record_does_not_promote_selected_menu_state(self):
        from pmca.analysis.creative_style_selector_code import EXPECTED_EXPORT

        getter = EXPECTED_EXPORT["getter_boundary"]
        self.assertEqual(getter["fixed_backup_read_call_site"], 0x48BA6A)
        self.assertEqual(getter["direct_output_reference_position"], 2)
        self.assertEqual(getter["output_zero_initialization_site"], 0x48B95C)
        self.assertEqual(getter["minus_one_skip_target"], 0x48BA82)
        self.assertEqual(getter["branch_dependent_backup_read_count"], 10)
        self.assertFalse(getter["manager_or_view_output_position_proven"])

    def test_unproven_semantics_cannot_be_promoted(self):
        from pmca.analysis.creative_style_selector_code import (
            CreativeStyleSelectorCodeError,
            EXPECTED_EXPORT,
            normalize_creative_style_selector_code_export,
        )

        for key in (
            "human_style_labels_mapped", "menu_selected_state_join_found",
            "caution_config_selected_state_join_found", "five_argument_semantics_resolved",
            "selector_code_fixed_record_found",
            "renderer_or_output_sink_found", "creative_look_equivalence_found",
            "runtime_execution_proven",
        ):
            self.assertFalse(EXPECTED_EXPORT["claims"][key])
            changed = copy.deepcopy(EXPECTED_EXPORT)
            changed["claims"][key] = True
            with self.subTest(key=key), self.assertRaises(CreativeStyleSelectorCodeError):
                normalize_creative_style_selector_code_export(changed)

    def test_checked_in_report_is_non_installable(self):
        from pmca.analysis.creative_style_selector_code import validate_creative_style_selector_code_report

        report = validate_creative_style_selector_code_report(json.loads(REPORT.read_text(encoding="utf-8")))
        self.assertEqual(report["readiness"], "TYPED_ELEMENT_SELECTOR_MAP_AND_ARGUMENT2_RECORD")
        self.assertFalse(report["camera_executed"])
        self.assertFalse(report["installable"])
        self.assertFalse(report["camera_test_eligible"])


class CreativeStyleSelectorCodeExporterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("creative_style_selector_code_exporter", EXPORTER)
        cls.exporter = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(cls.exporter)

    def test_adapter_is_normalized(self):
        from pmca.analysis.creative_style_selector_code import EXPECTED_EXPORT

        class FakeAdapter:
            def metadata(self):
                return copy.deepcopy(EXPECTED_EXPORT)

        self.assertEqual(self.exporter.build_raw_export(FakeAdapter()), EXPECTED_EXPORT)

    def _real_context(self):
        exporter = self.exporter
        blob = exporter.SOURCE_PATH.read_bytes()
        deps = exporter._dependencies()
        handle = exporter.SOURCE_PATH.open("rb")
        elf = deps["ELFFile"](handle)
        mappings = exporter._mappings(elf)
        plt_symbols = exporter._plt_symbols(elf, blob, mappings)
        return handle, blob, mappings, deps, plt_symbols

    def test_selector_table_mutation_is_rejected(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned source or parser dependencies are unavailable")
        exporter = self.exporter
        handle, blob, mappings, deps, plt_symbols = self._real_context()
        original_at = exporter._at

        def changed_at(local_blob, local_mappings, address, size):
            if (address, size) == (0x48940C, 2):
                return b"\x00\x00"
            return original_at(local_blob, local_mappings, address, size)

        try:
            with mock.patch.object(exporter, "_at", side_effect=changed_at):
                with self.assertRaisesRegex(RuntimeError, "table target"):
                    exporter._validate_selector_cases(blob, mappings, deps, plt_symbols)
        finally:
            handle.close()

    def test_persistence_pointer_mutations_are_rejected(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned source or parser dependencies are unavailable")
        exporter = self.exporter
        handle, blob, mappings, deps, plt_symbols = self._real_context()
        original_instruction = exporter._instruction

        class WrongInstruction:
            def __init__(self, item):
                self._item = item
                self.id = -1
                self.cc = -1

            def __getattr__(self, name):
                return getattr(self._item, name)

        try:
            for changed_site, message in ((0x489534, "argument 2 pointer"), (0x48954E, "selector code pointer")):
                def changed_instruction(local_blob, local_mappings, local_deps, site):
                    item = original_instruction(local_blob, local_mappings, local_deps, site)
                    return WrongInstruction(item) if site == changed_site else item

                with self.subTest(site=changed_site), mock.patch.object(exporter, "_instruction", side_effect=changed_instruction):
                    with self.assertRaisesRegex(RuntimeError, message):
                        exporter._validate_persistence(blob, mappings, deps, plt_symbols)
        finally:
            handle.close()

    def test_getter_decode_and_request_origin_mutations_are_rejected(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned source or parser dependencies are unavailable")
        exporter = self.exporter
        handle, blob, mappings, deps, plt_symbols = self._real_context()
        original_instruction = exporter._instruction

        class WrongInstruction:
            def __init__(self, item):
                self._item = item
                self.id = -1
                self.cc = -1

            def __getattr__(self, name):
                return getattr(self._item, name)

        try:
            for validator, changed_site, message in (
                (exporter._validate_getter, 0x48BA76, "getter argument 2 output"),
                (exporter._validate_request, 0x4894C4, "argument 4 normal input"),
            ):
                def changed_instruction(local_blob, local_mappings, local_deps, site):
                    item = original_instruction(local_blob, local_mappings, local_deps, site)
                    return WrongInstruction(item) if site == changed_site else item

                with self.subTest(site=changed_site), mock.patch.object(exporter, "_instruction", side_effect=changed_instruction):
                    with self.assertRaisesRegex(RuntimeError, message):
                        validator(blob, mappings, deps, plt_symbols)
        finally:
            handle.close()

    def test_cross_boundary_dataflow_mutations_are_rejected(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned source or parser dependencies are unavailable")
        exporter = self.exporter
        handle, blob, mappings, deps, plt_symbols = self._real_context()
        original_decode = exporter._decode
        original_instruction = exporter._instruction

        class RegisterClobber:
            def __init__(self, register):
                self.register = register

            def regs_access(self):
                return [], [self.register]

        class WrongInstruction:
            def __init__(self, item):
                self._item = item
                self.id = -1

            def __getattr__(self, name):
                return getattr(self._item, name)

        def changed_decode(local_blob, local_mappings, local_deps, start, end, *, complete=True):
            items = original_decode(local_blob, local_mappings, local_deps, start, end, complete=complete)
            if (start, end) == (0x4894AE, 0x4894C8):
                return [RegisterClobber(deps["r4"]), *items]
            return items

        try:
            with mock.patch.object(exporter, "_decode", side_effect=changed_decode):
                with self.assertRaisesRegex(RuntimeError, "selector holder preservation"):
                    exporter._validate_persistence(blob, mappings, deps, plt_symbols)

            for validator, changed_site, message in (
                (exporter._validate_getter, 0x48BA66, "getter read-buffer pointer"),
                (exporter._validate_request, 0x4895F2, "request model argument"),
            ):
                def changed_instruction(local_blob, local_mappings, local_deps, site):
                    item = original_instruction(local_blob, local_mappings, local_deps, site)
                    return WrongInstruction(item) if site == changed_site else item

                with self.subTest(site=changed_site), mock.patch.object(exporter, "_instruction", side_effect=changed_instruction):
                    with self.assertRaisesRegex(RuntimeError, message):
                        validator(blob, mappings, deps, plt_symbols)
        finally:
            handle.close()

    def test_real_export_matches_when_available(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned source or parser dependencies are unavailable")
        self.assertEqual(self.exporter.build_raw_export(), self.exporter.EXPECTED_EXPORT)


if __name__ == "__main__":
    unittest.main()
