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

    def test_dynamic_write_geometry_uses_initialized_numeric_record_tables(self):
        from pmca.analysis.creative_style_selector_code import EXPECTED_EXPORT

        dynamic = EXPECTED_EXPORT["dynamic_records"]
        self.assertEqual(
            [
                (
                    item["role"], item["backup_write_call_site"],
                    item["record_id_effective_byte_offset"],
                    item["record_id_argument_2_scale"], item["value_local_offset"],
                )
                for item in dynamic["writes"]
            ],
            [
                ("selector-code", 0x48955A, 0xF8, 4, 0x11E),
                ("argument-3", 0x489574, 0xDC, 4, 0x4),
                ("argument-4", 0x489588, 0x8C, 4, 0x140),
                ("argument-5", 0x489598, 0x3C, 4, 0x144),
            ],
        )
        self.assertEqual(dynamic["argument_2_plus_13_site"], 0x48955E)
        self.assertEqual(dynamic["argument_2_plus_13_scaled_site"], 0x489562)
        self.assertEqual(dynamic["writes"][0]["id_index_semantics"], "four-times-original-argument-2")
        self.assertEqual(dynamic["writes"][1]["id_index_semantics"], "four-times-(argument-2-plus-13)")
        self.assertEqual(dynamic["writes"][2]["id_index_semantics"], "four-times-(argument-2-plus-13)")
        self.assertEqual(dynamic["writes"][3]["id_index_semantics"], "four-times-(argument-2-plus-13)")
        self.assertTrue(dynamic["numeric_record_ids_resolved"])
        self.assertTrue(dynamic["record_id_source_initialization_resolved"])
        self.assertFalse(dynamic["record_id_human_semantics_resolved"])
        self.assertTrue(EXPECTED_EXPORT["claims"]["dynamic_record_geometry_found"])
        self.assertTrue(EXPECTED_EXPORT["claims"]["branch_dependent_getter_buffer_geometry_found"])
        self.assertTrue(EXPECTED_EXPORT["claims"]["dynamic_record_ids_resolved"])
        self.assertTrue(EXPECTED_EXPORT["claims"]["record_id_source_initialization_resolved"])
        self.assertTrue(EXPECTED_EXPORT["claims"]["static_setter_getter_family_join_found"])
        self.assertFalse(EXPECTED_EXPORT["claims"]["dynamic_setter_getter_record_join_found"])

    def test_static_record_id_tables_are_value_identical_across_setter_and_getter(self):
        from pmca.analysis.creative_style_selector_code import EXPECTED_EXPORT

        tables = EXPECTED_EXPORT["record_id_tables"]
        self.assertEqual(tables["rodata_range"], {"start": 0x666968, "end": 0x812DEE})
        self.assertEqual(tables["total_row_count"], 67)
        self.assertEqual(
            [
                (
                    item["role"], item["row_count"],
                    item["setter"]["source"], item["setter"]["destination_offset"],
                    item["getter"]["source"], item["getter"]["destination_offset"],
                )
                for item in tables["families"]
            ],
            [
                ("selector-code", 7, 0x7B8560, 0xF8, 0x7B8544, 0xF8),
                ("argument-3", 20, 0x7B82F8, 0xA8, 0x7B84F4, 0xA8),
                ("argument-4", 20, 0x7B8348, 0x58, 0x7B857C, 0x58),
                ("argument-5", 20, 0x7B8398, 0x08, 0x7B85CC, 0x08),
            ],
        )
        self.assertEqual(
            [item["record_ids"] for item in tables["families"]],
            [
                [0xFFFFFFFF, 0x0107075C, 0x0107075D, 0x0107075E, 0x0107075F, 0x01070760, 0x01070761],
                [0xFFFFFFFF, 0x01070735, 0x01070736, 0x0107073A, 0x0107073B, 0x0107073C, 0x0107073D, 0x0107073E, 0x0107073F, 0x01070740, 0x01070741, 0x01070737, 0x01070738, 0x01070739, 0x01070A0F, 0x01070A10, 0x01070A11, 0x01070A12, 0x01070A13, 0x01070A14],
                [0xFFFFFFFF, 0x01070742, 0x01070743, 0x01070747, 0x01070748, 0x01070749, 0x0107074A, 0x0107074B, 0x0107074C, 0x0107074D, 0x0107074E, 0x01070744, 0x01070745, 0x01070746, 0x01070A15, 0x01070A16, 0x01070A17, 0x01070A18, 0x01070A19, 0x01070A1A],
                [0xFFFFFFFF, 0x0107074F, 0x01070750, 0x01070754, 0x01070755, 0x01070756, 0x01070757, 0x01070758, 0x01070759, 0x0107075A, 0x0107075B, 0x01070751, 0x01070752, 0x01070753, 0x01070A1B, 0x01070A1C, 0x01070A1D, 0x01070A1E, 0x01070A1F, 0x01070A20],
            ],
        )
        self.assertTrue(all(item["setter_getter_values_equal"] for item in tables["families"]))
        self.assertTrue(tables["static_family_value_join_found"])
        self.assertFalse(tables["runtime_index_equality_proven"])
        self.assertFalse(tables["runtime_write_read_transaction_proven"])

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
            "dynamic_setter_getter_record_join_found",
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
        self.assertEqual(report["readiness"], "TYPED_ELEMENT_SELECTOR_AND_STATIC_RECORD_TABLES")
        self.assertFalse(report["camera_executed"])
        self.assertFalse(report["installable"])
        self.assertFalse(report["camera_test_eligible"])

    def test_report_builder_produces_the_validated_checked_in_contract(self):
        import pmca.analysis.creative_style_selector_code as selector_code

        builder = getattr(selector_code, "build_creative_style_selector_code_report", None)
        self.assertIsNotNone(builder)
        report = builder(selector_code.EXPECTED_EXPORT)
        self.assertEqual(
            selector_code.validate_creative_style_selector_code_report(report), report
        )
        self.assertEqual(report["readiness"], "TYPED_ELEMENT_SELECTOR_AND_STATIC_RECORD_TABLES")
        self.assertEqual(report["summary"]["record_id_table_family_count"], 4)
        self.assertEqual(report["summary"]["record_id_table_row_count"], 67)


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

    def test_dynamic_record_and_getter_buffer_mutations_are_rejected(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned source or parser dependencies are unavailable")
        exporter = self.exporter
        handle, blob, mappings, deps, plt_symbols = self._real_context()
        original_instruction = exporter._instruction
        original_decode = exporter._decode

        class WrongInstruction:
            def __init__(self, item):
                self._item = item
                self.id = -1

            def __getattr__(self, name):
                return getattr(self._item, name)

        class RegisterClobber:
            def __init__(self, register):
                self.register = register

            def regs_access(self):
                return [], [self.register]

        try:
            for validator, changed_site, message in (
                (exporter._validate_dynamic_records, 0x48955E, "plus-13"),
                (exporter._validate_dynamic_records, 0x489562, "scaled argument-2"),
                (exporter._validate_dynamic_records, 0x48956A, "record ID index"),
                (exporter._validate_dynamic_records, 0x489580, "record ID index"),
                (exporter._validate_dynamic_records, 0x489594, "record ID"),
                (exporter._validate_getter, 0x48BAD2, "buffer adjustment"),
            ):
                def changed_instruction(local_blob, local_mappings, local_deps, site):
                    item = original_instruction(local_blob, local_mappings, local_deps, site)
                    return WrongInstruction(item) if site == changed_site else item

                with self.subTest(site=changed_site), mock.patch.object(exporter, "_instruction", side_effect=changed_instruction):
                    with self.assertRaisesRegex(RuntimeError, message):
                        validator(blob, mappings, deps, plt_symbols)

            argument_2_register = original_instruction(blob, mappings, deps, 0x4893BA).operands[0].reg
            plus_13_register = original_instruction(blob, mappings, deps, 0x48955E).operands[0].reg
            for changed_range, register, message in (
                ((0x4893BC, 0x48955E), argument_2_register, "incoming argument-2 preservation"),
                ((0x489566, 0x48956A), argument_2_register, "scaled argument-2 preservation"),
                ((0x48956E, 0x489580), argument_2_register, "scaled argument-2 preservation"),
                ((0x489562, 0x489594), plus_13_register, "argument-2-plus-13 preservation"),
            ):
                def changed_decode(local_blob, local_mappings, local_deps, start, end, *, complete=True):
                    items = original_decode(local_blob, local_mappings, local_deps, start, end, complete=complete)
                    if (start, end) == changed_range:
                        return [RegisterClobber(register), *items]
                    return items

                with self.subTest(span=changed_range), mock.patch.object(exporter, "_decode", side_effect=changed_decode):
                    with self.assertRaisesRegex(RuntimeError, message):
                        exporter._validate_dynamic_records(blob, mappings, deps, plt_symbols)
        finally:
            handle.close()

    def test_record_id_table_source_mutations_are_rejected(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned source or parser dependencies are unavailable")
        exporter = self.exporter
        original_word = exporter._word
        source_sites = (
            0x7B8560, 0x7B82F8, 0x7B8348, 0x7B8398,
            0x7B8544, 0x7B84F4, 0x7B857C, 0x7B85CC,
        )

        for changed_site in source_sites:
            def changed_word(blob, mappings, address, *, signed=False):
                value = original_word(blob, mappings, address, signed=signed)
                return value ^ 1 if address == changed_site else value

            with self.subTest(site=changed_site), mock.patch.object(
                exporter, "_word", side_effect=changed_word
            ):
                with self.assertRaisesRegex(RuntimeError, "record ID table"):
                    exporter.build_raw_export()

    def test_record_id_table_copy_site_mutations_are_rejected(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned source or parser dependencies are unavailable")
        exporter = self.exporter
        original_instruction = exporter._instruction

        class WrongInstruction:
            def __init__(self, item):
                self._item = item
                self.id = -1

            def __getattr__(self, name):
                return getattr(self._item, name)

        copy_sites = (
            0x4893B2, 0x4893B8, 0x4893BE, 0x4893C2, 0x4893C4, 0x4893C6, 0x4893CA,
            0x4893CE, 0x4893D0, 0x4893D2, 0x4893D6,
            0x4893DC, 0x4893DE, 0x4893E0, 0x4893E4,
            0x4893EA, 0x4893EC, 0x4893EE, 0x4893F2,
            0x48B908, 0x48B90C, 0x48B914, 0x48B916, 0x48B91A, 0x48B91E, 0x48B922,
            0x48B926, 0x48B928, 0x48B92A, 0x48B92E,
            0x48B934, 0x48B936, 0x48B938, 0x48B93C,
            0x48B942, 0x48B944, 0x48B946, 0x48B94A,
        )
        blob = exporter.SOURCE_PATH.read_bytes()
        deps = exporter._dependencies()
        with exporter.SOURCE_PATH.open("rb") as handle:
            elf = deps["ELFFile"](handle)
            mappings = exporter._mappings(elf)
            plt_symbols = exporter._plt_symbols(elf, blob, mappings)

            for changed_site in copy_sites:
                def changed_instruction(local_blob, local_mappings, local_deps, site):
                    item = original_instruction(local_blob, local_mappings, local_deps, site)
                    return WrongInstruction(item) if site == changed_site else item

                with self.subTest(site=changed_site), mock.patch.object(
                    exporter, "_instruction", side_effect=changed_instruction
                ):
                    with self.assertRaisesRegex(RuntimeError, "record ID table"):
                        exporter._validate_record_id_tables(
                            elf, blob, mappings, deps, plt_symbols
                        )

            original_call_symbol = exporter._call_symbol
            for changed_site in (
                0x4893D8, 0x4893E6, 0x4893F4,
                0x48B930, 0x48B93E, 0x48B94C,
            ):
                def changed_call_symbol(local_blob, local_mappings, local_deps, local_symbols, site):
                    if site == changed_site:
                        return "not_memcpy"
                    return original_call_symbol(
                        local_blob, local_mappings, local_deps, local_symbols, site
                    )

                with self.subTest(call_site=changed_site), mock.patch.object(
                    exporter, "_call_symbol", side_effect=changed_call_symbol
                ):
                    with self.assertRaisesRegex(RuntimeError, "record ID table"):
                        exporter._validate_record_id_tables(
                            elf, blob, mappings, deps, plt_symbols
                        )

    def test_real_export_matches_when_available(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned source or parser dependencies are unavailable")
        self.assertEqual(self.exporter.build_raw_export(), self.exporter.EXPECTED_EXPORT)


if __name__ == "__main__":
    unittest.main()
