"""Fail-closed tests for anonymous generic model-owner provenance."""
from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "analysis" / "a6400-generic-model-owner-provenance.json"
EXPORTER = ROOT / "tools" / "static" / "export_a6400_generic_model_owner_provenance.py"


class GenericModelOwnerProvenanceContractTests(unittest.TestCase):
    def test_vu4_table_dispatch_provenance_is_exact(self):
        from pmca.analysis.generic_model_owner_provenance import (
            EXPECTED_EXPORT,
            normalize_generic_model_owner_provenance_export,
        )

        document = normalize_generic_model_owner_provenance_export(copy.deepcopy(EXPECTED_EXPORT))
        targets = document["view_unified4"]["targets"]
        self.assertEqual(len(targets), 2)
        first = targets[0]
        self.assertEqual((first["entry"], first["utility_member_offset"]), (0xCE0A8, 0x180))
        self.assertEqual(
            (first["inbound_dispatch"]["owner"]["start"], first["inbound_dispatch"]["site"]),
            (0xCF106, 0xCF2CC),
        )
        self.assertEqual(first["inbound_dispatch"]["selector_kind"], "tbh")
        self.assertEqual(
            first["inbound_dispatch"]["table_branch"],
            {
                "site": 0xCF112,
                "table_start": 0xCF116,
                "entry_width": 2,
                "selector_index": 0x29,
                "entry_site": 0xCF168,
                "entry_value": 0xD9,
                "landing": 0xCF2C8,
                "fallthrough_branch_site": 0xCF2CC,
            },
        )
        self.assertTrue(first["inbound_dispatch"]["selector_case_value_rederived"])
        self.assertTrue(first["inbound_dispatch"]["receiver_r0_preserved_linear_trace"])
        self.assertFalse(first["inbound_dispatch"]["path_sensitive_receiver_proof"])
        self.assertEqual(
            first["dispatcher_address_taken"],
            {"relocation_index": 2812, "site": 0x267930, "relocation_type": 23, "section": ".data.rel.ro", "target": 0xCF106},
        )

    def test_vu4_second_interval_is_not_promoted_to_one_function(self):
        from pmca.analysis.generic_model_owner_provenance import EXPECTED_EXPORT

        second = EXPECTED_EXPORT["view_unified4"]["targets"][1]
        self.assertEqual((second["exidx_interval"]["start"], second["exidx_interval"]["end"]), (0x17A91C, 0x17A9CE))
        self.assertEqual(second["entry"], 0x17A95A)
        self.assertTrue(second["entry_separated_by_prior_return"])
        self.assertEqual(second["prior_return_site"], 0x17A958)
        self.assertEqual(second["utility_member_offset"], 0x188)
        self.assertEqual(
            second["inbound_dispatch"]["table_branch"],
            {
                "site": 0x17AD58,
                "table_start": 0x17AD5C,
                "entry_width": 2,
                "selector_index": 0x0B,
                "entry_site": 0x17AD72,
                "entry_value": 0x3A,
                "landing": 0x17ADD0,
                "fallthrough_branch_site": 0x17ADD4,
            },
        )
        self.assertTrue(second["inbound_dispatch"]["selector_case_value_rederived"])
        self.assertFalse(second["exidx_interval_is_single_function"])
        self.assertNotIn("interval_first_entry_bounded_direct_inbound_count", second)

    def test_negative_reference_and_direct_scan_claims_are_explicitly_bounded(self):
        from pmca.analysis.generic_model_owner_provenance import EXPECTED_EXPORT

        vu4 = EXPECTED_EXPORT["view_unified4"]
        self.assertEqual(vu4["type_context"]["classification"], "address-taken-data-rel-ro-table-context")
        for target in vu4["targets"]:
            self.assertEqual(target["bounded_direct_inbound_count"], 1)
            self.assertEqual(target["direct_scan_scope"], "canonical-prefixes-across-exidx-ranges")
            self.assertFalse(target["direct_scan_complete"])
            self.assertFalse(target["direct_inventory_exhaustive"])
            self.assertEqual(target["creative_style_pc_literal_reference_count"], 0)
            self.assertNotIn("creative_style_reference_count", target)
        boundary = EXPECTED_EXPORT["creative_style_boundary"]
        self.assertEqual(boundary["target_or_dispatcher_pc_literal_reference_count"], 0)
        self.assertNotIn("target_or_dispatcher_reference_count", boundary)

    def test_vu7_has_shared_utility_member_and_untyped_static_dispatch(self):
        from pmca.analysis.generic_model_owner_provenance import EXPECTED_EXPORT

        target = EXPECTED_EXPORT["view_unified7"]["target"]
        self.assertEqual((target["range"]["start"], target["range"]["end"]), (0x2D284, 0x2D2AE))
        self.assertEqual(target["decoded_instruction_count"], 13)
        self.assertEqual(target["utility_member_offset"], 0x14C)
        self.assertEqual(target["receiver_sites"], [0x2D294, 0x2D29C, 0x2D2A4])
        self.assertEqual(
            target["static_inbound_inventory"],
            {
                "bounded_direct_transfer_count": 1,
                "canonical_direct_scan_complete": False,
                "direct_inventory_exhaustive": False,
                "mapped_pointer_word_count": 0,
                "relocation_reference_count": 0,
                "dynsym_owner_count": 0,
                "address_taken_table_count": 0,
            },
        )
        self.assertEqual(
            target["inbound_dispatch"]["table_branch"],
            {
                "site": 0x3104C,
                "table_start": 0x31050,
                "entry_width": 2,
                "selector_index": 0x30,
                "entry_site": 0x310B0,
                "entry_value": 0xF2,
                "landing": 0x31234,
                "fallthrough_branch_site": 0x31238,
            },
        )
        self.assertTrue(target["inbound_dispatch"]["receiver_r0_preserved_case_path"])
        self.assertFalse(target["inbound_dispatch"]["receiver_type_proven"])
        self.assertEqual(
            target["dispatcher_address_taken"],
            {"relocation_index": 850, "site": 0x6FEF0, "relocation_type": 23, "section": ".data.rel.ro", "target": 0x31040},
        )
        self.assertEqual(target["blocker"], "untyped-anonymous-table-dispatch")

    def test_vu7_initializer_is_only_structural_corroboration(self):
        from pmca.analysis.generic_model_owner_provenance import EXPECTED_EXPORT

        candidate = EXPECTED_EXPORT["view_unified7"]["initializer_candidate"]
        self.assertEqual((candidate["range"]["start"], candidate["range"]["end"]), (0x30750, 0x309A8))
        self.assertEqual(candidate["utility_member_offset"], 0x14C)
        self.assertEqual(candidate["setting_node_member_offset"], 0x148)
        self.assertEqual(candidate["utility_store_site"], 0x308AA)
        self.assertEqual(candidate["utility_store_width"], 4)
        self.assertFalse(candidate["direct_path_to_target"])
        self.assertFalse(candidate["same_field_proves_same_class"])
        self.assertFalse(candidate["creative_style_pc_literal_reference_found"])

    def test_claims_and_tampering_fail_closed(self):
        from pmca.analysis.generic_model_owner_provenance import (
            EXPECTED_EXPORT,
            GenericModelOwnerProvenanceError,
            normalize_generic_model_owner_provenance_export,
        )

        claims = EXPECTED_EXPORT["claims"]
        self.assertTrue(claims["generic_dispatcher_provenance_found"])
        self.assertTrue(claims["generic_utility_member_lifecycle_found"])
        self.assertFalse(claims["concrete_derived_type_found"])
        self.assertFalse(claims["creative_style_owner_binding_found"])
        self.assertFalse(claims["commit_or_persistence_found"])

        mutations = []
        changed = copy.deepcopy(EXPECTED_EXPORT)
        changed["view_unified4"]["targets"][1]["exidx_interval_is_single_function"] = True
        mutations.append(changed)
        changed = copy.deepcopy(EXPECTED_EXPORT)
        changed["view_unified7"]["initializer_candidate"]["same_field_proves_same_class"] = True
        mutations.append(changed)
        changed = copy.deepcopy(EXPECTED_EXPORT)
        changed["claims"]["creative_style_owner_binding_found"] = True
        mutations.append(changed)
        for document in mutations:
            with self.subTest(document=document):
                with self.assertRaises(GenericModelOwnerProvenanceError):
                    normalize_generic_model_owner_provenance_export(document)

    def test_checked_in_report_validates(self):
        from pmca.analysis.generic_model_owner_provenance import validate_generic_model_owner_provenance_report

        report = json.loads(REPORT.read_text(encoding="utf-8"))
        validated = validate_generic_model_owner_provenance_report(report)
        self.assertEqual(validated["readiness"], "GENERIC_OWNER_PROVENANCE_WITH_UNTYPED_BLOCKERS")
        self.assertFalse(validated["installable"])
        self.assertFalse(validated["camera_test_eligible"])


class GenericModelOwnerProvenanceExporterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("owner_provenance_exporter", EXPORTER)
        cls.exporter = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(cls.exporter)

    def test_adapter_is_normalized(self):
        from pmca.analysis.generic_model_owner_provenance import EXPECTED_EXPORT

        class FakeAdapter:
            def metadata(self):
                return copy.deepcopy(EXPECTED_EXPORT)

        self.assertEqual(self.exporter.build_raw_export(FakeAdapter()), EXPECTED_EXPORT)

    def test_direct_inbound_scan_uses_canonical_instruction_boundaries(self):
        class Operand:
            type = 1
            imm = 0x2000

        class Item:
            def __init__(self, address, size, mnemonic, operands=()):
                self.address = address
                self.size = size
                self.mnemonic = mnemonic
                self.operands = list(operands)

        class Decoder:
            detail = False

            def disasm(self, _data, address, count=0):
                if count == 1 and address == 0x1002:
                    return iter([Item(0x1002, 4, "b.w", [Operand()])])
                if address == 0x1000:
                    return iter([Item(0x1000, 4, "nop"), Item(0x1004, 2, "nop")])
                return iter([])

        deps = {"Cs": lambda *_args: Decoder(), "arch": 0, "mode": 0, "imm": 1}
        result, complete = self.exporter._global_direct_inbound(
            b"\x00" * 6,
            [(0x1000, 0x1006, 0)],
            deps,
            [(0x1000, 0x1006)],
            0x2000,
        )
        self.assertEqual(result, [])
        self.assertTrue(complete)

    def test_direct_inbound_scan_reports_incomplete_canonical_decode(self):
        class Operand:
            type = 1
            imm = 0x2000

        class Item:
            def __init__(self, address, size, mnemonic, operands=()):
                self.address = address
                self.size = size
                self.mnemonic = mnemonic
                self.operands = list(operands)

        class Decoder:
            detail = False

            def disasm(self, _data, address, count=0):
                if count == 1 and address == 0x1004:
                    return iter([Item(0x1004, 2, "b", [Operand()])])
                if address == 0x1000:
                    return iter([Item(0x1000, 2, "nop")])
                return iter([])

        deps = {"Cs": lambda *_args: Decoder(), "arch": 0, "mode": 0, "imm": 1}
        result, complete = self.exporter._global_direct_inbound(
            b"\x00" * 6,
            [(0x1000, 0x1006, 0)],
            deps,
            [(0x1000, 0x1006)],
            0x2000,
        )
        self.assertEqual(result, [])
        self.assertFalse(complete)

    def test_direct_inbound_scan_includes_conditional_jump_group(self):
        class Operand:
            type = 1
            imm = 0x2000

        class Item:
            address = 0x1000
            size = 4
            mnemonic = "beq.w"
            operands = [Operand()]

            def group(self, group):
                return group == 2

        class Decoder:
            detail = False

            def disasm(self, _data, address, count=0):
                return iter([Item()]) if address == 0x1000 and count == 0 else iter([])

        deps = {
            "Cs": lambda *_args: Decoder(),
            "arch": 0,
            "mode": 0,
            "imm": 1,
            "jump_group": 2,
            "call_group": 3,
        }
        result, complete = self.exporter._global_direct_inbound(
            b"\x00" * 4,
            [(0x1000, 0x1004, 0)],
            deps,
            [(0x1000, 0x1004)],
            0x2000,
        )
        self.assertEqual(result, [(0x1000, 0x1000, 0x1004, "beq.w")])
        self.assertTrue(complete)

    def test_real_export_matches_when_available(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned sources or parser dependencies are unavailable")
        self.assertEqual(self.exporter.build_raw_export(), self.exporter.EXPECTED_EXPORT)


if __name__ == "__main__":
    unittest.main()
