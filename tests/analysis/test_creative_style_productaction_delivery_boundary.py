"""Fail-closed tests for the cross-ELF ProductAction delivery boundary."""
from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "analysis" / "a6400-creative-style-productaction-delivery-boundary.json"
DEEP_DIVE = ROOT / "analysis" / "a6400a-updater-and-creative-style-deep-dive.md"
EXPORTER = ROOT / "tools" / "static" / "export_a6400_creative_style_productaction_delivery_boundary.py"


class CreativeStyleProductActionDeliveryBoundaryContractTests(unittest.TestCase):
    def test_contract_pins_cross_elf_scan_and_af_false_lead(self):
        from pmca.analysis.creative_style_productaction_delivery_boundary import (
            EXPECTED_RAW_EXPORT,
            normalize_creative_style_productaction_delivery_boundary_export,
        )

        document = normalize_creative_style_productaction_delivery_boundary_export(
            copy.deepcopy(EXPECTED_RAW_EXPORT)
        )
        self.assertEqual(document["schema_version"], 3)
        scan = document["canonical_slot37_scan"]
        self.assertEqual(document["firmware_inventory"]["elf_file_count"], 324)
        self.assertEqual(scan["exidx_scanned_file_count"], 222)
        self.assertEqual(scan["excluded_file_count"], 102)
        self.assertEqual(scan["canonical_call_count"], 111)
        self.assertEqual(scan["known_selector_histogram"], {"0": 2, "1": 1})
        self.assertEqual(scan["unknown_selector_count"], 108)
        self.assertEqual(scan["selector_10_call_count"], 0)
        self.assertFalse(scan["whole_elf_universe_absence_proven"])

        af = document["vu2_direct_caller_classification"]["af_slot36_route"]
        self.assertEqual(af["type_name"], "AfImplForOrientationRegisterAF")
        self.assertEqual(af["address_point"], 0x8E6228)
        self.assertEqual(af["slot"], 36)
        self.assertEqual(af["target"], 0x31286C)
        self.assertEqual(
            [item["target"] for item in af["direct_tail_routes"]],
            [0x3112DC, 0x3110BC],
        )
        self.assertFalse(document["claims"]["viewsettingmenu_receiver_proven"])
        self.assertFalse(document["claims"]["productaction_selector_10_delivery_proven"])

        slot64 = document["direct_slot64_scan"]
        self.assertEqual(slot64["canonical_call_count"], 50)
        self.assertEqual(slot64["known_selector_call_count"], 12)
        self.assertEqual(slot64["unknown_selector_count"], 38)
        self.assertEqual(slot64["selector_10_call_count"], 0)
        self.assertEqual(
            slot64["known_selector_histogram"],
            {"0": 1, "6": 1, "15": 2, "16": 2, "18": 2, "19": 2, "191": 1, "262": 1},
        )
        publications = document["productaction_symbol_publication"]
        self.assertEqual(publications["module_count"], 7)
        self.assertEqual(publications["abs32_publication_cell_count"], 186)
        self.assertEqual(publications["glob_dat_cell_count"], 0)
        self.assertEqual(publications["plt_relocation_count"], 0)
        self.assertEqual(publications["direct_call_count"], 0)
        self.assertFalse(publications["cross_module_provider_binding_proven"])

        typed = document["typed_productaction_publications"]
        self.assertEqual(typed["record_count"], 186)
        self.assertEqual(typed["zero_offset_to_top_count"], 186)
        self.assertEqual(typed["rtti_name_resolved_count"], 186)
        self.assertEqual(typed["rtti_header_relative_count"], 184)
        self.assertEqual(typed["rtti_header_abs32_count"], 2)
        self.assertEqual(typed["slot64_relative_count"], 184)
        self.assertEqual(typed["slot64_abs32_count"], 2)
        self.assertEqual(typed["viewsettingmenu"]["type_name"], "15ViewSettingMenu")
        self.assertEqual(typed["viewsettingmenu"]["address_point"], 0x8E2270)
        self.assertEqual(typed["viewcreativestyle"]["address_point"], 0x93ECC0)

        widened = document["widened_basic_block_slot37_scan"]
        self.assertEqual(widened["call_count"], 112)
        self.assertEqual(widened["explicit_selector_candidate_count"], 8)
        self.assertEqual(
            widened["explicit_selector_histogram"],
            {"0": 2, "1": 1, "4": 1, "16": 2, "4103": 1, "4138": 1},
        )
        self.assertEqual(widened["selector_10_candidate_count"], 0)
        self.assertEqual(widened["intervening_call_candidate_count"], 5)

        availability = document["viewsettingmenu_factory_availability"]
        self.assertEqual(availability["factory_entry"], 0x205574)
        self.assertEqual(availability["allocation_size"], 0x3D0)
        self.assertEqual(availability["constructor_entry"], 0x204C90)
        self.assertEqual(availability["vptr_store"]["address_point"], 0x8E2270)
        self.assertEqual(availability["registration_row"]["alias"], "view/SETTINGMENUX")
        self.assertFalse(availability["runtime_factory_invocation_proven"])

    def test_contract_rejects_promoted_or_widened_claims(self):
        from pmca.analysis.creative_style_productaction_delivery_boundary import (
            CreativeStyleProductActionDeliveryBoundaryError,
            EXPECTED_RAW_EXPORT,
            normalize_creative_style_productaction_delivery_boundary_export,
        )

        mutations = (
            lambda value: value["canonical_slot37_scan"].__setitem__("selector_10_call_count", 1),
            lambda value: value["canonical_slot37_scan"].__setitem__("whole_elf_universe_absence_proven", True),
            lambda value: value["vu2_direct_caller_classification"]["af_slot36_route"].__setitem__("type_name", "ViewSettingMenu"),
            lambda value: value["claims"].__setitem__("productaction_selector_10_delivery_proven", True),
            lambda value: value["claims"].__setitem__("runtime_creative_style_selection_proven", True),
            lambda value: value["direct_slot64_scan"].__setitem__("selector_10_call_count", 1),
            lambda value: value["productaction_symbol_publication"].__setitem__("direct_call_count", 1),
            lambda value: value["productaction_symbol_publication"].__setitem__("cross_module_provider_binding_proven", True),
            lambda value: value["typed_productaction_publications"].__setitem__("record_count", 185),
            lambda value: value["widened_basic_block_slot37_scan"].__setitem__("selector_10_candidate_count", 1),
            lambda value: value["viewsettingmenu_factory_availability"].__setitem__("runtime_factory_invocation_proven", True),
        )
        for mutate in mutations:
            candidate = copy.deepcopy(EXPECTED_RAW_EXPORT)
            mutate(candidate)
            with self.subTest(mutate=mutate), self.assertRaises(
                CreativeStyleProductActionDeliveryBoundaryError
            ):
                normalize_creative_style_productaction_delivery_boundary_export(candidate)

    def test_committed_report_is_safe_and_fail_closed(self):
        from pmca.analysis.creative_style_productaction_delivery_boundary import (
            validate_creative_style_productaction_delivery_boundary_report,
        )

        report = validate_creative_style_productaction_delivery_boundary_report(
            json.loads(REPORT.read_text(encoding="utf-8"))
        )
        self.assertFalse(report["installable"])
        self.assertFalse(report["recovery_validated"])
        self.assertFalse(report["camera_test_eligible"])
        self.assertIn("canonical", report["conclusion"])
        self.assertIn("does not prove whole-runtime absence", report["conclusion"])

    def test_deep_dive_preserves_the_bounded_negative_scope(self):
        prose = DEEP_DIVE.read_text(encoding="utf-8")
        for phrase in (
            "222 expose usable",
            "111 canonical receiver-vptr to slot-37 register transfers",
            "AfImplForOrientationRegisterAF",
            "does not establish whole-runtime absence",
            "a6400-creative-style-productaction-delivery-boundary.json",
            "50 canonical direct slot-64 transfers",
            "186 `R_ARM_ABS32` publication cells",
            "186 zero-offset RTTI-backed primary vtables",
            "112 whole-basic-block slot-37 transfers",
            "view/SETTINGMENUX",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, prose)
        self.assertNotIn("proves whole-runtime absence", prose)


class CreativeStyleProductActionDeliveryBoundaryExporterTests(unittest.TestCase):
    def _load(self):
        spec = importlib.util.spec_from_file_location(
            "creative_style_productaction_delivery_boundary_exporter", EXPORTER
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_real_source_export_matches_contract_when_available(self):
        exporter = self._load()
        if not exporter.sources_available():
            self.skipTest("pinned firmware sources are unavailable")
        raw = exporter.build_raw_export()
        self.assertEqual(raw, exporter.EXPECTED_RAW_EXPORT)

    def test_vu2_instruction_and_slot_mutations_fail_closed(self):
        exporter = self._load()
        if not exporter.SOURCE_PATH.is_file():
            self.skipTest("pinned viewUnified2 source is unavailable")
        direct_edges = {
            0x310CD8: [
                {"site": 0x31107E, "owner_start": 0x310E30, "owner_end": 0x3110BC},
                {"site": 0x3112A0, "owner_start": 0x3110BC, "owner_end": 0x3112DC},
                {"site": 0x3114C6, "owner_start": 0x3112DC, "owner_end": 0x311514},
            ],
            0x310E30: [],
            0x3110BC: [
                {"site": 0x31293A, "owner_start": 0x31286C, "owner_end": 0x31297C}
            ],
            0x3112DC: [
                {"site": 0x3128CA, "owner_start": 0x31286C, "owner_end": 0x31297C}
            ],
            0x2F1350: [],
            0x205574: [],
            0x204C90: [
                {"site": 0x205586, "owner_start": 0x205574, "owner_end": 0x205598}
            ],
        }
        deps = exporter._dependencies()
        baseline = exporter.SOURCE_PATH.read_bytes()
        exporter._validate_vu2_structure(baseline, deps, copy.deepcopy(direct_edges))

        import io

        elf = deps["ELFFile"](io.BytesIO(baseline))
        mappings = exporter._mappings(elf)
        for site in (0x3128CA, 0x8E62B8):
            mutated = bytearray(baseline)
            start, _end, file_start = next(
                item for item in mappings if item[0] <= site < item[1]
            )
            mutated[file_start + site - start] ^= 1
            with self.subTest(site=hex(site)), self.assertRaises(RuntimeError):
                exporter._validate_vu2_structure(
                    bytes(mutated), deps, copy.deepcopy(direct_edges)
                )

    def test_typed_publication_factory_and_false_lead_mutations_fail_closed(self):
        exporter = self._load()
        libobj_path = exporter.FIRMWARE_ROOT / "lib/libObj.so"
        if not exporter.SOURCE_PATH.is_file() or not libobj_path.is_file():
            self.skipTest("pinned VU2/libObj sources are unavailable")

        import io

        deps = exporter._dependencies()

        def mutate_at(blob, mappings, site):
            candidate = bytearray(blob)
            start, _end, file_start = next(
                item for item in mappings if item[0] <= site < item[1]
            )
            candidate[file_start + site - start] ^= 1
            return bytes(candidate)

        view = exporter.SOURCE_PATH.read_bytes()
        view_elf = deps["ELFFile"](io.BytesIO(view))
        view_mappings = exporter._mappings(view_elf)

        typed_mutation = mutate_at(view, view_mappings, 0x8E226C)
        typed_elf = deps["ELFFile"](io.BytesIO(typed_mutation))
        with self.assertRaises(RuntimeError):
            exporter._productaction_publication(
                typed_elf,
                "lib/viewUnified2.so",
                typed_mutation,
                exporter._mappings(typed_elf),
            )

        direct_edges = {
            0x205574: [],
            0x204C90: [
                {"site": 0x205586, "owner_start": 0x205574, "owner_end": 0x205598}
            ],
        }
        factory_mutation = mutate_at(view, view_mappings, 0x205576)
        with self.assertRaises(RuntimeError):
            exporter._validate_viewsettingmenu_factory(
                factory_mutation, deps, copy.deepcopy(direct_edges)
            )

        libobj = libobj_path.read_bytes()
        libobj_elf = deps["ELFFile"](io.BytesIO(libobj))
        false_lead_mutation = mutate_at(
            libobj, exporter._mappings(libobj_elf), 0x14062C
        )
        with self.assertRaises(RuntimeError):
            exporter._validate_sequence_false_lead(deps, false_lead_mutation)


if __name__ == "__main__":
    unittest.main()
