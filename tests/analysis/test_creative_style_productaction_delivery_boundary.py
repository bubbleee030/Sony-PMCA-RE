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


if __name__ == "__main__":
    unittest.main()
