"""Fail-closed tests for generic model consumers near Creative Style data."""
from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "analysis" / "a6400-creative-style-generic-model-consumers.json"
EXPORTER = ROOT / "tools" / "static" / "export_a6400_creative_style_generic_model_consumers.py"


class CreativeStyleGenericModelConsumerContractTests(unittest.TestCase):
    def test_exact_sources_and_sequences_are_pinned(self):
        from pmca.analysis.creative_style_generic_model_consumers import (
            EXPECTED_EXPORT,
            normalize_creative_style_generic_model_consumers_export,
        )

        document = normalize_creative_style_generic_model_consumers_export(
            copy.deepcopy(EXPECTED_EXPORT)
        )
        self.assertEqual(
            [(item["module"], item["size"]) for item in document["modules"]],
            [("lib/viewUnified4.so", 2_614_628), ("lib/viewUnified7.so", 541_024)],
        )
        sequences = document["generic_model_sequences"]
        self.assertEqual(len(sequences), 3)
        self.assertEqual(
            (sequences[0]["owner"]["start"], sequences[0]["owner"]["end"]),
            (0xCE0A8, 0xCE244),
        )
        self.assertEqual(
            [(item["role"], item["site"]) for item in sequences[2]["calls"]],
            [
                ("set-cursor-on-item-change", 0x2D294),
                ("set-value-to-model", 0x2D29C),
                ("get-process-value", 0x2D2A4),
            ],
        )
        self.assertTrue(all(item["call_order_exact"] for item in sequences))
        self.assertTrue(
            all(call["transfer"] == "thumb-blx-direct" for item in sequences for call in item["calls"])
        )
        self.assertTrue(all(item["owner"]["source"] == "arm-exidx" for item in sequences))
        self.assertTrue(all(item["owner"]["nonzero_dynsym_owner"] is None for item in sequences))

    def test_creative_root_relocations_are_data_only_and_outside_callers(self):
        from pmca.analysis.creative_style_generic_model_consumers import EXPECTED_EXPORT

        publications = EXPECTED_EXPORT["creative_style_publications"]
        self.assertEqual([len(item["relocations"]) for item in publications], [6, 2])
        self.assertTrue(all(item["symbol"] == "cmnViewSettingNodeRootCreativeStyle" for item in publications))
        for publication in publications:
            for relocation in publication["relocations"]:
                self.assertIn(relocation["section"], (".data", ".got"))
                self.assertFalse(relocation["inside_any_sequence_owner"])
        boundary = EXPECTED_EXPORT["ownership_boundary"]
        self.assertTrue(boundary["generic_sequences_found"])
        self.assertTrue(boundary["creative_root_co_contained"])
        self.assertFalse(boundary["creative_root_bound_to_sequence_owner"])

    def test_claims_do_not_promote_co_containment(self):
        from pmca.analysis.creative_style_generic_model_consumers import EXPECTED_EXPORT

        claims = EXPECTED_EXPORT["claims"]
        self.assertTrue(claims["generic_cursor_to_model_sequence_found"])
        self.assertFalse(claims["creative_style_specific_model_sequence_found"])
        self.assertFalse(claims["selected_model_value_storage_found"])
        self.assertFalse(claims["renderer_binding_found"])
        self.assertFalse(claims["commit_or_persistence_found"])
        self.assertFalse(claims["creative_look_equivalence_found"])

    def test_tampering_fails_closed(self):
        from pmca.analysis.creative_style_generic_model_consumers import (
            CreativeStyleGenericModelConsumersError,
            EXPECTED_EXPORT,
            normalize_creative_style_generic_model_consumers_export,
        )

        mutations = []
        changed = copy.deepcopy(EXPECTED_EXPORT)
        changed["generic_model_sequences"][0]["calls"][0]["site"] += 2
        mutations.append(changed)
        changed = copy.deepcopy(EXPECTED_EXPORT)
        changed["creative_style_publications"][0]["relocations"][0]["inside_any_sequence_owner"] = True
        mutations.append(changed)
        changed = copy.deepcopy(EXPECTED_EXPORT)
        changed["claims"]["creative_style_specific_model_sequence_found"] = True
        mutations.append(changed)
        changed = copy.deepcopy(EXPECTED_EXPORT)
        changed["device_payload"] = "forbidden"
        mutations.append(changed)
        for document in mutations:
            with self.subTest(document=document):
                with self.assertRaises(CreativeStyleGenericModelConsumersError):
                    normalize_creative_style_generic_model_consumers_export(document)

    def test_checked_in_report_validates(self):
        from pmca.analysis.creative_style_generic_model_consumers import (
            validate_creative_style_generic_model_consumers_report,
        )

        report = json.loads(REPORT.read_text(encoding="utf-8"))
        validated = validate_creative_style_generic_model_consumers_report(report)
        self.assertEqual(validated["readiness"], "GENERIC_MODEL_CONSUMER_SEQUENCES_ONLY")
        self.assertFalse(validated["installable"])
        self.assertFalse(validated["camera_test_eligible"])


class CreativeStyleGenericModelConsumerExporterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("generic_model_consumer_exporter", EXPORTER)
        cls.exporter = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(cls.exporter)

    def test_adapter_is_normalized(self):
        from pmca.analysis.creative_style_generic_model_consumers import EXPECTED_EXPORT

        class FakeAdapter:
            def metadata(self):
                return copy.deepcopy(EXPECTED_EXPORT)

        self.assertEqual(self.exporter.build_raw_export(FakeAdapter()), EXPECTED_EXPORT)

    def test_real_export_matches_when_sources_and_dependencies_are_available(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned local sources or parser dependencies are unavailable")
        self.assertEqual(self.exporter.build_raw_export(), self.exporter.EXPECTED_EXPORT)


if __name__ == "__main__":
    unittest.main()
