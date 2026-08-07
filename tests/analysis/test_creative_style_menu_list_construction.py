"""Fail-closed tests for Creative Style menu-list construction evidence."""
from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "analysis" / "a6400-creative-style-menu-list-construction.json"
REGISTRY_REPORT = ROOT / "analysis" / "a6400-creative-style-registry-consumers.json"
EXPORTER = ROOT / "tools" / "static" / "export_a6400_creative_style_menu_list_construction.py"


class CreativeStyleMenuListConstructionContractTests(unittest.TestCase):
    def test_prior_registry_digest_matches_the_current_validated_report(self):
        from pmca.analysis.creative_style_menu_list_construction import (
            PRIOR_REGISTRY_DIGEST,
        )
        from pmca.analysis.creative_style_registry_consumers import (
            validate_creative_style_registry_consumers_report,
        )

        upstream = validate_creative_style_registry_consumers_report(
            json.loads(REGISTRY_REPORT.read_text(encoding="utf-8"))
        )
        self.assertEqual(PRIOR_REGISTRY_DIGEST, upstream["summary"]["artifact_sha256"])

    def test_contract_pins_constructor_bounded_lists(self):
        from pmca.analysis.creative_style_menu_list_construction import (
            EXPECTED_RAW_EXPORT,
            normalize_creative_style_menu_list_construction_export,
        )

        document = normalize_creative_style_menu_list_construction_export(copy.deepcopy(EXPECTED_RAW_EXPORT))
        inventory = document["root_inventory"]
        self.assertEqual(inventory["root_pointer_relocation_count"], 6824)
        self.assertEqual(inventory["maximal_contiguous_run_count"], 321)
        self.assertEqual(inventory["creative_style_occurrence_count"], 51)
        self.assertEqual(inventory["creative_style_contiguous_run_count"], 47)
        self.assertFalse(inventory["contiguous_runs_are_constructor_boundaries"])

        self.assertEqual(document["constructor_binding"]["plt"], 0x154024)
        self.assertEqual(document["constructor_binding"]["symbol_index"], 1209)
        self.assertEqual(document["constructor_binding"]["relocation_index"], 1727)
        self.assertEqual([item["entry_count"] for item in document["list_constructions"]], [4, 4, 2])
        self.assertEqual([item["constructor_call_site"] for item in document["list_constructions"]], [0x1D9F88, 0x62B3C4, 0x65BE9C])
        self.assertEqual([item["root_list_start"] for item in document["list_constructions"]], [0x951284, 0xB068D8, 0xB06910])
        self.assertEqual([item["creative_style_index"] for item in document["list_constructions"]], [2, 2, 1])
        self.assertTrue(all(entry["addend"] == 0 for item in document["list_constructions"] for entry in item["entries"]))
        self.assertTrue(all(item["owner_complete"] for item in document["list_constructions"]))
        self.assertTrue(all(item["r1_flows_directly_to_constructor"] for item in document["list_constructions"]))
        self.assertEqual(
            [item["argument_definition_sites"]["r2_count_immediate"] for item in document["list_constructions"]],
            [0x1D9F7C, 0x62B3B8, 0x65BE90],
        )
        self.assertEqual(
            [item["argument_definition_sites"]["r3_null_immediate"] for item in document["list_constructions"]],
            [0x1D9F86, 0x62B3C2, 0x65BE9A],
        )
        self.assertTrue(all(item["prep_chain_entry_reachable"] for item in document["list_constructions"]))
        self.assertTrue(all(item["prep_chain_direct_fallthrough"] for item in document["list_constructions"]))
        self.assertTrue(all(item["prep_chain_unique_predecessors"] for item in document["list_constructions"]))

    def test_contract_pins_startup_and_view_factory_provenance(self):
        from pmca.analysis.creative_style_menu_list_construction import (
            EXPECTED_RAW_EXPORT,
            normalize_creative_style_menu_list_construction_export,
        )

        document = normalize_creative_style_menu_list_construction_export(copy.deepcopy(EXPECTED_RAW_EXPORT))
        factory, startup_four, startup_two = document["list_constructions"]
        self.assertEqual(factory["incoming_reference"], {"section": ".data.rel.ro", "cell": 0x8DEE84, "relocation_index": 16312, "relocation_type": 23})
        self.assertEqual(startup_four["incoming_reference"]["section"], ".init_array")
        self.assertEqual(startup_four["incoming_reference"]["cell"], 0x8B5640)
        self.assertEqual(startup_two["incoming_reference"]["cell"], 0x8B5648)
        self.assertEqual([factory["entry_path_edge_count"], startup_four["entry_path_edge_count"], startup_two["entry_path_edge_count"]], [64, 52, 52])
        self.assertEqual(document["constructor_trace_digest"], "484bd875feb7b1dac4c0f30247319ce13bbe95b5c08a69e7ca5e3f1145df6993")

        table = document["view_stlrec_vtable"]
        self.assertEqual(table["type_name"], "ViewStlrec")
        self.assertEqual(table["base_rtti_symbol"], "_ZTI13ViewBaseForMR")
        self.assertEqual(table["address_point"], 0x8DED90)
        self.assertEqual(table["slot"], 61)
        self.assertEqual(table["target"], 0x1CCDA8)
        self.assertEqual(table["observed_prefix_slot_count"], 62)
        self.assertEqual(table["prefix_relocation_shape_digest"], "a34c408200e725bf58bb98e4c06f8d37e9edc17f166aa76959554ed337aa4d01")
        self.assertFalse(table["table_end_established"])
        self.assertTrue(document["claims"]["view_stlrec_owner_found"])

    def test_contract_rejects_boundary_and_behavior_promotion(self):
        from pmca.analysis.creative_style_menu_list_construction import (
            CreativeStyleMenuListConstructionError,
            EXPECTED_RAW_EXPORT,
            normalize_creative_style_menu_list_construction_export,
            validate_creative_style_menu_list_construction_report,
        )

        mutations = (
            lambda value: value["root_inventory"].__setitem__("contiguous_runs_are_constructor_boundaries", True),
            lambda value: value["list_constructions"][0].__setitem__("entry_count", 25),
            lambda value: value["view_stlrec_vtable"].__setitem__("table_end_established", True),
            lambda value: value["claims"].__setitem__("selected_state_found", True),
            lambda value: value.__setitem__("instruction_text", []),
        )
        for mutate in mutations:
            candidate = copy.deepcopy(EXPECTED_RAW_EXPORT)
            mutate(candidate)
            with self.subTest(mutate=mutate), self.assertRaises(CreativeStyleMenuListConstructionError):
                normalize_creative_style_menu_list_construction_export(candidate)

        report = validate_creative_style_menu_list_construction_report(json.loads(REPORT.read_text(encoding="utf-8")))
        self.assertEqual(report["readiness"], "MENU_ROOT_LIST_CONSTRUCTION_ONLY")
        self.assertFalse(report["installable"])
        self.assertFalse(report["camera_test_eligible"])
        self.assertFalse(report["claims"]["touch_routing_found"])
        self.assertFalse(report["claims"]["commit_or_persistence_found"])


class CreativeStyleMenuListConstructionExporterTests(unittest.TestCase):
    def _load(self):
        spec = importlib.util.spec_from_file_location("creative_style_menu_list_construction_exporter", EXPORTER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_exporter_accepts_only_pinned_static_result(self):
        exporter = self._load()

        class Adapter:
            def metadata(self):
                return copy.deepcopy(exporter.EXPECTED_RAW_EXPORT)

        self.assertEqual([item["entry_count"] for item in exporter.build_raw_export(Adapter())["list_constructions"]], [4, 4, 2])

    def test_cfg_jump_fallthrough_is_fail_closed(self):
        exporter = self._load()
        arm_cc_invalid, arm_cc_ne, arm_cc_al = 0, 2, 15
        self.assertFalse(exporter._jump_has_fallthrough("bx", arm_cc_al, arm_cc_al, arm_cc_invalid))
        self.assertFalse(exporter._jump_has_fallthrough("tbb", arm_cc_invalid, arm_cc_al, arm_cc_invalid))
        self.assertTrue(exporter._jump_has_fallthrough("bne", arm_cc_ne, arm_cc_al, arm_cc_invalid))
        self.assertTrue(exporter._jump_has_fallthrough("cbz", arm_cc_invalid, arm_cc_al, arm_cc_invalid))

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
