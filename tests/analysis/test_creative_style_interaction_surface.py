"""Fail-closed tests for the native Creative Style interaction surface."""
from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "analysis" / "a6400-creative-style-interaction-surface.json"
EXPORTER = ROOT / "tools" / "static" / "export_a6400_creative_style_interaction_surface.py"


class CreativeStyleInteractionSurfaceContractTests(unittest.TestCase):
    def test_native_layout_and_helper_scaffold_is_exact(self):
        from pmca.analysis.creative_style_interaction_surface import EXPECTED_EXPORT

        layout = EXPECTED_EXPORT["creative_style_layout"]
        self.assertEqual(layout["layout_key"], 0x1FA14683)
        self.assertEqual(layout["layout_callback"], 0x5CD730)
        self.assertEqual(
            [(item["type"], item["size"], item["object_offset"]) for item in layout["helpers"]],
            [
                ("CmnViewMenuData", 0x50, 0x144),
                ("CmnMenuTableUtil", 0x14, 0x148),
                ("CmnZakoMenuUtil", 0x3C, 0x150),
            ],
        )

    def test_menu_table_and_belt_boundary_are_bounded(self):
        from pmca.analysis.creative_style_interaction_surface import EXPECTED_EXPORT

        dispatcher = EXPECTED_EXPORT["view_dispatcher"]
        self.assertEqual(dispatcher["selected_cases"], {"0": 0x5CF398, "13": 0x5CFD14, "16": 0x5CE0A8})
        menu = EXPECTED_EXPORT["menu_table"]
        self.assertEqual(
            {key: menu["index_loop"][key] for key in ("first", "last", "iteration_count")},
            {"first": 0, "last": 18, "iteration_count": 19},
        )
        self.assertEqual(len(menu["set_greyout_call_sites"]), 12)
        belt = EXPECTED_EXPORT["belt_cursor"]
        self.assertEqual((belt["belt_object_offset"], belt["menu_util_offset"]), (0x14C, 0x148))
        self.assertEqual((belt["flag_1"], belt["flag_2"]), (True, False))
        self.assertFalse(belt["concrete_belt_type_proven"])
        self.assertFalse(belt["belt_creation_or_store_proven"])

    def test_navigation_selector_is_not_controller_or_style_state(self):
        from pmca.analysis.creative_style_interaction_surface import EXPECTED_EXPORT

        navigation = EXPECTED_EXPORT["navigation"]
        self.assertEqual(navigation["field_offset"], 0x190)
        self.assertEqual(navigation["routes"], {
            "3": {"operation": "openView", "name": "view/FNMENU"},
            "2": {"operation": "openView", "name": "view/QUICK_NAVI"},
            "other": {"operation": "closeView", "name": "@V01D"},
        })
        self.assertFalse(navigation["creative_style_selection_proven"])

    def test_touchability_candidate_is_not_promoted(self):
        from pmca.analysis.creative_style_interaction_surface import (
            CreativeStyleInteractionSurfaceError,
            EXPECTED_EXPORT,
            normalize_creative_style_interaction_surface_export,
        )

        touch = EXPECTED_EXPORT["touchability_candidate"]
        self.assertEqual(touch["movie_view"]["type_name"], "ViewMovieRecPatch")
        self.assertEqual(touch["movie_view"]["set_touchable_value"], False)
        self.assertEqual(touch["converter"]["type_name"], "PAS_BarCtrlDialConverter")
        self.assertFalse(touch["converter"]["forwarded_value_semantics_resolved"])
        for key in (
            "creative_style_touch_route_found", "coordinate_input_found",
            "hit_test_found", "gesture_found", "selection_dispatch_found",
            "reusable_touch_adjustment_implementation_found",
        ):
            self.assertFalse(EXPECTED_EXPORT["claims"][key])
            changed = copy.deepcopy(EXPECTED_EXPORT)
            changed["claims"][key] = True
            with self.subTest(key=key), self.assertRaises(CreativeStyleInteractionSurfaceError):
                normalize_creative_style_interaction_surface_export(changed)

    def test_checked_in_report_is_non_installable(self):
        from pmca.analysis.creative_style_interaction_surface import validate_creative_style_interaction_surface_report

        report = validate_creative_style_interaction_surface_report(json.loads(REPORT.read_text(encoding="utf-8")))
        self.assertEqual(report["readiness"], "NATIVE_CREATIVE_STYLE_LAYOUT_AND_BELT_TOUCH_UNPROVEN")
        self.assertFalse(report["camera_executed"])
        self.assertFalse(report["installable"])
        self.assertFalse(report["camera_test_eligible"])


class CreativeStyleInteractionSurfaceExporterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("creative_style_interaction_surface_exporter", EXPORTER)
        cls.exporter = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(cls.exporter)

    def test_adapter_is_normalized(self):
        from pmca.analysis.creative_style_interaction_surface import EXPECTED_EXPORT

        class FakeAdapter:
            def metadata(self):
                return copy.deepcopy(EXPECTED_EXPORT)

        self.assertEqual(self.exporter.build_raw_export(FakeAdapter()), EXPECTED_EXPORT)

    def test_branch_join_checks_reject_nonbranches(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned source or parser dependencies are unavailable")
        exporter = self.exporter
        original_instruction = exporter._instruction

        class WrongMnemonic:
            def __init__(self, instruction):
                self._instruction = instruction
                self.mnemonic = "nop"

            def __getattr__(self, name):
                return getattr(self._instruction, name)

        for changed_site in (0x5CF3C0, 0x5CFF8A):
            def changed_instruction(blob, mappings, deps, site):
                item = original_instruction(blob, mappings, deps, site)
                return WrongMnemonic(item) if site == changed_site else item

            with self.subTest(site=changed_site), mock.patch.object(exporter, "_instruction", side_effect=changed_instruction):
                with self.assertRaises(RuntimeError):
                    exporter.ElfAdapter().metadata()

    def test_pointer_and_receiver_joins_reject_clobbers(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned source or parser dependencies are unavailable")
        exporter = self.exporter
        deps = exporter._dependencies()
        original_decode = exporter._decode

        class RegisterClobber:
            def __init__(self, register):
                self.register = register

            def regs_access(self):
                return [], [self.register]

        for changed_start, changed_end, register in (
            (0x5CE0B4, 0x5CE0C0, deps["r1"]),
            (0x627634, 0x62763A, deps["r0"]),
        ):
            def changed_decode(blob, mappings, local_deps, start, end, *, complete=True):
                items = original_decode(blob, mappings, local_deps, start, end, complete=complete)
                return [RegisterClobber(register), *items] if (start, end) == (changed_start, changed_end) else items

            with self.subTest(start=changed_start), mock.patch.object(exporter, "_decode", side_effect=changed_decode):
                with self.assertRaisesRegex(RuntimeError, "preservation"):
                    exporter.ElfAdapter().metadata()

    def test_real_export_matches_when_available(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned source or parser dependencies are unavailable")
        self.assertEqual(self.exporter.build_raw_export(), self.exporter.EXPECTED_EXPORT)


if __name__ == "__main__":
    unittest.main()
