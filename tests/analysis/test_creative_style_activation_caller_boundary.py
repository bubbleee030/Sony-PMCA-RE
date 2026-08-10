import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = ROOT / "analysis" / "a6400-creative-style-activation-caller-boundary.json"
DEEP_DIVE_PATH = ROOT / "analysis" / "a6400a-updater-and-creative-style-deep-dive.md"


class CreativeStyleActivationCallerBoundaryContractTests(unittest.TestCase):
    def test_schema_2_pins_the_typed_menu_route_but_not_selected_node_identity(self):
        """Break caught: property value 42 may not substitute for node identity."""
        from pmca.analysis.creative_style_activation_caller_boundary import (
            EXPECTED_EXPORT,
            normalize_creative_style_activation_caller_boundary_export,
        )

        validated = normalize_creative_style_activation_caller_boundary_export(
            EXPECTED_EXPORT
        )
        self.assertEqual(validated["schema_version"], 2)
        self.assertEqual(
            validated["supporting_source"],
            {
                "module": "lib/CautionConfig.so",
                "size": 12_070_800,
                "sha256": "bfd1bd7bad0ab3478b894da5dbb51c15464b1bedc4201240ccb61cd743150ef7",
            },
        )
        self.assertEqual(
            validated["supporting_dependency"]["artifact_sha256"],
            "febc2ce84490fcbf4072ce77b5323df8584a5c68dd41293a3bfa8e1a6587343a",
        )
        self.assertTrue(
            validated["supporting_dependency"]["root_constructor_binding_found"]
        )
        self.assertFalse(
            validated["supporting_dependency"][
                "root_constructor_runtime_provider_proven"
            ]
        )
        menu = validated["viewsettingmenu_identity"]
        self.assertEqual(menu["vtable_address_point"], 0x8E2270)
        self.assertEqual(menu["slot_54"]["target"], 0x2108B0)
        self.assertEqual(menu["slot_64"]["target"], 0x21355E)
        self.assertEqual(menu["manager_publication"]["field_offset"], 0x16C)
        self.assertEqual(menu["manager_publication"]["store_site"], 0x2109C4)

        route = validated["action_to_manager_route"]
        self.assertEqual(route["action_selector"], 10)
        self.assertEqual(route["action_target"], 0x20C7C0)
        self.assertEqual(route["selected_node_property_key"], 14)
        self.assertEqual(route["manager_field_offset"], 0x16C)
        self.assertEqual(route["condition_field_offset"], 0x174)
        self.assertTrue(route["manager_receiver_proven"])
        self.assertTrue(route["manager_vptr_proven"])
        self.assertTrue(route["selected_node_property_source_proven"])
        self.assertTrue(route["condition_r2_proven"])
        self.assertFalse(route["selected_node_is_creative_style_root_proven"])
        self.assertFalse(route["process_id_42_proven"])

        prop = validated["creative_style_property_14"]
        self.assertEqual(prop["root_object"], 0xC5AE38)
        self.assertEqual(prop["property_list"], 0xA54050)
        self.assertEqual(prop["record"], {"key": 14, "type": 1, "value": 42})
        self.assertEqual(prop["get_int_property_slot"], 23)
        self.assertEqual(prop["get_int_property_target"], 0x7C7518)
        self.assertTrue(prop["static_root_constructor_call_proven"])
        self.assertFalse(prop["root_constructor_runtime_provider_binding_proven"])
        self.assertTrue(
            prop["static_creative_style_root_property_14_equals_42_proven"]
        )

        boundary = validated["selected_node_identity_boundary"]
        self.assertEqual(boundary["runtime_selected_node_source"], "ViewSettingMenu")
        self.assertFalse(boundary["pointer_identity_proven"])
        self.assertFalse(
            validated["claims"]["process_id_42_activation_caller_proven"]
        )
        candidate = validated["caller_scan"]["canonical_slot_20_calls"][0]
        self.assertTrue(candidate["manager_receiver_proven"])
        self.assertTrue(candidate["manager_vptr_proven"])
        self.assertTrue(candidate["process_id_source_proven"])
        self.assertTrue(candidate["condition_r2_proven"])
        self.assertFalse(candidate["process_id_42_proven"])
        self.assertFalse(candidate["accepted"])

    def test_contract_rejects_promoting_the_bounded_scan_to_an_activation_caller(self):
        """Break caught: a report may not turn bounded negative evidence into activation."""
        try:
            from pmca.analysis.creative_style_activation_caller_boundary import (
                EXPECTED_EXPORT,
                FIRST_UNRESOLVED_BOUNDARY,
                READINESS,
                normalize_creative_style_activation_caller_boundary_export,
            )
        except ModuleNotFoundError:
            self.fail("Creative Style activation-caller boundary contract is missing")

        validated = normalize_creative_style_activation_caller_boundary_export(
            EXPECTED_EXPORT
        )
        self.assertEqual(validated["source"]["size"], 11_530_552)
        self.assertEqual(
            validated["source"]["sha256"],
            "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2",
        )
        manager = validated["manager_identity"]
        self.assertEqual(manager["instance_object"], 0xB06BB0)
        self.assertEqual(manager["vtable_address_point"], 0x905930)
        self.assertEqual(manager["bridge_target"], 0x4390BC)

        typed = validated["typed_activation_dependency"]
        self.assertEqual(typed["wrapper_target"], 0x489218)
        self.assertFalse(typed["typed_process_id_42_caller_proven"])

        scan = validated["caller_scan"]
        self.assertEqual(scan["fully_decoded_owner_count"], 28_869)
        self.assertEqual(scan["incomplete_or_terminal_owner_count"], 1_594)
        self.assertEqual(len(scan["canonical_slot_20_calls"]), 16)
        self.assertEqual(scan["accepted_candidates"], [])
        self.assertFalse(scan["whole_program_absence_proven"])

        self.assertFalse(validated["claims"]["process_id_42_activation_caller_proven"])
        self.assertFalse(validated["claims"]["menu_root_activation_join_proven"])
        self.assertFalse(validated["claims"]["runtime_factory_invocation_proven"])
        self.assertFalse(validated["claims"]["first_class_creative_look_equivalence_proven"])
        self.assertFalse(validated["claims"]["installable"])
        self.assertFalse(validated["claims"]["camera_test_eligible"])
        self.assertEqual(validated["readiness"], READINESS)
        self.assertEqual(
            validated["first_unresolved_boundary"], FIRST_UNRESOLVED_BOUNDARY
        )

    def test_report_validator_rejects_behavior_and_narrative_promotions(self):
        """Break caught: false readiness flags or prose must invalidate the report."""
        try:
            from pmca.analysis.creative_style_activation_caller_boundary import (
                EXPECTED_EXPORT,
                build_creative_style_activation_caller_boundary_report,
                validate_creative_style_activation_caller_boundary_report,
            )
        except ImportError:
            self.fail("Creative Style activation-caller report contract is missing")

        report = build_creative_style_activation_caller_boundary_report(
            EXPECTED_EXPORT
        )
        validated = validate_creative_style_activation_caller_boundary_report(report)
        self.assertEqual(validated["summary"]["canonical_slot_20_call_count"], 16)
        self.assertEqual(validated["summary"]["accepted_candidate_count"], 0)
        self.assertFalse(validated["summary"]["whole_program_absence_proven"])
        self.assertIn("28,869 fully decoded", validated["conclusion"])
        self.assertIn("does not prove process ID 42 activation", validated["conclusion"])

        mutations = (
            (
                "caller",
                lambda d: d["claims"].__setitem__(
                    "process_id_42_activation_caller_proven", True
                ),
            ),
            (
                "menu",
                lambda d: d["claims"].__setitem__(
                    "menu_root_activation_join_proven", True
                ),
            ),
            (
                "selected-node",
                lambda d: d["claims"].__setitem__(
                    "selected_node_is_creative_style_root_proven", True
                ),
            ),
            (
                "factory",
                lambda d: d["claims"].__setitem__(
                    "runtime_factory_invocation_proven", True
                ),
            ),
            (
                "creative-look",
                lambda d: d["claims"].__setitem__(
                    "first_class_creative_look_equivalence_proven", True
                ),
            ),
            ("installable", lambda d: d.__setitem__("installable", True)),
            ("recovery", lambda d: d.__setitem__("recovery_validated", True)),
            ("camera", lambda d: d.__setitem__("camera_test_eligible", True)),
            (
                "narrative",
                lambda d: d.__setitem__(
                    "conclusion",
                    "The menu invokes process ID 42 and opens Creative Style at runtime.",
                ),
            ),
        )
        for label, mutate in mutations:
            candidate = copy.deepcopy(report)
            mutate(candidate)
            with self.subTest(label=label), self.assertRaises(ValueError):
                validate_creative_style_activation_caller_boundary_report(candidate)

    def test_checked_report_and_deep_dive_preserve_the_bounded_stop(self):
        """Break caught: checked evidence may not imply an unscanned runtime caller."""
        from pmca.analysis.creative_style_activation_caller_boundary import (
            validate_creative_style_activation_caller_boundary_report,
        )

        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        validate_creative_style_activation_caller_boundary_report(report)
        text = DEEP_DIVE_PATH.read_text(encoding="utf-8")
        for phrase in (
            "concrete process-manager singleton",
            "`0xB06BB0`",
            "typed `ViewSettingMenu` slot-54 owner",
            "selector 10",
            "property-key 14",
            "exact `{14, 1, 42}`",
            "selected-node pointer is not joined",
            "28,869 fully decoded",
            "1,594 decode-incomplete or terminal",
            "sixteen canonical slot-20 call shapes",
            "whole-program absence claim",
            "analysis/a6400-creative-style-activation-caller-boundary.json",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)
        for forbidden in (
            "process ID 42 activation caller is proven",
            "selected node is proven to be the Creative Style root",
            "menu-root activation is proven",
            "runtime Creative Style factory invocation is proven",
            "Creative Look equivalence is proven",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)


class CreativeStyleActivationCallerBoundaryExporterTests(unittest.TestCase):
    def test_schema_2_source_mutations_reject_the_menu_and_property_joins(self):
        """Break caught: independent menu/property facts may not survive byte drift."""
        from tools.static import (
            export_a6400_creative_style_activation_caller_boundary as exporter,
        )

        if not exporter.dependencies_available() or not exporter.sources_available():
            self.skipTest("pinned static source or dependencies are unavailable")
        deps = exporter._dependencies()

        def context_with_mutation(path, address):
            blob = bytearray(path.read_bytes())
            context = exporter._context(bytes(blob), deps)
            for start, end, file_offset in context["mappings"]:
                if start <= address < end:
                    blob[file_offset + address - start] ^= 1
                    return exporter._context(bytes(blob), deps)
            self.fail(f"mutation address {address:#x} is not file-backed")

        for label, address in (
            ("slot-64-cell", 0x8E2370),
            ("manager-publication", 0x2109C4),
            ("action-tail", 0x2136E0),
            ("selected-node-producer", 0x20C7CE),
            ("property-key", 0x2078DC),
            ("manager-reload", 0x20C892),
            ("condition-load", 0x20C898),
        ):
            with self.subTest(source="viewUnified2", label=label), self.assertRaises(
                RuntimeError
            ):
                exporter._validate_viewsettingmenu_route(
                    context_with_mutation(exporter.SOURCE_PATH, address), deps
                )

        for label, address in (
            ("property-object-got", 0xB3A864),
            ("property-list-reference", 0x83CCDA),
            ("property-count", 0x83CCD6),
            ("property-record-value", 0xA54094),
            ("root-properties-load", 0x93B342),
            ("root-constructor-call", 0x93B344),
            ("get-int-property-cell", 0xAC8964),
        ):
            with self.subTest(source="CautionConfig", label=label), self.assertRaises(
                RuntimeError
            ):
                exporter._validate_creative_style_property_14(
                    context_with_mutation(exporter.CAUTION_SOURCE_PATH, address), deps
                )

    def test_real_export_reproduces_the_bounded_activation_caller_contract(self):
        """Break caught: source drift may not retain the checked activation boundary."""
        try:
            from tools.static import (
                export_a6400_creative_style_activation_caller_boundary as exporter,
            )
        except ImportError:
            self.fail("Creative Style activation-caller exporter is missing")
        from pmca.analysis.creative_style_activation_caller_boundary import (
            EXPECTED_EXPORT,
            normalize_creative_style_activation_caller_boundary_export,
        )

        if not exporter.dependencies_available() or not exporter.sources_available():
            self.skipTest("pinned static source or dependencies are unavailable")
        actual = exporter.build_raw_export()
        self.assertEqual(
            normalize_creative_style_activation_caller_boundary_export(actual),
            EXPECTED_EXPORT,
        )

    def test_operand_mutations_reject_unproven_manager_identity_or_condition_flow(self):
        """Break caught: independent instructions may not substitute for joined dataflow."""
        from tools.static import (
            export_a6400_creative_style_activation_caller_boundary as exporter,
        )

        if not exporter.dependencies_available() or not exporter.sources_available():
            self.skipTest("pinned static source or dependencies are unavailable")
        deps = exporter._dependencies()
        original = exporter.SOURCE_PATH.read_bytes()

        def mutated_context(address):
            blob = bytearray(original)
            context = exporter._context(bytes(blob), deps)
            for start, end, file_offset in context["mappings"]:
                if start <= address < end:
                    blob[file_offset + address - start] ^= 1
                    return exporter._context(bytes(blob), deps)
            self.fail(f"mutation address {address:#x} is not file-backed")

        cases = (
            ("instance-offset-load", 0x158362),
            ("constructor-return", 0x43907A),
            ("bridge-condition-capture", 0x4390C0),
        )
        for label, address in cases:
            with self.subTest(label=label), self.assertRaises(RuntimeError):
                exporter._validate_manager_identity(mutated_context(address), deps)

    def test_slot_operand_mutation_invalidates_the_bounded_call_inventory(self):
        """Break caught: removing one canonical slot-20 shape must fail the export."""
        from tools.static import (
            export_a6400_creative_style_activation_caller_boundary as exporter,
        )

        if not exporter.dependencies_available() or not exporter.sources_available():
            self.skipTest("pinned static source or dependencies are unavailable")
        deps = exporter._dependencies()
        blob = bytearray(exporter.SOURCE_PATH.read_bytes())
        context = exporter._context(bytes(blob), deps)
        address = 0x2A5256
        for start, end, file_offset in context["mappings"]:
            if start <= address < end:
                blob[file_offset + address - start] ^= 1
                break
        else:
            self.fail("canonical slot-load mutation is not file-backed")
        mutated = exporter._context(bytes(blob), deps)
        try:
            validator = exporter._validate_caller_scan
        except AttributeError:
            self.fail("bounded caller-inventory validator is missing")
        with self.assertRaises(RuntimeError):
            validator(mutated, deps)

    def test_outputs_are_deterministic_and_validation_failure_writes_nothing(self):
        """Break caught: a stale/invalid report may not partially update artifacts."""
        from tools.static import (
            export_a6400_creative_style_activation_caller_boundary as exporter,
        )

        try:
            build_outputs = exporter.build_outputs
        except AttributeError:
            self.fail("activation-caller output transaction is missing")

        with mock.patch.object(
            exporter,
            "build_raw_export",
            return_value=copy.deepcopy(exporter.EXPECTED_EXPORT),
        ):
            first = build_outputs()
            second = build_outputs()
        encode = lambda value: (
            json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        self.assertEqual(
            {path.name: encode(value) for path, value in first.items()},
            {path.name: encode(value) for path, value in second.items()},
        )
        self.assertEqual(
            {path.name for path in first},
            {
                "creative-style-activation-caller-boundary-export.json",
                "a6400-creative-style-activation-caller-boundary.json",
            },
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            raw_path = root / "creative-style-activation-caller-boundary-export.json"
            report_path = root / "a6400-creative-style-activation-caller-boundary.json"
            raw_path.write_text("old raw\n", encoding="utf-8")
            report_path.write_text("old report\n", encoding="utf-8")
            with (
                mock.patch.object(exporter, "RAW_OUTPUT_PATH", raw_path),
                mock.patch.object(exporter, "REPORT_PATH", report_path),
                mock.patch.object(
                    exporter,
                    "build_raw_export",
                    return_value=copy.deepcopy(exporter.EXPECTED_EXPORT),
                ),
                mock.patch.object(
                    exporter,
                    "validate_creative_style_activation_caller_boundary_report",
                    side_effect=RuntimeError("report validation failed"),
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "report validation failed"):
                    exporter.publish_outputs()
            self.assertEqual(raw_path.read_text(encoding="utf-8"), "old raw\n")
            self.assertEqual(report_path.read_text(encoding="utf-8"), "old report\n")


if __name__ == "__main__":
    unittest.main()
