import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = ROOT / "analysis" / "a6400-creative-style-view-lifecycle-boundary.json"
DEEP_DIVE_PATH = ROOT / "analysis" / "a6400a-updater-and-creative-style-deep-dive.md"


class CreativeStyleViewLifecycleBoundaryContractTests(unittest.TestCase):
    def test_expected_boundary_pins_typed_activation_and_runtime_stop(self):
        from pmca.analysis.creative_style_view_lifecycle_boundary import (
            EXPECTED_EXPORT,
            FIRST_UNRESOLVED_BOUNDARY,
            READINESS,
            normalize_creative_style_view_lifecycle_boundary_export,
        )

        validated = normalize_creative_style_view_lifecycle_boundary_export(EXPECTED_EXPORT)

        typed = validated["typed_activation"]
        self.assertEqual(typed["element"]["vtable_address_point"], 0x90ED88)
        self.assertEqual(typed["slot"], 25)
        self.assertEqual(typed["cell"], 0x90EDEC)
        self.assertEqual(
            typed["base_abi"]["symbol"],
            "_ZN31CmnViewProcessDataElementNormal21execProcWithConditionEi",
        )
        self.assertEqual(typed["wrapper"]["alias"], "view/CREATIVE_STYLE")
        self.assertTrue(typed["wrapper"]["condition_forwarded_unchanged"])

        registration = validated["registration"]
        self.assertEqual(registration["branch_source"]["backup_id"], 0x003E000B)
        self.assertEqual(
            [row["component"] for row in registration["rows"]],
            ["viewCreativeStyle.so", "viewUnified2.so"],
        )
        self.assertEqual(
            [row["factory"] for row in registration["rows"]],
            ["ViewCreativeStyleToInstance", "ViewCreativeStyleToInstance"],
        )
        self.assertFalse(registration["active_row_resolved"])

        identity = validated["conditional_table_identity"]
        self.assertEqual(identity["singleton_storage"], 0x14250D4)
        self.assertNotEqual(identity["singleton_storage"], 0x13A50D4)
        self.assertTrue(identity["registration_receiver_equals_loader_table_if_conditions_hold"])
        self.assertFalse(identity["unconditional_identity_proven"])
        self.assertGreaterEqual(len(identity["conditions"]), 3)

        claims = validated["claims"]
        self.assertTrue(claims["typed_creative_style_open_view_bridge_proven"])
        self.assertTrue(claims["alternative_registration_rows_proven"])
        self.assertTrue(claims["conditional_registration_loader_table_identity_proven"])
        self.assertFalse(claims["runtime_provider_binding_proven"])
        self.assertFalse(claims["runtime_registration_row_selected"])
        self.assertFalse(claims["runtime_factory_invocation_proven"])
        self.assertFalse(claims["first_class_creative_look_equivalence_proven"])
        self.assertFalse(claims["installable"])
        self.assertFalse(claims["camera_test_eligible"])
        self.assertEqual(validated["readiness"], READINESS)
        self.assertEqual(validated["first_unresolved_boundary"], FIRST_UNRESOLVED_BOUNDARY)

    def test_checked_report_preserves_conditional_identity_and_rejects_promotions(self):
        from pmca.analysis.creative_style_view_lifecycle_boundary import (
            EXPECTED_EXPORT,
            build_creative_style_view_lifecycle_boundary_report,
            validate_creative_style_view_lifecycle_boundary_report,
        )

        report = build_creative_style_view_lifecycle_boundary_report(EXPECTED_EXPORT)
        validated = validate_creative_style_view_lifecycle_boundary_report(report)
        self.assertTrue(validated["summary"]["conditional_table_identity_proven"])
        self.assertFalse(validated["summary"]["unconditional_table_identity_proven"])
        self.assertFalse(validated["claims"]["runtime_factory_invocation_proven"])
        self.assertIn("only if", validated["conclusion"])
        self.assertIn("does not prove runtime factory invocation", validated["conclusion"])

        mutations = (
            ("factory", lambda d: d["claims"].__setitem__("runtime_factory_invocation_proven", True)),
            ("creative-look", lambda d: d["claims"].__setitem__("first_class_creative_look_equivalence_proven", True)),
            ("installable", lambda d: d.__setitem__("installable", True)),
            ("narrative", lambda d: d.__setitem__("conclusion", "The selected row invokes the Creative Style factory at runtime.")),
        )
        for label, mutate in mutations:
            candidate = copy.deepcopy(report)
            mutate(candidate)
            with self.subTest(label=label), self.assertRaises(ValueError):
                validate_creative_style_view_lifecycle_boundary_report(candidate)

    def test_checked_artifact_and_deep_dive_preserve_the_runtime_stop(self):
        from pmca.analysis.creative_style_view_lifecycle_boundary import (
            validate_creative_style_view_lifecycle_boundary_report,
        )

        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        validate_creative_style_view_lifecycle_boundary_report(report)

        text = DEEP_DIVE_PATH.read_text(encoding="utf-8")
        for phrase in (
            "typed process-element slot 25",
            "two mutually exclusive registration rows",
            "corrected singleton storage `0x14250D4`",
            "only under the AppConfig selector and pinned provider bindings",
            "does not prove runtime factory invocation",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)
        for forbidden in (
            "the selected registration row is proven",
            "runtime factory invocation is proven",
            "Creative Look equivalence is proven",
            "camera-test eligible",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)


class CreativeStyleViewLifecycleBoundaryExporterTests(unittest.TestCase):
    def test_real_export_matches_exact_static_contract_when_available(self):
        from pmca.analysis.creative_style_view_lifecycle_boundary import (
            EXPECTED_EXPORT,
            normalize_creative_style_view_lifecycle_boundary_export,
        )
        from tools.static import export_a6400_creative_style_view_lifecycle_boundary as exporter

        if not exporter.dependencies_available() or not exporter.sources_available():
            self.skipTest("pinned static sources or dependencies are unavailable")

        actual = exporter.build_raw_export()
        self.assertEqual(
            normalize_creative_style_view_lifecycle_boundary_export(actual),
            EXPECTED_EXPORT,
        )

    def test_in_memory_source_mutations_reject_critical_lifecycle_edges(self):
        from tools.static import export_a6400_creative_style_view_lifecycle_boundary as exporter

        if not exporter.dependencies_available() or not exporter.sources_available():
            self.skipTest("pinned static sources or dependencies are unavailable")

        deps = exporter._dependencies()
        mutations = (
            ("view", 0x90EDF4, exporter._validate_view_source, "typed-element-rtti-name"),
            ("view", 0x489224, exporter._validate_view_source, "open-view-return"),
            ("view", 0x2DC214, exporter._validate_view_source, "registration-branch-value"),
            ("view", 0x40BD76, exporter._validate_view_source, "first-registration-add"),
            ("view", 0x40DBD6, exporter._validate_view_source, "second-registration-add"),
            ("view", 0x8FC744, exporter._validate_view_source, "view-config-slot"),
            ("object", 0x3FD442, exporter._validate_object_source, "app-config-thunk"),
            ("object", 0x8472BC, exporter._validate_object_source, "singleton-address"),
            ("object", 0x3F2BD4, exporter._validate_object_source, "open-view-event-id"),
            ("object", 0x845EA0, exporter._validate_object_source, "dlopen-call"),
            ("object", 0x845F28, exporter._validate_object_source, "dlsym-call"),
            ("object", 0x845F4C, exporter._validate_object_source, "factory-indirect-call"),
        )
        original = {
            role: exporter.SOURCE_PATHS[role].read_bytes() for role in ("view", "object")
        }

        for role, address, validator, label in mutations:
            with self.subTest(label=label):
                blob = bytearray(original[role])
                elf = deps["ELFFile"](__import__("io").BytesIO(blob))
                mappings = exporter._mappings(elf)
                for start, end, file_offset in mappings:
                    if start <= address < end:
                        blob[file_offset + address - start] ^= 1
                        break
                else:
                    self.fail(f"mutation address {address:#x} is not file-backed")
                context = exporter._context(bytes(blob), deps)
                with self.assertRaises(RuntimeError):
                    validator(context, deps)

    def test_outputs_are_deterministic_and_validated_before_any_write(self):
        from tools.static import export_a6400_creative_style_view_lifecycle_boundary as exporter

        with mock.patch.object(
            exporter,
            "build_raw_export",
            return_value=copy.deepcopy(exporter.EXPECTED_EXPORT),
        ):
            first = exporter.build_outputs()
            second = exporter.build_outputs()

        encode = lambda document: (
            json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        self.assertEqual(
            {path.name: encode(value) for path, value in first.items()},
            {path.name: encode(value) for path, value in second.items()},
        )
        self.assertEqual(
            set(path.name for path in first),
            {
                "creative-style-view-lifecycle-boundary-export.json",
                "a6400-creative-style-view-lifecycle-boundary.json",
            },
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            raw_root = root / "raw"
            report_root = root / "report"
            raw_root.mkdir()
            report_root.mkdir()
            raw_path = raw_root / "creative-style-view-lifecycle-boundary-export.json"
            report_path = report_root / "a6400-creative-style-view-lifecycle-boundary.json"
            raw_path.write_text("old raw\n", encoding="utf-8")
            report_path.write_text("old report\n", encoding="utf-8")
            with (
                mock.patch.object(exporter, "RAW_OUTPUT_ROOT", raw_root),
                mock.patch.object(exporter, "REPORT_OUTPUT_ROOT", report_root),
                mock.patch.object(exporter, "RAW_OUTPUT_PATH", raw_path),
                mock.patch.object(exporter, "REPORT_PATH", report_path),
                mock.patch.object(
                    exporter,
                    "build_raw_export",
                    return_value=copy.deepcopy(exporter.EXPECTED_EXPORT),
                ),
                mock.patch.object(
                    exporter,
                    "validate_creative_style_view_lifecycle_boundary_report",
                    side_effect=RuntimeError("report validation failed"),
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "report validation failed"):
                    exporter.publish_outputs()
            self.assertEqual(raw_path.read_text(encoding="utf-8"), "old raw\n")
            self.assertEqual(report_path.read_text(encoding="utf-8"), "old report\n")


if __name__ == "__main__":
    unittest.main()
