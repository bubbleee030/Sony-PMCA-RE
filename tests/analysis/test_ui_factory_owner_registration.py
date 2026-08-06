import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = ROOT / "analysis" / "a6400-ui-factory-owner-registration.json"
EXPORTER_PATH = ROOT / "tools" / "static" / "export_a6400_ui_factory_owner_registration.py"


RELATIVE_REGISTRATIONS = [
    {"address": 0x70EE8, "target": 0x529CC, "thumb_pointer": 0x529CD, "evidence_kind": "relocation", "relocation_type": "R_ARM_RELATIVE", "section_name": ".rel.dyn"},
    {"address": 0x70FA0, "target": 0x529CC, "thumb_pointer": 0x529CD, "evidence_kind": "relocation", "relocation_type": "R_ARM_RELATIVE", "section_name": ".rel.dyn"},
    {"address": 0x71040, "target": 0x529CC, "thumb_pointer": 0x529CD, "evidence_kind": "relocation", "relocation_type": "R_ARM_RELATIVE", "section_name": ".rel.dyn"},
    {"address": 0x710F0, "target": 0x529CC, "thumb_pointer": 0x529CD, "evidence_kind": "relocation", "relocation_type": "R_ARM_RELATIVE", "section_name": ".rel.dyn"},
    {"address": 0x711A0, "target": 0x529CC, "thumb_pointer": 0x529CD, "evidence_kind": "relocation", "relocation_type": "R_ARM_RELATIVE", "section_name": ".rel.dyn"},
]
ORIENTATION_IMPORTS = [
    {"id": "camera_orientation", "symbol": "_ZN27CmnWrpOrientationRegisterAF20getCameraOrientationEv", "plt": 0x14958, "owners": [{"owner": 0x2D2C6, "site": 0x2D2CC}, {"owner": 0x30750, "site": 0x30934}]},
    {"id": "status_orientation", "symbol": "_ZN27CmnWrpOrientationRegisterAF23getStsCameraOrientationEv", "plt": 0x15008, "owners": [{"owner": 0x189DC, "site": 0x189EE}, {"owner": 0x1B070, "site": 0x1B08C}, {"owner": 0x1C56C, "site": 0x1C584}, {"owner": 0x1C56C, "site": 0x1C5E4}]},
]


def raw_export(*, registrations=None):
    return {
        "schema_version": 1,
        "program": "viewUnified7.so",
        "sha256": "c48cde43ff22d808ad23c42019ddae516fff7da060004eb81ed2bb85012aa538",
        "image_size": 541024,
        "analysis_mode": {"engine": "elf-capstone-thumb-metadata", "read_only": True, "source_unchanged": True},
        "owner": {
            "range": {"start": 0x529CC, "end": 0x529E8},
            "forwarding_edge": {"caller": 0x529CC, "site": 0x529D6, "target": 0x52840, "kind": "direct"},
            "direct_callers": [],
        },
        "typed_registration_references": copy.deepcopy(RELATIVE_REGISTRATIONS if registrations is None else registrations),
        "orientation_imports": copy.deepcopy(ORIENTATION_IMPORTS),
        "direct_path_summary": {
            "max_depth": 32,
            "orientation_roots": [0x2D2C6, 0x30750, 0x189DC, 0x1B070, 0x1C56C],
            "layout_mode_roots": [0x193E0, 0x27458, 0x27540, 0x29660, 0x2D68C, 0x2D770, 0x2D82C, 0x3260C, 0x53598, 0x53B9C, 0x54440, 0x56CCC, 0x56D8C, 0x56E4C, 0x56F0C],
            "paths_to_owner": [],
            "paths_to_factory": [],
        },
        "truncated": False,
    }


class UIFactoryOwnerRegistrationTests(unittest.TestCase):
    def test_relative_thumb_relocations_establish_registration_without_behavior_promotion(self):
        from pmca.analysis.ui_factory_owner_registration import normalize_ui_factory_owner_registration_export

        normalized = normalize_ui_factory_owner_registration_export(raw_export())

        self.assertEqual(normalized["owner"]["range"], {"start": 0x529CC, "end": 0x529E8})
        self.assertEqual(normalized["typed_registration_references"], RELATIVE_REGISTRATIONS)
        self.assertTrue(normalized["claims"]["vertical_layout_factory_found"])
        self.assertTrue(normalized["claims"]["factory_forwarding_owner_found"])
        self.assertTrue(normalized["claims"]["typed_owner_registration_found"])
        self.assertEqual(normalized["orientation_imports"], ORIENTATION_IMPORTS)
        self.assertFalse(normalized["claims"]["orientation_layout_selector_found"])
        self.assertFalse(normalized["behavior_support"]["menu-touch-selection"])

    def test_registration_requires_typed_relocation_symbol_or_section_evidence(self):
        from pmca.analysis.ui_factory_owner_registration import UIFactoryOwnerRegistrationError, normalize_ui_factory_owner_registration_export

        for reference in (
            {"address": 0x40000, "target": 0x529CC, "evidence_kind": "pointer-scan"},
            {"address": 0x70EE8, "target": 0x529CD, "thumb_pointer": 0x529CD, "evidence_kind": "relocation", "relocation_type": "R_ARM_RELATIVE", "section_name": ".rel.dyn"},
            {"address": 0x70EE8, "target": 0x529CC, "thumb_pointer": 0x529CC, "evidence_kind": "relocation", "relocation_type": "R_ARM_RELATIVE", "section_name": ".rel.dyn"},
            {"address": 0x70EE8, "target": 0x529CC, "thumb_pointer": 0x529CD, "evidence_kind": "relocation", "relocation_type": "", "section_name": ".rel.dyn"},
        ):
            with self.subTest(reference=reference), self.assertRaises(UIFactoryOwnerRegistrationError):
                normalize_ui_factory_owner_registration_export(raw_export(registrations=[reference]))

    def test_exact_owner_edge_paths_and_metadata_scope_are_fail_closed(self):
        from pmca.analysis.ui_factory_owner_registration import UIFactoryOwnerRegistrationError, normalize_ui_factory_owner_registration_export

        for mutate in (
            lambda value: value["owner"]["direct_callers"].append({"caller": 0x1, "site": 0x2, "target": 0x529CC, "kind": "direct"}),
            lambda value: value["owner"]["forwarding_edge"].__setitem__("site", 0x529D4),
            lambda value: value["direct_path_summary"].__setitem__("max_depth", 33),
            lambda value: value["orientation_imports"][1]["owners"].pop(),
            lambda value: value.__setitem__("bytes", "forbidden"),
            lambda value: value.__setitem__("truncated", True),
        ):
            candidate = raw_export()
            mutate(candidate)
            with self.subTest(candidate=candidate), self.assertRaises(UIFactoryOwnerRegistrationError):
                normalize_ui_factory_owner_registration_export(candidate)

    def test_report_rejects_digest_and_selector_touch_promotion(self):
        from pmca.analysis.ui_factory_owner_registration import UIFactoryOwnerRegistrationError, validate_ui_factory_owner_registration_report

        original = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        validated = validate_ui_factory_owner_registration_report(original)
        self.assertTrue(validated["claims"]["typed_owner_registration_found"])
        self.assertEqual(validated["export_summary"]["typed_registration_reference_count"], 5)
        forged = copy.deepcopy(original)
        forged["export_summary"]["canonical_export_sha256"] = "0" * 64
        with self.assertRaises(UIFactoryOwnerRegistrationError):
            validate_ui_factory_owner_registration_report(forged)
        for section, field in (("claims", "orientation_layout_selector_found"), ("behavior_support", "menu-touch-hit-test")):
            candidate = copy.deepcopy(original)
            candidate[section][field] = True
            with self.subTest(section=section), self.assertRaises(UIFactoryOwnerRegistrationError):
                validate_ui_factory_owner_registration_report(candidate)


class UIFactoryOwnerRegistrationExporterTests(unittest.TestCase):
    def _load(self):
        spec = importlib.util.spec_from_file_location("ui_owner_registration_exporter", EXPORTER_PATH)
        exporter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(exporter)
        return exporter

    def test_exporter_requires_exact_typed_registrations_imports_and_paths(self):
        exporter = self._load()

        class Adapter:
            def program_name(self): return exporter.EXPECTED_PROGRAM
            def program_sha256(self): return exporter.EXPECTED_SHA256
            def program_size(self): return exporter.EXPECTED_IMAGE_SIZE
            def analysis_mode(self): return exporter.EXPECTED_ANALYSIS_MODE
            def owner_metadata(self): return exporter.EXPECTED_OWNER
            def typed_registration_references(self): return exporter.EXPECTED_TYPED_REGISTRATIONS
            def orientation_imports(self): return exporter.EXPECTED_ORIENTATION_IMPORTS
            def direct_path_summary(self): return exporter.EXPECTED_PATH_SUMMARY

        raw = exporter.build_raw_export(Adapter())
        self.assertEqual(raw["typed_registration_references"], RELATIVE_REGISTRATIONS)
        self.assertEqual(raw["orientation_imports"], ORIENTATION_IMPORTS)
        self.assertEqual(raw["owner"]["direct_callers"], [])

    def test_exporter_rejects_untyped_reference_dirty_source_and_escaped_output(self):
        exporter = self._load()

        class Adapter:
            def program_name(self): return exporter.EXPECTED_PROGRAM
            def program_sha256(self): return exporter.EXPECTED_SHA256
            def program_size(self): return exporter.EXPECTED_IMAGE_SIZE
            def analysis_mode(self): return exporter.EXPECTED_ANALYSIS_MODE
            def owner_metadata(self): return exporter.EXPECTED_OWNER
            def typed_registration_references(self): return ({"address": 0x40000, "target": 0x529CC, "evidence_kind": "pointer-scan"},)
            def orientation_imports(self): return exporter.EXPECTED_ORIENTATION_IMPORTS
            def direct_path_summary(self): return exporter.EXPECTED_PATH_SUMMARY

        with self.assertRaises(RuntimeError):
            exporter.build_raw_export(Adapter())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            exporter.write_json_atomic(root / "raw-ui-factory-owner-registration.json", {"schema_version": 1}, root)
            with self.assertRaises(RuntimeError):
                exporter.write_json_atomic(root / "other.json", {}, root)
            with self.assertRaises(RuntimeError):
                exporter.write_json_atomic(root.parent / "raw-ui-factory-owner-registration.json", {}, root)

    def test_missing_elf_dependencies_fail_closed(self):
        exporter = self._load()
        with mock.patch.object(exporter, "_require_dependencies", side_effect=RuntimeError("missing")):
            with self.assertRaisesRegex(RuntimeError, "missing"):
                exporter._metadata_from_file(ROOT / "missing.so")


if __name__ == "__main__":
    unittest.main()
