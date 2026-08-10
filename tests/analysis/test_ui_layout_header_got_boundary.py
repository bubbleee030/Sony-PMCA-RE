import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = ROOT / "analysis" / "a6400-ui-layout-header-got-boundary.json"
SLOT34_REPORT_PATH = ROOT / "analysis" / "a6400-ui-slot34-dispatch.json"
EXPORTER_PATH = ROOT / "tools" / "static" / "export_a6400_ui_layout_header_got_boundary.py"


class UILayoutHeaderGotBoundaryTests(unittest.TestCase):
    def test_prior_slot34_digest_matches_the_current_validated_report(self):
        from pmca.analysis.ui_layout_header_got_boundary import (
            SLOT34_DISPATCH_DIGEST,
        )
        from pmca.analysis.ui_slot34_dispatch import validate_ui_slot34_dispatch_report

        slot34 = validate_ui_slot34_dispatch_report(
            json.loads(SLOT34_REPORT_PATH.read_text(encoding="utf-8"))
        )
        self.assertEqual(
            SLOT34_DISPATCH_DIGEST,
            slot34["export_summary"]["canonical_export_sha256"],
        )

    def test_normalizer_accepts_only_the_exact_loader_boundary(self):
        from pmca.analysis.ui_layout_header_got_boundary import (
            EXPECTED_RAW_EXPORT,
            normalize_ui_layout_header_got_boundary_export,
        )

        normalized = normalize_ui_layout_header_got_boundary_export(copy.deepcopy(EXPECTED_RAW_EXPORT))
        self.assertEqual(normalized["got_section"]["start"], 0x71B0C)
        self.assertEqual(normalized["got_section"]["end"], 0x724F0)
        self.assertEqual(normalized["unsymbolized_relative_got_count"], 194)
        self.assertEqual(
            [entry["relocation_index"] for entry in normalized["layout_header_relocations"]],
            [1629, 1633, 1684, 1739, 1744],
        )
        self.assertEqual(normalized["separated_named_import"]["site"], 0x72434)
        self.assertFalse(normalized["claims"]["typed_consumer_found"])
        self.assertFalse(normalized["behavior_support"]["menu_touch_selection"])

    def test_normalizer_rejects_symbol_fabrication_adjacency_and_promotions(self):
        from pmca.analysis.ui_layout_header_got_boundary import (
            EXPECTED_RAW_EXPORT,
            UILayoutHeaderGotBoundaryError,
            normalize_ui_layout_header_got_boundary_export,
        )

        mutations = (
            lambda value: value["layout_header_relocations"][0].__setitem__("symbol_index", 1),
            lambda value: value["layout_header_relocations"][0]["site_symbol_coverage"].__setitem__("covering", ["invented"]),
            lambda value: value["layout_header_relocations"][0]["header_symbol_coverage"].__setitem__("exact", ["invented"]),
            lambda value: value["layout_header_relocations"][0].__setitem__("object_membership", "adjacent-object"),
            lambda value: value["separated_named_import"].__setitem__("symbol", "cmnViewSettingNodeRootPictureProfile"),
            lambda value: value["claims"].__setitem__("factory_or_resource_owner_found", True),
            lambda value: value["behavior_support"].__setitem__("menu_touch_selection", True),
            lambda value: value.__setitem__("instructions", []),
        )
        for mutate in mutations:
            candidate = copy.deepcopy(EXPECTED_RAW_EXPORT)
            mutate(candidate)
            with self.subTest(mutate=mutate), self.assertRaises(UILayoutHeaderGotBoundaryError):
                normalize_ui_layout_header_got_boundary_export(candidate)

    def test_report_is_noninstallable_and_retains_external_boundary(self):
        from pmca.analysis.ui_layout_header_got_boundary import (
            UILayoutHeaderGotBoundaryError,
            validate_ui_layout_header_got_boundary_report,
        )

        report = validate_ui_layout_header_got_boundary_report(json.loads(REPORT_PATH.read_text(encoding="utf-8")))
        self.assertFalse(report["installable"])
        self.assertFalse(report["camera_test_eligible"])
        self.assertIn("loader/GOT", report["conclusion"])
        forged = copy.deepcopy(report)
        forged["claims"]["orientation_layout_selector_found"] = True
        with self.assertRaises(UILayoutHeaderGotBoundaryError):
            validate_ui_layout_header_got_boundary_report(forged)


class UILayoutHeaderGotBoundaryExporterTests(unittest.TestCase):
    def _load(self):
        spec = importlib.util.spec_from_file_location("ui_layout_header_got_boundary_exporter", EXPORTER_PATH)
        exporter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(exporter)
        return exporter

    def test_exporter_requires_exact_static_metadata(self):
        exporter = self._load()

        class Adapter:
            def metadata(self):
                return copy.deepcopy(exporter.EXPECTED_RAW_EXPORT)

        raw = exporter.build_raw_export(Adapter())
        self.assertEqual(raw["unsymbolized_relative_got_count"], 194)
        self.assertEqual(len(raw["layout_header_relocations"]), 5)

    def test_exporter_rejects_escape_and_symbol_promotion(self):
        exporter = self._load()

        class Adapter:
            def metadata(self):
                value = copy.deepcopy(exporter.EXPECTED_RAW_EXPORT)
                value["layout_header_relocations"][0]["symbol_index"] = 99
                return value

        with self.assertRaises(RuntimeError):
            exporter.build_raw_export(Adapter())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with mock.patch.object(exporter, "OUTPUT_ROOT", root):
                exporter.write_json_atomic(root / "raw-ui-layout-header-got-boundary.json", exporter.EXPECTED_RAW_EXPORT)
                with self.assertRaises(RuntimeError):
                    exporter.write_json_atomic(root / "elsewhere.json", exporter.EXPECTED_RAW_EXPORT)

    def test_exporter_rejects_a_symlinked_output_root(self):
        exporter = self._load()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with mock.patch.object(exporter, "OUTPUT_ROOT", root), mock.patch.object(exporter.Path, "is_symlink", return_value=True):
                with self.assertRaises(RuntimeError):
                    exporter.write_json_atomic(root / "raw-ui-layout-header-got-boundary.json", exporter.EXPECTED_RAW_EXPORT)

    def test_exporter_rejects_a_live_symlinked_output_root_when_available(self):
        exporter = self._load()
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            target = parent / "target"
            target.mkdir()
            link = parent / "link"
            try:
                link.symlink_to(target, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symlink creation unavailable: {error}")
            with mock.patch.object(exporter, "OUTPUT_ROOT", link):
                with self.assertRaises(RuntimeError):
                    exporter.write_json_atomic(link / "raw-ui-layout-header-got-boundary.json", exporter.EXPECTED_RAW_EXPORT)


if __name__ == "__main__":
    unittest.main()
