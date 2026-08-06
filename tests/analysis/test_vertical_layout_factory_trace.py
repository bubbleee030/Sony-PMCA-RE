import copy
import importlib.util
import json
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from pmca.analysis.vertical_layout_factory_trace import (
    VerticalLayoutFactoryTraceError,
    normalize_vertical_layout_factory_export,
    summarize_vertical_layout_factory_export,
    validate_vertical_layout_factory_report,
)


ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = ROOT / "analysis" / "a6400-vertical-layout-factory.json"
EXPORTER_PATH = ROOT / "tools" / "static" / "export_a6400_vertical_layout_factory.py"


def raw_export(*, reverse_callers=None):
    return {
        "schema_version": 1,
        "program": "viewUnified7.so",
        "sha256": "c48cde43ff22d808ad23c42019ddae516fff7da060004eb81ed2bb85012aa538",
        "image_size": 541024,
        "analysis_mode": {"engine": "elf-capstone-thumb", "read_only": True, "source_unchanged": True},
        "factory": {
            "root": 0x52840,
            "branch_value_classification": "local-branching-observed",
            "constructors": [
                {"id": "header-manual-info", "caller": 0x52840, "site": 0x52914, "target": 0x14148, "kind": "direct"},
                {"id": "error", "caller": 0x52840, "site": 0x52924, "target": 0x14B04, "kind": "direct"},
                {"id": "info", "caller": 0x52840, "site": 0x52934, "target": 0x14E9C, "kind": "direct"},
                {"id": "footer", "caller": 0x52840, "site": 0x52944, "target": 0x14028, "kind": "direct"},
                {"id": "manual", "caller": 0x52840, "site": 0x52954, "target": 0x14D64, "kind": "direct"},
            ],
            "reverse_callers": copy.deepcopy(reverse_callers if reverse_callers is not None else [{"caller": 0x529CC, "site": 0x529D6, "target": 0x52840, "kind": "direct"}]),
            "unresolved_indirect_terminals": [],
        },
        "upstream_roots": {
            "camera_orientation_owners": [0x2D2C6, 0x30750],
            "status_orientation_owners": [0x189DC, 0x1B070, 0x1C56C],
            "layout_mode": {"site_count": 28, "owner_count": 15, "owner_overlap_with_factory": False},
        },
        "truncated": False,
    }


class VerticalLayoutFactoryTraceTests(unittest.TestCase):
    def test_exact_five_way_factory_normalizes_without_ui_promotion(self):
        normalized = normalize_vertical_layout_factory_export(raw_export())

        self.assertEqual(normalized["factory"]["root"], 0x52840)
        self.assertEqual(
            [edge["site"] for edge in normalized["factory"]["constructors"]],
            [0x52914, 0x52924, 0x52934, 0x52944, 0x52954],
        )
        self.assertTrue(normalized["claims"]["vertical_layout_factory_found"])
        self.assertFalse(normalized["claims"]["orientation_layout_selector_found"])
        self.assertFalse(normalized["behavior_support"]["touch-coordinate-transform"])

    def test_factory_requires_exact_membership_and_order(self):
        for mutate in (
            lambda value: value["factory"]["constructors"].pop(),
            lambda value: value["factory"]["constructors"].reverse(),
            lambda value: value["factory"]["constructors"].__setitem__(0, {**value["factory"]["constructors"][0], "site": 0x52916}),
        ):
            candidate = raw_export()
            mutate(candidate)
            with self.subTest(candidate=candidate), self.assertRaises(VerticalLayoutFactoryTraceError):
                normalize_vertical_layout_factory_export(candidate)

    def test_ambiguous_or_unresolved_reverse_evidence_cannot_promote_selector(self):
        candidate = raw_export(reverse_callers=[
            {"caller": 0x2D2C6, "site": 0x2D2CC, "kind": "direct"},
            {"caller": 0x30750, "site": 0x30934, "kind": "direct"},
        ])
        with self.assertRaises(VerticalLayoutFactoryTraceError):
            normalize_vertical_layout_factory_export(candidate)

    def test_identity_scope_and_forbidden_material_are_strict(self):
        bad_identity = raw_export()
        bad_identity["sha256"] = "0" * 64
        forbidden = raw_export()
        forbidden["factory"]["instructions"] = ["forbidden"]
        for candidate in (bad_identity, forbidden):
            with self.subTest(candidate=candidate), self.assertRaises(VerticalLayoutFactoryTraceError):
                normalize_vertical_layout_factory_export(candidate)

    def test_summary_is_digestable_and_noninstallable(self):
        summary = summarize_vertical_layout_factory_export(raw_export())

        self.assertRegex(summary["canonical_export_sha256"], r"^[0-9a-f]{64}$")
        self.assertTrue(summary["claims"]["vertical_layout_factory_found"])
        self.assertFalse(summary["claims"]["orientation_layout_selector_found"])

    def test_committed_report_is_fail_closed(self):
        report = validate_vertical_layout_factory_report(
            json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        )

        self.assertTrue(report["claims"]["vertical_layout_factory_found"])
        self.assertFalse(report["claims"]["orientation_layout_selector_found"])
        self.assertFalse(report["installable"])
        self.assertFalse(report["camera_test_eligible"])
        self.assertIn("not established by this bounded slice", report["conclusion"])

    def test_report_rejects_selector_touch_or_digest_promotion(self):
        original = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        forged = copy.deepcopy(original)
        forged["export_summary"]["canonical_export_sha256"] = "0" * 64
        for section, field in (("claims", "orientation_layout_selector_found"), ("behavior_support", "touch-coordinate-transform")):
            candidate = copy.deepcopy(original)
            candidate[section][field] = True
            with self.subTest(section=section), self.assertRaises(VerticalLayoutFactoryTraceError):
                validate_vertical_layout_factory_report(candidate)
        with self.assertRaises(VerticalLayoutFactoryTraceError):
            validate_vertical_layout_factory_report(forged)


class VerticalLayoutFactoryExporterTests(unittest.TestCase):
    def test_exporter_requests_only_pinned_factory_and_upstream_roots(self):
        spec = importlib.util.spec_from_file_location("vertical_factory_exporter", EXPORTER_PATH)
        exporter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(exporter)

        class Adapter:
            def program_name(self): return exporter.EXPECTED_PROGRAM
            def program_sha256(self): return exporter.EXPECTED_SHA256
            def program_size(self): return exporter.EXPECTED_IMAGE_SIZE
            def analysis_mode(self): return {"engine": "elf-capstone-thumb", "read_only": True, "source_unchanged": True}
            def factory_metadata(self, root): self.root = root; return {"constructors": exporter.CONSTRUCTORS, "reverse_callers": exporter.REVERSE_CALLERS, "unresolved_indirect_terminals": ()}
            def upstream_roots(self): self.upstream_requested = True; return exporter.UPSTREAM_ROOTS

        adapter = Adapter()
        raw = exporter.build_raw_export(adapter)
        self.assertEqual(adapter.root, 0x52840)
        self.assertTrue(adapter.upstream_requested)
        self.assertEqual(raw["upstream_roots"]["camera_orientation_owners"], [0x2D2C6, 0x30750])
        self.assertFalse(raw["truncated"])

    def test_exporter_rejects_dirty_analyzed_bad_target_and_escaping_output(self):
        spec = importlib.util.spec_from_file_location("vertical_factory_exporter", EXPORTER_PATH)
        exporter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(exporter)

        class Adapter:
            def __init__(self, read_only=True, unchanged=True, target=0x14148): self.read_only, self.unchanged, self.target = read_only, unchanged, target
            def program_name(self): return exporter.EXPECTED_PROGRAM
            def program_sha256(self): return exporter.EXPECTED_SHA256
            def program_size(self): return exporter.EXPECTED_IMAGE_SIZE
            def analysis_mode(self): return {"engine": "elf-capstone-thumb", "read_only": self.read_only, "source_unchanged": self.unchanged}
            def upstream_roots(self): return exporter.UPSTREAM_ROOTS
            def factory_metadata(self, root):
                constructors = [dict(item) for item in exporter.CONSTRUCTORS]
                constructors[0]["target"] = self.target
                return {"constructors": tuple(constructors), "reverse_callers": exporter.REVERSE_CALLERS, "unresolved_indirect_terminals": ()}

        for adapter in (Adapter(read_only=False), Adapter(unchanged=False), Adapter(target=0x1414A)):
            with self.subTest(adapter=adapter), self.assertRaises(RuntimeError): exporter.build_raw_export(adapter)

        bad_upstream = Adapter()
        bad_upstream.upstream_roots = lambda: {
            **exporter.UPSTREAM_ROOTS,
            "layout_mode": {"site_count": 27, "owner_count": 15, "owner_overlap_with_factory": False},
        }
        with self.assertRaises(RuntimeError):
            exporter.build_raw_export(bad_upstream)

    def test_output_is_contained(self):
        spec = importlib.util.spec_from_file_location("vertical_factory_exporter", EXPORTER_PATH)
        exporter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(exporter)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            document = {"schema_version": 1}
            good = root / "raw-vertical-layout-factory.json"
            exporter.write_json_atomic(good, document, root)
            self.assertEqual(json.loads(good.read_text(encoding="utf-8")), document)
            for escaped in (root / "wrong.json", root.parent / "raw-vertical-layout-factory.json"):
                with self.subTest(escaped=escaped), self.assertRaises(RuntimeError):
                    exporter.write_json_atomic(escaped, document, root)

    def test_missing_static_dependencies_fail_closed(self):
        spec = importlib.util.spec_from_file_location("vertical_factory_exporter", EXPORTER_PATH)
        exporter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(exporter)
        with mock.patch.object(exporter, "_require_dependencies", side_effect=RuntimeError("missing")):
            with self.assertRaisesRegex(RuntimeError, "missing"):
                exporter._metadata_from_file(ROOT / "missing.so")


if __name__ == "__main__":
    unittest.main()
