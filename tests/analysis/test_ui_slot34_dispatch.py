import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = ROOT / "analysis" / "a6400-ui-slot34-dispatch.json"
EXPORTER_PATH = ROOT / "tools" / "static" / "export_a6400_ui_slot34_dispatch.py"


class UISlot34DispatchTests(unittest.TestCase):
    def test_normalizer_accepts_only_the_pinned_empty_structural_result(self):
        from pmca.analysis.ui_slot34_dispatch import (
            EXPECTED_RAW_EXPORT,
            normalize_ui_slot34_dispatch_export,
        )

        normalized = normalize_ui_slot34_dispatch_export(copy.deepcopy(EXPECTED_RAW_EXPORT))
        self.assertEqual(len(normalized["header_references"]), 5)
        self.assertEqual(
            normalized["header_references"][0]["addend"],
            normalized["table_evidence"][0]["header"],
        )
        self.assertEqual(
            set(normalized["structural_scan"]["direct_pc_literal_loads"][0]),
            {"kind", "function", "site"},
        )
        self.assertEqual(normalized["structural_scan"]["accepted_candidates"], [])
        self.assertEqual(normalized["direct_owner_inbound_edges"], [])
        self.assertEqual(normalized["root_path_summary"]["paths_to_owner"], [])
        self.assertFalse(normalized["claims"]["slot_34_dispatch_found"])
        self.assertFalse(normalized["behavior_support"]["menu_touch_selection"])

    def test_normalizer_rejects_fabricated_dispatches_promotions_and_unpinned_evidence(self):
        from pmca.analysis.ui_slot34_dispatch import (
            UISlot34DispatchError,
            EXPECTED_RAW_EXPORT,
            normalize_ui_slot34_dispatch_export,
        )

        mutations = (
            lambda value: value["structural_scan"].__setitem__("accepted_candidates", [{"function": 0x529CC}]),
            lambda value: value["header_references"][0].__setitem__("addend", value["table_evidence"][0]["address_point"]),
            lambda value: value["direct_owner_inbound_edges"].append({"caller": 0x1000, "site": 0x1002}),
            lambda value: value["root_path_summary"]["paths_to_owner"].append([0x2D2C6, 0x529CC]),
            lambda value: value["prior_vtable_interface"].__setitem__("canonical_export_sha256", "0" * 64),
            lambda value: value["claims"].__setitem__("slot_34_dispatch_found", True),
            lambda value: value.__setitem__("instructions", []),
        )
        for mutate in mutations:
            candidate = copy.deepcopy(EXPECTED_RAW_EXPORT)
            mutate(candidate)
            with self.subTest(mutate=mutate), self.assertRaises(UISlot34DispatchError):
                normalize_ui_slot34_dispatch_export(candidate)

    def test_report_is_pinned_noninstallable_and_retains_unresolved_routes(self):
        from pmca.analysis.ui_slot34_dispatch import (
            UISlot34DispatchError,
            validate_ui_slot34_dispatch_report,
        )

        report = validate_ui_slot34_dispatch_report(json.loads(REPORT_PATH.read_text(encoding="utf-8")))
        self.assertFalse(report["installable"])
        self.assertFalse(report["camera_test_eligible"])
        self.assertEqual(report["structural_scan"]["accepted_candidate_count"], 0)
        self.assertIn("cross-module", report["conclusion"])
        forged = copy.deepcopy(report)
        forged["behavior_support"]["menu_touch_selection"] = True
        with self.assertRaises(UISlot34DispatchError):
            validate_ui_slot34_dispatch_report(forged)


class UISlot34DispatchExporterTests(unittest.TestCase):
    def _load(self):
        spec = importlib.util.spec_from_file_location("ui_slot34_dispatch_exporter", EXPORTER_PATH)
        exporter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(exporter)
        return exporter

    def test_exporter_requires_exact_static_metadata(self):
        exporter = self._load()

        class Adapter:
            def metadata(self):
                return copy.deepcopy(exporter.EXPECTED_RAW_EXPORT)

        raw = exporter.build_raw_export(Adapter())
        self.assertEqual(raw["structural_scan"]["accepted_candidates"], [])
        self.assertEqual(len(raw["header_references"]), 5)

    def test_exporter_rejects_escape_and_nonempty_structural_result(self):
        exporter = self._load()

        class Adapter:
            def metadata(self):
                value = copy.deepcopy(exporter.EXPECTED_RAW_EXPORT)
                value["structural_scan"]["accepted_candidates"] = [{"function": 0x529CC}]
                return value

        with self.assertRaises(RuntimeError):
            exporter.build_raw_export(Adapter())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with mock.patch.object(exporter, "OUTPUT_ROOT", root):
                exporter.write_json_atomic(root / "raw-ui-slot34-dispatch.json", exporter.EXPECTED_RAW_EXPORT)
                with self.assertRaises(RuntimeError):
                    exporter.write_json_atomic(root / "other.json", exporter.EXPECTED_RAW_EXPORT)

    def test_exporter_rejects_a_symlinked_output_root(self):
        exporter = self._load()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with mock.patch.object(exporter, "OUTPUT_ROOT", root), mock.patch.object(exporter.Path, "is_symlink", return_value=True):
                with self.assertRaises(RuntimeError):
                    exporter.write_json_atomic(root / "raw-ui-slot34-dispatch.json", exporter.EXPECTED_RAW_EXPORT)


if __name__ == "__main__":
    unittest.main()
