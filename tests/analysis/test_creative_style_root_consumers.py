import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = ROOT / "analysis" / "a6400-creative-style-root-consumers.json"
EXPORTER_PATH = ROOT / "tools" / "static" / "export_a6400_creative_style_root_consumers.py"


class CreativeStyleRootConsumerTests(unittest.TestCase):
    def test_normalizer_accepts_only_the_pinned_zero_result(self):
        from pmca.analysis.creative_style_root_consumers import (
            EXPECTED_RAW_EXPORT,
            normalize_creative_style_root_consumers_export,
        )

        raw = normalize_creative_style_root_consumers_export(copy.deepcopy(EXPECTED_RAW_EXPORT))
        self.assertEqual(raw["dynamic_symbol"]["index"], 544)
        self.assertEqual(raw["relocations"][0]["index"], 3858)
        self.assertEqual(raw["relocations"][1]["index"], 3859)
        self.assertEqual(raw["executable_scan"]["range_count"], 1358)
        self.assertEqual(raw["executable_scan"]["accepted_candidates"], [])
        self.assertFalse(raw["claims"]["creative_style_selection_found"])

    def test_normalizer_rejects_unsafe_fabricated_and_promoted_metadata(self):
        from pmca.analysis.creative_style_root_consumers import (
            EXPECTED_RAW_EXPORT,
            CreativeStyleRootConsumersError,
            normalize_creative_style_root_consumers_export,
        )

        mutations = (
            lambda value: value["dynamic_symbol"].__setitem__("index", 545),
            lambda value: value["relocations"][1].__setitem__("site", 0x805CC),
            lambda value: value["data_cell_symbol_coverage"].__setitem__("exact", ["invented"]),
            lambda value: value["executable_scan"].__setitem__("accepted_candidates", [{"owner": 0x1000}]),
            lambda value: value["claims"].__setitem__("creative_style_selection_found", True),
            lambda value: value.__setitem__("instructions", []),
        )
        for mutate in mutations:
            candidate = copy.deepcopy(EXPECTED_RAW_EXPORT)
            mutate(candidate)
            with self.subTest(mutate=mutate), self.assertRaises(CreativeStyleRootConsumersError):
                normalize_creative_style_root_consumers_export(candidate)

    def test_report_is_static_noninstallable_and_external_consumers_remain_open(self):
        from pmca.analysis.creative_style_root_consumers import (
            CreativeStyleRootConsumersError,
            validate_creative_style_root_consumers_report,
        )

        report = validate_creative_style_root_consumers_report(json.loads(REPORT_PATH.read_text(encoding="utf-8")))
        self.assertFalse(report["installable"])
        self.assertFalse(report["camera_test_eligible"])
        self.assertIn("External", report["conclusion"])
        forged = copy.deepcopy(report)
        forged["claims"]["menu_touch_selection"] = True
        with self.assertRaises(CreativeStyleRootConsumersError):
            validate_creative_style_root_consumers_report(forged)


class CreativeStyleRootConsumerExporterTests(unittest.TestCase):
    def _load(self):
        spec = importlib.util.spec_from_file_location("creative_style_root_consumers_exporter", EXPORTER_PATH)
        exporter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(exporter)
        return exporter

    def test_exporter_requires_exact_provenance_backed_metadata(self):
        exporter = self._load()

        class Adapter:
            def metadata(self):
                return copy.deepcopy(exporter.EXPECTED_RAW_EXPORT)

        raw = exporter.build_raw_export(Adapter())
        self.assertEqual(raw["executable_scan"]["range_count"], 1358)
        self.assertEqual(raw["executable_scan"]["accepted_candidates"], [])

    def test_scanner_ignores_capstone_skipdata_records_before_reading_operands(self):
        exporter = self._load()

        class SkipData:
            id = 0

            @property
            def operands(self):
                raise AssertionError("skipdata operands must not be inspected")

        self.assertIsNone(exporter._instruction_operands(SkipData()))

    def test_provenance_tracks_adr_through_mov_add_to_an_exact_root_cell_load(self):
        exporter = self._load()
        ids = SimpleNamespace(
            adr=1, add=2, ldr=3, mov=4, movt=5, movw=6, sub=7,
            imm=8, mem=9, reg=10, pc=11,
        )

        def register(number):
            return SimpleNamespace(type=ids.reg, reg=number)

        def immediate(value):
            return SimpleNamespace(type=ids.imm, imm=value)

        def memory(base, displacement=0):
            return SimpleNamespace(type=ids.mem, mem=SimpleNamespace(base=base, disp=displacement))

        def instruction(kind, operands):
            return SimpleNamespace(id=kind, operands=operands)

        known = {}
        self.assertIsNone(exporter._advance_root_cell_provenance(
            instruction(ids.adr, [register(1), immediate(0x80560)]), known, ids, {0x8056C},
        ))
        self.assertIsNone(exporter._advance_root_cell_provenance(
            instruction(ids.mov, [register(2), register(1)]), known, ids, {0x8056C},
        ))
        self.assertIsNone(exporter._advance_root_cell_provenance(
            instruction(ids.add, [register(3), register(2), immediate(12)]), known, ids, {0x8056C},
        ))
        self.assertEqual(
            exporter._advance_root_cell_provenance(
                instruction(ids.ldr, [register(4), memory(3)]), known, ids, {0x8056C},
            ),
            0x8056C,
        )

    def test_exporter_rejects_escape_and_fabricated_consumer(self):
        exporter = self._load()

        class Adapter:
            def metadata(self):
                value = copy.deepcopy(exporter.EXPECTED_RAW_EXPORT)
                value["executable_scan"]["accepted_candidates"] = [{"owner": 0x1000}]
                return value

        with self.assertRaises(RuntimeError):
            exporter.build_raw_export(Adapter())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with mock.patch.object(exporter, "OUTPUT_ROOT", root):
                exporter.write_json_atomic(root / "raw-creative-style-root-consumers.json", exporter.EXPECTED_RAW_EXPORT)
                with self.assertRaises(RuntimeError):
                    exporter.write_json_atomic(root / "elsewhere.json", exporter.EXPECTED_RAW_EXPORT)

    def test_exporter_rejects_a_symlinked_output_root(self):
        exporter = self._load()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with mock.patch.object(exporter, "OUTPUT_ROOT", root), mock.patch.object(exporter.Path, "is_symlink", return_value=True):
                with self.assertRaises(RuntimeError):
                    exporter.write_json_atomic(root / "raw-creative-style-root-consumers.json", exporter.EXPECTED_RAW_EXPORT)


if __name__ == "__main__":
    unittest.main()
