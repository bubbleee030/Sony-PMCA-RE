import json
import unittest
from pathlib import Path

from firmware_structure import validate_structure_report


ROOT = Path(__file__).resolve().parents[2]
STRUCTURES = ROOT / "analysis" / "structures"
EXPECTED_SCAN_RANGES = {
    "a6400-tw-v2.00": [
        {"label": "pe-overlay", "offset": 452_608, "size": 313_778_104}
    ],
    "a6700-tw-v2.00": [
        {"label": "fdat-payload", "offset": 156, "size": 1_024_017_680}
    ],
    "a7v-tw-v2.00": [
        {"label": "fdat-payload", "offset": 148, "size": 376_540_560}
    ],
}
EXPECTED_A6400_PE = {
    "machine": 332,
    "section_count": 5,
    "optional_header_kind": "PE32",
    "pe_header_offset": 280,
    "pe_header_size": 248,
    "section_table_offset": 528,
    "section_table_size": 200,
    "certificate_offset": 314_220_688,
    "certificate_size": 10_024,
    "overlay_offset": 452_608,
    "overlay_size": 313_778_104,
}


class StructureReportVersionTwoTests(unittest.TestCase):
    def _load(self, source_key):
        return json.loads(
            (STRUCTURES / f"{source_key}.json").read_text(encoding="utf-8")
        )

    def test_a6400_pe_layout_and_scan_scope_are_exact(self):
        report = self._load("a6400-tw-v2.00")

        self.assertIs(validate_structure_report(report), report)
        self.assertEqual(report["format"], "pe-updater")
        self.assertEqual(report["pe"], EXPECTED_A6400_PE)
        self.assertEqual(report["dat_chunks"], [])
        self.assertEqual(report["unknown_ranges"], [])
        self.assertEqual(
            report["scan_ranges"], EXPECTED_SCAN_RANGES["a6400-tw-v2.00"]
        )

    def test_all_magic_hits_are_inside_the_narrowest_approved_ranges(self):
        for source_key, expected_ranges in EXPECTED_SCAN_RANGES.items():
            with self.subTest(source_key=source_key):
                report = self._load(source_key)
                self.assertIs(validate_structure_report(report), report)
                self.assertEqual(report["scan_ranges"], expected_ranges)
                if source_key != "a6400-tw-v2.00":
                    self.assertEqual(report["format"], "sony-dat")
                    self.assertIsNone(report["pe"])

                for hit in report["magic_hits"]:
                    self.assertTrue(
                        any(
                            value["offset"]
                            <= hit["offset"]
                            <= value["offset"] + value["size"] - 1
                            for value in expected_ranges
                        )
                    )


if __name__ == "__main__":
    unittest.main()
