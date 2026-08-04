import tempfile
import unittest
from pathlib import Path

from firmware_structure import StructureError, parse_pe_layout
from tests.analysis.test_static import _minimal_pe32


class PeStructureMappingTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.path = Path(self.temporary_directory.name) / "updater.exe"

    def test_pe_layout_reports_only_bounded_numeric_ranges(self):
        payload = _minimal_pe32()
        self.path.write_bytes(payload)

        self.assertEqual(
            parse_pe_layout(self.path),
            {
                "machine": 0x014C,
                "section_count": 1,
                "optional_header_kind": "PE32",
                "pe_header_offset": 0x80,
                "pe_header_size": 24 + 0xE0,
                "section_table_offset": 0x178,
                "section_table_size": 40,
                "certificate_offset": 0x240,
                "certificate_size": 0x10,
                "overlay_offset": 0x220,
                "overlay_size": len(payload) - 0x220,
            },
        )

    def test_non_pe_is_rejected(self):
        self.path.write_bytes(b"not a PE updater")

        with self.assertRaises(StructureError):
            parse_pe_layout(self.path)


if __name__ == "__main__":
    unittest.main()
