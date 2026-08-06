import hashlib
import tempfile
import unittest
from pathlib import Path

from pmca.analysis.quarantine import Patch
from pmca.analysis.ranges import ByteRange
from pmca.analysis.signatures import (
    PeCoverage,
    classify_patch_impact,
    pe_authenticode_coverage,
)
from tests.analysis.test_static import _minimal_pe32


class SignatureCoverageTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.path = Path(self.temporary_directory.name) / "signed.exe"
        self.payload = _minimal_pe32()
        self.path.write_bytes(self.payload)

    def _patch(self, offset, size):
        preimage = self.payload[offset : offset + size]
        return Patch(offset, hashlib.sha256(preimage).hexdigest(), b"X" * size)

    def test_authenticode_coverage_is_exact_complement_of_exclusions(self):
        coverage = pe_authenticode_coverage(self.path)

        self.assertEqual(
            coverage,
            PeCoverage(
                signed=(
                    ByteRange("authenticode-signed", 0, 216, "computed complement"),
                    ByteRange("authenticode-signed", 220, 60, "computed complement"),
                    ByteRange("authenticode-signed", 288, 288, "computed complement"),
                    ByteRange("authenticode-signed", 592, 7, "computed complement"),
                ),
                excluded=(
                    ByteRange("pe-checksum", 216, 4, "Authenticode exclusion"),
                    ByteRange(
                        "certificate-directory",
                        280,
                        8,
                        "Authenticode exclusion",
                    ),
                    ByteRange(
                        "certificate-blob",
                        576,
                        16,
                        "Authenticode exclusion",
                    ),
                ),
            ),
        )

    def test_patch_impacts_are_signed_excluded_and_mixed(self):
        coverage = pe_authenticode_coverage(self.path)
        patches = (
            self._patch(544, 1),
            self._patch(576, 1),
            self._patch(214, 4),
        )

        self.assertEqual(
            classify_patch_impact(patches, coverage),
            ("signed", "excluded", "mixed"),
        )


if __name__ == "__main__":
    unittest.main()
