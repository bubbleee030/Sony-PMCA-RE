import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pmca.analysis.fingerprints import (
    SCAN_CHUNK_SIZE,
    FingerprintError,
    MagicHit,
    MagicSpec,
    scan_magics,
)
from pmca.analysis.ranges import ByteRange


class FingerprintScannerTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.path = Path(self.temporary_directory.name) / "fixture.bin"

    def _range(self, offset: int, size: int) -> ByteRange:
        return ByteRange("scan", offset, size, "synthetic approved range")

    def test_magic_wholly_inside_approved_range_is_reported(self):
        self.path.write_bytes(b"prefix-MAGIC-suffix")

        self.assertEqual(
            scan_magics(
                self.path,
                (self._range(0, self.path.stat().st_size),),
                (MagicSpec("fixture", b"MAGIC", None),),
            ),
            (MagicHit("fixture", 7),),
        )

    def test_magic_split_across_two_reads_is_reported_once(self):
        payload = b"x" * (SCAN_CHUNK_SIZE - 2) + b"MAGIC" + b"tail"
        self.path.write_bytes(payload)

        self.assertEqual(
            scan_magics(
                self.path,
                (self._range(0, len(payload)),),
                (MagicSpec("fixture", b"MAGIC", None),),
            ),
            (MagicHit("fixture", SCAN_CHUNK_SIZE - 2),),
        )

    def test_magic_outside_approved_range_is_not_reported(self):
        self.path.write_bytes(b"MAGIC----MAGIC")

        self.assertEqual(
            scan_magics(
                self.path,
                (self._range(0, 5),),
                (MagicSpec("fixture", b"MAGIC", None),),
            ),
            (MagicHit("fixture", 0),),
        )

    def test_hit_limit_exhaustion_is_an_error_not_truncation(self):
        self.path.write_bytes(b"AAAA")

        with self.assertRaises(FingerprintError):
            scan_magics(
                self.path,
                (self._range(0, 4),),
                (MagicSpec("fixture", b"A", None),),
                max_hits=3,
            )

    def test_alignment_filters_unaligned_hits(self):
        self.path.write_bytes(b"xMAGMAG")

        self.assertEqual(
            scan_magics(
                self.path,
                (self._range(0, 7),),
                (MagicSpec("fixture", b"MAG", 4),),
            ),
            (MagicHit("fixture", 4),),
        )

    def test_empty_specs_return_no_hits_without_opening_file(self):
        self.path.write_bytes(b"fixture")

        with patch("pathlib.Path.open") as open_file:
            self.assertEqual(
                scan_magics(
                    self.path,
                    (self._range(0, 7),),
                    (),
                ),
                (),
            )
        open_file.assert_not_called()

    def test_overlapping_ranges_are_rejected_before_opening_file(self):
        self.path.write_bytes(b"fixture")
        ranges = (
            self._range(0, 5),
            self._range(4, 3),
        )

        with patch("pathlib.Path.open") as open_file:
            with self.assertRaises(FingerprintError):
                scan_magics(
                    self.path,
                    ranges,
                    (MagicSpec("fixture", b"x", None),),
                )
        open_file.assert_not_called()


if __name__ == "__main__":
    unittest.main()
