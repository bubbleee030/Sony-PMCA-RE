import sys
import unittest

from pmca.analysis.ranges import (
    ByteRange,
    RangeError,
    unknown_ranges,
    validate_ranges,
)


class RangeLedgerTests(unittest.TestCase):
    def test_validate_ranges_sorts_non_overlapping_ranges(self):
        ranges = (
            ByteRange("payload", 12, 4, "synthetic"),
            ByteRange("header", 0, 8, "synthetic"),
        )

        self.assertEqual(
            validate_ranges(20, ranges),
            (
                ByteRange("header", 0, 8, "synthetic"),
                ByteRange("payload", 12, 4, "synthetic"),
            ),
        )

    def test_invalid_sizes_offsets_and_file_size_are_rejected(self):
        invalid_cases = (
            (-1, ()),
            (8, (ByteRange("negative", -1, 1, "synthetic"),)),
            (8, (ByteRange("empty", 0, 0, "synthetic"),)),
            (8, (ByteRange("boolean", True, 1, "synthetic"),)),
        )

        for file_size, ranges in invalid_cases:
            with self.subTest(file_size=file_size, ranges=ranges):
                with self.assertRaises(RangeError):
                    validate_ranges(file_size, ranges)

    def test_integer_overflow_style_range_is_rejected_without_wrapping(self):
        with self.assertRaises(RangeError):
            validate_ranges(
                sys.maxsize,
                (ByteRange("overflow", sys.maxsize, 1, "synthetic"),),
            )

    def test_overlap_and_beyond_eof_are_rejected(self):
        invalid_cases = (
            (
                ByteRange("first", 0, 5, "synthetic"),
                ByteRange("second", 4, 2, "synthetic"),
            ),
            (ByteRange("past-eof", 7, 2, "synthetic"),),
        )

        for ranges in invalid_cases:
            with self.subTest(ranges=ranges):
                with self.assertRaises(RangeError):
                    validate_ranges(8, ranges)

    def test_unknown_ranges_cover_every_unclaimed_byte(self):
        known = (
            ByteRange("header", 0, 8, "synthetic"),
            ByteRange("payload", 12, 4, "synthetic"),
        )

        self.assertEqual(
            unknown_ranges(20, known),
            (
                ByteRange("unknown", 8, 4, "computed complement"),
                ByteRange("unknown", 16, 4, "computed complement"),
            ),
        )

    def test_unknown_ranges_include_prefix_and_empty_known_set(self):
        self.assertEqual(
            unknown_ranges(
                8,
                (ByteRange("tail", 4, 4, "synthetic"),),
            ),
            (ByteRange("unknown", 0, 4, "computed complement"),),
        )
        self.assertEqual(
            unknown_ranges(5, ()),
            (ByteRange("unknown", 0, 5, "computed complement"),),
        )

    def test_complete_range_has_no_unknown_bytes(self):
        self.assertEqual(
            unknown_ranges(
                8,
                (ByteRange("complete", 0, 8, "synthetic"),),
            ),
            (),
        )


if __name__ == "__main__":
    unittest.main()
