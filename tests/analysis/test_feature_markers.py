import tempfile
import unittest
from pathlib import Path

from pmca.analysis.features import FeatureError, count_feature_markers


class FeatureMarkerTests(unittest.TestCase):
    def test_ascii_and_utf16_markers_crossing_chunks_are_counted_once(self):
        markers = ("Vertical Display", "portrait")
        payload = (
            b"xxVertical Displayyy"
            + "portrait".encode("utf-16le")
            + b"Vertical Display"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.bin"
            path.write_bytes(payload)
            ascii_hits, utf16_hits = count_feature_markers(
                path,
                2,
                len(payload) - 2,
                markers,
                chunk_size=7,
            )

        self.assertEqual(ascii_hits, {"Vertical Display": 2, "portrait": 0})
        self.assertEqual(utf16_hits, {"Vertical Display": 0, "portrait": 1})

    def test_invalid_or_out_of_bounds_scopes_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.bin"
            path.write_bytes(b"fixture")
            for offset, size, markers in ((-1, 1, ("x",)), (0, 99, ("x",)), (0, 1, ())):
                with self.subTest(offset=offset, size=size, markers=markers):
                    with self.assertRaises(FeatureError):
                        count_feature_markers(path, offset, size, markers)


if __name__ == "__main__":
    unittest.main()
