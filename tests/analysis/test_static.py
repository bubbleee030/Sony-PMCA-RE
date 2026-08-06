import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pmca.analysis.static import (
    inspect_artifact,
    parse_pe_summary,
    scan_allowlisted_tokens,
    scan_entropy,
    shannon_entropy,
)


WINDOW_SIZE = 1_048_576


def _minimal_pe32() -> bytes:
    pe_offset = 0x80
    optional_header_size = 0xE0
    section_table_offset = pe_offset + 24 + optional_header_size
    raw_offset = 0x200
    raw_size = 0x20
    certificate_offset = 0x240
    certificate_size = 0x10
    overlay = b"overlay"
    file_size = certificate_offset + certificate_size + len(overlay)

    image = bytearray(file_size)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        image,
        pe_offset + 4,
        0x014C,
        1,
        0,
        0,
        0,
        optional_header_size,
        0x010F,
    )

    optional_offset = pe_offset + 24
    struct.pack_into("<H", image, optional_offset, 0x10B)
    struct.pack_into("<I", image, optional_offset + 60, raw_offset)
    struct.pack_into("<I", image, optional_offset + 92, 16)
    struct.pack_into(
        "<II", image, optional_offset + 128, certificate_offset, certificate_size
    )

    struct.pack_into("<I", image, section_table_offset + 16, raw_size)
    struct.pack_into("<I", image, section_table_offset + 20, raw_offset)
    image[raw_offset : raw_offset + raw_size] = bytes(range(raw_size))
    image[certificate_offset : certificate_offset + certificate_size] = b"C" * 16
    image[-len(overlay) :] = overlay
    return bytes(image)


class _TrackingReader:
    def __init__(self, stream):
        self._stream = stream
        self.read_sizes = []

    def __enter__(self):
        self._stream.__enter__()
        return self

    def __exit__(self, *args):
        return self._stream.__exit__(*args)

    def read(self, size=-1):
        self.read_sizes.append(size)
        if size < 0:
            raise AssertionError("scanner attempted an unbounded read")
        return self._stream.read(size)


class StaticInspectionTests(unittest.TestCase):
    def setUp(self):
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary_directory.name)

    def tearDown(self):
        self._temporary_directory.cleanup()

    def write_fixture(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.write_bytes(data)
        return path

    def test_empty_input_has_zero_entropy(self):
        self.assertEqual(shannon_entropy(b""), 0.0)

    def test_all_byte_values_have_eight_bits_of_entropy(self):
        self.assertAlmostEqual(shannon_entropy(bytes(range(256))), 8.0, places=6)

    def test_mz_with_out_of_bounds_pe_offset_is_not_a_pe(self):
        fixture = bytearray(64)
        fixture[:2] = b"MZ"
        struct.pack_into("<I", fixture, 0x3C, 0x01000000)

        self.assertIsNone(parse_pe_summary(self.write_fixture("invalid.exe", fixture)))

    def test_minimal_pe32_reports_only_bounded_numeric_metadata(self):
        summary = parse_pe_summary(self.write_fixture("minimal.exe", _minimal_pe32()))

        self.assertEqual(
            summary,
            {
                "machine": 0x014C,
                "section_count": 1,
                "optional_header_kind": "PE32",
                "certificate_offset": 0x240,
                "certificate_size": 0x10,
                "overlay_offset": 0x220,
            },
        )
        self.assertFalse(any(isinstance(value, bytes) for value in summary.values()))
        self.assertNotIn("preview", repr(summary).lower())
        self.assertNotIn("hex", repr(summary).lower())

    def test_pe_with_section_table_outside_file_is_rejected(self):
        fixture = bytearray(_minimal_pe32())
        struct.pack_into("<H", fixture, 0x80 + 6, 96)

        self.assertIsNone(parse_pe_summary(self.write_fixture("bad-table.exe", fixture)))

    def test_pe_with_directory_table_outside_optional_header_is_rejected(self):
        fixture = bytearray(_minimal_pe32())
        struct.pack_into("<I", fixture, 0x80 + 24 + 92, 17)

        self.assertIsNone(
            parse_pe_summary(self.write_fixture("bad-directories.exe", fixture))
        )

    def test_pe_with_section_headers_outside_declared_headers_is_rejected(self):
        fixture = bytearray(_minimal_pe32())
        struct.pack_into("<I", fixture, 0x80 + 24 + 60, 0x100)

        self.assertIsNone(
            parse_pe_summary(self.write_fixture("bad-header-size.exe", fixture))
        )

    def test_raw_dat_is_labelled_opaque_and_does_not_leak_strings(self):
        secret = "PRINTABLE_SECRET_NOT_ALLOWLISTED"
        result = inspect_artifact(
            self.write_fixture("BODYDATA.DAT", secret.encode("ascii")),
            "a6700-tw-v2.00",
        )

        self.assertEqual(result["format"], "opaque-dat")
        self.assertIsNone(result["pe"])
        self.assertNotIn(secret, repr(result))
        self.assertNotIn("raw", result)
        self.assertNotIn("strings", result)
        self.assertNotIn("hex", result)
        self.assertNotIn("preview", result)

    def test_token_scan_counts_all_hits_but_keeps_only_eight_offsets(self):
        token = b"ILCE6400"
        fixture = self.write_fixture("tokens.dat", b"|".join([token] * 12))

        self.assertEqual(
            scan_allowlisted_tokens(fixture, (token,)),
            [
                {
                    "token": "ILCE6400",
                    "count": 12,
                    "offsets": [0, 9, 18, 27, 36, 45, 54, 63],
                }
            ],
        )

    def test_token_scan_detects_a_match_crossing_a_chunk_boundary(self):
        token = b"Update_ILCE6400V200"
        start = WINDOW_SIZE - 5
        fixture = self.write_fixture(
            "boundary.dat", b"x" * start + token + b"trailer"
        )

        self.assertEqual(
            scan_allowlisted_tokens(fixture, (token,)),
            [{"token": token.decode("ascii"), "count": 1, "offsets": [start]}],
        )

    def test_entropy_scan_uses_three_bounded_windows_for_three_mib(self):
        fixture = self.write_fixture("three-mib.dat", b"z" * (3 * WINDOW_SIZE))
        real_stream = fixture.open("rb")
        tracking_stream = _TrackingReader(real_stream)

        with mock.patch.object(Path, "open", return_value=tracking_stream):
            summary = scan_entropy(fixture)

        self.assertEqual(summary["window_size"], WINDOW_SIZE)
        self.assertEqual(summary["window_count"], 3)
        self.assertEqual(
            [window["offset"] for window in summary["windows"]],
            [0, WINDOW_SIZE, 2 * WINDOW_SIZE],
        )
        self.assertEqual(
            [window["size"] for window in summary["windows"]],
            [WINDOW_SIZE, WINDOW_SIZE, WINDOW_SIZE],
        )
        self.assertTrue(tracking_stream.read_sizes)
        self.assertTrue(all(size == WINDOW_SIZE for size in tracking_stream.read_sizes))


if __name__ == "__main__":
    unittest.main()
