import struct
import tempfile
import unittest
from pathlib import Path

from pmca.analysis.dat import DAT_MAGIC, DatChunk, DatError, parse_dat_chunks
from pmca.analysis.ranges import ByteRange, unknown_ranges


def chunk(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I4s", len(payload), kind) + payload


def fixture_bytes() -> bytes:
    return (
        DAT_MAGIC
        + chunk(b"DATV", b"\x01\x00\x00\x00")
        + chunk(b"PROV", b"\x01\x00\x00\x00")
        + chunk(b"UDID", b"camera-id")
        + chunk(b"FDAT", b"encrypted-payload")
    )


class DatParserTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)

    def _write(self, payload: bytes) -> Path:
        path = self.root / "BODYDATA.DAT"
        path.write_bytes(payload)
        return path

    def test_parser_returns_only_exact_chunk_boundaries(self):
        path = self._write(fixture_bytes())

        self.assertEqual(
            parse_dat_chunks(path),
            (
                DatChunk("DATV", 8, 16, 4),
                DatChunk("PROV", 20, 28, 4),
                DatChunk("UDID", 32, 40, 9),
                DatChunk("FDAT", 49, 57, 17),
            ),
        )

    def test_chunk_limit_is_exhaustion_not_truncation(self):
        path = self._write(fixture_bytes())

        with self.assertRaises(DatError):
            parse_dat_chunks(path, max_chunks=3)
        for invalid_limit in (0, -1, True):
            with self.subTest(limit=invalid_limit):
                with self.assertRaises(DatError):
                    parse_dat_chunks(path, max_chunks=invalid_limit)

    def test_wrong_magic_is_rejected(self):
        path = self._write(b"NOT-A-DAT" + chunk(b"FDAT", b"payload"))

        with self.assertRaises(DatError):
            parse_dat_chunks(path)

    def test_truncated_header_is_rejected_before_fdat(self):
        path = self._write(DAT_MAGIC + b"\x00" * 7)

        with self.assertRaises(DatError):
            parse_dat_chunks(path)

    def test_payload_beyond_eof_is_rejected(self):
        path = self._write(DAT_MAGIC + struct.pack(">I4s", 10, b"DATV") + b"x")

        with self.assertRaises(DatError):
            parse_dat_chunks(path)

    def test_non_ascii_kind_is_rejected(self):
        path = self._write(DAT_MAGIC + chunk(b"\xffDAT", b"payload"))

        with self.assertRaises(DatError):
            parse_dat_chunks(path)

    def test_absent_and_duplicate_fdat_are_rejected(self):
        invalid_payloads = (
            DAT_MAGIC + chunk(b"DATV", b"version"),
            DAT_MAGIC + chunk(b"FDAT", b"first") + chunk(b"FDAT", b"second"),
        )

        for payload in invalid_payloads:
            with self.subTest(payload_size=len(payload)):
                with self.assertRaises(DatError):
                    parse_dat_chunks(self._write(payload))

    def test_bytes_after_last_chunk_are_explicitly_unknown(self):
        tail = b"\xaa\xbb\xcc"
        payload = DAT_MAGIC + chunk(b"DATV", b"v") + chunk(b"FDAT", b"firmware") + tail
        path = self._write(payload)
        chunks = parse_dat_chunks(path)
        known = [ByteRange("magic", 0, len(DAT_MAGIC), "sony-dat magic")]
        for value in chunks:
            known.extend(
                (
                    ByteRange(
                        f"{value.kind}-header",
                        value.header_offset,
                        8,
                        "parsed chunk header",
                    ),
                    ByteRange(
                        f"{value.kind}-payload",
                        value.payload_offset,
                        value.size,
                        "declared chunk payload",
                    ),
                )
            )

        self.assertEqual(
            unknown_ranges(len(payload), tuple(known)),
            (
                ByteRange(
                    "unknown",
                    len(payload) - len(tail),
                    len(tail),
                    "computed complement",
                ),
            ),
        )


if __name__ == "__main__":
    unittest.main()
