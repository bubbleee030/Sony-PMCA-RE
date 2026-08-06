import hashlib
import struct
import tempfile
import unittest
from pathlib import Path

from pmca.analysis.packman import (
    PackmanError,
    extract_packman_cab,
    inspect_packman,
)


MARKER = "!!!53AAED7C-68E7-413C-A5FD-D9F76477D66A"
CAB_NAME = "E8FF0748-2339-49f9-9A79-824D7561736C.cab"


def _cabinet(size=80):
    cabinet = bytearray(size)
    cabinet[:4] = b"MSCF"
    struct.pack_into("<I", cabinet, 8, size)
    struct.pack_into("<I", cabinet, 16, 36)
    cabinet[24:26] = bytes((3, 1))
    struct.pack_into("<HHH", cabinet, 26, 1, 1, 0)
    return bytes(cabinet)


def _packman_pe(*, marker=MARKER, padding_byte=0, cab=None):
    cabinet = _cabinet() if cab is None else cab
    settings = b"\xff\xfe" + "[Package]\r\nCompression=True\r\n".encode("utf-16le")
    entries = (("Settings.ini", settings), (CAB_NAME, bytes(value ^ 0xFF for value in cabinet)))

    header = bytearray(b"T" * 16)
    header.extend(struct.pack("<IIIII", 2, 0, 1, len(marker), len(entries)))
    header.extend(marker.encode("utf-16le"))
    for name, payload in entries:
        header.extend(struct.pack("<II", len(name), len(payload)))
        header.extend(name.encode("utf-16le"))
        header.extend(b"D" * 8)
    container = bytes(header) + b"".join(payload for _, payload in entries)

    pe_offset = 0x80
    optional_size = 0xE0
    section_table = pe_offset + 24 + optional_size
    raw_offset = 0x200
    raw_size = 0x200
    overlay_offset = raw_offset + raw_size
    padding_size = (-(overlay_offset + len(container))) % 8
    certificate_offset = overlay_offset + len(container) + padding_size
    certificate_size = 0x10
    image = bytearray(certificate_offset + certificate_size)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH", image, pe_offset + 4, 0x014C, 1, 0, 0, 0, optional_size, 0x010F
    )
    optional = pe_offset + 24
    struct.pack_into("<H", image, optional, 0x10B)
    struct.pack_into("<I", image, optional + 60, raw_offset)
    struct.pack_into("<I", image, optional + 92, 16)
    struct.pack_into("<II", image, optional + 128, certificate_offset, certificate_size)
    image[section_table : section_table + 8] = b".text\0\0\0"
    struct.pack_into("<I", image, section_table + 8, raw_size)
    struct.pack_into("<I", image, section_table + 12, 0x1000)
    struct.pack_into("<I", image, section_table + 16, raw_size)
    struct.pack_into("<I", image, section_table + 20, raw_offset)
    image[overlay_offset : overlay_offset + len(container)] = container
    image[overlay_offset + len(container) : certificate_offset] = bytes((padding_byte,)) * padding_size
    image[certificate_offset:] = b"C" * certificate_size
    return bytes(image), cabinet, settings, overlay_offset, certificate_offset, padding_size


class PackmanTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)

    def write_fixture(self, payload):
        path = self.root / "Update_ILCE7SM3V301.exe"
        path.write_bytes(payload)
        return path

    def test_inspection_proves_header_entries_transform_and_alignment(self):
        payload, cabinet, settings, overlay, certificate, padding = _packman_pe()

        report = inspect_packman(self.write_fixture(payload))

        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["file"]["size"], len(payload))
        self.assertEqual(report["file"]["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(report["container"]["offset"], overlay)
        self.assertEqual(report["container"]["format_version"], 2)
        self.assertEqual(report["container"]["marker"], MARKER)
        self.assertEqual(report["container"]["padding_size"], padding)
        self.assertEqual(report["certificate"]["offset"], certificate)
        self.assertEqual(
            report["container"]["entries"],
            [
                {
                    "name": "Settings.ini",
                    "offset": report["container"]["header_end"],
                    "size": len(settings),
                    "transformation": "identity",
                },
                {
                    "name": CAB_NAME,
                    "offset": report["container"]["header_end"] + len(settings),
                    "size": len(cabinet),
                    "transformation": "xor-ff",
                },
            ],
        )

    def test_extractor_writes_only_the_decoded_cabinet(self):
        payload, cabinet, _, _, _, _ = _packman_pe()
        source = self.write_fixture(payload)
        output = self.root / "decoded.cab"

        result = extract_packman_cab(source, output, artifacts_root=self.root)

        self.assertEqual(output.read_bytes(), cabinet)
        self.assertEqual(result["size"], len(cabinet))
        self.assertEqual(result["sha256"], hashlib.sha256(cabinet).hexdigest())
        self.assertEqual(result["magic"], "MSCF")
        self.assertEqual(result["transformation"], "xor-ff")

    def test_wrong_decoded_cabinet_size_is_rejected(self):
        cabinet = bytearray(_cabinet())
        struct.pack_into("<I", cabinet, 8, len(cabinet) + 1)
        payload, _, _, _, _, _ = _packman_pe(cab=bytes(cabinet))

        with self.assertRaises(PackmanError):
            inspect_packman(self.write_fixture(payload))

    def test_nonzero_alignment_padding_is_rejected(self):
        payload, _, _, _, _, padding = _packman_pe(padding_byte=1)
        self.assertGreater(padding, 0)

        with self.assertRaises(PackmanError):
            inspect_packman(self.write_fixture(payload))

    def test_unknown_marker_and_existing_output_are_hard_errors(self):
        payload, _, _, _, _, _ = _packman_pe(marker="!!!UNKNOWN")
        with self.assertRaises(PackmanError):
            inspect_packman(self.write_fixture(payload))

        valid, _, _, _, _, _ = _packman_pe()
        source = self.write_fixture(valid)
        output = self.root / "decoded.cab"
        output.write_bytes(b"keep")
        with self.assertRaises(PackmanError):
            extract_packman_cab(source, output, artifacts_root=self.root)
        self.assertEqual(output.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
