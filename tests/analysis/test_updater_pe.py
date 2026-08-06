import copy
import hashlib
import struct
import tempfile
import unittest
from pathlib import Path

from pmca.analysis.updater_pe import (
    UpdaterPeError,
    inspect_updater_pe,
    validate_updater_pe_report,
)


def _nested_pe() -> bytes:
    pe_offset = 0x80
    optional_size = 0xE0
    section_table = pe_offset + 24 + optional_size
    raw_offset = 0x200
    raw_size = 0x20
    image = bytearray(raw_offset + raw_size)
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
        optional_size,
        0x010F,
    )
    optional = pe_offset + 24
    struct.pack_into("<H", image, optional, 0x10B)
    struct.pack_into("<I", image, optional + 60, raw_offset)
    struct.pack_into("<I", image, optional + 92, 16)
    image[section_table : section_table + 8] = b".text\0\0\0"
    struct.pack_into("<I", image, section_table + 8, raw_size)
    struct.pack_into("<I", image, section_table + 12, 0x1000)
    struct.pack_into("<I", image, section_table + 16, raw_size)
    struct.pack_into("<I", image, section_table + 20, raw_offset)
    image[raw_offset:] = bytes(range(raw_size))
    return bytes(image)


def _updater_fixture() -> tuple[bytes, bytes]:
    pe_offset = 0x80
    optional_size = 0xE0
    section_table = pe_offset + 24 + optional_size
    raw_offset = 0x200
    raw_size = 0x700
    certificate_offset = 0xC00
    certificate_size = 0x10
    image = bytearray(certificate_offset + certificate_size + 4)
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
        optional_size,
        0x010F,
    )
    optional = pe_offset + 24
    struct.pack_into("<H", image, optional, 0x10B)
    struct.pack_into("<I", image, optional + 60, raw_offset)
    struct.pack_into("<I", image, optional + 92, 16)
    struct.pack_into("<II", image, optional + 104, 0x1100, 40)
    struct.pack_into("<II", image, optional + 112, 0x1200, 0x80)
    struct.pack_into(
        "<II", image, optional + 128, certificate_offset, certificate_size
    )

    image[section_table : section_table + 8] = b".rdata\0\0"
    struct.pack_into("<I", image, section_table + 8, raw_size)
    struct.pack_into("<I", image, section_table + 12, 0x1000)
    struct.pack_into("<I", image, section_table + 16, raw_size)
    struct.pack_into("<I", image, section_table + 20, raw_offset)

    struct.pack_into("<IIIII", image, 0x300, 0x1140, 0, 0, 0x1160, 0x1140)
    struct.pack_into("<II", image, 0x340, 0x1170, 0)
    image[0x360 : 0x360 + len(b"KERNEL32.dll\0")] = b"KERNEL32.dll\0"
    image[0x370 : 0x370 + len(b"\0\0CreateFileW\0")] = b"\0\0CreateFileW\0"

    struct.pack_into("<HH", image, 0x400 + 12, 0, 1)
    struct.pack_into("<II", image, 0x410, 10, 0x80000020)
    struct.pack_into("<HH", image, 0x420 + 12, 0, 1)
    struct.pack_into("<II", image, 0x430, 1, 0x80000040)
    struct.pack_into("<HH", image, 0x440 + 12, 0, 1)
    struct.pack_into("<II", image, 0x450, 1033, 0x60)

    nested = _nested_pe()
    struct.pack_into("<IIII", image, 0x460, 0x1300, len(nested), 0, 0)
    image[0x500 : 0x500 + len(nested)] = nested
    image[0x980 : 0x980 + len(nested)] = nested
    image[certificate_offset : certificate_offset + certificate_size] = b"C" * 16
    image[-4:] = b"tail"
    return bytes(image), nested


class UpdaterPeTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)

    def write_fixture(self, data: bytes) -> Path:
        path = self.root / "Update_ILCE6400V200.exe"
        path.write_bytes(data)
        return path

    def test_imports_resources_overlay_certificate_and_candidates_are_bounded(self):
        payload, nested = _updater_fixture()
        path = self.write_fixture(payload)

        report = inspect_updater_pe(path)

        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["file"]["size"], len(payload))
        self.assertEqual(
            report["file"]["sha256"], hashlib.sha256(payload).hexdigest()
        )
        self.assertEqual(report["pe"]["machine"], 0x014C)
        self.assertEqual(report["pe"]["kind"], "PE32")
        self.assertEqual(report["pe"]["section_count"], 1)
        self.assertEqual(
            report["imports"],
            {
                "allowlisted": [
                    {
                        "dll": "kernel32.dll",
                        "function_count": 1,
                        "ordinal_count": 0,
                        "allowlisted_functions": ["CreateFileW"],
                    }
                ],
                "unlisted_dll_count": 0,
            },
        )
        self.assertEqual(
            report["resources"],
            [
                {
                    "type": "RCDATA",
                    "name_id": 1,
                    "language_id": 1033,
                    "offset": 0x500,
                    "size": len(nested),
                    "sha256": hashlib.sha256(nested).hexdigest(),
                }
            ],
        )
        self.assertEqual(report["overlay"]["offset"], 0x900)
        self.assertEqual(report["overlay"]["size"], len(payload) - 0x900)
        self.assertEqual(
            report["certificate"],
            {
                "offset": 0xC00,
                "size": 0x10,
                "sha256": hashlib.sha256(b"C" * 16).hexdigest(),
            },
        )
        self.assertEqual(
            report["embedded_pe_candidates"],
            [
                {
                    "source": "resource",
                    "offset": 0x500,
                    "declared_size": len(nested),
                    "sha256": hashlib.sha256(nested).hexdigest(),
                },
                {
                    "source": "overlay",
                    "offset": 0x980,
                    "declared_size": len(nested),
                    "sha256": hashlib.sha256(nested).hexdigest(),
                },
            ],
        )
        self.assertTrue(report["authenticode"]["signed_ranges"])
        self.assertEqual(
            [item["label"] for item in report["authenticode"]["excluded_ranges"]],
            ["pe-checksum", "certificate-directory", "certificate-blob"],
        )
        self.assertEqual(validate_updater_pe_report(report), report)
        self.assertNotIn("bytes", repr(report).lower())

    def test_malformed_import_directory_is_a_hard_error(self):
        payload, _ = _updater_fixture()
        malformed = bytearray(payload)
        struct.pack_into("<I", malformed, 0x300 + 12, 0x1FFF)

        with self.assertRaises(UpdaterPeError):
            inspect_updater_pe(self.write_fixture(malformed))

    def test_false_mz_in_overlay_is_not_promoted_to_a_candidate(self):
        payload, _ = _updater_fixture()
        changed = bytearray(payload)
        changed[0x910:0x912] = b"MZ"

        report = inspect_updater_pe(self.write_fixture(changed))

        self.assertEqual(len(report["embedded_pe_candidates"]), 2)

    def test_report_tampering_or_ambiguity_is_rejected(self):
        payload, _ = _updater_fixture()
        report = inspect_updater_pe(self.write_fixture(payload))
        cases = []

        extra = copy.deepcopy(report)
        extra["raw"] = "payload"
        cases.append(extra)

        bad_digest = copy.deepcopy(report)
        bad_digest["file"]["sha256"] = "not-a-digest"
        cases.append(bad_digest)

        out_of_bounds = copy.deepcopy(report)
        out_of_bounds["resources"][0]["offset"] = len(payload)
        cases.append(out_of_bounds)

        duplicate_candidate = copy.deepcopy(report)
        duplicate_candidate["embedded_pe_candidates"].append(
            copy.deepcopy(duplicate_candidate["embedded_pe_candidates"][0])
        )
        cases.append(duplicate_candidate)

        wrong_candidate_source = copy.deepcopy(report)
        wrong_candidate_source["embedded_pe_candidates"][1]["source"] = "resource"
        cases.append(wrong_candidate_source)

        mismatched_certificate = copy.deepcopy(report)
        mismatched_certificate["certificate"]["offset"] -= 1
        cases.append(mismatched_certificate)

        for document in cases:
            with self.subTest(document=document):
                with self.assertRaises(UpdaterPeError):
                    validate_updater_pe_report(document)


if __name__ == "__main__":
    unittest.main()
