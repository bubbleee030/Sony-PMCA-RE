import ast
import copy
import json
import struct
import unittest
from pathlib import Path

from pmca.analysis.sa_registry import (
    SaRegistryError,
    analyze_sa_boundary,
    parse_sabin_identity,
    validate_sa_boundary_report,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = REPOSITORY_ROOT / "analysis" / "a6400-sa-boundary.json"
REGISTRY_PATH = (
    REPOSITORY_ROOT
    / ".artifacts"
    / "decrypted"
    / "a6400-tw-v2.00"
    / "ma1co"
    / "firmware.tar_unpacked"
    / "0110_backup"
    / "SYSASTRA-DSLR"
    / "DX2"
    / "CX62600_ALLLANG.bin"
)
SABIN_PATH = (
    REPOSITORY_ROOT
    / ".artifacts"
    / "decrypted"
    / "a6400-tw-v2.00"
    / "ma1co"
    / "firmware.tar_unpacked"
    / "0700_part_image"
    / "dev"
    / "nflasha15_unpacked"
    / "sabin"
    / "sa_aes_sha2.bin"
)
UDRT_SABIN_PATH = (
    REPOSITORY_ROOT
    / ".artifacts"
    / "decrypted"
    / "a6400-tw-v2.00"
    / "ma1co"
    / "firmware.tar_unpacked"
    / "0700_part_image"
    / "dev"
    / "nflasha15_unpacked"
    / "sabin"
    / "sa_udrt.bin"
)


class SaRegistryTests(unittest.TestCase):
    def test_sabin_identity_reports_observed_fields_without_naming_unknowns(self):
        data = bytearray(0x200)
        data[:4] = bytes.fromhex("aa0a1391")
        data[8:12] = bytes.fromhex("00130001")
        data[0x14:0x20] = b"SA_AESSH0x01"
        data[0x48:0x54] = b"AES_SHA20x01"

        identity = parse_sabin_identity(bytes(data))

        self.assertEqual(identity["identity"], "SA_AESSH0x01")
        self.assertEqual(identity["module"], "AES_SHA20x01")
        self.assertEqual(identity["header_u16_be"], [0x13, 0x1])
        self.assertNotIn("signature", identity)
        self.assertNotIn("key", identity)

    def test_real_registry_cross_checks_aes_index_record_and_header(self):
        result = analyze_sa_boundary(
            registry_data=REGISTRY_PATH.read_bytes(),
            sabin_data=SABIN_PATH.read_bytes(),
            names_offset=0xAC204,
            name_slot_size=0x20,
            record_length_offset=0xAD6CA,
            target_name="sa_aes_sha2.bin",
        )

        self.assertEqual(result["registry"]["filename_index"], 0x36)
        self.assertEqual(result["registry"]["record_u16_le"], [0x36, 0x93, 0x13, 0x1])
        self.assertEqual(result["container"]["header_u16_be"], [0x13, 0x1])
        self.assertTrue(result["cross_checks"]["record_first_matches_filename_index"])
        self.assertTrue(result["cross_checks"]["record_tail_matches_container_header"])
        self.assertEqual(result["firmware_decryption_link"], "unproven")
        self.assertFalse(result["camera_executed"])
        self.assertFalse(result["installable"])

    def test_real_registry_cross_checks_udrt_index_record_and_header(self):
        result = analyze_sa_boundary(
            registry_data=REGISTRY_PATH.read_bytes(),
            sabin_data=UDRT_SABIN_PATH.read_bytes(),
            names_offset=0xAC204,
            name_slot_size=0x20,
            record_length_offset=0xAD6CA,
            target_name="sa_udrt.bin",
        )

        self.assertEqual(result["registry"]["filename_index"], 0x5B)
        self.assertEqual(result["registry"]["record_u16_le"], [0x5B, 0x93, 0x3F, 0x1])
        self.assertEqual(result["container"]["identity"], "SA_UDRT_0x04")
        self.assertEqual(result["container"]["module"], "UDRT____0x04")
        self.assertEqual(result["container"]["header_u16_be"], [0x3F, 0x1])
        self.assertTrue(result["cross_checks"]["record_first_matches_filename_index"])
        self.assertTrue(result["cross_checks"]["record_tail_matches_container_header"])
        self.assertEqual(result["firmware_decryption_link"], "unproven")

    def test_parser_hard_stops_on_bad_magic_truncation_and_ambiguous_names(self):
        good_sabin = bytearray(0x200)
        good_sabin[:4] = bytes.fromhex("aa0a1391")
        good_sabin[8:12] = bytes.fromhex("00130001")
        good_sabin[0x14:0x20] = b"SA_AESSH0x01"
        good_sabin[0x48:0x54] = b"AES_SHA20x01"

        with self.assertRaises(SaRegistryError):
            parse_sabin_identity(b"not-a-sabin")

        registry = bytearray(0x100)
        target = b"sa_aes_sha2.bin"
        registry[0x10 : 0x10 + len(target)] = target
        registry[0x30 : 0x30 + len(target)] = target
        struct.pack_into("<H", registry, 0x80, 16)
        struct.pack_into("<4H", registry, 0x82, 0, 0x93, 0x13, 1)
        struct.pack_into("<4H", registry, 0x8A, 1, 0x93, 0x13, 1)
        with self.assertRaises(SaRegistryError):
            analyze_sa_boundary(
                registry_data=bytes(registry),
                sabin_data=bytes(good_sabin),
                names_offset=0x10,
                name_slot_size=0x20,
                record_length_offset=0x80,
                target_name="sa_aes_sha2.bin",
            )

        struct.pack_into("<H", registry, 0x80, 7)
        with self.assertRaises(SaRegistryError):
            analyze_sa_boundary(
                registry_data=bytes(registry),
                sabin_data=bytes(good_sabin),
                names_offset=0x10,
                name_slot_size=0x20,
                record_length_offset=0x80,
                target_name="missing.bin",
            )

    def test_committed_report_cannot_promote_an_unproven_link(self):
        document = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        self.assertEqual(validate_sa_boundary_report(document), document)

        self.assertTrue(document["aes_program_registered"])
        self.assertTrue(document["udrt_program_registered"])
        self.assertFalse(document["programs_loaded_by_updater"])
        self.assertEqual(document["imdb_namespace_link"], "unproven")
        self.assertEqual(document["evidence"]["udrt_filename_index"], 0x5B)
        self.assertEqual(
            document["evidence"]["udrt_record_u16_le"], [0x5B, 0x93, 0x3F, 0x1]
        )

        for field, value in (
            ("camera_executed", True),
            ("installable", True),
            ("firmware_decryption_link", "proven"),
            ("programs_loaded_by_updater", True),
            ("imdb_namespace_link", "proven"),
        ):
            candidate = copy.deepcopy(document)
            candidate[field] = value
            with self.subTest(field=field), self.assertRaises(SaRegistryError):
                validate_sa_boundary_report(candidate)

    def test_analyzer_has_no_device_crypto_or_execution_backend(self):
        source = (
            REPOSITORY_ROOT / "pmca" / "analysis" / "sa_registry.py"
        ).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".", 1)[0])

        self.assertTrue(
            imported_roots.isdisjoint({"Crypto", "Cryptodome", "ctypes", "subprocess", "usb"})
        )
        folded = source.casefold()
        for forbidden in ("writefirmware", "writememory", "private_key", "deviceiocontrol"):
            self.assertNotIn(forbidden, folded)


if __name__ == "__main__":
    unittest.main()
