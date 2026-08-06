import ast
import copy
import json
import unittest
from pathlib import Path

from pmca.analysis.updater_crypto_boundary import (
    UpdaterCryptoBoundaryError,
    describe_protection_profile,
    validate_updater_crypto_boundary_report,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = REPOSITORY_ROOT / "analysis" / "a6400-updater-crypto-boundary.json"


class UpdaterCryptoBoundaryTests(unittest.TestCase):
    def test_profile_arithmetic_matches_the_observed_a6400_layout(self):
        result = describe_protection_profile(
            raw_fdat_bytes=304_833_808,
            decoded_fdat_bytes=303_642_112,
            header_bytes=512,
            updater_image_bytes=143_360,
            firmware_archive_bytes=303_498_240,
            outer_trailer_bytes=0x110,
        )

        self.assertEqual(result["ciphertext_bytes"], 304_833_536)
        self.assertEqual(result["outer_iv_bytes"], 16)
        self.assertEqual(result["outer_suffix_bytes"], 256)
        self.assertEqual(result["outer_suffix_role"], "unresolved")
        self.assertEqual(result["missing_cbc_stage"], "inferred-before-crypter")
        self.assertFalse(result["signature_proven"])
        self.assertFalse(result["installable"])

    def test_profile_hard_stops_on_unaligned_or_inconsistent_sizes(self):
        cases = (
            dict(
                raw_fdat_bytes=304_833_809,
                decoded_fdat_bytes=303_642_112,
                header_bytes=512,
                updater_image_bytes=143_360,
                firmware_archive_bytes=303_498_240,
                outer_trailer_bytes=0x110,
            ),
            dict(
                raw_fdat_bytes=304_833_808,
                decoded_fdat_bytes=303_642_111,
                header_bytes=512,
                updater_image_bytes=143_360,
                firmware_archive_bytes=303_498_240,
                outer_trailer_bytes=0x110,
            ),
        )
        for case in cases:
            with self.subTest(case=case), self.assertRaises(UpdaterCryptoBoundaryError):
                describe_protection_profile(**case)

    def test_committed_report_preserves_unresolved_security_boundaries(self):
        document = json.loads(REPORT_PATH.read_text(encoding="utf-8"))

        self.assertEqual(validate_updater_crypto_boundary_report(document), document)
        self.assertFalse(document["camera_executed"])
        self.assertFalse(document["bypass_established"])
        self.assertFalse(document["installable"])
        self.assertFalse(document["model_mismatch_safe"])
        self.assertEqual(
            document["host_transfer"]["guard_sequence2_scope"],
            "first-negotiated-chunk",
        )
        self.assertTrue(document["host_transfer"]["reconnect_resets_to_fdat_start"])
        self.assertFalse(
            document["updater_mode_receiver"]["system_receiver_located"]
        )
        self.assertEqual(
            document["crypter"]["missing_cbc_stage"], "inferred-before-crypter"
        )
        self.assertEqual(document["integrity"]["outer_suffix_role"], "unresolved")
        self.assertFalse(document["integrity"]["signature_proven"])
        self.assertFalse(document["sa_boundary"]["updater_invocation_proven"])

    def test_report_rejects_promoted_or_flashable_claims(self):
        document = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        cases = []

        for field in (
            "camera_executed",
            "bypass_established",
            "installable",
            "model_mismatch_safe",
        ):
            candidate = copy.deepcopy(document)
            candidate[field] = True
            cases.append(candidate)

        candidate = copy.deepcopy(document)
        candidate["updater_mode_receiver"]["system_receiver_located"] = True
        cases.append(candidate)

        candidate = copy.deepcopy(document)
        candidate["crypter"]["missing_cbc_stage"] = "proven"
        cases.append(candidate)

        candidate = copy.deepcopy(document)
        candidate["integrity"]["outer_suffix_role"] = "signature"
        candidate["integrity"]["signature_proven"] = True
        cases.append(candidate)

        candidate = copy.deepcopy(document)
        candidate["sa_boundary"]["updater_invocation_proven"] = True
        cases.append(candidate)

        for candidate in cases:
            with self.subTest(candidate=candidate), self.assertRaises(
                UpdaterCryptoBoundaryError
            ):
                validate_updater_crypto_boundary_report(candidate)

    def test_analyzer_has_no_device_crypto_or_execution_backend(self):
        source = (
            REPOSITORY_ROOT
            / "pmca"
            / "analysis"
            / "updater_crypto_boundary.py"
        ).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".", 1)[0])

        self.assertTrue(
            imported_roots.isdisjoint(
                {"Crypto", "Cryptodome", "ctypes", "subprocess", "usb"}
            )
        )
        folded = source.casefold()
        for forbidden in (
            "deviceiocontrol",
            "private_key",
            "writefirmware",
            "writememory",
            "aes_decrypt",
        ):
            self.assertNotIn(forbidden, folded)


if __name__ == "__main__":
    unittest.main()
