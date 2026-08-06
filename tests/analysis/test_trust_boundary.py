import ast
import copy
import json
import unittest
from pathlib import Path

from pmca.analysis.trust_boundary import (
    TrustBoundaryError,
    characterize_pmca_sources,
    validate_trust_boundary_report,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = REPOSITORY_ROOT / "analysis" / "a6400-trust-boundary.json"
FWTOOL_ROOT = REPOSITORY_ROOT / ".artifacts" / "tools" / "ma1co-fwtool"


class TrustBoundaryTests(unittest.TestCase):
    def test_source_characterizer_finds_the_generation_four_cutoff(self):
        result = characterize_pmca_sources(
            pack_source=(REPOSITORY_ROOT / "updatershell" / "pack.py").read_text(
                encoding="utf-8"
            ),
            fdat_source=(FWTOOL_ROOT / "fwtool" / "sony" / "fdat.py").read_text(
                encoding="utf-8"
            ),
            usb_command_source=(
                REPOSITORY_ROOT / "pmca" / "commands" / "usb.py"
            ).read_text(encoding="utf-8"),
            updater_protocol_source=(
                REPOSITORY_ROOT / "pmca" / "usb" / "sony.py"
            ).read_text(encoding="utf-8"),
            service_backend_source=(
                REPOSITORY_ROOT / "pmca" / "platform" / "backend" / "senser.py"
            ).read_text(encoding="utf-8"),
        )

        self.assertEqual(
            result["updater_shell_body_architectures"],
            [
                "CXD4105",
                "CXD4115",
                "CXD4115_ilc",
                "CXD4120",
                "CXD4132",
                "CXD90014",
            ],
        )
        self.assertEqual(result["generation_four_architecture"], "CXD90045")
        self.assertEqual(result["generation_four_encrypt"], "not-supported")
        self.assertEqual(
            result["firmware_update_sequence"],
            ["init", "checkGuard", "getFirmwareVersion", "switchMode", "writeFirmware", "complete"],
        )
        self.assertEqual(
            result["service_read_capabilities"], ["readFile", "readMemory"]
        )
        self.assertTrue(result["guard_precedes_mode_switch"])
        self.assertEqual(result["guard_initial_window_bytes"], 0)
        self.assertTrue(result["guard_can_finish_before_eof"])
        self.assertTrue(result["full_fdat_reseek_after_updater_reconnect"])
        self.assertTrue(result["service_path_is_separate"])

    def test_committed_report_preserves_host_camera_and_service_boundaries(self):
        document = json.loads(REPORT_PATH.read_text(encoding="utf-8"))

        self.assertEqual(validate_trust_boundary_report(document), document)
        self.assertFalse(document["camera_executed"])
        self.assertFalse(document["bypass_established"])
        self.assertFalse(document["installable"])
        self.assertEqual(document["host_verification"]["component_count"], 29)
        self.assertEqual(
            document["host_verification"]["firmware_verifier_import_hits"], 0
        )
        self.assertEqual(document["host_verification"]["mapped_key_marker_hits"], 0)
        self.assertEqual(document["updater_shell"]["target_architecture"], "CXD90045")
        self.assertFalse(document["updater_shell"]["generation_four_body_present"])
        self.assertEqual(
            document["camera_guard"]["candidate_scope"],
            "first-negotiated-fdat-chunk",
        )
        self.assertEqual(document["camera_guard"]["initial_sequence_payload_bytes"], 0)
        self.assertEqual(document["camera_guard"]["camera_decrypted_prefix_bytes"], 512)
        self.assertTrue(document["camera_guard"]["success_before_eof_permitted"])
        self.assertTrue(document["camera_guard"]["full_resend_after_reconnect"])
        self.assertEqual(
            document["service_acquisition"]["allowed_operations"],
            ["identity", "read-file", "read-memory", "read-bootrom"],
        )

    def test_report_rejects_promoted_claims_and_write_capabilities(self):
        document = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        cases = []

        for field in ("camera_executed", "bypass_established", "installable"):
            candidate = copy.deepcopy(document)
            candidate[field] = True
            cases.append(candidate)

        candidate = copy.deepcopy(document)
        candidate["host_verification"]["firmware_verifier_import_hits"] = 1
        cases.append(candidate)

        candidate = copy.deepcopy(document)
        candidate["updater_shell"]["generation_four_body_present"] = True
        cases.append(candidate)

        candidate = copy.deepcopy(document)
        candidate["service_acquisition"]["allowed_operations"].append("write-file")
        cases.append(candidate)

        candidate = copy.deepcopy(document)
        candidate["raw_payload"] = "deadbeef"
        cases.append(candidate)

        for candidate in cases:
            with self.subTest(candidate=candidate), self.assertRaises(TrustBoundaryError):
                validate_trust_boundary_report(candidate)

    def test_analyzer_contains_no_transport_or_secret_backend(self):
        source_path = REPOSITORY_ROOT / "pmca" / "analysis" / "trust_boundary.py"
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".", 1)[0])

        self.assertTrue(
            imported_roots.isdisjoint({"Crypto", "Cryptodome", "ctypes", "usb"})
        )
        folded = source.casefold()
        for forbidden in (
            "deviceiocontrol",
            "private_key",
            "writefirmware",
            "writefile(",
            "writememory(",
        ):
            self.assertNotIn(forbidden, folded)


if __name__ == "__main__":
    unittest.main()
