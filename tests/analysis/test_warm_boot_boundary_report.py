import ast
import copy
import json
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = REPOSITORY_ROOT / "analysis" / "a6400-warm-boot-boundary.json"


class WarmBootBoundaryReportTests(unittest.TestCase):
    def _validator(self):
        try:
            from pmca.analysis.warm_boot_boundary_report import (
                WarmBootBoundaryReportError,
                validate_warm_boot_boundary_report,
            )
        except ModuleNotFoundError as exc:
            self.fail(f"Warm-boot boundary validator is missing: {exc}")
        return validate_warm_boot_boundary_report, WarmBootBoundaryReportError

    def _document(self):
        if not REPORT_PATH.is_file():
            self.fail(f"Warm-boot boundary report is missing: {REPORT_PATH}")
        return json.loads(REPORT_PATH.read_text(encoding="utf-8"))

    def test_report_excludes_wbi_and_main_partition_from_updater_selection(self):
        validate, _ = self._validator()
        document = self._document()

        self.assertEqual(validate(document), document)
        self.assertEqual(document["schema_version"], 5)
        self.assertEqual(len(document["warm_boot_images"]), 3)
        self.assertEqual(
            [item["sections"] for item in document["warm_boot_images"]],
            [644, 621, 625],
        )
        self.assertEqual(
            document["resume_path"]["role"], "cpu-context-restore-trampoline"
        )
        self.assertFalse(document["resume_path"]["reads_boot_mode"])
        self.assertFalse(document["resume_path"]["reads_updater_partition"])
        self.assertFalse(document["resume_path"]["verifies_firmware"])
        self.assertFalse(document["resume_path"]["updater_selector"])
        self.assertTrue(document["normal_main_partition"]["init_copies_identical"])
        self.assertFalse(
            document["normal_main_partition"]["init_mounts_updater_partition"]
        )
        self.assertEqual(
            document["normal_main_partition"]["kernel_updater_partition_mentions"],
            0,
        )
        self.assertTrue(document["loader_driver"]["identical_across_packages"])
        self.assertFalse(document["loader_driver"]["filesystem_access"])
        self.assertFalse(document["loader_driver"]["boot_mode_policy"])
        self.assertFalse(document["loader_driver"]["signature_verifier"])
        self.assertTrue(document["service_acquisition_route"]["read_primitive_present"])
        self.assertFalse(document["service_acquisition_route"]["write_required"])
        self.assertFalse(document["service_acquisition_route"]["camera_validated"])
        self.assertFalse(document["service_acquisition_route"]["dump_acquired"])
        for field in (
            "camera_executed",
            "bypass_established",
            "installable",
            "model_mismatch_safe",
        ):
            self.assertFalse(document[field])

    def test_report_rejects_promoted_or_reconstructive_claims(self):
        validate, error_type = self._validator()
        document = self._document()
        candidates = []

        for field in (
            "camera_executed",
            "bypass_established",
            "installable",
            "model_mismatch_safe",
        ):
            candidate = copy.deepcopy(document)
            candidate[field] = True
            candidates.append(candidate)

        for section, field in (
            ("resume_path", "reads_boot_mode"),
            ("resume_path", "reads_updater_partition"),
            ("resume_path", "verifies_firmware"),
            ("resume_path", "updater_selector"),
            ("normal_main_partition", "init_mounts_updater_partition"),
            ("loader_driver", "filesystem_access"),
            ("loader_driver", "boot_mode_policy"),
            ("loader_driver", "signature_verifier"),
            ("service_acquisition_route", "camera_validated"),
            ("service_acquisition_route", "dump_acquired"),
        ):
            candidate = copy.deepcopy(document)
            candidate[section][field] = True
            candidates.append(candidate)

        candidate = copy.deepcopy(document)
        candidate["key_bytes"] = "not-allowed"
        candidates.append(candidate)

        candidate = copy.deepcopy(document)
        candidate["unexpected"] = "field"
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(error_type):
                validate(candidate)

    def test_validator_has_no_device_crypto_or_execution_backend(self):
        source_path = (
            REPOSITORY_ROOT
            / "pmca"
            / "analysis"
            / "warm_boot_boundary_report.py"
        )
        if not source_path.is_file():
            self.fail(f"Warm-boot boundary validator is missing: {source_path}")
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(
                    alias.name.split(".", 1)[0] for alias in node.names
                )
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
