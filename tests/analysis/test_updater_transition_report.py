import ast
import copy
import json
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = REPOSITORY_ROOT / "analysis" / "a6400-updater-transition-boundary.json"


class UpdaterTransitionReportTests(unittest.TestCase):
    def _validator(self):
        try:
            from pmca.analysis.updater_transition_report import (
                UpdaterTransitionReportError,
                validate_updater_transition_report,
            )
        except ModuleNotFoundError as exc:
            self.fail(f"updater transition report validator is missing: {exc}")
        return validate_updater_transition_report, UpdaterTransitionReportError

    def _document(self):
        if not REPORT_PATH.is_file():
            self.fail(f"updater transition report is missing: {REPORT_PATH}")
        return json.loads(REPORT_PATH.read_text(encoding="utf-8"))

    def test_report_separates_installed_artifacts_from_installing_receiver(self):
        validate, _ = self._validator()
        document = self._document()

        self.assertEqual(validate(document), document)
        self.assertEqual(document["schema_version"], 3)
        self.assertEqual(document["package_target_version"], "2.00")
        self.assertEqual(document["analyzed_system_version"], "2.00")
        self.assertEqual(document["installing_system_version"], "pre-2.00")
        self.assertFalse(document["same_receiver_artifact_proven"])
        self.assertTrue(document["host_path"]["raw_fdat_sent"])
        self.assertTrue(document["v2_system_path"]["raw_fdat_written"])
        self.assertEqual(
            document["v2_system_path"]["module_chain"],
            ["BaseFirmware", "MsDecryptorModule", "FileInputBodyLoaderModule"],
        )
        self.assertEqual(document["v2_system_path"]["frame_bytes"], 0x400)
        self.assertEqual(document["v2_system_path"]["block_bytes"], 0x10)
        self.assertEqual(document["v2_system_path"]["decrypt_api"], "Dec_Scramble")
        self.assertFalse(document["v2_system_path"]["cbc_stage_present"])
        self.assertFalse(document["installing_receiver"]["artifact_located"])
        self.assertEqual(
            document["installing_receiver"]["generation4_transform_location"],
            "unresolved",
        )
        self.assertFalse(document["installable"])
        self.assertFalse(document["bypass_established"])

    def test_report_rejects_version_conflation_and_promoted_claims(self):
        validate, error_type = self._validator()
        document = self._document()
        candidates = []

        for field in (
            "same_receiver_artifact_proven",
            "camera_executed",
            "bypass_established",
            "installable",
            "model_mismatch_safe",
        ):
            candidate = copy.deepcopy(document)
            candidate[field] = True
            candidates.append(candidate)

        candidate = copy.deepcopy(document)
        candidate["installing_receiver"]["artifact_located"] = True
        candidates.append(candidate)

        candidate = copy.deepcopy(document)
        candidate["installing_receiver"]["generation4_transform_location"] = "v2-crypter"
        candidates.append(candidate)

        candidate = copy.deepcopy(document)
        candidate["v2_system_path"]["cbc_stage_present"] = True
        candidates.append(candidate)

        candidate = copy.deepcopy(document)
        candidate["unexpected"] = "field"
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(error_type):
                validate(candidate)

    def test_validator_has_no_device_crypto_or_execution_backend(self):
        source_path = REPOSITORY_ROOT / "pmca" / "analysis" / "updater_transition_report.py"
        if not source_path.is_file():
            self.fail(f"updater transition validator is missing: {source_path}")
        source = source_path.read_text(encoding="utf-8")
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
