import ast
import copy
import json
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = (
    REPOSITORY_ROOT / "analysis" / "a6400-updater-pipeline-boundary-v2.json"
)


class UpdaterPipelineReportTests(unittest.TestCase):
    def _validator(self):
        try:
            from pmca.analysis.updater_pipeline_report import (
                UpdaterPipelineReportError,
                validate_updater_pipeline_report,
            )
        except ModuleNotFoundError as exc:
            self.fail(f"updater pipeline report validator is missing: {exc}")
        return validate_updater_pipeline_report, UpdaterPipelineReportError

    def _document(self):
        if not REPORT_PATH.is_file():
            self.fail(f"updater pipeline report is missing: {REPORT_PATH}")
        return json.loads(REPORT_PATH.read_text(encoding="utf-8"))

    def test_committed_report_locates_receiver_and_body_pipeline(self):
        validate, _ = self._validator()
        document = self._document()

        self.assertEqual(validate(document), document)
        self.assertEqual(document["schema_version"], 2)
        self.assertTrue(document["receiver"]["system_receiver_located"])
        self.assertEqual(document["receiver"]["receive_command"], "0x0040")
        self.assertEqual(document["receiver"]["completion_command"], "0x0100")
        self.assertFalse(document["receiver"]["second_host_transfer"])
        self.assertEqual(
            document["crypter"]["pre_crypter_transform"],
            "generation4-to-legacy-ecb-transcode-required",
        )
        self.assertEqual(
            document["crypter"]["pre_crypter_transform_implementation"],
            "unresolved",
        )
        self.assertEqual(
            document["body_pipeline"]["consumer_entry"], "UpdaterBody::Execute"
        )
        self.assertEqual(
            document["body_pipeline"]["consumer_input"], "Updater::RingBuffer"
        )
        self.assertFalse(document["secure_apps"]["updater_invocation_proven"])
        self.assertFalse(
            document["secure_apps"]["generation4_transform_link_proven"]
        )
        self.assertFalse(document["integrity"]["signature_proven"])
        self.assertFalse(document["camera_executed"])
        self.assertFalse(document["bypass_established"])
        self.assertFalse(document["installable"])
        self.assertFalse(document["model_mismatch_safe"])

    def test_report_rejects_promoted_or_flashable_claims(self):
        validate, error_type = self._validator()
        document = self._document()
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
        candidate["receiver"]["system_receiver_located"] = False
        cases.append(candidate)

        candidate = copy.deepcopy(document)
        candidate["crypter"]["pre_crypter_transform_implementation"] = "located"
        cases.append(candidate)

        candidate = copy.deepcopy(document)
        candidate["secure_apps"]["updater_invocation_proven"] = True
        cases.append(candidate)

        candidate = copy.deepcopy(document)
        candidate["secure_apps"]["generation4_transform_link_proven"] = True
        cases.append(candidate)

        candidate = copy.deepcopy(document)
        candidate["integrity"]["signature_proven"] = True
        cases.append(candidate)

        candidate = copy.deepcopy(document)
        candidate["unexpected"] = "field"
        cases.append(candidate)

        for candidate in cases:
            with self.subTest(candidate=candidate), self.assertRaises(error_type):
                validate(candidate)

    def test_validator_has_no_device_crypto_or_execution_backend(self):
        source_path = (
            REPOSITORY_ROOT
            / "pmca"
            / "analysis"
            / "updater_pipeline_report.py"
        )
        if not source_path.is_file():
            self.fail(f"updater pipeline validator is missing: {source_path}")
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
