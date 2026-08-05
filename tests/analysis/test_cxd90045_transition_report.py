import ast
import copy
import json
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = (
    REPOSITORY_ROOT
    / "analysis"
    / "a6400-cxd90045-transition-boundary.json"
)


class Cxd90045TransitionReportTests(unittest.TestCase):
    def _validator(self):
        try:
            from pmca.analysis.cxd90045_transition_report import (
                Cxd90045TransitionReportError,
                validate_cxd90045_transition_report,
            )
        except ModuleNotFoundError as exc:
            self.fail(f"CXD90045 transition validator is missing: {exc}")
        return validate_cxd90045_transition_report, Cxd90045TransitionReportError

    def _document(self):
        if not REPORT_PATH.is_file():
            self.fail(f"CXD90045 transition report is missing: {REPORT_PATH}")
        return json.loads(REPORT_PATH.read_text(encoding="utf-8"))

    def test_report_locates_persistent_updater_partition_boundary(self):
        validate, _ = self._validator()
        document = self._document()

        self.assertEqual(validate(document), document)
        self.assertEqual(document["schema_version"], 4)
        self.assertTrue(document["host_transfer"]["raw_fdat_sent"])
        self.assertFalse(document["host_transfer"]["transform_before_usb"])
        self.assertEqual(
            [item["version"] for item in document["generation4_packages"]["examples"]],
            ["2.00", "4.00", "4.01"],
        )
        self.assertTrue(
            all(
                item["offline_decode_validated"]
                for item in document["generation4_packages"]["examples"]
            )
        )
        self.assertTrue(document["shared_static_artifacts"]["partinf_identical"])
        self.assertTrue(document["shared_static_artifacts"]["up_sh_identical"])
        self.assertTrue(
            document["shared_static_artifacts"]["secure_apps_identical"]
        )
        self.assertEqual(document["updater_partition"]["device"], "/dev/nflasha1")
        self.assertEqual(
            document["updater_partition"]["payload_partition_images"],
            ["nflasha3", "nflasha5", "nflasha7", "nflasha15"],
        )
        self.assertFalse(document["updater_partition"]["included_in_payload"])
        self.assertEqual(
            document["updater_partition"]["selection_stage"],
            "before-normal-userspace",
        )
        self.assertFalse(document["updater_partition"]["contents_acquired"])
        self.assertFalse(document["updater_partition"]["cbc_stage_located"])
        self.assertFalse(document["updater_partition"]["signature_verifier_located"])
        self.assertFalse(document["updater_partition"]["trust_anchor_located"])
        self.assertEqual(
            document["visible_runtime"]["normal_init_bootmode_values"],
            ["USB_CHARGE", "ADJUST", "BIS"],
        )
        self.assertEqual(
            document["visible_runtime"]["lsi_handoff"],
            "numeric-mode-via-message-queue",
        )
        self.assertFalse(document["camera_executed"])
        self.assertFalse(document["bypass_established"])
        self.assertFalse(document["installable"])
        self.assertFalse(document["model_mismatch_safe"])

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

        for field in (
            "included_in_payload",
            "contents_acquired",
            "cbc_stage_located",
            "signature_verifier_located",
            "trust_anchor_located",
        ):
            candidate = copy.deepcopy(document)
            candidate["updater_partition"][field] = True
            candidates.append(candidate)

        candidate = copy.deepcopy(document)
        candidate["updater_partition"]["selection_stage"] = "normal-userspace"
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
            / "cxd90045_transition_report.py"
        )
        if not source_path.is_file():
            self.fail(f"CXD90045 transition validator is missing: {source_path}")
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
