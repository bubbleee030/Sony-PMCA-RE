import ast
import copy
import json
import unittest
from pathlib import Path

from pmca.analysis.updater_control_bootstrap import (
    UpdaterControlBootstrapError,
    validate_updater_control_bootstrap,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = REPOSITORY_ROOT / "analysis" / "a6400a-updater-control-bootstrap.json"
MODULE_PATH = REPOSITORY_ROOT / "pmca" / "analysis" / "updater_control_bootstrap.py"


class UpdaterControlBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(REPORT_PATH.read_text(encoding="utf-8"))

    def test_committed_control_graph_is_exact_and_nontransferable(self):
        validated = validate_updater_control_bootstrap(self.document)

        self.assertEqual(validated, self.document)
        self.assertEqual(validated["source"]["model_id"], "0x81030017")
        self.assertEqual(validated["target"]["model_id"], "0x81030011")
        self.assertFalse(validated["target"]["architecture_transfer_proven"])
        self.assertFalse(validated["target"]["recovery_supported"])
        self.assertFalse(validated["target"]["camera_test_eligible"])

    def test_bootstrap_edges_are_bounded_and_ordered(self):
        graph = validate_updater_control_bootstrap(self.document)

        self.assertEqual(
            [item["id"] for item in graph["artifacts"]],
            [
                "updater-init",
                "boot-validity-check",
                "mode-dispatcher",
                "production-branch",
                "ufp-branch",
                "usb-preparation",
                "production-engine",
                "system-update-receiver",
                "input-feeder",
                "reboot-boundary",
            ],
        )
        self.assertEqual(
            [(item["caller"], item["callee"]) for item in graph["edges"]],
            [
                ("updater-init", "boot-validity-check"),
                ("updater-init", "mode-dispatcher"),
                ("mode-dispatcher", "production-branch"),
                ("mode-dispatcher", "ufp-branch"),
                ("production-branch", "usb-preparation"),
                ("production-branch", "production-engine"),
                ("ufp-branch", "usb-preparation"),
                ("ufp-branch", "system-update-receiver"),
                ("ufp-branch", "input-feeder"),
                ("ufp-branch", "reboot-boundary"),
            ],
        )
        self.assertTrue(all(item["kind"] == "STATIC_SCRIPT_REFERENCE" for item in graph["edges"]))

    def test_guard_and_signature_roots_do_not_establish_write_or_completion(self):
        graph = validate_updater_control_bootstrap(self.document)
        boundaries = {item["id"]: item for item in graph["sauu_boundaries"]}

        for boundary_id in (
            "guard-dispatch",
            "model-compare",
            "region-compare",
            "version-compare",
            "verification-key-hash",
            "signature-verifier",
            "signature-workflow-caller",
        ):
            self.assertEqual(boundaries[boundary_id]["status"], "BOUNDED_CONTROL")
            self.assertIsInstance(boundaries[boundary_id]["address"], int)
        for boundary_id in ("write-orchestrator", "completion-verification"):
            self.assertEqual(boundaries[boundary_id]["status"], "UNESTABLISHED")
            self.assertIsNone(boundaries[boundary_id]["address"])

    def test_control_or_unestablished_boundary_cannot_be_promoted(self):
        mutations = []
        candidate = copy.deepcopy(self.document)
        candidate["target"]["architecture_transfer_proven"] = True
        mutations.append(candidate)
        candidate = copy.deepcopy(self.document)
        candidate["target"]["recovery_supported"] = True
        mutations.append(candidate)
        candidate = copy.deepcopy(self.document)
        candidate["sauu_boundaries"][-2]["status"] = "BOUNDED_CONTROL"
        candidate["sauu_boundaries"][-2]["address"] = 0x1234
        mutations.append(candidate)

        for candidate in mutations:
            with self.subTest(candidate=candidate), self.assertRaises(
                UpdaterControlBootstrapError
            ):
                validate_updater_control_bootstrap(candidate)

    def test_raw_commands_device_paths_and_key_material_are_rejected(self):
        for field in (
            "raw_command",
            "device_path",
            "partition_bytes",
            "private_key",
            "raw_payload",
        ):
            candidate = copy.deepcopy(self.document)
            candidate[field] = "forbidden"
            with self.subTest(field=field), self.assertRaises(
                UpdaterControlBootstrapError
            ):
                validate_updater_control_bootstrap(candidate)

    def test_validator_has_no_execution_device_or_crypto_backend(self):
        tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
        imports = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }

        self.assertTrue(
            imports.isdisjoint(
                {
                    "Crypto",
                    "Cryptodome",
                    "ctypes",
                    "subprocess",
                    "usb",
                    "serial",
                    "socket",
                }
            )
        )


if __name__ == "__main__":
    unittest.main()
