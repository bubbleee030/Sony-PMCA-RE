import ast
import copy
import json
import unittest
from pathlib import Path

from pmca.analysis.offline_receiver_inventory import (
    OfflineReceiverInventoryError,
    validate_offline_receiver_inventory,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = REPOSITORY_ROOT / "analysis" / "a6400-offline-receiver-inventory.json"
MODULE_PATH = (
    REPOSITORY_ROOT / "pmca" / "analysis" / "offline_receiver_inventory.py"
)


class OfflineReceiverInventoryTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(REPORT_PATH.read_text(encoding="utf-8"))

    def test_committed_inventory_is_exact_and_fail_closed(self):
        validated = validate_offline_receiver_inventory(self.document)

        self.assertEqual(validated, self.document)
        self.assertEqual(
            validated["classification"],
            "BLOCKED_MISSING_EXACT_PRE_2_00_SOURCE",
        )
        self.assertFalse(validated["camera_executed"])
        self.assertFalse(validated["sony_binary_executed"])
        self.assertFalse(validated["installable"])
        self.assertFalse(validated["exact_target"]["pre_2_00_package_present"])
        self.assertFalse(validated["exact_target"]["installing_receiver_located"])
        self.assertFalse(validated["exact_target"]["pre_normal_selector_located"])

    def test_search_scopes_pin_only_reproducible_target_counts(self):
        validated = validate_offline_receiver_inventory(self.document)

        self.assertEqual(
            [item["id"] for item in validated["search_scopes"]],
            ["canonical-workspace", "offline-downloads"],
        )
        self.assertEqual(
            [item["exact_pre_2_00_target_packages"] for item in validated["search_scopes"]],
            [0, 0],
        )
        self.assertTrue(
            all("control_packages" not in item for item in validated["search_scopes"])
        )

    def test_a6400a_control_cannot_be_promoted_to_target_recovery(self):
        control = validate_offline_receiver_inventory(self.document)[
            "control_samples"
        ][0]

        self.assertEqual(control["id"], "a6400a-eu-v1.01")
        self.assertEqual(control["model_id"], "0x81030017")
        self.assertNotEqual(control["model_id"], "0x81030011")
        self.assertTrue(control["persistent_updater_partition_present"])
        self.assertFalse(control["target_transferable"])
        self.assertFalse(control["target_recovery_supported"])

        for field in ("target_transferable", "target_recovery_supported"):
            candidate = copy.deepcopy(self.document)
            candidate["control_samples"][0][field] = True
            with self.subTest(field=field), self.assertRaises(
                OfflineReceiverInventoryError
            ):
                validate_offline_receiver_inventory(candidate)

    def test_target_identity_or_missing_source_cannot_be_reworded(self):
        mutations = (
            ("model_id", "0x81030017"),
            ("stock_version", "1.01"),
            ("pre_2_00_package_present", True),
            ("installing_receiver_located", True),
            ("pre_normal_selector_located", True),
        )
        for field, value in mutations:
            candidate = copy.deepcopy(self.document)
            candidate["exact_target"][field] = value
            with self.subTest(field=field), self.assertRaises(
                OfflineReceiverInventoryError
            ):
                validate_offline_receiver_inventory(candidate)

    def test_raw_reconstructive_or_operational_fields_are_rejected(self):
        for field in (
            "raw_payload",
            "private_key",
            "partition_bytes",
            "write_command",
            "firmware_path",
        ):
            candidate = copy.deepcopy(self.document)
            candidate[field] = "forbidden"
            with self.subTest(field=field), self.assertRaises(
                OfflineReceiverInventoryError
            ):
                validate_offline_receiver_inventory(candidate)

    def test_validator_has_no_device_execution_or_crypto_backend(self):
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
