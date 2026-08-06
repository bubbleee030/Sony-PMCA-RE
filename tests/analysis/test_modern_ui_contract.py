import copy
import json
import unittest
from pathlib import Path

from pmca.analysis.modern_ui_contract import (
    ModernUiContractError,
    validate_modern_ui_contract,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = REPOSITORY_ROOT / "analysis" / "a6400-modern-ui-contract.json"
BEHAVIOR_IDS = [
    "shooting-layout-landscape",
    "shooting-layout-portrait-shutter-up",
    "shooting-layout-portrait-shutter-down",
    "orientation-layout-selection",
    "control-direction-transform",
    "touch-coordinate-transform",
    "menu-touch-hit-test",
    "menu-touch-selection",
    "ui-state-persistence",
]


class ModernUiContractTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))

    def test_committed_contract_contains_exact_required_behaviors(self):
        validated = validate_modern_ui_contract(self.document)

        self.assertEqual(
            [item["id"] for item in validated["behaviors"]],
            BEHAVIOR_IDS,
        )
        self.assertTrue(
            all(item["status"] == "UNESTABLISHED" for item in validated["behaviors"])
        )
        self.assertTrue(all(item["evidence"] == [] for item in validated["behaviors"]))
        self.assertTrue(all(item["acceptance"].strip() for item in validated["behaviors"]))

    def test_contract_rejects_unproven_implementation_status(self):
        for status in (
            "TARGET_NATIVE",
            "TARGET_REIMPLEMENTABLE",
            "DONOR_COMPATIBLE",
            "APPROXIMATION_ONLY",
            "HARDWARE_BLOCKED",
        ):
            candidate = copy.deepcopy(self.document)
            candidate["behaviors"][3]["status"] = status
            with self.subTest(status=status), self.assertRaises(ModernUiContractError):
                validate_modern_ui_contract(candidate)

    def test_contract_rejects_wrong_identity_membership_and_order(self):
        candidates = []

        candidate = copy.deepcopy(self.document)
        candidate["target"] = "ILCE-7M5"
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["reference"] = "ILCE-6400-stock-ui"
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["behaviors"] = list(reversed(candidate["behaviors"]))
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["behaviors"].append(copy.deepcopy(candidate["behaviors"][0]))
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                ModernUiContractError
            ):
                validate_modern_ui_contract(candidate)

    def test_contract_rejects_unknown_fields_bad_types_and_empty_text(self):
        candidates = []

        candidate = copy.deepcopy(self.document)
        candidate["unexpected"] = True
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["schema_version"] = True
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["behaviors"][0]["unexpected"] = "field"
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["behaviors"][0]["evidence"] = "not-a-list"
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["behaviors"][0]["acceptance"] = "  "
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                ModernUiContractError
            ):
                validate_modern_ui_contract(candidate)

    def test_validated_contract_is_a_deep_copy(self):
        validated = validate_modern_ui_contract(self.document)

        validated["behaviors"][0]["acceptance"] = "changed"

        self.assertNotEqual(
            validated["behaviors"][0]["acceptance"],
            self.document["behaviors"][0]["acceptance"],
        )


if __name__ == "__main__":
    unittest.main()
