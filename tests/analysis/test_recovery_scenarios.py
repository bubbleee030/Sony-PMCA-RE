import ast
import copy
import json
import unittest
from pathlib import Path

from pmca.analysis.recovery_scenarios import (
    SCENARIO_IDS,
    RecoveryScenarioError,
    validate_recovery_scenarios,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = REPOSITORY_ROOT / "analysis" / "a6400-recovery-scenarios.json"


class RecoveryScenarioTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(REPORT_PATH.read_text(encoding="utf-8"))

    def test_every_required_scenario_is_explicit_and_unestablished(self):
        validated = validate_recovery_scenarios(self.document)

        self.assertEqual(
            [item["id"] for item in validated["scenarios"]], list(SCENARIO_IDS)
        )
        self.assertTrue(
            all(item["status"] == "UNESTABLISHED" for item in validated["scenarios"])
        )
        self.assertFalse(validated["recovery_validated"])

    def test_every_scenario_has_exact_independent_recovery_fields(self):
        validated = validate_recovery_scenarios(self.document)
        expected_fields = {
            "id",
            "status",
            "entry_available",
            "runtime_independent",
            "write_scope_known",
            "verification_available",
            "power_loss_behavior_known",
            "candidate_coverage",
            "evidence",
            "blocker",
        }

        for scenario in validated["scenarios"]:
            with self.subTest(scenario=scenario["id"]):
                self.assertEqual(set(scenario), expected_fields)
                for field in (
                    "entry_available",
                    "runtime_independent",
                    "write_scope_known",
                    "verification_available",
                    "power_loss_behavior_known",
                ):
                    self.assertIs(scenario[field], False)
                self.assertIsInstance(scenario["evidence"], list)
                self.assertTrue(scenario["blocker"])

    def test_every_scenario_assesses_all_three_candidates_independently(self):
        validated = validate_recovery_scenarios(self.document)
        candidate_ids = [
            "official-updater-reinstall",
            "usb-recovery-or-updater-mode",
            "independent-maintenance-path",
        ]

        for scenario in validated["scenarios"]:
            with self.subTest(scenario=scenario["id"]):
                self.assertEqual(
                    [item["id"] for item in scenario["candidate_coverage"]],
                    candidate_ids,
                )
                self.assertTrue(
                    all(
                        item == {"id": candidate_id, "status": "UNESTABLISHED"}
                        for item, candidate_id in zip(
                            scenario["candidate_coverage"], candidate_ids
                        )
                    )
                )

    def test_candidate_coverage_cannot_be_aggregated_or_promoted(self):
        candidates = []

        candidate = copy.deepcopy(self.document)
        candidate["scenarios"][0]["candidate_coverage"].pop()
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["scenarios"][0]["candidate_coverage"][0]["status"] = "PARTIAL"
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["scenarios"][0]["candidate_coverage"][0]["id"] = "aggregate"
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                RecoveryScenarioError
            ):
                validate_recovery_scenarios(candidate)

    def test_report_consumes_exact_authenticated_stock_bundle(self):
        validated = validate_recovery_scenarios(self.document)

        self.assertEqual(
            validated["stock_bundle"],
            {
                "reference": "analysis/a6400-stock-200-bundle.json",
                "source_key": "a6400-tw-v2.00",
                "model_id": "0x81030011",
                "region": "TW",
                "region_code": 0,
                "version": "2.00",
            },
        )

    def test_unestablished_scenario_cannot_promote_any_capability(self):
        capability_fields = (
            "entry_available",
            "runtime_independent",
            "write_scope_known",
            "verification_available",
            "power_loss_behavior_known",
        )
        for field in capability_fields:
            candidate = copy.deepcopy(self.document)
            candidate["scenarios"][0][field] = True
            with self.subTest(field=field), self.assertRaises(
                RecoveryScenarioError
            ):
                validate_recovery_scenarios(candidate)

    def test_recoverable_requires_entry_runtime_scope_verification_and_evidence(self):
        base = copy.deepcopy(self.document)
        scenario = base["scenarios"][0]
        scenario["status"] = "RECOVERABLE"
        for field in (
            "entry_available",
            "runtime_independent",
            "write_scope_known",
            "verification_available",
        ):
            scenario[field] = True

        candidates = []
        for field in (
            "entry_available",
            "runtime_independent",
            "write_scope_known",
            "verification_available",
        ):
            candidate = copy.deepcopy(base)
            candidate["scenarios"][0][field] = False
            candidates.append(candidate)

        candidate = copy.deepcopy(base)
        candidate["scenarios"][0]["evidence"] = []
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                RecoveryScenarioError
            ):
                validate_recovery_scenarios(candidate)

    def test_power_loss_scenario_requires_known_power_loss_behavior(self):
        candidate = copy.deepcopy(self.document)
        scenario = candidate["scenarios"][-1]
        scenario["status"] = "RECOVERABLE"
        for field in (
            "entry_available",
            "runtime_independent",
            "write_scope_known",
            "verification_available",
        ):
            scenario[field] = True
        scenario["evidence"] = [
            {
                "evidence_id": "unknown-static-evidence",
                "classification": "BOUNDED_STATIC",
                "source": "analysis/a6400-updater-gates.json",
                "direct": False,
                "claim": "Static evidence cannot establish power-loss behavior.",
            }
        ]

        with self.assertRaises(RecoveryScenarioError):
            validate_recovery_scenarios(candidate)

    def test_unrecoverable_requires_direct_evidence_not_absence(self):
        candidates = []

        candidate = copy.deepcopy(self.document)
        candidate["scenarios"][0]["status"] = "UNRECOVERABLE"
        candidate["scenarios"][0]["evidence"] = []
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["scenarios"][0]["status"] = "UNRECOVERABLE"
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                RecoveryScenarioError
            ):
                validate_recovery_scenarios(candidate)

    def test_partial_requires_evidence_capability_and_blocker(self):
        candidates = []

        candidate = copy.deepcopy(self.document)
        candidate["scenarios"][0]["status"] = "PARTIAL"
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["scenarios"][0]["status"] = "PARTIAL"
        candidate["scenarios"][0]["entry_available"] = True
        candidate["scenarios"][0]["evidence"] = []
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["scenarios"][0]["status"] = "PARTIAL"
        candidate["scenarios"][0]["entry_available"] = True
        candidate["scenarios"][0]["blocker"] = " "
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                RecoveryScenarioError
            ):
                validate_recovery_scenarios(candidate)

    def test_allowlisted_static_prose_cannot_promote_partial_capability(self):
        candidate = copy.deepcopy(self.document)
        scenario = candidate["scenarios"][0]
        scenario["status"] = "PARTIAL"
        scenario["entry_available"] = True
        scenario["evidence"] = [
            {
                "evidence_id": "missing-installing-receiver",
                "classification": "BOUNDED_STATIC",
                "source": "analysis/a6400-updater-gates.json",
                "direct": False,
                "claim": "No unresolved issue: an external entry is established.",
            }
        ]
        scenario["blocker"] = "Unknown details remain."

        with self.assertRaises(RecoveryScenarioError):
            validate_recovery_scenarios(candidate)

    def test_stock_identity_drift_and_boolean_region_are_rejected(self):
        candidates = []
        for field, value in (
            ("source_key", "other-source"),
            ("model_id", "0x00000000"),
            ("region", "US"),
            ("region_code", 1),
            ("version", "2.01"),
        ):
            candidate = copy.deepcopy(self.document)
            candidate["stock_bundle"][field] = value
            candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["stock_bundle"]["region_code"] = False
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                RecoveryScenarioError
            ):
                validate_recovery_scenarios(candidate)

    def test_direct_evidence_is_rejected_while_camera_flags_are_static(self):
        candidate = copy.deepcopy(self.document)
        candidate["scenarios"][0]["evidence"] = [
            {
                "evidence_id": "future-authorized-physical-validation",
                "classification": "BOUNDED_STATIC",
                "source": "future-authorized-physical-validation",
                "direct": True,
                "claim": "A future observation would require fresh authorization.",
            }
        ]

        with self.assertRaises(RecoveryScenarioError):
            validate_recovery_scenarios(candidate)

    def test_missing_duplicate_reordered_or_unknown_scenarios_are_rejected(self):
        candidates = []

        candidate = copy.deepcopy(self.document)
        candidate["scenarios"].pop()
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["scenarios"][1]["id"] = candidate["scenarios"][0]["id"]
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["scenarios"].reverse()
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["scenarios"][0]["unexpected"] = False
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                RecoveryScenarioError
            ):
                validate_recovery_scenarios(candidate)

    def test_operational_commands_paths_and_partition_material_are_rejected(self):
        forbidden_text = (
            "C:\\firmware\\restore.bin",
            "dd if=stock.bin of=/dev/device",
            "fastboot flash system stock.img",
            "diskpart select disk 1",
            "AA" * 160,
        )
        for text in forbidden_text:
            candidate = copy.deepcopy(self.document)
            candidate["scenarios"][0]["blocker"] = text
            with self.subTest(text=text[:32]), self.assertRaises(
                RecoveryScenarioError
            ):
                validate_recovery_scenarios(candidate)

    def test_empty_blockers_bad_boolean_types_and_static_promotion_are_rejected(self):
        candidates = []

        candidate = copy.deepcopy(self.document)
        candidate["scenarios"][0]["blocker"] = ""
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["scenarios"][0]["entry_available"] = 1
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["recovery_validated"] = True
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["camera_executed"] = True
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                RecoveryScenarioError
            ):
                validate_recovery_scenarios(candidate)

    def test_validated_report_is_an_isolated_copy(self):
        validated = validate_recovery_scenarios(self.document)
        validated["scenarios"][0]["blocker"] = "changed"

        self.assertNotEqual(
            validated["scenarios"][0]["blocker"],
            self.document["scenarios"][0]["blocker"],
        )

    def test_validator_has_no_device_execution_or_write_backend(self):
        source_path = (
            REPOSITORY_ROOT / "pmca" / "analysis" / "recovery_scenarios.py"
        )
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        imported_roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".", 1)[0])

        self.assertTrue(
            imported_roots.isdisjoint(
                {"subprocess", "ctypes", "usb", "serial", "socket", "shutil"}
            )
        )


if __name__ == "__main__":
    unittest.main()
