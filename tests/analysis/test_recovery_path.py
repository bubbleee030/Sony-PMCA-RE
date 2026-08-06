import ast
import copy
import importlib.util
import json
import unittest
from pathlib import Path
from unittest import mock

import pmca.analysis.recovery_path as recovery_path

from pmca.analysis.recovery_path import (
    CANDIDATE_IDS,
    DETAIL_IDS,
    GATE_IDS,
    RecoveryPathError,
    normalize_restore_gate_export,
    validate_recovery_report,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = REPOSITORY_ROOT / "analysis" / "a6400-stock-200-recovery.json"
EXPORTER_PATH = (
    REPOSITORY_ROOT / "tools" / "ghidra" / "export_a6400_restore_gates.py"
)


def _load_exporter():
    spec = importlib.util.spec_from_file_location("recovery_gate_exporter", EXPORTER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def synthetic_gate_export():
    return json.loads(REPORT_PATH.read_text(encoding="utf-8"))["static_gate_export"]


class RecoveryPathTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(REPORT_PATH.read_text(encoding="utf-8"))

    def test_committed_report_separates_every_gate_and_detail(self):
        validated = validate_recovery_report(self.document)

        self.assertEqual([item["id"] for item in validated["gates"]], list(GATE_IDS))
        self.assertEqual(
            [item["id"] for item in validated["details"]], list(DETAIL_IDS)
        )
        self.assertEqual(
            {item["id"]: item["status"] for item in validated["gates"]},
            {
                "host_updater": "PARTIAL",
                "transport": "PARTIAL",
                "camera_updater": "PARTIAL",
                "boot_chain": "UNESTABLISHED",
                "runtime_integrity": "UNESTABLISHED",
            },
        )
        self.assertEqual(
            {item["id"]: item["status"] for item in validated["details"]},
            {
                "signed_ranges": "UNESTABLISHED",
                "model_check": "PARTIAL",
                "version_check": "PARTIAL",
                "write_scope": "UNESTABLISHED",
                "write_order": "UNESTABLISHED",
                "post_write_verification": "UNESTABLISHED",
                "downgrade_or_reinstall": "UNESTABLISHED",
                "power_loss_behavior": "UNESTABLISHED",
            },
        )

    def test_host_mapping_does_not_prove_camera_boot_or_recovery_acceptance(self):
        validated = validate_recovery_report(self.document)

        self.assertEqual(validated["gates"][0]["status"], "PARTIAL")
        self.assertEqual(validated["gates"][2]["status"], "PARTIAL")
        self.assertEqual(validated["gates"][3]["status"], "UNESTABLISHED")
        self.assertFalse(validated["recovery_validated"])
        self.assertFalse(validated["camera_test_eligible"])

    def test_static_evidence_cannot_mark_recovery_or_camera_eligibility(self):
        for field in ("recovery_validated", "camera_test_eligible", "installable"):
            candidate = copy.deepcopy(self.document)
            candidate[field] = True
            with self.subTest(field=field), self.assertRaises(RecoveryPathError):
                validate_recovery_report(candidate)

    def test_recovery_readiness_basis_is_derived_and_blocked(self):
        validated = validate_recovery_report(self.document)

        self.assertEqual(
            validated["readiness_basis"],
            {
                "authenticated_stock_bundle": True,
                "runtime_independent_entry_established": False,
                "write_scope_established": False,
                "write_order_established": False,
                "post_write_verification_established": False,
                "scenario_overclaim_count": 0,
            },
        )
        self.assertEqual(validated["readiness"], "BLOCKED_STATIC_EVIDENCE")

        candidate = copy.deepcopy(self.document)
        candidate["readiness"] = "READY_FOR_FUTURE_VALIDATION_DESIGN"
        with self.assertRaises(RecoveryPathError):
            validate_recovery_report(candidate)

    def test_each_detail_cannot_be_promoted_without_typed_support(self):
        for index, detail_id in enumerate(DETAIL_IDS):
            candidate = copy.deepcopy(self.document)
            candidate["details"][index]["status"] = "ESTABLISHED"
            with self.subTest(detail_id=detail_id), self.assertRaises(
                RecoveryPathError
            ):
                validate_recovery_report(candidate)

    def test_report_rejects_aggregate_bypass_and_firmware_material(self):
        candidates = []

        candidate = copy.deepcopy(self.document)
        candidate["bypass"] = False
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["details"][0]["raw_payload"] = "forbidden"
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["gates"][0]["evidence"][0]["private_key"] = "forbidden"
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                RecoveryPathError
            ):
                validate_recovery_report(candidate)

    def test_missing_duplicate_or_reordered_gate_and_detail_ids_are_rejected(self):
        candidates = []

        candidate = copy.deepcopy(self.document)
        candidate["gates"].pop()
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["gates"][1]["id"] = candidate["gates"][0]["id"]
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["details"].reverse()
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                RecoveryPathError
            ):
                validate_recovery_report(candidate)

    def test_stock_and_scenario_references_are_cross_validated(self):
        validated = validate_recovery_report(self.document)

        self.assertEqual(
            validated["stock_bundle"]["reference"],
            "analysis/a6400-stock-200-bundle.json",
        )
        self.assertEqual(
            validated["recovery_scenarios"]["reference"],
            "analysis/a6400-recovery-scenarios.json",
        )
        self.assertEqual(validated["recovery_scenarios"]["recoverable_count"], 0)

        for section in ("stock_bundle", "recovery_scenarios"):
            candidate = copy.deepcopy(self.document)
            candidate[section]["reference"] = "analysis/other.json"
            with self.subTest(section=section), self.assertRaises(RecoveryPathError):
                validate_recovery_report(candidate)

    def test_different_model_control_is_pinned_and_cannot_promote_recovery(self):
        before = {
            "gates": copy.deepcopy(self.document["gates"]),
            "details": copy.deepcopy(self.document["details"]),
            "candidates": copy.deepcopy(self.document["candidates"]),
            "readiness_basis": copy.deepcopy(self.document["readiness_basis"]),
            "readiness": self.document["readiness"],
        }

        validated = validate_recovery_report(self.document)

        self.assertEqual(
            validated["architecture_controls"],
            [
                {
                    "id": "a6400a-eu-v1.01-receiver-control",
                    "reference": "analysis/a6400a-updater-control-bootstrap.json",
                    "source_model_id": "0x81030017",
                    "target_model_id": "0x81030011",
                    "canonical_export_sha256": "0e80cb19f9d4f227f04503e6d3f6ace4f1b0c7fe6194e2a3c7ede89a8ed9ad38",
                    "function_count": 37,
                    "call_count": 71,
                    "status": "NON_TRANSFERABLE_CONTROL",
                    "target_acceptance_established": False,
                    "write_scope_established": False,
                    "post_write_verification_established": False,
                    "recovery_supported": False,
                    "claim": "Different-model updater architecture control only; it does not establish the original alpha6400 selector, receiver, acceptance, write order, terminal verification, or recovery.",
                }
            ],
        )
        self.assertEqual(
            {
                "gates": validated["gates"],
                "details": validated["details"],
                "candidates": validated["candidates"],
                "readiness_basis": validated["readiness_basis"],
                "readiness": validated["readiness"],
            },
            before,
        )

    def test_different_model_control_identity_and_nonpromotion_flags_are_strict(self):
        mutations = (
            ("status", "PARTIAL"),
            ("source_model_id", "0x81030011"),
            ("target_model_id", "0x81030017"),
            ("canonical_export_sha256", "0" * 64),
            ("function_count", 38),
            ("call_count", 72),
            ("target_acceptance_established", True),
            ("write_scope_established", True),
            ("post_write_verification_established", True),
            ("recovery_supported", True),
        )
        for field, value in mutations:
            candidate = copy.deepcopy(self.document)
            candidate["architecture_controls"][0][field] = value
            with self.subTest(field=field), self.assertRaises(RecoveryPathError):
                validate_recovery_report(candidate)

    def test_different_model_control_dependency_is_validated_dynamically(self):
        original_load = recovery_path._load_json

        def corrupted_load(relative_path, label):
            dependency = original_load(relative_path, label)
            if relative_path == "analysis/a6400a-updater-control-bootstrap.json":
                dependency["sauu_control_export"]["target_transferable"] = True
            return dependency

        with mock.patch.object(
            recovery_path, "_load_json", side_effect=corrupted_load
        ), self.assertRaises(RecoveryPathError):
            validate_recovery_report(self.document)

    def test_validated_report_is_an_isolated_copy(self):
        validated = validate_recovery_report(self.document)
        validated["details"][0]["blocker"] = "changed"

        self.assertNotEqual(
            validated["details"][0]["blocker"],
            self.document["details"][0]["blocker"],
        )

    def test_candidate_paths_are_independent_and_non_equivalent(self):
        validated = validate_recovery_report(self.document)

        self.assertEqual(
            [item["id"] for item in validated["candidates"]],
            list(CANDIDATE_IDS),
        )
        expected_fields = {
            "id",
            "status",
            "entry_layer",
            "runtime_independent",
            "stock_source",
            "write_scope",
            "verification",
            "evidence",
            "blocker",
        }
        for candidate in validated["candidates"]:
            with self.subTest(candidate=candidate["id"]):
                self.assertEqual(set(candidate), expected_fields)
                self.assertEqual(candidate["status"], "UNESTABLISHED")
                self.assertIs(candidate["runtime_independent"], False)
                self.assertEqual(candidate["stock_source"], "a6400-tw-v2.00")
                self.assertEqual(candidate["write_scope"], "UNESTABLISHED")
                self.assertEqual(candidate["verification"], "UNESTABLISHED")

    def test_official_candidate_stops_at_the_windows_host_layer(self):
        official = validate_recovery_report(self.document)["candidates"][0]

        self.assertEqual(official["entry_layer"], "windows-host-updater-only")
        self.assertEqual(
            [item["evidence_id"] for item in official["evidence"]],
            [
                "candidate-official-host-engine-static",
                "candidate-official-installer-missing",
            ],
        )

    def test_candidate_runtime_scope_or_verification_cannot_be_promoted(self):
        mutations = (
            ("runtime_independent", True),
            ("write_scope", "ESTABLISHED"),
            ("verification", "ESTABLISHED"),
            ("status", "PARTIAL"),
        )
        for index, candidate_id in enumerate(CANDIDATE_IDS):
            for field, value in mutations:
                candidate = copy.deepcopy(self.document)
                candidate["candidates"][index][field] = value
                with self.subTest(
                    candidate_id=candidate_id, field=field
                ), self.assertRaises(RecoveryPathError):
                    validate_recovery_report(candidate)

    def test_candidate_aggregation_or_string_only_maintenance_claim_is_rejected(self):
        candidates = []

        candidate = copy.deepcopy(self.document)
        candidate["candidates"].pop(1)
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["candidates"][2]["entry_layer"] = "maintenance string found"
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["candidates"][2]["evidence"][0]["claim"] = (
            "A maintenance path is established by a string."
        )
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                RecoveryPathError
            ):
                validate_recovery_report(candidate)


class RestoreGateExportTests(unittest.TestCase):
    def test_bounded_export_normalizes_deterministically(self):
        raw = synthetic_gate_export()
        normalized = normalize_restore_gate_export(raw)

        self.assertEqual(normalized, normalize_restore_gate_export(raw))
        self.assertEqual(normalized["program"], "signed-updater-engine-8f2e8b22.exe")
        self.assertEqual(
            [item["id"] for item in normalized["roots"]],
            [item["id"] for item in raw["roots"]],
        )
        self.assertTrue(
            {
                ("firmware-write-command", 0x40),
                ("completion-command", 0x100),
                ("invalid-model-status", 0x140),
                ("invalid-model-status", 0x141),
                ("invalid-version-status", 0x142),
            }.issubset(
                {
                    (item["semantic"], item["value"])
                    for item in normalized["scalar_comparisons"]
                }
            )
        )
        self.assertEqual(len(normalized["scalar_comparisons"]), 35)
        self.assertEqual(len(normalized["calls"]), 359)
        self.assertEqual(normalized["unresolved_direct_calls"], 308)
        self.assertEqual(normalized["unresolved_indirect_calls"], 29)
        self.assertTrue(normalized["analysis_mode"]["read_only"])
        self.assertTrue(normalized["analysis_mode"]["noanalysis"])
        self.assertFalse(normalized["truncated"])

    def test_export_rejects_wrong_identity_missing_roots_and_unbounded_values(self):
        candidates = []

        candidate = synthetic_gate_export()
        candidate["sha256"] = "0" * 64
        candidates.append(candidate)

        candidate = synthetic_gate_export()
        candidate["roots"].pop()
        candidates.append(candidate)

        candidate = synthetic_gate_export()
        candidate["roots"][0]["address"] = True
        candidates.append(candidate)

        candidate = synthetic_gate_export()
        candidate["scalar_comparisons"][0]["value"] = 0xDEADBEEF
        candidates.append(candidate)

        candidate = synthetic_gate_export()
        candidate["analysis_mode"]["read_only"] = False
        candidates.append(candidate)

        candidate = synthetic_gate_export()
        candidate["truncated"] = True
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                RecoveryPathError
            ):
                normalize_restore_gate_export(candidate)

    def test_export_rejects_duplicate_sites_unknown_imports_and_raw_material(self):
        candidates = []

        candidate = synthetic_gate_export()
        candidate["scalar_comparisons"][1]["site"] = candidate[
            "scalar_comparisons"
        ][0]["site"]
        candidates.append(candidate)

        candidate = synthetic_gate_export()
        candidate["imports"].append("WriteFile")
        candidates.append(candidate)

        candidate = synthetic_gate_export()
        candidate["calls"][0]["site"] = candidate["scalar_comparisons"][0]["site"]
        candidates.append(candidate)

        candidate = synthetic_gate_export()
        candidate["raw_bytes"] = [1, 2, 3]
        candidates.append(candidate)

        candidate = synthetic_gate_export()
        candidate["key_material"] = "forbidden"
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                RecoveryPathError
            ):
                normalize_restore_gate_export(candidate)

    def test_export_call_targets_are_bounded_and_tied_to_roots(self):
        candidates = []

        candidate = synthetic_gate_export()
        candidate["calls"][0]["caller_root"] = "unknown"
        candidates.append(candidate)

        candidate = synthetic_gate_export()
        candidate["calls"][0]["target"] = 0x90000000
        candidates.append(candidate)

        candidate = synthetic_gate_export()
        candidate["calls"][0]["target_root"] = "status-decoder"
        candidates.append(candidate)

        candidate = synthetic_gate_export()
        candidate["unresolved_indirect_calls"] = -1
        candidates.append(candidate)

        candidate = synthetic_gate_export()
        candidate["unresolved_indirect_calls"] = 1
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                RecoveryPathError
            ):
                normalize_restore_gate_export(candidate)

    def test_export_rejects_reduced_scalar_or_call_trace_as_incomplete(self):
        candidate = synthetic_gate_export()
        candidate["scalar_comparisons"] = [
            item
            for item in candidate["scalar_comparisons"]
            if (item["semantic"], item["value"])
            in {
                ("firmware-write-command", 0x40),
                ("completion-command", 0x100),
                ("invalid-model-status", 0x140),
                ("invalid-model-status", 0x141),
                ("invalid-version-status", 0x142),
            }
        ]

        candidate_without_calls = synthetic_gate_export()
        candidate_without_calls["calls"] = []
        candidate_without_calls["unresolved_direct_calls"] = 0
        candidate_without_calls["unresolved_indirect_calls"] = 0

        candidate_with_drifted_site = synthetic_gate_export()
        candidate_with_drifted_site["calls"][0]["site"] += 1

        for reduced in (
            candidate,
            candidate_without_calls,
            candidate_with_drifted_site,
        ):
            with self.subTest(reduced=reduced), self.assertRaises(
                RecoveryPathError
            ):
                normalize_restore_gate_export(reduced)


class RecoveryGateExporterTests(unittest.TestCase):
    def test_build_refuses_analysis_enabled_headless_mode(self):
        exporter = _load_exporter()

        class Adapter:
            def program_name(self):
                return exporter.EXPECTED_PROGRAM

            def program_sha256(self):
                return exporter.EXPECTED_SHA256

            def program_headless_read_only(self):
                return True

            def program_noanalysis(self):
                return False

            def program_is_changed(self):
                return False

        with self.assertRaises(RuntimeError):
            exporter.build_raw_export(
                Adapter(), exporter.EXPECTED_PROGRAM, exporter.EXPECTED_SHA256
            )

    def test_unclassified_direct_call_is_preserved_as_unresolved(self):
        exporter = _load_exporter()

        class Address:
            def __init__(self, value):
                self.value = value

            def getOffset(self):
                return self.value

        class FlowType:
            def isCall(self):
                return True

            def isComputed(self):
                return False

        class Instruction:
            def getFlowType(self):
                return FlowType()

            def getAddress(self):
                return Address(0x406A80)

            def getFlows(self):
                return [Address(0x409000)]

        class Listing:
            def getInstructions(self, body, forward):
                return [Instruction()]

        class Manager:
            def getFunctionAt(self, address):
                return None

        class Monitor:
            def checkCanceled(self):
                pass

        adapter = exporter.GhidraProgramAdapter.__new__(
            exporter.GhidraProgramAdapter
        )
        adapter._listing = Listing()
        adapter._manager = Manager()
        adapter._monitor = Monitor()
        adapter._function = lambda address: type("Function", (), {"getBody": lambda self: object()})()
        adapter._address = lambda value: Address(value)

        self.assertEqual(
            adapter.call_relationships(
                0x406A70, exporter.ROOT_MAP, exporter.ALLOWED_IMPORTS
            ),
            [
                {
                    "site": 0x406A80,
                    "target": None,
                    "target_root": None,
                    "target_symbol": None,
                    "kind": "unresolved-direct",
                }
            ],
        )


class RecoveryPathSafetyTests(unittest.TestCase):
    def test_validator_and_exporter_have_no_device_execution_or_write_backend(self):
        paths = (
            REPOSITORY_ROOT / "pmca" / "analysis" / "recovery_path.py",
            REPOSITORY_ROOT / "tools" / "ghidra" / "export_a6400_restore_gates.py",
        )
        for path in paths:
            with self.subTest(path=path):
                tree = ast.parse(path.read_text(encoding="utf-8"))
                imports = set()
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        imports.update(
                            alias.name.split(".", 1)[0] for alias in node.names
                        )
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        imports.add(node.module.split(".", 1)[0])
                self.assertTrue(
                    imports.isdisjoint(
                        {
                            "subprocess",
                            "ctypes",
                            "usb",
                            "serial",
                            "socket",
                            "shutil",
                        }
                    )
                )


if __name__ == "__main__":
    unittest.main()
