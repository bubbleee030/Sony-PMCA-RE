import ast
import copy
import importlib.util
import json
import unittest
from pathlib import Path

from pmca.analysis.updater_control_bootstrap import (
    UpdaterControlBootstrapError,
    normalize_sauu_control_export,
    summarize_sauu_control_export,
    validate_updater_control_bootstrap,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = REPOSITORY_ROOT / "analysis" / "a6400a-updater-control-bootstrap.json"
MODULE_PATH = REPOSITORY_ROOT / "pmca" / "analysis" / "updater_control_bootstrap.py"
EXPORTER_PATH = REPOSITORY_ROOT / "tools" / "ghidra" / "export_a6400a_sauu_control.py"


def _load_exporter():
    spec = importlib.util.spec_from_file_location("a6400a_sauu_exporter", EXPORTER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def synthetic_sauu_export():
    roots = []
    for root_id, address in (
            ("guard-dispatch", 0xDF5C),
            ("model-compare", 0xDEA2),
            ("region-compare", 0xDE84),
            ("version-compare", 0xDEC0),
            ("verification-key-hash", 0x10368),
            ("signature-verifier", 0x104E0),
            ("signature-workflow-caller", 0x10A88),
        ):
        instruction_only = root_id == "signature-workflow-caller"
        roots.append(
            {
                "id": root_id,
                "source_address": address,
                "resolution": "instruction-only" if instruction_only else "function",
                "function_address": None if instruction_only else address,
            }
        )
    return {
        "schema_version": 1,
        "program": "sauu",
        "sha256": "d79af0e6958e47c9b50622b1bedb4afe86b7384e3513ffd62ce09f9e2c18a322",
        "file_size": 84428,
        "analysis_mode": {"read_only": True, "noanalysis": True},
        "roots": roots,
        "functions": sorted(
            [
                {"address": item["function_address"], "depth": 0}
                for item in roots
                if item["function_address"] is not None
            ],
            key=lambda item: item["address"],
        ),
        "calls": [
            {
                "caller": 0xDF5C,
                "site": 0xDF60,
                "target": 0xDEA2,
                "kind": "direct",
            },
            {
                "caller": 0x104E0,
                "site": 0x104F0,
                "target": None,
                "kind": "unresolved-indirect",
            },
        ],
        "unresolved_direct_calls": 0,
        "unresolved_indirect_calls": 1,
        "max_depth": 0,
        "truncated": False,
    }


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

    def test_committed_export_summary_pins_bounded_nontransferable_graph(self):
        graph = validate_updater_control_bootstrap(self.document)
        summary = graph["sauu_control_export"]

        self.assertEqual(summary["canonical_export_sha256"],
            "0e80cb19f9d4f227f04503e6d3f6ace4f1b0c7fe6194e2a3c7ede89a8ed9ad38")
        self.assertEqual(summary["function_count"], 37)
        self.assertEqual(summary["call_count"], 71)
        self.assertEqual(summary["unresolved_direct_calls"], 0)
        self.assertEqual(summary["unresolved_indirect_calls"], 3)
        self.assertEqual(summary["max_depth"], 2)
        self.assertFalse(summary["truncated"])
        self.assertFalse(summary["write_orchestrator_identified"])
        self.assertFalse(summary["completion_verification_identified"])
        self.assertFalse(summary["target_transferable"])
        self.assertEqual(summary["root_resolutions"][-1]["resolution"],
            "instruction-only")
        self.assertIsNone(summary["root_resolutions"][-1]["function_address"])

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


class SauuControlExportTests(unittest.TestCase):
    def test_synthetic_export_is_bounded_and_canonical(self):
        raw = synthetic_sauu_export()

        normalized = normalize_sauu_control_export(raw)
        summary = summarize_sauu_control_export(raw)

        self.assertEqual(normalized, raw)
        self.assertEqual(len(normalized["roots"]), 7)
        self.assertEqual(normalized["roots"][-1]["resolution"], "instruction-only")
        self.assertIsNone(normalized["roots"][-1]["function_address"])
        self.assertEqual(summary["function_count"], 6)
        self.assertEqual(summary["call_count"], 2)
        self.assertEqual(summary["root_resolutions"], normalized["roots"])
        self.assertFalse(summary["write_orchestrator_identified"])
        self.assertFalse(summary["completion_verification_identified"])
        self.assertFalse(summary["target_transferable"])
        self.assertEqual(
            {item["kind"] for item in normalized["calls"]},
            {"direct", "unresolved-indirect"},
        )

    def test_export_rejects_promotion_truncation_and_inconsistent_calls(self):
        mutations = []
        candidate = synthetic_sauu_export()
        candidate["analysis_mode"]["read_only"] = False
        mutations.append(candidate)
        candidate = synthetic_sauu_export()
        candidate["truncated"] = True
        mutations.append(candidate)
        candidate = synthetic_sauu_export()
        candidate["calls"][1]["target"] = 0x104E0
        mutations.append(candidate)
        candidate = synthetic_sauu_export()
        candidate["unresolved_indirect_calls"] = 0
        mutations.append(candidate)
        candidate = synthetic_sauu_export()
        candidate["functions"].append({"address": 0x11000, "depth": 0})
        mutations.append(candidate)
        candidate = synthetic_sauu_export()
        model = next(
            item for item in candidate["functions"] if item["address"] == 0xDEA2
        )
        model["depth"] = 1
        candidate["max_depth"] = 1
        mutations.append(candidate)

        for candidate in mutations:
            with self.subTest(candidate=candidate), self.assertRaises(
                UpdaterControlBootstrapError
            ):
                normalize_sauu_control_export(candidate)

    def test_exporter_preserves_unresolved_calls_and_refuses_analysis(self):
        exporter = _load_exporter()

        class Adapter:
            def program_name(self):
                return exporter.EXPECTED_PROGRAM

            def program_sha256(self):
                return exporter.EXPECTED_SHA256

            def program_headless_read_only(self):
                return True

            def program_noanalysis(self):
                return True

            def program_is_changed(self):
                return False

            def discover_function(self, address):
                return None if address == 0x10A88 else address

            def probe_address(self, address):
                return {
                    "instruction_address": address,
                    "function_before": 0x10998,
                    "function_after": 0x10D08,
                }

            def iter_calls(self, address):
                if address == 0xDF5C:
                    return [
                        {
                            "caller": address,
                            "site": 0xDF60,
                            "target": None,
                            "kind": "unresolved-direct",
                        },
                        {
                            "caller": address,
                            "site": 0xDF64,
                            "target": None,
                            "kind": "unresolved-indirect",
                        },
                    ]
                return []

        document = exporter.build_raw_export(
            Adapter(), exporter.EXPECTED_PROGRAM, exporter.EXPECTED_SHA256
        )
        self.assertEqual(document["unresolved_direct_calls"], 1)
        self.assertEqual(document["unresolved_indirect_calls"], 1)

        class AnalysisEnabledAdapter(Adapter):
            def program_noanalysis(self):
                return False

        with self.assertRaises(RuntimeError):
            exporter.build_raw_export(
                AnalysisEnabledAdapter(),
                exporter.EXPECTED_PROGRAM,
                exporter.EXPECTED_SHA256,
            )

        class UnbracketedAdapter(Adapter):
            def probe_address(self, address):
                return {
                    "instruction_address": address,
                    "function_before": 0x10D08,
                    "function_after": 0x10998,
                }

        with self.assertRaises(RuntimeError):
            exporter.build_raw_export(
                UnbracketedAdapter(),
                exporter.EXPECTED_PROGRAM,
                exporter.EXPECTED_SHA256,
            )

    def test_ghidra_adapter_rejects_ambiguous_direct_flow_destinations(self):
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
                return Address(0xDF60)

            def getFlows(self):
                return [Address(0xDEA2), Address(0xDEC0)]

        class Function:
            def isExternal(self):
                return False

            def getBody(self):
                return object()

            def getEntryPoint(self):
                return Address(0xDF5C)

        class Listing:
            def getInstructions(self, body, forward):
                return [Instruction()]

        class Manager:
            def getFunctionAt(self, address):
                return Function()

        class Monitor:
            def checkCanceled(self):
                pass

        adapter = exporter.GhidraProgramAdapter.__new__(
            exporter.GhidraProgramAdapter
        )
        adapter._listing = Listing()
        adapter._manager = Manager()
        adapter._monitor = Monitor()
        adapter._instruction_count = 0
        adapter._function = lambda address: Function()
        adapter._address = lambda value: Address(value)

        with self.assertRaises(RuntimeError):
            adapter.iter_calls(0xDF5C)

    def test_exporter_and_validator_have_no_execution_or_device_backend(self):
        for path in (MODULE_PATH, EXPORTER_PATH):
            with self.subTest(path=path):
                tree = ast.parse(path.read_text(encoding="utf-8"))
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
                            "shutil",
                        }
                    )
                )



if __name__ == "__main__":
    unittest.main()
