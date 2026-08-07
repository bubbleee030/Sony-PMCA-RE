import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pmca.analysis.ui_terminal_trace import (
    UiTerminalTraceError,
    build_ui_terminal_report,
    normalize_ui_terminal_export,
    summarize_ui_terminal_export,
    validate_ui_terminal_report,
)


ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = ROOT / "analysis" / "a6400-ui-terminal-trace.json"
EXPORTER_PATH = ROOT / "tools" / "ghidra" / "export_a6400_ui_terminals.py"


EXPOSURE_GETTER_SYMBOL = (
    "_ZN33CmnViewModelWrpCameraExposureMode21getExposureModeActValEv"
)


def synthetic_raw():
    return {
        "schema_version": 1,
        "program": "viewUnified2.so",
        "sha256": "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2",
        "image_size": 11530552,
        "analysis_mode": {"read_only": True, "noanalysis": True},
        "source_graph_sha256": "d19fc94fd52583f3d321535fd8b6a01aa03f4efc0c4dadde52adce3a9d246f22",
        "classification_methods": [
            "instruction-flow",
            "reference-target",
            "symbol-identity",
        ],
        "tracks": [
            {
                "id": "orientation-handler-local-branch-landing",
                "traversal_entry": 0x1BB41C,
                "predecessor_edges": [
                    {
                        "caller": 0x1BB41C,
                        "site": 0x1BB74C,
                        "target": 0x1B9B44,
                        "kind": "direct",
                    }
                ],
                "site": {
                    "owner": {"start": 0x1B97E4, "end": 0x1B9C1C},
                    "offset": 0x1B9B6A,
                    "classification": "local-branch-landing",
                    "flow_target": None,
                    "symbol": None,
                },
            },
            {
                "id": "layout-attach-exposure-mode-getter",
                "traversal_entry": 0x1BB2D2,
                "predecessor_edges": [],
                "site": {
                    "owner": {"start": 0x1BB2C6, "end": 0x1BB3F8},
                    "offset": 0x1BB30E,
                    "classification": "exposure-mode-getter-plt-call",
                    "flow_target": 0x14E688,
                    "symbol": EXPOSURE_GETTER_SYMBOL,
                },
            },
        ],
        "truncated": False,
    }


class UiTerminalNormalizationTests(unittest.TestCase):
    def test_exact_two_sites_normalize_as_non_factory_handoffs(self):
        normalized = normalize_ui_terminal_export(synthetic_raw())

        self.assertEqual(
            [item["id"] for item in normalized["tracks"]],
            [
                "orientation-handler-local-branch-landing",
                "layout-attach-exposure-mode-getter",
            ],
        )
        self.assertEqual(
            [item["site"]["classification"] for item in normalized["tracks"]],
            ["local-branch-landing", "exposure-mode-getter-plt-call"],
        )
        self.assertEqual(normalized["tracks"][1]["site"]["flow_target"], 0x14E688)
        self.assertEqual(normalized["tracks"][1]["site"]["symbol"], EXPOSURE_GETTER_SYMBOL)
        self.assertFalse(normalized["claims"]["view_unified2_to_view_unified7_factory_edge_found"])
        self.assertFalse(normalized["claims"]["orientation_layout_selector_found"])
        self.assertTrue(all(value is False for value in normalized["behavior_support"].values()))

    def test_identity_sites_provenance_and_forbidden_material_are_strict(self):
        candidates = []

        candidate = synthetic_raw()
        candidate["tracks"][0]["site"]["classification"] = "unresolved-indirect"
        candidates.append(candidate)

        candidate = synthetic_raw()
        candidate["tracks"][1]["site"]["flow_target"] = 0x14E68A
        candidates.append(candidate)

        candidate = synthetic_raw()
        candidate["tracks"][1]["site"]["symbol"] = "wrong"
        candidates.append(candidate)

        candidate = synthetic_raw()
        candidate["tracks"][0]["site"]["owner"]["start"] = 0x1B9B44
        candidates.append(candidate)

        candidate = synthetic_raw()
        candidate["tracks"].reverse()
        candidates.append(candidate)

        candidate = synthetic_raw()
        candidate["raw_bytes"] = [1, 2, 3]
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                UiTerminalTraceError
            ):
                normalize_ui_terminal_export(candidate)

    def test_summary_counts_classified_non_handoff_sites(self):
        summary = summarize_ui_terminal_export(synthetic_raw())

        self.assertRegex(summary["canonical_export_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(summary["local_branch_landing_count"], 1)
        self.assertEqual(summary["exposure_mode_getter_plt_call_count"], 1)
        self.assertFalse(summary["claims"]["view_unified2_to_view_unified7_factory_edge_found"])
        self.assertFalse(summary["claims"]["orientation_layout_selector_found"])


class UiTerminalReportTests(unittest.TestCase):
    def test_builder_renders_a_fail_closed_report_from_the_pinned_sites(self):
        report = build_ui_terminal_report(synthetic_raw())

        self.assertEqual(report["readiness"], "CLASSIFIED_NO_FACTORY_HANDOFF")
        self.assertEqual(
            [item["site"]["classification"] for item in report["tracks"]],
            ["local-branch-landing", "exposure-mode-getter-plt-call"],
        )
        self.assertFalse(report["claims"]["view_unified2_to_view_unified7_factory_edge_found"])
        self.assertTrue(all(value is False for value in report["behavior_support"].values()))
        self.assertEqual(
            report,
            json.loads(REPORT_PATH.read_text(encoding="utf-8")),
        )

    def test_committed_report_is_fail_closed_and_dynamically_validated(self):
        document = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        validated = validate_ui_terminal_report(document)

        self.assertEqual(validated["readiness"], "CLASSIFIED_NO_FACTORY_HANDOFF")
        self.assertEqual(
            validated["export_summary"]["canonical_export_sha256"],
            "a41f4fdf6490ab9df14c60e1b1c319affd67c0390253163b04293aa6f9dcec9f",
        )
        self.assertEqual(
            {
                item["site"]["offset"]: item["site"]["classification"]
                for item in validated["tracks"]
            },
            {
                "0x1b9b6a": "local-branch-landing",
                "0x1bb30e": "exposure-mode-getter-plt-call",
            },
        )
        self.assertEqual(validated["tracks"][1]["site"]["flow_target"], "0x14e688")
        self.assertEqual(validated["tracks"][1]["site"]["symbol"], EXPOSURE_GETTER_SYMBOL)
        self.assertEqual(
            validated["tracks"][0]["site"]["owner"],
            {"start": "0x1b97e4", "end": "0x1b9c1c"},
        )
        self.assertEqual(
            validated["tracks"][1]["site"]["owner"],
            {"start": "0x1bb2c6", "end": "0x1bb3f8"},
        )
        self.assertEqual(validated["tracks"][1]["traversal_entry"], "0x1bb2d2")
        self.assertNotIn("root", validated["tracks"][1])
        self.assertFalse(validated["claims"]["view_unified2_to_view_unified7_factory_edge_found"])
        self.assertFalse(validated["claims"]["orientation_layout_selector_found"])
        self.assertTrue(all(value is False for value in validated["behavior_support"].values()))
        self.assertFalse(validated["installable"])
        self.assertFalse(validated["camera_test_eligible"])

    def test_report_claims_cannot_be_promoted_without_complete_path(self):
        document = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        for section, field in (
            ("claims", "view_unified2_to_view_unified7_factory_edge_found"),
            ("claims", "orientation_layout_selector_found"),
            ("behavior_support", "orientation-layout-selection"),
            ("behavior_support", "touch-coordinate-transform"),
        ):
            candidate = copy.deepcopy(document)
            candidate[section][field] = True
            with self.subTest(section=section), self.assertRaises(
                UiTerminalTraceError
            ):
                validate_ui_terminal_report(candidate)

    def test_report_rejects_forged_digest_or_factory_handoff_metadata(self):
        document = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        forged_digest = copy.deepcopy(document)
        forged_digest["export_summary"]["canonical_export_sha256"] = "0" * 64

        forged_handoff = copy.deepcopy(document)
        forged_handoff["tracks"][0]["site"]["classification"] = "unresolved-indirect"

        for candidate in (forged_digest, forged_handoff):
            with self.subTest(candidate=candidate), self.assertRaises(
                UiTerminalTraceError
            ):
                validate_ui_terminal_report(candidate)

    def test_report_joins_traversal_entries_to_ui_dispatch_dependency(self):
        document = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        dependency = json.loads(
            (ROOT / "analysis" / "a6400-ui-dispatch-boundary.json").read_text(
                encoding="utf-8"
            )
        )
        dependency["roots"][1]["traversal_entry_address"] = "0x1bb420"

        with patch(
            "pmca.analysis.ui_terminal_trace._load_ui_boundary",
            return_value=dependency,
        ), self.assertRaisesRegex(
            UiTerminalTraceError, "differs from the dispatch dependency"
        ):
            validate_ui_terminal_report(document)


class UiTerminalExporterTests(unittest.TestCase):
    @staticmethod
    def _load_exporter():
        spec = importlib.util.spec_from_file_location("ui_terminal_exporter", EXPORTER_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_exporter_verifies_only_the_two_pinned_non_handoff_sites(self):
        exporter = self._load_exporter()

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

            def verify_owner_range(self, start, end):
                self.owner_ranges = getattr(self, "owner_ranges", []) + [(start, end)]
                return True

            def verify_traversal_entry(self, entry):
                self.traversal_entries = getattr(self, "traversal_entries", []) + [
                    entry
                ]
                return True

            def verify_predecessor_edge(self, caller, site, target, kind):
                self.predecessors = getattr(self, "predecessors", []) + [
                    (caller, site, target, kind)
                ]
                return True

            def verify_site(
                self,
                owner_start,
                owner_end,
                offset,
                classification,
                flow_target,
                symbol,
            ):
                self.requested = getattr(self, "requested", []) + [
                    (
                        owner_start,
                        owner_end,
                        offset,
                        classification,
                        flow_target,
                        symbol,
                    )
                ]
                return True

        adapter = Adapter()
        raw = exporter.build_raw_export(adapter)

        self.assertEqual(
            adapter.owner_ranges,
            [(0x1B97E4, 0x1B9C1C), (0x1BB2C6, 0x1BB3F8)],
        )
        self.assertEqual(adapter.traversal_entries, [0x1BB41C, 0x1BB2D2])
        self.assertEqual(
            adapter.predecessors,
            [(0x1BB41C, 0x1BB74C, 0x1B9B44, "direct")],
        )
        self.assertEqual(
            adapter.requested,
            [
                (
                    0x1B97E4,
                    0x1B9C1C,
                    0x1B9B6A,
                    "local-branch-landing",
                    None,
                    None,
                ),
                (
                    0x1BB2C6,
                    0x1BB3F8,
                    0x1BB30E,
                    "exposure-mode-getter-plt-call",
                    0x14E688,
                    EXPOSURE_GETTER_SYMBOL,
                ),
            ],
        )
        self.assertFalse(raw["truncated"])

    def test_exporter_refuses_writable_or_analyzed_projects(self):
        exporter = self._load_exporter()

        class Adapter:
            def __init__(self, read_only=True, noanalysis=True):
                self.read_only = read_only
                self.noanalysis = noanalysis

            def program_name(self):
                return exporter.EXPECTED_PROGRAM

            def program_sha256(self):
                return exporter.EXPECTED_SHA256

            def program_headless_read_only(self):
                return self.read_only

            def program_noanalysis(self):
                return self.noanalysis

            def program_is_changed(self):
                return False

            def verify_owner_range(self, start, end):
                return True

            def verify_traversal_entry(self, entry):
                return True

            def verify_predecessor_edge(self, caller, site, target, kind):
                return True

            def verify_site(
                self,
                owner_start,
                owner_end,
                offset,
                classification,
                flow_target,
                symbol,
            ):
                return True

        for adapter in (Adapter(read_only=False), Adapter(noanalysis=False)):
            with self.subTest(adapter=adapter), self.assertRaises(RuntimeError):
                exporter.build_raw_export(adapter)

        dirty = Adapter()
        dirty.program_is_changed = lambda: True
        with self.assertRaises(RuntimeError):
            exporter.build_raw_export(dirty)

    def test_exporter_rejects_unverified_owner_traversal_and_predecessor(self):
        exporter = self._load_exporter()

        class Adapter:
            def __init__(self, rejected):
                self.rejected = rejected

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

            def verify_owner_range(self, start, end):
                return self.rejected != "owner"

            def verify_traversal_entry(self, entry):
                return self.rejected != "traversal"

            def verify_predecessor_edge(self, caller, site, target, kind):
                return self.rejected != "predecessor"

            def verify_site(
                self,
                owner_start,
                owner_end,
                offset,
                classification,
                flow_target,
                symbol,
            ):
                return True

        for rejected in ("owner", "traversal", "predecessor"):
            with self.subTest(rejected=rejected), self.assertRaises(RuntimeError):
                exporter.build_raw_export(Adapter(rejected))

    def test_exporter_output_is_confined_to_approved_root(self):
        exporter = self._load_exporter()
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            approved = temporary / "approved"
            outside = temporary / "outside"
            approved.mkdir()
            outside.mkdir()

            with self.assertRaises(RuntimeError):
                exporter.write_json_atomic(
                    outside / "raw-ui-terminals.json", {}, approved
                )

    def test_ghidra_adapter_requires_exact_exposure_getter_target_and_symbol(self):
        exporter = self._load_exporter()

        class Address:
            def __init__(self, value):
                self.value = value

            def getOffset(self):
                return self.value

        class FlowType:
            def __init__(self, *, call=False, jump=False):
                self.call = call
                self.jump = jump

            def isCall(self):
                return self.call

            def isJump(self):
                return self.jump

        class Instruction:
            def __init__(self, target, *, call=True):
                self.target = target
                self.call = call

            def getFlowType(self):
                return FlowType(call=self.call)

            def getFlows(self):
                return (Address(self.target),)

        class Function:
            def getEntryPoint(self):
                return Address(0x1BB2D2)

            def isExternal(self):
                return False

        class Symbol:
            def __init__(self, name):
                self.name = name

            def getName(self):
                return self.name

        class AddressSpace:
            def getAddress(self, value):
                return Address(int(value, 16))

        class AddressFactory:
            def getDefaultAddressSpace(self):
                return AddressSpace()

        class Listing:
            def __init__(self, instruction):
                self.instruction = instruction

            def getInstructionAt(self, address):
                return self.instruction if address.value == 0x1BB30E else None

        class Manager:
            def getFunctionContaining(self, address):
                return Function() if address.value == 0x1BB30E else None

        class References:
            def getReferencesTo(self, address):
                return ()

        class Symbols:
            def __init__(self, name):
                self.name = name

            def getPrimarySymbol(self, address):
                return Symbol(self.name) if address.value == 0x14E688 else None

        class Monitor:
            def checkCanceled(self):
                return None

        class Program:
            def __init__(self, instruction, symbol):
                self.listing = Listing(instruction)
                self.symbols = Symbols(symbol)

            def getListing(self):
                return self.listing

            def getFunctionManager(self):
                return Manager()

            def getReferenceManager(self):
                return References()

            def getAddressFactory(self):
                return AddressFactory()

            def getSymbolTable(self):
                return self.symbols

        def verify(instruction, symbol):
            adapter = exporter.GhidraProgramAdapter(
                Program(instruction, symbol), Monitor()
            )
            return adapter.verify_site(
                0x1BB2C6,
                0x1BB3F8,
                0x1BB30E,
                "exposure-mode-getter-plt-call",
                0x14E688,
                EXPOSURE_GETTER_SYMBOL,
            )

        self.assertTrue(verify(Instruction(0x14E688), EXPOSURE_GETTER_SYMBOL))
        self.assertFalse(verify(Instruction(0x14E68A), EXPOSURE_GETTER_SYMBOL))
        self.assertFalse(verify(Instruction(0x14E688), "wrong"))
        self.assertFalse(
            verify(Instruction(0x14E688, call=False), EXPOSURE_GETTER_SYMBOL)
        )

    def test_ghidra_adapter_derives_exact_exidx_owner_ranges(self):
        exporter = self._load_exporter()
        exidx_start = 0x900000
        owner_starts = [0x1B97E4, 0x1B9C1C, 0x1BB2C6, 0x1BB3F8, 0x1BB400]

        class Address:
            def __init__(self, value):
                self.value = value

            def getOffset(self):
                return self.value

        class AddressSpace:
            def getAddress(self, value):
                return Address(int(value, 16))

        class AddressFactory:
            def getDefaultAddressSpace(self):
                return AddressSpace()

        class Block:
            def getStart(self):
                return Address(exidx_start)

            def getSize(self):
                return len(owner_starts) * 8

        class Memory:
            def getBlock(self, name):
                return Block() if name == ".ARM.exidx" else None

            def getInt(self, address):
                index = (address.value - exidx_start) // 8
                return (owner_starts[index] - address.value) & 0x7FFFFFFF

        class Program:
            def getListing(self):
                return None

            def getFunctionManager(self):
                return None

            def getReferenceManager(self):
                return None

            def getSymbolTable(self):
                return None

            def getAddressFactory(self):
                return AddressFactory()

            def getMemory(self):
                return Memory()

        class Monitor:
            def checkCanceled(self):
                return None

        adapter = exporter.GhidraProgramAdapter(Program(), Monitor())
        self.assertTrue(adapter.verify_owner_range(0x1B97E4, 0x1B9C1C))
        self.assertTrue(adapter.verify_owner_range(0x1BB2C6, 0x1BB3F8))
        self.assertFalse(adapter.verify_owner_range(0x1B97E4, 0x1B9C20))


if __name__ == "__main__":
    unittest.main()
