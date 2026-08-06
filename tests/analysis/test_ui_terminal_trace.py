import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from pmca.analysis.ui_terminal_trace import (
    UiTerminalTraceError,
    normalize_ui_terminal_export,
    summarize_ui_terminal_export,
    validate_ui_terminal_report,
)


ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = ROOT / "analysis" / "a6400-ui-terminal-trace.json"
EXPORTER_PATH = ROOT / "tools" / "ghidra" / "export_a6400_ui_terminals.py"


def synthetic_raw(candidates=None):
    return {
        "schema_version": 1,
        "program": "viewUnified2.so",
        "sha256": "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2",
        "image_size": 11530552,
        "analysis_mode": {"read_only": True, "noanalysis": True},
        "source_graph_sha256": "d19fc94fd52583f3d321535fd8b6a01aa03f4efc0c4dadde52adce3a9d246f22",
        "resolution_methods": [
            "instruction-flow",
            "pcode-literal",
            "reference-target",
        ],
        "tracks": [
            {
                "id": "orientation-handler-terminal",
                "root": 0x1BB41C,
                "predecessor_edges": [
                    {
                        "caller": 0x1BB41C,
                        "site": 0x1BB74C,
                        "target": 0x1B9B44,
                        "kind": "direct",
                    }
                ],
                "terminal": {
                    "caller": 0x1B9B44,
                    "site": 0x1B9B6A,
                    "kind": "unresolved-indirect",
                },
                "candidates": copy.deepcopy((candidates or {}).get("orientation", [])),
            },
            {
                "id": "layout-attach-terminal",
                "root": 0x1BB2D2,
                "predecessor_edges": [],
                "terminal": {
                    "caller": 0x1BB2D2,
                    "site": 0x1BB30E,
                    "kind": "unresolved-indirect",
                },
                "candidates": copy.deepcopy((candidates or {}).get("layout", [])),
            },
        ],
        "truncated": False,
    }


class UiTerminalNormalizationTests(unittest.TestCase):
    def test_exact_two_tracks_normalize_without_promotion(self):
        normalized = normalize_ui_terminal_export(synthetic_raw())

        self.assertEqual(
            [item["id"] for item in normalized["tracks"]],
            ["orientation-handler-terminal", "layout-attach-terminal"],
        )
        self.assertEqual(
            [item["terminal"]["site"] for item in normalized["tracks"]],
            [0x1B9B6A, 0x1BB30E],
        )
        self.assertTrue(
            all(item["resolution"]["status"] == "UNRESOLVED" for item in normalized["tracks"])
        )
        self.assertFalse(normalized["claims"]["orientation_layout_selector_found"])
        self.assertFalse(normalized["behavior_support"]["orientation-layout-selection"])

    def test_unique_candidate_resolves_only_its_track_not_the_selector(self):
        candidate = {
            "kind": "function-pointer-table",
            "target": 0x24222C,
            "table": 0x8DED88,
            "slot": 12,
            "provenance": "reference-target",
        }
        normalized = normalize_ui_terminal_export(
            synthetic_raw({"layout": [candidate]})
        )

        self.assertEqual(normalized["tracks"][1]["resolution"]["status"], "RESOLVED")
        self.assertFalse(normalized["claims"]["orientation_layout_selector_found"])

    def test_ambiguous_candidates_remain_nonpromoting(self):
        first = {
            "kind": "vtable-slot",
            "target": 0x181F18,
            "table": 0x8DED88,
            "slot": 4,
            "provenance": "reference-target",
        }
        second = {**first, "target": 0x24222C}
        normalized = normalize_ui_terminal_export(
            synthetic_raw({"orientation": [first, second]})
        )

        self.assertEqual(normalized["tracks"][0]["resolution"]["status"], "AMBIGUOUS")
        self.assertFalse(normalized["claims"]["orientation_layout_selector_found"])

    def test_identity_sites_provenance_and_forbidden_material_are_strict(self):
        candidates = []

        candidate = synthetic_raw()
        candidate["tracks"][0]["terminal"]["site"] += 2
        candidates.append(candidate)

        candidate = synthetic_raw()
        candidate["tracks"].reverse()
        candidates.append(candidate)

        candidate = synthetic_raw(
            {
                "orientation": [
                    {
                        "kind": "vtable-slot",
                        "target": 0x181F18,
                        "table": 0x8DED88,
                        "slot": 4,
                        "provenance": "guess",
                    }
                ]
            }
        )
        candidates.append(candidate)

        candidate = synthetic_raw()
        candidate["raw_bytes"] = [1, 2, 3]
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                UiTerminalTraceError
            ):
                normalize_ui_terminal_export(candidate)

    def test_summary_is_digest_pinned_and_retains_false_claims(self):
        summary = summarize_ui_terminal_export(synthetic_raw())

        self.assertRegex(summary["canonical_export_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(summary["resolved_track_count"], 0)
        self.assertEqual(summary["ambiguous_track_count"], 0)
        self.assertEqual(summary["unresolved_track_count"], 2)
        self.assertFalse(summary["claims"]["orientation_layout_selector_found"])


class UiTerminalReportTests(unittest.TestCase):
    def test_committed_report_is_fail_closed_and_dynamically_validated(self):
        document = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        validated = validate_ui_terminal_report(document)

        self.assertEqual(validated["readiness"], "UNRESOLVED")
        self.assertEqual(
            validated["export_summary"]["canonical_export_sha256"],
            "caf4f85e3edc4f558915fcbe5e6926f901c64c75a5a24c83b742449d94d8a16c",
        )
        self.assertFalse(validated["claims"]["orientation_layout_selector_found"])
        self.assertFalse(
            validated["behavior_support"]["orientation-layout-selection"]
        )
        self.assertFalse(validated["installable"])
        self.assertFalse(validated["camera_test_eligible"])

    def test_report_claims_cannot_be_promoted_without_complete_path(self):
        document = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        for section, field in (
            ("claims", "orientation_layout_selector_found"),
            ("behavior_support", "orientation-layout-selection"),
        ):
            candidate = copy.deepcopy(document)
            candidate[section][field] = True
            with self.subTest(section=section), self.assertRaises(
                UiTerminalTraceError
            ):
                validate_ui_terminal_report(candidate)

    def test_report_rejects_forged_digest_or_resolved_metadata(self):
        document = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        forged_digest = copy.deepcopy(document)
        forged_digest["export_summary"]["canonical_export_sha256"] = "0" * 64

        forged_resolution = copy.deepcopy(document)
        forged_resolution["export_summary"].update(
            {
                "resolved_track_count": 1,
                "ambiguous_track_count": 0,
                "unresolved_track_count": 1,
            }
        )
        forged_resolution["tracks"][0]["resolution"] = {
            "status": "RESOLVED",
            "candidate_count": 1,
            "kind": "not-a-kind",
            "target": "not-an-address",
            "table": -1,
            "slot": "any",
            "provenance": "forged",
        }

        for candidate in (forged_digest, forged_resolution):
            with self.subTest(candidate=candidate), self.assertRaises(
                UiTerminalTraceError
            ):
                validate_ui_terminal_report(candidate)


class UiTerminalExporterTests(unittest.TestCase):
    @staticmethod
    def _load_exporter():
        spec = importlib.util.spec_from_file_location("ui_terminal_exporter", EXPORTER_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_exporter_requests_only_the_two_pinned_terminals(self):
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

            def candidate_targets(self, caller, site):
                self.requested = getattr(self, "requested", []) + [(caller, site)]
                return []

        adapter = Adapter()
        raw = exporter.build_raw_export(adapter)

        self.assertEqual(
            adapter.requested,
            [(0x1B9B44, 0x1B9B6A), (0x1BB2D2, 0x1BB30E)],
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

            def candidate_targets(self, caller, site):
                return []

        for adapter in (Adapter(read_only=False), Adapter(noanalysis=False)):
            with self.subTest(adapter=adapter), self.assertRaises(RuntimeError):
                exporter.build_raw_export(adapter)

        dirty = Adapter()
        dirty.program_is_changed = lambda: True
        with self.assertRaises(RuntimeError):
            exporter.build_raw_export(dirty)

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


if __name__ == "__main__":
    unittest.main()
