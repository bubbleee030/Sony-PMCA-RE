import copy
import json
import unittest
from pathlib import Path

from pmca.analysis.ui_dispatch import (
    VIEW_UNIFIED2_SHA256,
    UiDispatchError,
    validate_ui_dispatch_report,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = REPOSITORY_ROOT / "analysis" / "a6400-ui-dispatch-boundary.json"


def _edge(
    *,
    edge_id="edge-001",
    caller="0x22355e",
    site="0x2237a2",
    callee="0x230000",
    kind="vtable-slot",
    owner="ViewSettingMenu",
    slot=12,
    table="0x8ded88",
):
    return {
        "id": edge_id,
        "caller": caller,
        "site": site,
        "callee": callee,
        "kind": kind,
        "owner": owner,
        "slot": slot,
        "table": table,
    }


def _report(*, edges=None, paths=None, claims=None, uxc_references=None):
    return {
        "schema_version": 1,
        "analysis_scope": "offline-static-target-filesystem",
        "module": {
            "name": "lib/viewUnified2.so",
            "size": 11530552,
            "sha256": VIEW_UNIFIED2_SHA256,
        },
        "roots": [
            {"name": "ViewSettingMenu", "offset": "0x22355e"},
            {"name": "ViewStlrec", "offset": "0x1ab41c"},
        ],
        "edges": [] if edges is None else edges,
        "paths": [] if paths is None else paths,
        "uxc_references": [] if uxc_references is None else uxc_references,
        "negative_searches": [],
        "claims": claims
        or {
            "coordinate_consumer_found": False,
            "menu_selection_dispatch_found": False,
            "orientation_layout_selector_found": False,
        },
    }


class UiDispatchTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(REPORT_PATH.read_text(encoding="utf-8"))

    def test_committed_report_preserves_existing_boundaries_without_promotion(self):
        validated = validate_ui_dispatch_report(self.document)

        self.assertEqual(validated, self.document)
        self.assertEqual(validated["module"]["sha256"], VIEW_UNIFIED2_SHA256)
        self.assertEqual(
            [item["semantic"] for item in validated["paths"]],
            [
                "status-read-not-coordinate-dispatch",
                "configuration-not-menu-selection",
            ],
        )
        self.assertEqual(len(validated["negative_searches"]), 6)
        self.assertEqual(
            validated["claims"],
            {
                "coordinate_consumer_found": False,
                "menu_selection_dispatch_found": False,
                "orientation_layout_selector_found": False,
            },
        )

    def test_unresolved_indirect_edge_does_not_establish_selection(self):
        report = _report(
            edges=[
                _edge(
                    callee=None,
                    kind="unresolved-indirect",
                    slot=None,
                    table=None,
                )
            ]
        )

        validated = validate_ui_dispatch_report(report)

        self.assertFalse(validated["claims"]["menu_selection_dispatch_found"])

    def test_resolved_executable_path_can_support_matching_claim(self):
        report = _report(
            edges=[_edge()],
            paths=[
                {
                    "id": "path-menu-selection",
                    "root": "ViewSettingMenu",
                    "offsets": ["0x22355e", "0x230000"],
                    "edge_ids": ["edge-001"],
                    "semantic": "menu-selection-dispatch",
                    "resolved": True,
                }
            ],
            claims={
                "coordinate_consumer_found": False,
                "menu_selection_dispatch_found": True,
                "orientation_layout_selector_found": False,
            },
        )

        validated = validate_ui_dispatch_report(report)

        self.assertTrue(validated["claims"]["menu_selection_dispatch_found"])

    def test_positive_claim_requires_matching_resolved_path(self):
        report = _report(
            claims={
                "coordinate_consumer_found": False,
                "menu_selection_dispatch_found": True,
                "orientation_layout_selector_found": False,
            }
        )

        with self.assertRaises(UiDispatchError):
            validate_ui_dispatch_report(report)

    def test_uxc_reference_only_cannot_support_executable_claim(self):
        report = _report(
            edges=[
                _edge(
                    callee=None,
                    kind="uxc-reference-only",
                    slot=None,
                    table=None,
                )
            ],
            paths=[
                {
                    "id": "path-orientation-reference",
                    "root": "ViewStlrec",
                    "offsets": ["0x1ab41c"],
                    "edge_ids": ["edge-001"],
                    "semantic": "orientation-layout-selection",
                    "resolved": True,
                }
            ],
            claims={
                "coordinate_consumer_found": False,
                "menu_selection_dispatch_found": False,
                "orientation_layout_selector_found": True,
            },
        )

        with self.assertRaises(UiDispatchError):
            validate_ui_dispatch_report(report)

    def test_report_rejects_bad_digest_addresses_edge_kinds_and_duplicates(self):
        candidates = []

        candidate = _report()
        candidate["module"]["sha256"] = "00" * 32
        candidates.append(candidate)

        candidate = _report(edges=[_edge(site="0x2237a3")])
        candidates.append(candidate)

        candidate = _report(edges=[_edge(kind="guessed-virtual")])
        candidates.append(candidate)

        candidate = _report(edges=[_edge(), _edge(edge_id="edge-002")])
        candidates.append(candidate)

        candidate = _report(
            edges=[_edge()],
            paths=[
                {
                    "id": "path-missing-edge",
                    "root": "ViewSettingMenu",
                    "offsets": ["0x22355e"],
                    "edge_ids": ["edge-999"],
                    "semantic": "unresolved",
                    "resolved": False,
                }
            ],
        )
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(UiDispatchError):
                validate_ui_dispatch_report(candidate)

    def test_report_rejects_unknown_or_reconstructive_fields_recursively(self):
        for key in (
            "unexpected",
            "raw",
            "bytes",
            "payload",
            "disassembly",
            "private_key",
            "hex_dump",
        ):
            candidate = copy.deepcopy(self.document)
            candidate["paths"][0][key] = "forbidden"
            with self.subTest(key=key), self.assertRaises(UiDispatchError):
                validate_ui_dispatch_report(candidate)

    def test_validated_report_is_a_deep_copy(self):
        validated = validate_ui_dispatch_report(self.document)

        validated["claims"]["coordinate_consumer_found"] = True

        self.assertFalse(self.document["claims"]["coordinate_consumer_found"])


if __name__ == "__main__":
    unittest.main()
