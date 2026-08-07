import copy
from collections import Counter
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from pmca.analysis.ui_dispatch import (
    VIEW_UNIFIED2_SHA256,
    VIEW_UNIFIED7_SHA256,
    UiDispatchError,
    build_ui_dispatch_report,
    normalize_ui_dispatch_export,
    validate_ui_dispatch_report,
)
from pmca.analysis.ui_factory_owner_registration import (
    REPORT_CANONICAL_EXPORT_SHA256 as OWNER_REGISTRATION_SHA256,
)
from pmca.analysis.vertical_layout_factory_trace import (
    CANONICAL_EXPORT_SHA256 as VERTICAL_FACTORY_SHA256,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = REPOSITORY_ROOT / "analysis" / "a6400-ui-dispatch-boundary.json"
EXPORTER_PATH = REPOSITORY_ROOT / "tools" / "ghidra" / "export_a6400_ui_dispatch.py"
REGENERATOR_PATH = (
    REPOSITORY_ROOT / "tools" / "static" / "regenerate_a6400_ui_evidence_reports.py"
)
BEHAVIOR_IDS = (
    "shooting-layout-landscape",
    "shooting-layout-portrait-shutter-up",
    "shooting-layout-portrait-shutter-down",
    "orientation-layout-selection",
    "control-direction-transform",
    "touch-coordinate-transform",
    "menu-touch-hit-test",
    "menu-touch-selection",
    "ui-state-persistence",
)
BOUNDED_EXPORT_SUMMARY = {
    "root_count": 4,
    "edge_count": 2046,
    "direct_edge_count": 1697,
    "unresolved_indirect_edge_count": 349,
    "truncated": False,
    "depth_cap": 32,
    "unresolved_indirect_terminal": True,
    "artifact_sha256": "d19fc94fd52583f3d321535fd8b6a01aa03f4efc0c4dadde52adce3a9d246f22",
}
INVALID_OFFSET_CLASSIFICATIONS = [
    {
        "module": "lib/viewUnified2.so",
        "offset": offset,
        "owner": {"start": owner_start, "end": owner_end},
        "instruction_boundary": instruction_boundary,
        "classification": classification,
        "callable_owner": False,
        "factory": False,
        "class_id_load": False,
    }
    for offset, owner_start, owner_end, instruction_boundary, classification in (
        ("0x181f18", "0x1729e8", "0x184ac4", True, "internal-selector-branch"),
        ("0x24222c", "0x23a8c0", "0x2a3680", False, "thumb2-second-halfword"),
        ("0x3ba6dc", "0x3b6940", "0x3bbed8", False, "thumb2-second-halfword"),
        ("0x651684", "0x64da44", "0x6549e4", False, "thumb2-second-halfword"),
        ("0x37b614", "0x37b60c", "0x37b630", True, "constructor-vptr-material"),
        ("0x37aa18", "0x37aa10", "0x37aa34", True, "constructor-vptr-material"),
        ("0x37b5e0", "0x37b5d8", "0x37b5fc", True, "constructor-vptr-material"),
        ("0x37b648", "0x37b640", "0x37b664", True, "constructor-vptr-material"),
        ("0x37b578", "0x37b570", "0x37b594", True, "constructor-vptr-material"),
    )
]
VERTICAL_FACTORY_REFERENCE = {
    "factory_report": "analysis/a6400-vertical-layout-factory.json",
    "factory_report_sha256": VERTICAL_FACTORY_SHA256,
    "owner_registration_report": "analysis/a6400-ui-factory-owner-registration.json",
    "owner_registration_report_sha256": OWNER_REGISTRATION_SHA256,
    "factory_owner": {"start": "0x52840", "end": "0x529b8"},
    "wrapper_owner": {"start": "0x529cc", "end": "0x529e8"},
    "resource_reference_count": 10,
    "total_constructor_arm_count": 12,
    "vertical_constructor_arm_count": 5,
    "wrapper_registration_count": 5,
    "runtime_factory_invocation_proven": False,
    "view_unified2_to_factory_edge_found": False,
    "orientation_to_factory_join_proven": False,
}


def _load_exporter():
    spec = importlib.util.spec_from_file_location("a6400_ui_dispatch_exporter", EXPORTER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _edge(
    *,
    edge_id="edge-001",
    caller_module="lib/viewUnified2.so",
    caller="0x22355e",
    site="0x2237a2",
    callee_module="lib/viewUnified2.so",
    callee="0x230000",
    kind="vtable-slot",
    owner="ViewSettingMenu",
    slot=12,
    table_module="lib/viewUnified2.so",
    table="0x8ded88",
):
    return {
        "id": edge_id,
        "caller_module": caller_module,
        "caller": caller,
        "site": site,
        "callee_module": callee_module,
        "callee": callee,
        "kind": kind,
        "owner": owner,
        "slot": slot,
        "table_module": table_module,
        "table": table,
    }


def _report(
    *,
    edges=None,
    paths=None,
    claims=None,
    behavior_support=None,
    uxc_references=None,
    negative_searches=None,
):
    return {
        "schema_version": 1,
        "analysis_scope": "offline-static-target-filesystem",
        "modules": [
            {
                "name": "lib/viewUnified2.so",
                "size": 11530552,
                "sha256": VIEW_UNIFIED2_SHA256,
            },
            {
                "name": "lib/viewUnified7.so",
                "size": 541024,
                "sha256": VIEW_UNIFIED7_SHA256,
            },
            {
                "name": "share/app/master_camera.uxc",
                "size": 101720,
                "sha256": "5a0370408dff25dab43ed677c3b8e6c9be3b8bb8630d7ea15273d4f996cca7ec",
            },
            {
                "name": "share/app/viewStlrec.uxc",
                "size": 32104,
                "sha256": "f5aaa2f70f9b262b515a529ee2d80bf21928f0898504643cc7f174efa405d4f5",
            },
        ],
        "roots": [
            {
                "name": "ViewSettingMenuEventSwitch",
                "role": "setting-menu-event-switch",
                "module": "lib/viewUnified2.so",
                "source_kind": "analysis-address",
                "source_offset": "0x22355e",
                "analysis_address": "0x22355e",
                "traversal_entry_address": "0x22355e",
            },
            {
                "name": "ViewStlrecOrientationRegistration",
                "role": "orientation-registration",
                "module": "lib/viewUnified2.so",
                "source_kind": "elf-file-offset",
                "source_offset": "0x1ab41c",
                "analysis_address": "0x1bb41c",
                "traversal_entry_address": "0x1bb41c",
            },
            {
                "name": "ViewStlrecLayoutModeAttach",
                "role": "layout-mode-attach",
                "module": "lib/viewUnified2.so",
                "source_kind": "elf-file-offset",
                "source_offset": "0x1ab2d2",
                "analysis_address": "0x1bb2d2",
                "traversal_entry_address": "0x1bb2d2",
            },
            {
                "name": "ViewStlrecAfOrientationDispatch",
                "role": "af-orientation-dispatch",
                "module": "lib/viewUnified2.so",
                "source_kind": "elf-file-offset",
                "source_offset": "0x1b1e76",
                "analysis_address": "0x1c1e76",
                "traversal_entry_address": "0x1c1e76",
            },
        ],
        "bounded_export_summary": copy.deepcopy(BOUNDED_EXPORT_SUMMARY),
        "invalid_offset_classifications": copy.deepcopy(INVALID_OFFSET_CLASSIFICATIONS),
        "vertical_factory_reference": copy.deepcopy(VERTICAL_FACTORY_REFERENCE),
        "edges": [] if edges is None else edges,
        "paths": [] if paths is None else paths,
        "uxc_references": [] if uxc_references is None else uxc_references,
        "negative_searches": [] if negative_searches is None else negative_searches,
        "claims": claims
        or {
            "coordinate_consumer_found": False,
            "menu_selection_dispatch_found": False,
            "orientation_layout_selector_found": False,
        },
        "behavior_support": behavior_support
        or {behavior_id: False for behavior_id in BEHAVIOR_IDS},
    }


class UiDispatchTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(REPORT_PATH.read_text(encoding="utf-8"))

    def test_committed_report_preserves_existing_boundaries_without_promotion(self):
        validated = validate_ui_dispatch_report(self.document)

        self.assertEqual(validated, self.document)
        for root in validated["roots"]:
            self.assertIn("traversal_entry_address", root)
            self.assertNotIn("function_address", root)
        self.assertEqual(
            validated["roots"][2]["traversal_entry_address"], "0x1bb2d2"
        )
        self.assertEqual(validated["modules"][0]["sha256"], VIEW_UNIFIED2_SHA256)
        self.assertEqual(
            [item["semantic"] for item in validated["paths"]],
            [
                "status-read-not-coordinate-dispatch",
                "configuration-not-menu-selection",
            ],
        )
        self.assertEqual(len(validated["negative_searches"]), 4)
        self.assertEqual(
            validated["claims"],
            {
                "coordinate_consumer_found": False,
                "menu_selection_dispatch_found": False,
                "orientation_layout_selector_found": False,
            },
        )
        self.assertEqual(
            validated["behavior_support"],
            {behavior_id: False for behavior_id in BEHAVIOR_IDS},
        )

    def test_committed_report_contains_exact_reference_only_uxc_findings(self):
        valid_searches = [
            copy.deepcopy(item)
            for item in self.document["negative_searches"]
            if item["target_name"] in {
                "root_resource_call_owner",
                "sample_view_resource_setup_owner",
            }
        ]
        candidate = _report(
            uxc_references=copy.deepcopy(self.document["uxc_references"]),
            negative_searches=valid_searches,
        )
        try:
            validated = validate_ui_dispatch_report(candidate)
        except UiDispatchError as error:
            self.fail(f"corrected UI metadata was rejected: {error}")

        self.assertEqual(validated["bounded_export_summary"], BOUNDED_EXPORT_SUMMARY)
        self.assertEqual(
            validated["invalid_offset_classifications"],
            INVALID_OFFSET_CLASSIFICATIONS,
        )
        self.assertEqual(validated["vertical_factory_reference"], VERTICAL_FACTORY_REFERENCE)
        self.assertEqual(len(validated["uxc_references"]), 10)
        self.assertEqual(
            Counter(
                (item["source"], item["kind"], item["semantic"])
                for item in validated["uxc_references"]
            ),
            Counter(
                {
                    (
                        "share/app/master_camera.uxc",
                        "class-id",
                        "reference-only",
                    ): 5,
                    (
                        "share/app/viewStlrec.uxc",
                        "class-id",
                        "reference-only",
                    ): 5,
                }
            ),
        )
        self.assertEqual(len(validated["negative_searches"]), 4)
        self.assertTrue(
            all(
                item["search_method"] == "static-mixed-call-graph"
                and item["edge_kinds"] == ["direct"]
                and item["terminal_edge_kinds"] == ["unresolved-indirect"]
                and item["depth_cap"] == 32
                and item["path_found"] is False
                for item in validated["negative_searches"][-2:]
            )
        )

    def test_builder_migrates_legacy_owner_claims_without_mutating_source(self):
        source = copy.deepcopy(self.document)
        source_before = copy.deepcopy(source)

        built = build_ui_dispatch_report(source)

        self.assertEqual(source, source_before)
        self.assertNotIn("uxc_owner_functions", built)
        self.assertEqual(
            built["invalid_offset_classifications"],
            INVALID_OFFSET_CLASSIFICATIONS,
        )
        self.assertEqual(built["vertical_factory_reference"], VERTICAL_FACTORY_REFERENCE)
        self.assertEqual(len(built["negative_searches"]), 4)
        self.assertEqual(
            {item["target_name"] for item in built["negative_searches"]},
            {"root_resource_call_owner", "sample_view_resource_setup_owner"},
        )
        self.assertEqual(validate_ui_dispatch_report(built), built)

    def test_invalid_offset_classification_fields_are_all_pinned(self):
        mutations = (
            ("module", "lib/viewUnified7.so"),
            ("offset", "0x181f1a"),
            ("instruction_boundary", False),
            ("classification", "thumb2-second-halfword"),
            ("callable_owner", True),
            ("factory", True),
            ("class_id_load", True),
        )
        for field, value in mutations:
            candidate = _report()
            candidate["invalid_offset_classifications"][0][field] = value
            with self.subTest(field=field), self.assertRaises(UiDispatchError):
                validate_ui_dispatch_report(candidate)

        for field, value in (("start", "0x1729ea"), ("end", "0x184ac2")):
            candidate = _report()
            candidate["invalid_offset_classifications"][0]["owner"][field] = value
            with self.subTest(owner_field=field), self.assertRaises(UiDispatchError):
                validate_ui_dispatch_report(candidate)

    def test_vertical_factory_reference_fields_are_all_pinned(self):
        mutations = (
            ("factory_report", "analysis/wrong.json"),
            ("factory_report_sha256", "0" * 64),
            ("owner_registration_report", "analysis/wrong.json"),
            ("owner_registration_report_sha256", "0" * 64),
            ("resource_reference_count", 9),
            ("total_constructor_arm_count", 11),
            ("vertical_constructor_arm_count", 4),
            ("wrapper_registration_count", 4),
            ("runtime_factory_invocation_proven", True),
            ("view_unified2_to_factory_edge_found", True),
            ("orientation_to_factory_join_proven", True),
        )
        for field, value in mutations:
            candidate = _report()
            candidate["vertical_factory_reference"][field] = value
            with self.subTest(field=field), self.assertRaises(UiDispatchError):
                validate_ui_dispatch_report(candidate)

        for owner_field in ("factory_owner", "wrapper_owner"):
            for range_field in ("start", "end"):
                candidate = _report()
                candidate["vertical_factory_reference"][owner_field][range_field] = "0x52842"
                with self.subTest(owner=owner_field, edge=range_field), self.assertRaises(
                    UiDispatchError
                ):
                    validate_ui_dispatch_report(candidate)

    def test_export_summary_invalid_offsets_and_factory_reference_are_pinned(self):
        bad_count = _report()
        bad_count["bounded_export_summary"]["direct_edge_count"] += 1

        bad_classification = _report()
        bad_classification["invalid_offset_classifications"][0]["factory"] = True

        bad_reference = _report()
        bad_reference["vertical_factory_reference"]["runtime_factory_invocation_proven"] = True

        for candidate in (bad_count, bad_classification, bad_reference):
            with self.subTest(candidate=candidate), self.assertRaises(UiDispatchError):
                validate_ui_dispatch_report(candidate)

    def test_unresolved_indirect_edge_does_not_establish_selection(self):
        report = _report(
            edges=[
                _edge(
                    callee=None,
                    callee_module=None,
                    kind="unresolved-indirect",
                    slot=None,
                    table_module=None,
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
                    "root": "ViewSettingMenuEventSwitch",
                    "offsets": [
                        {"module": "lib/viewUnified2.so", "offset": "0x22355e"},
                        {"module": "lib/viewUnified2.so", "offset": "0x230000"},
                    ],
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

    def test_positive_claim_rejects_disconnected_root_and_edge_chain(self):
        report = _report(
            edges=[
                _edge(
                    caller="0x1ab41c",
                    site="0x1ab420",
                    callee="0x230000",
                    owner="ViewStlrec",
                )
            ],
            paths=[
                {
                    "id": "path-disconnected-selection",
                    "root": "ViewSettingMenuEventSwitch",
                    "offsets": [
                        {"module": "lib/viewUnified2.so", "offset": "0x22355e"},
                        {"module": "lib/viewUnified2.so", "offset": "0x230000"},
                    ],
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

        with self.assertRaises(UiDispatchError):
            validate_ui_dispatch_report(report)

    def test_uxc_reference_only_cannot_support_executable_claim(self):
        report = _report(
            edges=[
                _edge(
                    callee=None,
                    callee_module=None,
                    kind="uxc-reference-only",
                    slot=None,
                    table_module=None,
                    table=None,
                )
            ],
            paths=[
                {
                    "id": "path-orientation-reference",
                    "root": "ViewStlrecOrientationRegistration",
                    "offsets": [
                        {"module": "lib/viewUnified2.so", "offset": "0x1ab41c"}
                    ],
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
        candidate["modules"][0]["sha256"] = "00" * 32
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
                    "root": "ViewSettingMenuEventSwitch",
                    "offsets": [
                        {"module": "lib/viewUnified2.so", "offset": "0x22355e"}
                    ],
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

    def test_negative_search_requires_nonzero_unique_bounded_scope(self):
        zero_scope = copy.deepcopy(self.document)
        zero_scope["negative_searches"][0]["requested_roots"] = 0
        zero_scope["negative_searches"][0]["resolved_roots"] = 0

        duplicate = copy.deepcopy(self.document)
        duplicate["negative_searches"].append(
            copy.deepcopy(duplicate["negative_searches"][0])
        )

        for candidate in (zero_scope, duplicate):
            with self.subTest(candidate=candidate), self.assertRaises(UiDispatchError):
                validate_ui_dispatch_report(candidate)

    def test_negative_search_separates_traversed_and_terminal_edges(self):
        mixed_traverses_terminal = copy.deepcopy(self.document)
        mixed_traverses_terminal["negative_searches"][-1]["edge_kinds"] = [
            "direct",
            "unresolved-indirect",
        ]

        mixed_omits_terminal = copy.deepcopy(self.document)
        mixed_omits_terminal["negative_searches"][-1]["terminal_edge_kinds"] = []

        direct_declares_terminal = copy.deepcopy(self.document)
        direct_declares_terminal["negative_searches"][0]["terminal_edge_kinds"] = [
            "unresolved-indirect"
        ]

        for candidate in (
            mixed_traverses_terminal,
            mixed_omits_terminal,
            direct_declares_terminal,
        ):
            with self.subTest(candidate=candidate), self.assertRaises(UiDispatchError):
                validate_ui_dispatch_report(candidate)

    def test_validated_report_is_a_deep_copy(self):
        validated = validate_ui_dispatch_report(self.document)

        validated["claims"]["coordinate_consumer_found"] = True

        self.assertFalse(self.document["claims"]["coordinate_consumer_found"])

    def test_cross_module_path_keeps_caller_and_callee_identity(self):
        report = _report(
            edges=[
                _edge(
                    callee_module="lib/viewUnified7.so",
                    callee="0x52840",
                    kind="direct",
                    slot=None,
                    table_module=None,
                    table=None,
                )
            ],
            paths=[
                {
                    "id": "path-cross-module-selection",
                    "root": "ViewSettingMenuEventSwitch",
                    "offsets": [
                        {"module": "lib/viewUnified2.so", "offset": "0x22355e"},
                        {"module": "lib/viewUnified7.so", "offset": "0x52840"},
                    ],
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

        self.assertEqual(
            validated["edges"][0]["callee_module"], "lib/viewUnified7.so"
        )

    def test_resolved_path_can_support_matching_modern_ui_behavior(self):
        support = {behavior_id: False for behavior_id in BEHAVIOR_IDS}
        support["menu-touch-selection"] = True
        report = _report(
            edges=[_edge()],
            paths=[
                {
                    "id": "path-menu-touch-selection",
                    "root": "ViewSettingMenuEventSwitch",
                    "offsets": [
                        {"module": "lib/viewUnified2.so", "offset": "0x22355e"},
                        {"module": "lib/viewUnified2.so", "offset": "0x230000"},
                    ],
                    "edge_ids": ["edge-001"],
                    "semantic": "menu-touch-selection",
                    "resolved": True,
                }
            ],
            behavior_support=support,
        )

        validated = validate_ui_dispatch_report(report)

        self.assertTrue(validated["behavior_support"]["menu-touch-selection"])

    def test_resolved_path_uses_discovered_function_root_not_interior_request(self):
        support = {behavior_id: False for behavior_id in BEHAVIOR_IDS}
        support["orientation-layout-selection"] = True
        report = _report(
            edges=[
                _edge(
                    caller="0x1bb000",
                    site="0x1bb420",
                    callee="0x230000",
                    owner="ViewStlrec",
                )
            ],
            paths=[
                {
                    "id": "path-orientation-selector",
                    "root": "ViewStlrecOrientationRegistration",
                    "offsets": [
                        {"module": "lib/viewUnified2.so", "offset": "0x1bb000"},
                        {"module": "lib/viewUnified2.so", "offset": "0x230000"},
                    ],
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
            behavior_support=support,
        )
        report["roots"][1]["traversal_entry_address"] = "0x1bb000"

        validated = validate_ui_dispatch_report(report)

        self.assertTrue(validated["claims"]["orientation_layout_selector_found"])

    def test_resolved_path_rejects_root_without_discovered_function(self):
        report = _report(
            edges=[
                _edge(
                    caller="0x1bb000",
                    site="0x1bb420",
                    callee="0x230000",
                    owner="ViewStlrec",
                )
            ],
            paths=[
                {
                    "id": "path-undiscovered-orientation-root",
                    "root": "ViewStlrecOrientationRegistration",
                    "offsets": [
                        {"module": "lib/viewUnified2.so", "offset": "0x1bb000"},
                        {"module": "lib/viewUnified2.so", "offset": "0x230000"},
                    ],
                    "edge_ids": ["edge-001"],
                    "semantic": "orientation-layout-selection",
                    "resolved": True,
                }
            ],
        )
        report["roots"][1]["traversal_entry_address"] = None

        with self.assertRaisesRegex(
            UiDispatchError, "root has no discovered function"
        ):
            validate_ui_dispatch_report(report)

    def test_modern_ui_behavior_support_requires_matching_executable_path(self):
        support = {behavior_id: False for behavior_id in BEHAVIOR_IDS}
        support["ui-state-persistence"] = True

        with self.assertRaises(UiDispatchError):
            validate_ui_dispatch_report(_report(behavior_support=support))

    def test_address_is_checked_against_its_named_module(self):
        report = _report(
            edges=[
                _edge(
                    callee_module="lib/viewUnified7.so",
                    callee="0x90000",
                    kind="direct",
                    slot=None,
                    table_module=None,
                    table=None,
                )
            ]
        )

        with self.assertRaises(UiDispatchError):
            validate_ui_dispatch_report(report)

    def test_uxc_reference_is_bounded_by_pinned_source_identity(self):
        reference = {
            "source": "share/app/viewStlrec.uxc",
            "kind": "name",
            "value": "Layoutlayout_CMN_M_REC_VERTICAL_CLASSICAL_INFO_LR",
            "offset": 32103,
            "semantic": "reference-only",
        }
        validated = validate_ui_dispatch_report(
            _report(uxc_references=[reference])
        )
        self.assertEqual(validated["uxc_references"], [reference])

        candidate = _report(uxc_references=[{**reference, "offset": 32104}])
        with self.assertRaises(UiDispatchError):
            validate_ui_dispatch_report(candidate)


class UiDispatchExportTests(unittest.TestCase):
    def _raw_export(self, *, edges=None, **overrides):
        document = {
            "program": "viewUnified2.so",
            "sha256": VIEW_UNIFIED2_SHA256,
            "image_size": 11530552,
            "roots": [
                {
                    "name": "ViewSettingMenuEventSwitch",
                    "role": "setting-menu-event-switch",
                    "source_kind": "analysis-address",
                    "source_offset": 0x22355E,
                    "analysis_address": 0x22355E,
                    "function_address": 0x22355E,
                },
                {
                    "name": "ViewStlrecOrientationRegistration",
                    "role": "orientation-registration",
                    "source_kind": "elf-file-offset",
                    "source_offset": 0x1AB41C,
                    "analysis_address": 0x1BB41C,
                    "function_address": 0x1BB41C,
                },
                {
                    "name": "ViewStlrecLayoutModeAttach",
                    "role": "layout-mode-attach",
                    "source_kind": "elf-file-offset",
                    "source_offset": 0x1AB2D2,
                    "analysis_address": 0x1BB2D2,
                    "function_address": 0x1BB2D2,
                },
                {
                    "name": "ViewStlrecAfOrientationDispatch",
                    "role": "af-orientation-dispatch",
                    "source_kind": "elf-file-offset",
                    "source_offset": 0x1B1E76,
                    "analysis_address": 0x1C1E76,
                    "function_address": 0x1C1E76,
                },
            ],
            "edges": [] if edges is None else edges,
            "truncated": False,
        }
        document.update(overrides)
        return document

    def test_normalizes_sorted_vtable_and_unresolved_edges(self):
        raw = self._raw_export(
            edges=[
                {
                    "caller": 0x22355E,
                    "site": 0x2237A4,
                    "target": None,
                    "kind": "unresolved-indirect",
                    "slot": None,
                    "table": None,
                    "owner": "ViewSettingMenu",
                },
                {
                    "caller": 0x22355E,
                    "site": 0x2237A2,
                    "target": 0x230000,
                    "kind": "vtable-slot",
                    "slot": 12,
                    "table": 0x8DED88,
                    "owner": "ViewSettingMenu",
                },
            ]
        )

        normalized = normalize_ui_dispatch_export(raw)

        self.assertEqual(normalized["module"]["name"], "lib/viewUnified2.so")
        self.assertEqual(
            [item["role"] for item in normalized["traversal_roots"]],
            [
                "setting-menu-event-switch",
                "orientation-registration",
                "layout-mode-attach",
                "af-orientation-dispatch",
            ],
        )
        self.assertEqual(
            normalized["traversal_roots"][1]["traversal_entry_address"], "0x1bb41c"
        )
        self.assertEqual(
            normalized["edges"],
            [
                {
                    "id": "edge-0001",
                    "caller_module": "lib/viewUnified2.so",
                    "caller": "0x22355e",
                    "site": "0x2237a2",
                    "callee_module": "lib/viewUnified2.so",
                    "callee": "0x230000",
                    "kind": "vtable-slot",
                    "owner": "ViewSettingMenu",
                    "slot": 12,
                    "table_module": "lib/viewUnified2.so",
                    "table": "0x8ded88",
                },
                {
                    "id": "edge-0002",
                    "caller_module": "lib/viewUnified2.so",
                    "caller": "0x22355e",
                    "site": "0x2237a4",
                    "callee_module": None,
                    "callee": None,
                    "kind": "unresolved-indirect",
                    "owner": "ViewSettingMenu",
                    "slot": None,
                    "table_module": None,
                    "table": None,
                },
            ],
        )

    def test_export_rejects_wrong_identity_truncation_and_unknown_fields(self):
        candidates = [
            self._raw_export(program="other.so"),
            self._raw_export(sha256="00" * 32),
            self._raw_export(image_size=1),
            self._raw_export(truncated=True),
            self._raw_export(unexpected=True),
        ]

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(UiDispatchError):
                normalize_ui_dispatch_export(candidate)

    def test_export_requires_all_four_named_traversal_roots(self):
        candidate = self._raw_export()
        candidate["roots"] = candidate["roots"][:2]

        with self.assertRaises(UiDispatchError):
            normalize_ui_dispatch_export(candidate)

    def test_export_rejects_noninteger_odd_out_of_range_and_duplicate_sites(self):
        base_edge = {
            "caller": 0x22355E,
            "site": 0x2237A2,
            "target": 0x230000,
            "kind": "direct",
            "slot": None,
            "table": None,
            "owner": "ViewSettingMenu",
        }
        candidates = []

        edge = copy.deepcopy(base_edge)
        edge["caller"] = "0x22355e"
        candidates.append(self._raw_export(edges=[edge]))

        edge = copy.deepcopy(base_edge)
        edge["site"] = 0x2237A3
        candidates.append(self._raw_export(edges=[edge]))

        edge = copy.deepcopy(base_edge)
        edge["target"] = 11530552
        candidates.append(self._raw_export(edges=[edge]))

        candidates.append(
            self._raw_export(edges=[base_edge, copy.deepcopy(base_edge)])
        )

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(UiDispatchError):
                normalize_ui_dispatch_export(candidate)

    def test_export_rejects_more_than_fixed_edge_cap(self):
        edge = {
            "caller": 0x22355E,
            "site": 0x2237A2,
            "target": None,
            "kind": "unresolved-indirect",
            "slot": None,
            "table": None,
            "owner": "ViewSettingMenu",
        }
        raw = self._raw_export(edges=[edge] * 10001)

        with self.assertRaises(UiDispatchError):
            normalize_ui_dispatch_export(raw)


class GhidraUiDispatchExporterTests(unittest.TestCase):
    class FakeAdapter:
        def __init__(
            self,
            *,
            can_save=False,
            headless_read_only=True,
            active_transaction=False,
            name="viewUnified2.so",
            sha256=VIEW_UNIFIED2_SHA256,
        ):
            self.can_save = can_save
            self.headless_read_only = headless_read_only
            self.active_transaction = active_transaction
            self.name = name
            self.sha256 = sha256
            self.functions = {
                0x22355E: 0x22355E,
                0x1BB41C: 0x1BB41C,
                0x1BB2D2: 0x1BB2D2,
                0x1C1E76: 0x1C1E76,
            }
            self.edges = {
                0x22355E: [
                    {
                        "caller": 0x22355E,
                        "site": 0x2237A2,
                        "target": 0x230000,
                        "kind": "direct",
                        "slot": None,
                        "table": None,
                        "owner": "ViewSettingMenu",
                    }
                ],
                0x230000: [
                    {
                        "caller": 0x230000,
                        "site": 0x230010,
                        "target": None,
                        "kind": "unresolved-indirect",
                        "slot": None,
                        "table": None,
                        "owner": "FUN_00230000",
                    }
                ],
            }

        def program_name(self):
            return self.name

        def program_sha256(self):
            return self.sha256

        def program_can_save(self):
            return self.can_save

        def program_headless_read_only(self):
            return self.headless_read_only

        def program_has_active_transaction(self):
            return self.active_transaction

        def discover_function(self, requested_offset):
            return self.functions.get(requested_offset)

        def iter_edges(self, function_offset):
            return self.edges.get(function_offset, ())

    def test_builds_bounded_metadata_from_all_four_roots(self):
        exporter = _load_exporter()

        raw = exporter.build_raw_export(
            self.FakeAdapter(), "viewUnified2.so", VIEW_UNIFIED2_SHA256
        )

        self.assertEqual(raw["program"], "viewUnified2.so")
        self.assertEqual(raw["image_size"], 11530552)
        self.assertEqual(
            [item["function_address"] for item in raw["roots"]],
            [0x22355E, 0x1BB41C, 0x1BB2D2, 0x1C1E76],
        )
        self.assertEqual(
            [(item["site"], item["kind"]) for item in raw["edges"]],
            [(0x2237A2, "direct"), (0x230010, "unresolved-indirect")],
        )
        self.assertFalse(raw["truncated"])
        normalize_ui_dispatch_export(raw)

    def test_runtime_detection_uses_direct_ghidra_binding_lookup(self):
        exporter = _load_exporter()
        self.assertFalse(exporter.ghidra_runtime_available())

        exporter.currentProgram = object()
        exporter.getScriptArgs = lambda: []

        self.assertTrue(exporter.ghidra_runtime_available())

    def test_headless_read_only_mode_is_authoritative_over_can_save(self):
        exporter = _load_exporter()

        raw = exporter.build_raw_export(
            self.FakeAdapter(can_save=True, headless_read_only=True),
            "viewUnified2.so",
            VIEW_UNIFIED2_SHA256,
        )

        self.assertFalse(raw["truncated"])

    def test_read_only_host_transaction_is_not_treated_as_write_authority(self):
        exporter = _load_exporter()

        raw = exporter.build_raw_export(
            self.FakeAdapter(headless_read_only=True, active_transaction=True),
            "viewUnified2.so",
            VIEW_UNIFIED2_SHA256,
        )

        self.assertFalse(raw["truncated"])

    def test_refuses_non_read_only_or_identity_mismatched_program(self):
        exporter = _load_exporter()
        candidates = [
            self.FakeAdapter(headless_read_only=False),
            self.FakeAdapter(name="other.so"),
            self.FakeAdapter(sha256="00" * 32),
        ]

        for adapter in candidates:
            with self.subTest(adapter=adapter), self.assertRaises(RuntimeError):
                exporter.build_raw_export(
                    adapter, "viewUnified2.so", VIEW_UNIFIED2_SHA256
                )

    def test_rejects_out_of_range_adapter_roots_and_edges(self):
        exporter = _load_exporter()

        bad_root = self.FakeAdapter()
        bad_root.functions[0x1BB41C] = 11530552

        bad_edge = self.FakeAdapter()
        bad_edge.edges[0x22355E][0]["target"] = 11530552

        for adapter in (bad_root, bad_edge):
            with self.subTest(adapter=adapter), self.assertRaises(RuntimeError):
                exporter.build_raw_export(
                    adapter, "viewUnified2.so", VIEW_UNIFIED2_SHA256
                )

    def test_call_classification_does_not_label_external_direct_as_indirect(self):
        exporter = _load_exporter()

        self.assertIsNone(exporter.classify_call("CALL", None))
        self.assertEqual(
            exporter.classify_call("CALLIND", None),
            ("unresolved-indirect", None),
        )
        self.assertEqual(
            exporter.classify_call("CALLIND", 0x230000),
            ("direct", 0x230000),
        )

    def test_exporter_enforces_function_depth_and_edge_caps(self):
        exporters_and_adapters = []

        exporter = _load_exporter()
        exporter.MAX_FUNCTIONS = 1
        exporters_and_adapters.append((exporter, self.FakeAdapter()))

        exporter = _load_exporter()
        exporter.MAX_DEPTH = 0
        exporters_and_adapters.append((exporter, self.FakeAdapter()))

        exporter = _load_exporter()
        exporter.MAX_EDGES = 1
        adapter = self.FakeAdapter()
        adapter.edges[0x22355E].append(
            {
                "caller": 0x22355E,
                "site": 0x2237A4,
                "target": None,
                "kind": "unresolved-indirect",
                "slot": None,
                "table": None,
                "owner": "ViewSettingMenu",
            }
        )
        exporters_and_adapters.append((exporter, adapter))

        for exporter, adapter in exporters_and_adapters:
            with self.subTest(exporter=exporter), self.assertRaises(RuntimeError):
                exporter.build_raw_export(
                    adapter, "viewUnified2.so", VIEW_UNIFIED2_SHA256
                )

    def test_owner_sanitizer_rejects_all_unicode_controls(self):
        exporter = _load_exporter()

        self.assertEqual(
            exporter.sanitize_owner("bad\u202eowner", 0x22355E),
            "function@0x22355e",
        )

    def test_writes_json_atomically_without_reconstructive_fields(self):
        exporter = _load_exporter()
        raw = exporter.build_raw_export(
            self.FakeAdapter(), "viewUnified2.so", VIEW_UNIFIED2_SHA256
        )

        with tempfile.TemporaryDirectory() as directory:
            approved_root = Path(directory)
            output = approved_root / "raw-ui-dispatch.json"
            exporter.write_json_atomic(output, raw, approved_root)
            written = json.loads(output.read_text(encoding="utf-8"))

            with self.assertRaises(RuntimeError):
                exporter.write_json_atomic(
                    approved_root / "other.json", raw, approved_root
                )

        self.assertEqual(written, raw)
        serialized = json.dumps(written, sort_keys=True)
        for forbidden in ("raw", "bytes", "payload", "disassembly", "hex_dump"):
            self.assertNotIn(f'"{forbidden}":', serialized)


class UiEvidenceRegeneratorTests(unittest.TestCase):
    @staticmethod
    def _load_regenerator():
        spec = importlib.util.spec_from_file_location(
            "regenerate_a6400_ui_evidence_reports", REGENERATOR_PATH
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_regenerator_builds_all_four_reports_and_is_idempotent(self):
        from tests.analysis.test_ui_factory_owner_registration import (
            raw_export as registration_export,
        )
        from tests.analysis.test_vertical_layout_factory_trace import (
            raw_export as vertical_export,
        )

        module = self._load_regenerator()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {
                "VERTICAL_EXPORT_PATH": root / "raw-vertical.json",
                "REGISTRATION_EXPORT_PATH": root / "raw-registration.json",
                "VERTICAL_PATH": root / "vertical.json",
                "REGISTRATION_PATH": root / "registration.json",
                "DISPATCH_PATH": root / "dispatch.json",
                "TARGET_PATH": root / "target.json",
            }
            sources = {
                paths["VERTICAL_EXPORT_PATH"]: vertical_export(),
                paths["REGISTRATION_EXPORT_PATH"]: registration_export(),
                paths["VERTICAL_PATH"]: json.loads(
                    (
                        REPOSITORY_ROOT
                        / "analysis"
                        / "a6400-vertical-layout-factory.json"
                    ).read_text(encoding="utf-8")
                ),
                paths["REGISTRATION_PATH"]: json.loads(
                    (
                        REPOSITORY_ROOT
                        / "analysis"
                        / "a6400-ui-factory-owner-registration.json"
                    ).read_text(encoding="utf-8")
                ),
                paths["DISPATCH_PATH"]: json.loads(
                    REPORT_PATH.read_text(encoding="utf-8")
                ),
                paths["TARGET_PATH"]: json.loads(
                    (
                        REPOSITORY_ROOT / "analysis" / "a6400-target-features.json"
                    ).read_text(encoding="utf-8")
                ),
            }
            for path, document in sources.items():
                path.write_text(
                    json.dumps(document, indent=2) + "\n", encoding="utf-8"
                )
            for field, path in paths.items():
                setattr(module, field, path)

            module.main()
            first = {
                field: path.read_bytes()
                for field, path in paths.items()
                if not field.endswith("EXPORT_PATH")
            }
            module.main()
            second = {
                field: path.read_bytes()
                for field, path in paths.items()
                if not field.endswith("EXPORT_PATH")
            }

            self.assertEqual(first, second)
            target = json.loads(paths["TARGET_PATH"].read_text(encoding="utf-8"))
            self.assertEqual(
                list(target["creative_look_stack"]["layers"]),
                [
                    "interface",
                    "state",
                    "base_looks",
                    "adjustment_axes",
                    "pipeline_binding",
                ],
            )
            self.assertEqual(len(target["ui_static_trace"]["negative_searches"]), 2)
            self.assertNotIn("uxc_owner_functions", target["ui_indirect_trace"])


if __name__ == "__main__":
    unittest.main()
