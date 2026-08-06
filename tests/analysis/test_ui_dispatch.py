import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from pmca.analysis.ui_dispatch import (
    VIEW_UNIFIED2_SHA256,
    VIEW_UNIFIED7_SHA256,
    UiDispatchError,
    normalize_ui_dispatch_export,
    validate_ui_dispatch_report,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = REPOSITORY_ROOT / "analysis" / "a6400-ui-dispatch-boundary.json"
EXPORTER_PATH = REPOSITORY_ROOT / "tools" / "ghidra" / "export_a6400_ui_dispatch.py"
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
                "function_address": "0x22355e",
            },
            {
                "name": "ViewStlrecOrientationRegistration",
                "role": "orientation-registration",
                "module": "lib/viewUnified2.so",
                "source_kind": "elf-file-offset",
                "source_offset": "0x1ab41c",
                "analysis_address": "0x1bb41c",
                "function_address": "0x1bb41c",
            },
            {
                "name": "ViewStlrecLayoutModeAttach",
                "role": "layout-mode-attach",
                "module": "lib/viewUnified2.so",
                "source_kind": "elf-file-offset",
                "source_offset": "0x1ab2d2",
                "analysis_address": "0x1bb2d2",
                "function_address": "0x1bb2d2",
            },
            {
                "name": "ViewStlrecAfOrientationDispatch",
                "role": "af-orientation-dispatch",
                "module": "lib/viewUnified2.so",
                "source_kind": "elf-file-offset",
                "source_offset": "0x1b1e76",
                "analysis_address": "0x1c1e76",
                "function_address": "0x1c1e76",
            },
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
        "behavior_support": behavior_support
        or {behavior_id: False for behavior_id in BEHAVIOR_IDS},
    }


class UiDispatchTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(REPORT_PATH.read_text(encoding="utf-8"))

    def test_committed_report_preserves_existing_boundaries_without_promotion(self):
        validated = validate_ui_dispatch_report(self.document)

        self.assertEqual(validated, self.document)
        self.assertEqual(validated["modules"][0]["sha256"], VIEW_UNIFIED2_SHA256)
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
        self.assertEqual(
            validated["behavior_support"],
            {behavior_id: False for behavior_id in BEHAVIOR_IDS},
        )

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
        report["roots"][1]["function_address"] = "0x1bb000"

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
        report["roots"][1]["function_address"] = None

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
            normalized["traversal_roots"][1]["function_address"], "0x1bb41c"
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


if __name__ == "__main__":
    unittest.main()
