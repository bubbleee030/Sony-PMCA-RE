import copy
import importlib.util
import json
import unittest
from pathlib import Path

from pmca.analysis.creative_look_trace import (
    CAUTION_CONFIG_SHA256,
    CreativeLookTraceError,
    normalize_creative_look_export,
    validate_creative_look_boundary,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = REPOSITORY_ROOT / "analysis" / "a6400-creative-look-boundary.json"
EXPORTER_PATH = (
    REPOSITORY_ROOT / "tools" / "ghidra" / "export_creative_look_boundaries.py"
)


def _load_exporter():
    spec = importlib.util.spec_from_file_location("creative_look_exporter", EXPORTER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _path(
    *,
    path_id="selector-to-style-graph",
    source_id="a6400-tw-v2.00",
    source="0x7eb958",
    sink="0xb936cc",
    semantic="menu-graph-selection",
    resolved=True,
    output_scope=None,
    evidence_kind="compiled-graph-selector",
):
    return {
        "id": path_id,
        "source_id": source_id,
        "source_module": "lib/CautionConfig.so",
        "source": source,
        "sink_module": None if sink is None else "lib/CautionConfig.so",
        "sink": sink,
        "semantic": semantic,
        "resolved": resolved,
        "output_scope": [] if output_scope is None else output_scope,
        "evidence_kind": evidence_kind,
    }


def _axis_negative_searches():
    return [
        {
            "id": f"axis-{axis.replace('_', '-')}-boundaries-not-found",
            "source_id": "a6400-tw-v2.00",
            "module": "lib/CautionConfig.so",
            "semantic": "axis-range-validation",
            "root_count": 10,
            "edge_kinds": ["direct"],
            "depth_cap": 16,
            "path_found": False,
            "blocker": f"No independent {axis} UI, state, range, and processing boundary was identified.",
        }
        for axis in (
            "contrast",
            "highlights",
            "shadows",
            "fade",
            "saturation",
            "sharpness",
            "sharpness_range",
            "clarity",
        )
    ]


def _report(*, paths=None, claims=None, output_support=None):
    return {
        "schema_version": 1,
        "analysis_scope": "offline-static-creative-look-boundaries",
        "source_states": [
            {
                "id": "a6400-tw-v2.00",
                "state": "AUTHENTICATED_EXTRACTED",
                "executable_evidence_available": True,
            },
            {
                "id": "a6400a-eu-v1.01",
                "state": "AUTHENTICATED_EXTRACTED",
                "executable_evidence_available": True,
            },
            {
                "id": "a6700-tw-v2.00",
                "state": "AUTHENTICATED_OPAQUE",
                "executable_evidence_available": False,
            },
            {
                "id": "a7v-tw-v2.00",
                "state": "AUTHENTICATED_OPAQUE",
                "executable_evidence_available": False,
            },
        ],
        "modules": [
            {
                "source_id": "a6400-tw-v2.00",
                "name": "lib/CautionConfig.so",
                "size": 12070800,
                "sha256": CAUTION_CONFIG_SHA256,
            },
            {
                "source_id": "a6400a-eu-v1.01",
                "name": "lib/CautionConfig.so",
                "size": 12070832,
                "sha256": "5ff622c8a30595fe88195d3e492643ceeb5ad2da68e556076eed593851a4d3e9",
            },
        ],
        "bounded_export_summary": {
            "root_count": 0,
            "function_root_count": 0,
            "data_root_count": 0,
            "call_count": 0,
            "direct_call_count": 0,
            "unresolved_direct_call_count": 0,
            "unresolved_indirect_call_count": 0,
            "reference_count": 0,
            "truncated": False,
            "depth_cap": 16,
            "artifact_sha256": "00" * 32,
        },
        "roots": [],
        "paths": [_path()] if paths is None else paths,
        "negative_searches": _axis_negative_searches(),
        "source_skips": [
            {
                "source_id": "a6700-tw-v2.00",
                "state": "AUTHENTICATED_OPAQUE",
                "reason": "source-not-extracted",
            },
            {
                "source_id": "a7v-tw-v2.00",
                "state": "AUTHENTICATED_OPAQUE",
                "reason": "source-not-extracted",
            },
        ],
        "claims": claims
        or {
            "native_creative_look_interface_found": False,
            "state_persistence_found": False,
            "base_look_processing_found": False,
            "pipeline_binding_found": False,
        },
        "output_support": output_support
        or {"live_view": False, "still_jpeg": False, "movie": False},
    }


class CreativeLookBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(REPORT_PATH.read_text(encoding="utf-8"))

    def test_committed_boundary_keeps_menu_graph_separate_from_processing(self):
        validated = validate_creative_look_boundary(self.document)

        self.assertEqual(
            [item["semantic"] for item in validated["paths"]],
            ["menu-graph-selection"],
        )
        self.assertEqual(
            validated["claims"],
            {
                "native_creative_look_interface_found": False,
                "state_persistence_found": False,
                "base_look_processing_found": False,
                "pipeline_binding_found": False,
            },
        )
        self.assertEqual(
            validated["output_support"],
            {"live_view": False, "still_jpeg": False, "movie": False},
        )

    def test_selector_to_menu_graph_is_not_a_pipeline_binding(self):
        validated = validate_creative_look_boundary(_report(paths=[_path()]))

        self.assertFalse(validated["claims"]["base_look_processing_found"])
        self.assertFalse(validated["claims"]["pipeline_binding_found"])

    def test_pipeline_claim_requires_matching_output_sink(self):
        candidate = _report(
            claims={
                "native_creative_look_interface_found": False,
                "state_persistence_found": False,
                "base_look_processing_found": False,
                "pipeline_binding_found": True,
            }
        )

        with self.assertRaises(CreativeLookTraceError):
            validate_creative_look_boundary(candidate)

    def test_hand_authored_output_sink_cannot_promote_support(self):
        report = _report(
            paths=[
                _path(
                    path_id="still-output-path",
                    source="0x1000",
                    sink="0x2000",
                    semantic="still-jpeg-sink",
                    output_scope=["still_jpeg"],
                    evidence_kind="bounded-direct-call-path",
                )
            ],
            claims={
                "native_creative_look_interface_found": False,
                "state_persistence_found": False,
                "base_look_processing_found": False,
                "pipeline_binding_found": True,
            },
            output_support={"live_view": False, "still_jpeg": True, "movie": False},
        )

        with self.assertRaises(CreativeLookTraceError):
            validate_creative_look_boundary(report)

    def test_arbitrary_or_creative_style_ui_evidence_cannot_promote_processing(self):
        for evidence_kind in ("arbitrary", "creative-style-ui-node"):
            candidate = _report(
                paths=[
                    _path(
                        semantic="base-look-table-load",
                        evidence_kind=evidence_kind,
                    )
                ],
                claims={
                    "native_creative_look_interface_found": False,
                    "state_persistence_found": False,
                    "base_look_processing_found": True,
                    "pipeline_binding_found": False,
                },
            )

            with self.subTest(evidence_kind=evidence_kind), self.assertRaises(
                CreativeLookTraceError
            ):
                validate_creative_look_boundary(candidate)

    def test_opaque_donor_cannot_supply_offsets_or_paths(self):
        candidate = _report(
            paths=[
                _path(
                    source_id="a7v-tw-v2.00",
                    source="0x1000",
                    sink="0x2000",
                    semantic="base-look-table-load",
                    evidence_kind="resolved-data-reference",
                )
            ]
        )

        with self.assertRaises(CreativeLookTraceError):
            validate_creative_look_boundary(candidate)

    def test_creative_style_graph_cannot_claim_creative_look_processing(self):
        candidate = _report(
            paths=[
                _path(
                    semantic="base-look-table-load",
                    evidence_kind="compiled-graph-selector",
                )
            ],
            claims={
                "native_creative_look_interface_found": False,
                "state_persistence_found": False,
                "base_look_processing_found": True,
                "pipeline_binding_found": False,
            },
        )

        with self.assertRaises(CreativeLookTraceError):
            validate_creative_look_boundary(candidate)

    def test_unresolved_path_cannot_have_a_sink_or_output_scope(self):
        candidate = _report(
            paths=[
                _path(
                    sink=None,
                    semantic="unresolved",
                    resolved=False,
                    output_scope=["movie"],
                    evidence_kind="unresolved-indirect",
                )
            ]
        )

        with self.assertRaises(CreativeLookTraceError):
            validate_creative_look_boundary(candidate)

    def test_raw_reconstructive_fields_and_unbounded_paths_are_rejected(self):
        raw = copy.deepcopy(self.document)
        raw["paths"][0]["table_bytes"] = "forbidden"

        too_many = copy.deepcopy(self.document)
        too_many["paths"] = [
            _path(path_id=f"path-{index:04d}") for index in range(513)
        ]

        for candidate in (raw, too_many):
            with self.subTest(candidate=candidate), self.assertRaises(
                CreativeLookTraceError
            ):
                validate_creative_look_boundary(candidate)

    def test_source_skips_are_exact_for_opaque_modern_donors(self):
        candidate = copy.deepcopy(self.document)
        candidate["source_skips"][0]["reason"] = "no-interesting-symbols"

        with self.assertRaises(CreativeLookTraceError):
            validate_creative_look_boundary(candidate)

    def test_validated_boundary_is_a_deep_copy(self):
        validated = validate_creative_look_boundary(self.document)
        validated["paths"][0]["semantic"] = "changed"

        self.assertNotEqual(
            validated["paths"][0]["semantic"],
            self.document["paths"][0]["semantic"],
        )

    def test_root_outside_pinned_elf_memory_image_is_rejected(self):
        candidate = copy.deepcopy(self.document)
        candidate["roots"][0]["source_offset"] = "0xc5b720"
        candidate["roots"][0]["analysis_address"] = "0xc6b720"

        with self.assertRaises(CreativeLookTraceError):
            validate_creative_look_boundary(candidate)

    def test_each_axis_requires_an_independent_negative_or_positive_boundary(self):
        candidate = _report()
        candidate["negative_searches"].pop()

        with self.assertRaises(CreativeLookTraceError):
            validate_creative_look_boundary(candidate)

    def test_negative_searches_must_disclose_unresolved_indirect_edges(self):
        candidate = copy.deepcopy(self.document)
        candidate["bounded_export_summary"]["call_count"] += 1
        candidate["bounded_export_summary"]["unresolved_indirect_call_count"] = 1

        with self.assertRaises(CreativeLookTraceError):
            validate_creative_look_boundary(candidate)


class CreativeLookExportNormalizationTests(unittest.TestCase):
    def test_normalizes_bounded_selector_graph_reference(self):
        raw = {
            "program": "CautionConfig.so",
            "sha256": CAUTION_CONFIG_SHA256,
            "file_size": 12070800,
            "selector_source_offset": 0x7DB958,
            "selector_analysis_address": 0x7EB958,
            "selector_function": 0x7EB958,
            "compiled_graph_source_offset": 0xB836CC,
            "compiled_graph_analysis_address": 0xB936CC,
            "named_functions": [
                {
                    "address": 0x7EB958,
                    "symbol": "CmnViewSettingNodeCreativeStyle::_getSubNodeEv",
                }
            ],
            "references": [
                {
                    "owner": 0x7EB958,
                    "site": 0x7EB970,
                    "target": 0xB936CC,
                    "kind": "data-reference",
                    "symbol": "CmnViewSettingNodeCreativeStyle::_getSubNodeEv",
                }
            ],
            "calls": [],
            "truncated": False,
            "depth_cap": 16,
        }

        normalized = normalize_creative_look_export(raw)

        self.assertEqual(normalized["bounded_export_summary"]["reference_count"], 1)
        self.assertEqual(normalized["paths"][0]["semantic"], "menu-graph-selection")
        self.assertFalse(normalized["paths"][0]["output_scope"])
        self.assertEqual(normalized["roots"][0]["source_offset"], "0x7db958")
        self.assertEqual(normalized["roots"][0]["analysis_address"], "0x7eb958")
        self.assertEqual(normalized["roots"][0]["source_kind"], "elf-virtual-address")
        self.assertEqual(normalized["roots"][1]["source_offset"], "0xb836cc")
        self.assertEqual(normalized["roots"][1]["analysis_address"], "0xb936cc")
        self.assertEqual(normalized["roots"][1]["source_kind"], "elf-virtual-address")

    def test_normalizer_rejects_wrong_identity_truncation_or_raw_fields(self):
        base = {
            "program": "CautionConfig.so",
            "sha256": CAUTION_CONFIG_SHA256,
            "file_size": 12070800,
            "selector_source_offset": 0x7DB958,
            "selector_analysis_address": 0x7EB958,
            "selector_function": 0x7EB958,
            "compiled_graph_source_offset": 0xB836CC,
            "compiled_graph_analysis_address": 0xB936CC,
            "named_functions": [],
            "references": [],
            "calls": [],
            "truncated": False,
            "depth_cap": 16,
        }
        candidates = []

        candidate = copy.deepcopy(base)
        candidate["sha256"] = "00" * 32
        candidates.append(candidate)

        candidate = copy.deepcopy(base)
        candidate["truncated"] = True
        candidates.append(candidate)

        candidate = copy.deepcopy(base)
        candidate["raw_bytes"] = "forbidden"
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                CreativeLookTraceError
            ):
                normalize_creative_look_export(candidate)

    def test_normalizer_preserves_unresolved_direct_calls(self):
        raw = {
            "program": "CautionConfig.so",
            "sha256": CAUTION_CONFIG_SHA256,
            "file_size": 12070800,
            "selector_source_offset": 0x7DB958,
            "selector_analysis_address": 0x7EB958,
            "selector_function": 0x7EB958,
            "compiled_graph_source_offset": 0xB836CC,
            "compiled_graph_analysis_address": 0xB936CC,
            "named_functions": [],
            "references": [],
            "calls": [
                {
                    "caller": 0x7EB958,
                    "site": 0x7EB970,
                    "target": None,
                    "kind": "unresolved-direct",
                    "owner": "CmnViewSettingNodeCreativeStyle::_getSubNodeEv",
                }
            ],
            "truncated": False,
            "depth_cap": 16,
        }

        normalized = normalize_creative_look_export(raw)

        self.assertEqual(
            normalized["bounded_export_summary"]["unresolved_direct_call_count"],
            1,
        )


class CreativeLookGhidraExporterTests(unittest.TestCase):
    class Adapter:
        def program_name(self):
            return "CautionConfig.so"

        def program_sha256(self):
            return CAUTION_CONFIG_SHA256

        def program_headless_read_only(self):
            return True

        def program_is_changed(self):
            return False

        def discover_function(self, address):
            return 0x7EB958 if address == 0x7EB958 else None

        def creative_style_functions(self):
            return [
                {
                    "address": 0x7EB958,
                    "symbol": "CmnViewSettingNodeCreativeStyle::_getSubNodeEv",
                }
            ]

        def graph_references(self, address):
            self.graph_address = address
            return [
                {
                    "owner": 0x7EB958,
                    "site": 0x7EB970,
                    "target": address,
                    "kind": "data-reference",
                    "symbol": "CmnViewSettingNodeCreativeStyle::_getSubNodeEv",
                }
            ]

        def iter_calls(self, function_addresses, depth_cap):
            self.function_addresses = tuple(function_addresses)
            self.depth_cap = depth_cap
            return []

    def test_builds_read_only_bounded_export_from_selector_and_graph(self):
        exporter = _load_exporter()
        adapter = self.Adapter()

        document = exporter.build_raw_export(
            adapter, "CautionConfig.so", CAUTION_CONFIG_SHA256
        )

        self.assertEqual(document["selector_source_offset"], 0x7DB958)
        self.assertEqual(document["selector_analysis_address"], 0x7EB958)
        self.assertEqual(document["selector_function"], 0x7EB958)
        self.assertEqual(document["compiled_graph_source_offset"], 0xB836CC)
        self.assertEqual(document["compiled_graph_analysis_address"], 0xB936CC)
        self.assertEqual(adapter.graph_address, 0xB936CC)
        self.assertEqual(adapter.depth_cap, 16)

    def test_exporter_refuses_non_read_only_program(self):
        exporter = _load_exporter()
        adapter = self.Adapter()
        adapter.program_headless_read_only = lambda: False

        with self.assertRaises(RuntimeError):
            exporter.build_raw_export(
                adapter, "CautionConfig.so", CAUTION_CONFIG_SHA256
            )

    def test_exporter_preserves_unresolved_direct_calls(self):
        exporter = _load_exporter()
        adapter = self.Adapter()
        adapter.iter_calls = lambda function_addresses, depth_cap: [
            {
                "caller": 0x7EB958,
                "site": 0x7EB970,
                "target": None,
                "kind": "unresolved-direct",
                "owner": "CmnViewSettingNodeCreativeStyle::_getSubNodeEv",
            }
        ]

        document = exporter.build_raw_export(
            adapter, "CautionConfig.so", CAUTION_CONFIG_SHA256
        )

        self.assertEqual(document["calls"][0]["kind"], "unresolved-direct")


if __name__ == "__main__":
    unittest.main()
