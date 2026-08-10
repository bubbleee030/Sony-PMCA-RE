"""Contract tests for bounded α6400 Picture Profile trace metadata."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from pmca.analysis.picture_profile_trace import (
    CAUTION_CONFIG_SHA256,
    PICTURE_PROFILE_ROOTS,
    PICTURE_PROFILE_SLOT_NODES,
    PICTURE_PROFILE_EXPORT_SHA256,
    PictureProfileTraceError,
    normalize_picture_profile_export,
    validate_picture_profile_boundary,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = REPOSITORY_ROOT / "analysis" / "a6400-picture-profile-boundary.json"
EXPORTER_PATH = (
    REPOSITORY_ROOT / "tools" / "ghidra" / "export_a6400_picture_profile.py"
)


def _load_exporter():
    spec = importlib.util.spec_from_file_location("picture_profile_exporter", EXPORTER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _report():
    return {
        "schema_version": 1,
        "analysis_scope": "offline-static-picture-profile-reimplementation-boundary",
        "camera_policy": "physically-disconnected",
        "camera_executed": False,
        "installable": False,
        "camera_test_eligible": False,
        "source": {
            "source_id": "a6400-tw-v2.00",
            "module": "lib/CautionConfig.so",
            "size": 12070800,
            "sha256": CAUTION_CONFIG_SHA256,
        },
        "roots": [
            {
                "id": item["id"],
                "role": item["role"],
                "elf_thumb_offset": item["elf_thumb_offset"],
                "analysis_address": item["analysis_address"],
                "symbol": item["symbol"],
            }
            for item in PICTURE_PROFILE_ROOTS
        ],
        "slot_nodes": [
            {
                "id": item["id"],
                "elf_offset": item["elf_offset"],
                "analysis_address": item["analysis_address"],
                "symbol": item["symbol"],
            }
            for item in PICTURE_PROFILE_SLOT_NODES
        ],
        "bounded_export_summary": {
            "direct_call_count": 0,
            "data_reference_count": 0,
            "unresolved_indirect_count": 0,
            "truncated": False,
            "depth_cap": 16,
            "artifact_sha256": "00" * 32,
        },
        "direct_calls": [],
        "data_references": [],
        "unresolved_indirect_edges": [],
        "candidates": {
            "named_slots": True,
            "copy_subnode": True,
            "uxc_reference": False,
        },
        "claims": {
            "reusable_target_interface_primitives": False,
            "reusable_target_state_primitives": False,
            "persistence_found": False,
            "base_look_processing": False,
            "live_view_binding": False,
            "still_jpeg_binding": False,
            "movie_binding": False,
        },
        "readiness": "INFRASTRUCTURE_CANDIDATE_ONLY",
        "conclusion": (
            "Picture Profile exposes target-native preset, copy, gamma, color-mode, "
            "and PP1-PP9 node candidates, but no Creative Look state, persistence, "
            "processing, live-view, still-JPEG, or movie binding is established."
        ),
    }


class PictureProfileBoundaryTests(unittest.TestCase):
    def test_committed_baseline_pins_non_creative_style_roots_and_false_claims(self):
        validated = validate_picture_profile_boundary(
            json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        )

        self.assertEqual(validated["roots"], _report()["roots"])
        self.assertEqual(validated["slot_nodes"], _report()["slot_nodes"])
        self.assertEqual(
            validated["claims"],
            {
                "reusable_target_interface_primitives": False,
                "reusable_target_state_primitives": False,
                "persistence_found": False,
                "base_look_processing": False,
                "live_view_binding": False,
                "still_jpeg_binding": False,
                "movie_binding": False,
            },
        )
        self.assertFalse(validated["camera_executed"])
        self.assertFalse(validated["installable"])
        self.assertFalse(validated["camera_test_eligible"])
        self.assertNotEqual(
            validated["bounded_export_summary"]["artifact_sha256"], "00" * 32
        )
        self.assertEqual(
            validated["bounded_export_summary"]["artifact_sha256"],
            PICTURE_PROFILE_EXPORT_SHA256,
        )

    def test_thumb_roots_are_normalized_before_load_bias(self):
        report = _report()
        report["roots"][0]["analysis_address"] = "0x7ebc05"

        with self.assertRaises(PictureProfileTraceError):
            validate_picture_profile_boundary(report)

    def test_creative_style_or_raw_material_is_rejected(self):
        creative_style = _report()
        creative_style["roots"][0]["symbol"] = "CmnViewSettingNodeCreativeStyle::_getSubNodeEv"
        raw = _report()
        raw["raw_bytes"] = "forbidden"
        key_material = _report()
        key_material["key_material"] = "forbidden"

        for report in (creative_style, raw, key_material):
            with self.subTest(report=report), self.assertRaises(PictureProfileTraceError):
                validate_picture_profile_boundary(report)

    def test_named_slots_and_copy_candidate_cannot_promote_persistence_or_outputs(self):
        report = _report()
        report["claims"]["persistence_found"] = True
        report["claims"]["movie_binding"] = True

        with self.assertRaises(PictureProfileTraceError):
            validate_picture_profile_boundary(report)

    def test_committed_export_digest_binds_exact_edges(self):
        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        tampered_edge = copy.deepcopy(report)
        tampered_edge["direct_calls"][0]["target"] = "0x0"
        tampered_digest = copy.deepcopy(report)
        tampered_digest["bounded_export_summary"]["artifact_sha256"] = "1" * 64

        for candidate in (tampered_edge, tampered_digest):
            with self.subTest(candidate=candidate), self.assertRaises(
                PictureProfileTraceError
            ):
                validate_picture_profile_boundary(candidate)

    def test_normalizer_accepts_only_bounded_metadata(self):
        committed = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        raw = {
            "program": "CautionConfig.so",
            "sha256": CAUTION_CONFIG_SHA256,
            "file_size": 12070800,
            "analysis_mode": {"read_only": True, "noanalysis": True},
            "roots": [
                {"address": item["analysis_address_int"], "symbol": item["symbol"]}
                for item in PICTURE_PROFILE_ROOTS
            ],
            "slot_nodes": [
                {"address": item["analysis_address_int"], "symbol": item["symbol"]}
                for item in PICTURE_PROFILE_SLOT_NODES
            ],
            "direct_calls": copy.deepcopy(committed["direct_calls"]),
            "data_references": copy.deepcopy(committed["data_references"]),
            "unresolved_indirect_edges": copy.deepcopy(
                committed["unresolved_indirect_edges"]
            ),
            "truncated": False,
            "depth_cap": 16,
        }

        normalized = normalize_picture_profile_export(raw)

        self.assertEqual(normalized["roots"], _report()["roots"])
        self.assertEqual(normalized["slot_nodes"], _report()["slot_nodes"])

    def test_normalizer_rejects_partial_root_set_or_raw_disassembly(self):
        raw = {
            "program": "CautionConfig.so",
            "sha256": CAUTION_CONFIG_SHA256,
            "file_size": 12070800,
            "analysis_mode": {"read_only": True, "noanalysis": True},
            "roots": [],
            "slot_nodes": [],
            "direct_calls": [],
            "data_references": [],
            "unresolved_indirect_edges": [],
            "truncated": False,
            "depth_cap": 16,
        }
        disassembly = copy.deepcopy(raw)
        disassembly["disassembly"] = "forbidden"

        for candidate in (raw, disassembly):
            with self.subTest(candidate=candidate), self.assertRaises(
                PictureProfileTraceError
            ):
                normalize_picture_profile_export(candidate)


class PictureProfileExporterTests(unittest.TestCase):
    class Adapter:
        def program_name(self):
            return "CautionConfig.so"

        def program_sha256(self):
            return CAUTION_CONFIG_SHA256

        def program_headless_read_only(self):
            return True

        def program_is_changed(self):
            return False

        def program_noanalysis(self):
            return True

        def roots(self):
            return [
                {"address": item["analysis_address_int"], "symbol": item["symbol"]}
                for item in PICTURE_PROFILE_ROOTS
            ]

        def slot_nodes(self):
            return [
                {"address": item["analysis_address_int"], "symbol": item["symbol"]}
                for item in PICTURE_PROFILE_SLOT_NODES
            ]

        def iter_edges(self, roots, depth_cap):
            self.roots_seen = tuple(roots)
            self.depth_cap = depth_cap
            return [], [], []

    def test_exporter_builds_only_pinned_metadata(self):
        exporter = _load_exporter()
        adapter = self.Adapter()

        raw = exporter.build_raw_export(adapter, "CautionConfig.so", CAUTION_CONFIG_SHA256)

        self.assertEqual([item["address"] for item in raw["roots"]], [
            item["analysis_address_int"] for item in PICTURE_PROFILE_ROOTS
        ])
        self.assertEqual(adapter.depth_cap, 16)
        self.assertEqual(raw["direct_calls"], [])

    def test_exporter_refuses_mutable_or_wrong_source(self):
        exporter = _load_exporter()
        adapter = self.Adapter()
        adapter.program_is_changed = lambda: True

        with self.assertRaises(RuntimeError):
            exporter.build_raw_export(adapter, "CautionConfig.so", CAUTION_CONFIG_SHA256)

        adapter = self.Adapter()
        adapter.program_noanalysis = lambda: False
        with self.assertRaises(RuntimeError):
            exporter.build_raw_export(adapter, "CautionConfig.so", CAUTION_CONFIG_SHA256)

        for mutate in (
            lambda adapter: setattr(adapter, "program_headless_read_only", lambda: False),
            lambda adapter: setattr(adapter, "program_name", lambda: "wrong.so"),
            lambda adapter: setattr(adapter, "program_sha256", lambda: "0" * 64),
        ):
            adapter = self.Adapter()
            mutate(adapter)
            with self.subTest(adapter=adapter), self.assertRaises(RuntimeError):
                exporter.build_raw_export(
                    adapter, "CautionConfig.so", CAUTION_CONFIG_SHA256
                )

    def test_reference_filter_requires_ghidra_data_type(self):
        exporter = _load_exporter()

        class ReferenceType:
            def __init__(self, data):
                self.data = data

            def isData(self):
                return self.data

        class Reference:
            def __init__(self, data):
                self.reference_type = ReferenceType(data)

            def getReferenceType(self):
                return self.reference_type

        self.assertTrue(exporter.reference_is_data(Reference(True)))
        self.assertFalse(exporter.reference_is_data(Reference(False)))

    def test_exporter_output_is_confined_to_approved_root(self):
        exporter = _load_exporter()
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            approved = temporary / "approved"
            outside = temporary / "outside"
            approved.mkdir()
            outside.mkdir()

            with self.assertRaises(RuntimeError):
                exporter.write_json_atomic(
                    outside / "raw-picture-profile.json", {}, approved
                )


if __name__ == "__main__":
    unittest.main()
