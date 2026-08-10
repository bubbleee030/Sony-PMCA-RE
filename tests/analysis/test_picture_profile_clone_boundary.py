"""Fail-closed tests for the α6400 Picture Profile clone boundary."""
from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from pmca.analysis.picture_profile_clone_boundary import (
    CAUTION_CONFIG_SHA256,
    CAUTION_CONFIG_SIZE,
    CLAIMS,
    CLONE_EDGES,
    CLONE_OWNER,
    COPY_CONSTRUCTOR_SYMBOL,
    PictureProfileCloneBoundaryError,
    normalize_picture_profile_clone_boundary_export,
    validate_picture_profile_clone_boundary_report,
)

ROOT = Path(__file__).resolve().parents[2]
EXPORTER = ROOT / "tools" / "static" / "export_a6400_picture_profile_clone_boundary.py"
REPORT = ROOT / "analysis" / "a6400-picture-profile-clone-boundary.json"


def raw():
    return {
        "program": "CautionConfig.so",
        "sha256": CAUTION_CONFIG_SHA256,
        "file_size": CAUTION_CONFIG_SIZE,
        "analysis_mode": {"read_only": True, "static_elf_metadata": True},
        "program_changed": False,
        "clone_owner": copy.deepcopy(CLONE_OWNER),
        "clone_edges": copy.deepcopy(CLONE_EDGES),
        "plt_binding_scope": "targeted-exact",
        "copy_constructor_relocation": {
            "edge_site": "0x7ebbf0",
            "plt_address": "0x7c3540",
            "plt_elf_address": "0x7b3540",
            "relocation_index": 676,
            "got_address": "0xb0cc64",
            "intra_entry_offset": 0,
            "relocation_type": "R_ARM_JUMP_SLOT",
            "symbol": COPY_CONSTRUCTOR_SYMBOL,
        },
        "other_import": {
            "edge_site": "0x7ebbe8",
            "plt_address": "0x7c7528",
            "plt_elf_address": "0x7b7528",
            "relocation_index": 2038,
            "got_address": "0xb0e1ac",
            "intra_entry_offset": 0,
            "relocation_type": "R_ARM_JUMP_SLOT",
            "symbol": "_Znwj",
            "semantic_classification": "allocation",
        },
        "typed_interface_registrations": [{
            "address": "0xb11d20",
            "elf_address": "0xb01d20",
            "evidence_type": "dynamic-symbol",
            "symbol": "_ZTV32CmnViewSettingNodePictureProfile",
            "elf_symbol_type": "STT_OBJECT",
            "size": 268,
        }],
        "property_list_evidence": {"classification": "construction-only", "slots": ["PP%d" % x for x in range(1, 10)]},
        "selected_slot_paths": [],
        "persistence_paths": [],
        "processing_paths": [],
        "output_paths": [],
        "truncated": False,
    }


def exporter_module():
    spec = importlib.util.spec_from_file_location("pp_clone_exporter", EXPORTER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CloneBoundaryTests(unittest.TestCase):
    def test_exact_clone_evidence_is_fail_closed(self):
        summary = normalize_picture_profile_clone_boundary_export(raw())
        self.assertEqual(summary["clone_edge_count"], 2)
        self.assertEqual(summary["typed_interface_registration_count"], 1)
        self.assertEqual(summary["claims"], CLAIMS)

    def test_source_edges_copy_relocation_and_promoted_paths_are_rejected(self):
        mutators = (
            lambda value: value.update(program="other.so"),
            lambda value: value["analysis_mode"].update(static_elf_metadata=False),
            lambda value: value.update(program_changed=True),
            lambda value: value["clone_owner"].update(end="0x7ebc00"),
            lambda value: value["clone_edges"][1].update(target="0x0"),
            lambda value: value.update(plt_binding_scope="global"),
            lambda value: value["copy_constructor_relocation"].update(symbol="forged"),
            lambda value: value["copy_constructor_relocation"].update(relocation_index=677),
            lambda value: value["other_import"].update(symbol="arbitrary"),
            lambda value: value["other_import"].update(got_address="0x0"),
            lambda value: value["property_list_evidence"].update(classification="selected-state"),
            lambda value: value["selected_slot_paths"].append({"source": "0x1"}),
            lambda value: value["persistence_paths"].append({"source": "0x1"}),
            lambda value: value["processing_paths"].append({"source": "0x1"}),
            lambda value: value["output_paths"].append({"source": "0x1"}),
            lambda value: value.update(raw_bytes="forbidden"),
        )
        for mutate in mutators:
            value = raw()
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(PictureProfileCloneBoundaryError):
                normalize_picture_profile_clone_boundary_export(value)

    def test_interface_registration_must_be_typed_and_complete(self):
        value = raw()
        value["typed_interface_registrations"][0]["evidence_type"] = "pointer-scan"
        with self.assertRaises(PictureProfileCloneBoundaryError):
            normalize_picture_profile_clone_boundary_export(value)

        value = raw()
        value["typed_interface_registrations"][0]["address"] = "0xb11d24"
        with self.assertRaises(PictureProfileCloneBoundaryError):
            normalize_picture_profile_clone_boundary_export(value)
        value = raw()
        value["typed_interface_registrations"][0]["size"] = 267
        with self.assertRaises(PictureProfileCloneBoundaryError):
            normalize_picture_profile_clone_boundary_export(value)

    def test_report_is_digest_pinned_and_cannot_promote_claims(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertEqual(validate_picture_profile_clone_boundary_report(report), report)
        for mutate in (
            lambda value: value["summary"].update(artifact_sha256="0" * 64),
            lambda value: value["claims"].update(first_class_creative_look=True),
            lambda value: value.update(camera_policy="unknown"),
        ):
            value = copy.deepcopy(report)
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(PictureProfileCloneBoundaryError):
                validate_picture_profile_clone_boundary_report(value)


class ExporterTests(unittest.TestCase):
    def test_output_is_contained(self):
        module = exporter_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            allowed = root / "allowed"
            denied = root / "denied"
            allowed.mkdir()
            denied.mkdir()
            with self.assertRaises(RuntimeError):
                module.write_json_atomic(denied / "raw-picture-profile-clone-boundary.json", {}, allowed)


if __name__ == "__main__":
    unittest.main()
