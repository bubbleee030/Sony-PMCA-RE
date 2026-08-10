"""Fail-closed tests for the α6400 Picture Profile typed vtable interface."""
from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from pmca.analysis.picture_profile_vtable_interface import (
    CAUTION_CONFIG_SHA256,
    CAUTION_CONFIG_SIZE,
    CLAIMS,
    PictureProfileVtableInterfaceError,
    normalize_picture_profile_vtable_interface_export,
    validate_picture_profile_vtable_interface_report,
)

ROOT = Path(__file__).resolve().parents[2]
EXPORTER = ROOT / "tools" / "static" / "export_a6400_picture_profile_vtable_interface.py"
REPORT = ROOT / "analysis" / "a6400-picture-profile-vtable-interface.json"
RAW_ARTIFACT = ROOT / ".artifacts" / "picture-profile-vtable-interface-trace" / "a6400-v2.00" / "raw-picture-profile-vtable-interface.json"


def raw():
    return {
        "program": "CautionConfig.so",
        "sha256": CAUTION_CONFIG_SHA256,
        "file_size": CAUTION_CONFIG_SIZE,
        "analysis_mode": {"read_only": True, "static_elf_metadata": True},
        "program_changed": False,
        "analysis_load_bias": "0x10000",
        "vtable": {
            "elf_address": "0xb01d20", "analysis_address": "0xb11d20",
            "symbol": "_ZTV32CmnViewSettingNodePictureProfile", "elf_symbol_type": "STT_OBJECT",
            "size": 268, "word_count": 67, "address_point": "0xb01d28",
            "typed_relocation_count": 66,
        },
        "clone_slot": {
            "relocation_index": 86117, "relocation_type": "R_ARM_ABS32",
            "slot": 59, "offset": 236, "virtual_index": 57, "vtable_offset": "0xec",
            "symbol": "_ZN32CmnViewSettingNodePictureProfile5cloneEv",
            "elf_thumb_target": "0x7dbbe1", "elf_owner": "0x7dbbe0", "analysis_owner": "0x7ebbe0", "function_size": 34,
        },
        "adjacent_slots": [
            {"role": "update", "relocation_index": 71417, "relocation_type": "R_ARM_ABS32", "slot": 58, "offset": 232, "virtual_index": 56, "vtable_offset": "0xe8", "symbol": "_ZN18CmnViewSettingNode17updateSettingNodeEv", "elf_thumb_target": "0x7c72b9", "elf_owner": "0x7c72b8", "analysis_owner": "0x7d72b8", "function_size": 20},
            {"role": "init-before", "relocation_index": 72607, "relocation_type": "R_ARM_ABS32", "slot": 60, "offset": 240, "virtual_index": 58, "vtable_offset": "0xf0", "symbol": "_ZN18CmnViewSettingNode14userBeforeInitEv", "elf_thumb_target": "0x7c72eb", "elf_owner": "0x7c72ea", "analysis_owner": "0x7d72ea", "function_size": 8},
            {"role": "init-after", "relocation_index": 73796, "relocation_type": "R_ARM_ABS32", "slot": 61, "offset": 244, "virtual_index": 59, "vtable_offset": "0xf4", "symbol": "_ZN18CmnViewSettingNode13userAfterInitEv", "elf_thumb_target": "0x7c72f3", "elf_owner": "0x7c72f2", "analysis_owner": "0x7d72f2", "function_size": 8},
            {"role": "get-sub-node", "relocation_index": 74985, "relocation_type": "R_ARM_ABS32", "slot": 62, "offset": 248, "virtual_index": 60, "vtable_offset": "0xf8", "symbol": "_ZN18CmnViewSettingNode10getSubNodeEPPPS_Ri", "elf_thumb_target": "0x7c72cd", "elf_owner": "0x7c72cc", "analysis_owner": "0x7d72cc", "function_size": 30},
        ],
        "inherited_slot_groups": {
            "selected-item": [
                {"slot": 12, "symbol": "_ZN18CmnViewSettingNode15getSelectedItemEPPS_"},
                {"slot": 13, "symbol": "_ZN18CmnViewSettingNode20getIndexSelectedItemERi"},
                {"slot": 14, "symbol": "_ZN18CmnViewSettingNode20getSRNumSelectedItemERi"},
                {"slot": 39, "symbol": "_ZN18CmnViewSettingNode14isItemSelectedEv"},
                {"slot": 40, "symbol": "_ZN18CmnViewSettingNode21isItemSelectedByIndexEi"},
                {"slot": 41, "symbol": "_ZN18CmnViewSettingNode21isItemSelectedBySRNumEi"},
            ],
            "state": [
                {"slot": 21, "symbol": "_ZN18CmnViewSettingNode8getStateERi"},
                {"slot": 22, "symbol": "_ZN18CmnViewSettingNode15getStateByIndexEiRi"},
                {"slot": 23, "symbol": "_ZN18CmnViewSettingNode15getStateBySRNumEiRi"},
            ],
            "set-selected": [
                {"slot": 48, "symbol": "_ZN18CmnViewSettingNode15setItemSelectedEv"},
                {"slot": 49, "symbol": "_ZN18CmnViewSettingNode22setItemSelectedByIndexEi"},
                {"slot": 50, "symbol": "_ZN18CmnViewSettingNode22setItemSelectedBySRNumEi"},
                {"slot": 51, "symbol": "_ZN18CmnViewSettingNode26setItemSelectedByDiffSRNumEi"},
                {"slot": 63, "symbol": "_ZN18CmnViewSettingNode17setItemUnselectedEv"},
            ],
        },
        "vtable_glob_dat": {
            "relocation_index": 100975, "got_address": "0xb17c40", "relocation_type": "R_ARM_GLOB_DAT",
            "symbol": "_ZTV32CmnViewSettingNodePictureProfile",
        },
        "constructor_aliases": [
            {"role": "constructor", "symbols": ["_ZN32CmnViewSettingNodePictureProfileC1EPP18CmnViewSettingNodeiPK24CmnViewSettingProperties", "_ZN32CmnViewSettingNodePictureProfileC2EPP18CmnViewSettingNodeiPK24CmnViewSettingProperties"], "elf_thumb_target": "0x7dbcbd", "elf_owner": "0x7dbcbc", "analysis_owner": "0x7ebcbc", "function_size": 52},
            {"role": "copy-constructor", "symbols": ["_ZN32CmnViewSettingNodePictureProfileC1ERKS_", "_ZN32CmnViewSettingNodePictureProfileC2ERKS_"], "elf_thumb_target": "0x7dbbbd", "elf_owner": "0x7dbbbc", "analysis_owner": "0x7ebbbc", "function_size": 36},
        ],
        "prior_artifacts": {
            "clone_boundary_sha256": "d95b525159e1ad291eab0a6b05dfede9cfedb49398ceb811db512ae8102690da",
            "handoff_sha256": "c1c792b2aa28bbae168209329df4c0ce46dc5834f0d024f8d21cebb364aa74ff",
        },
        "pp1_pp9_bindings": [], "selected_slot_paths": [], "persistence_paths": [],
        "processing_paths": [], "output_paths": [], "truncated": False,
    }


def exporter_module():
    spec = importlib.util.spec_from_file_location("pp_vtable_exporter", EXPORTER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PictureProfileVtableInterfaceTests(unittest.TestCase):
    def test_exact_typed_interface_metadata_is_fail_closed(self):
        summary = normalize_picture_profile_vtable_interface_export(raw())
        self.assertEqual(summary["typed_vtable_relocation_count"], 66)
        self.assertEqual(summary["claims"], CLAIMS)

    def test_vtable_slot_alias_path_and_safety_tampering_is_rejected(self):
        mutations = (
            lambda value: value.update(program="other.so"),
            lambda value: value["analysis_mode"].update(static_elf_metadata=False),
            lambda value: value.update(program_changed=True),
            lambda value: value["vtable"].update(size=264),
            lambda value: value["vtable"].update(typed_relocation_count=65),
            lambda value: value["clone_slot"].update(slot=58),
            lambda value: value["clone_slot"].update(elf_thumb_target="0x0"),
            lambda value: value["clone_slot"].update(analysis_owner="0x7dbbe0"),
            lambda value: value.update(analysis_load_bias="0x0"),
            lambda value: value["adjacent_slots"].reverse(),
            lambda value: value["inherited_slot_groups"]["state"][0].update(slot=20),
            lambda value: value["vtable_glob_dat"].update(relocation_type="R_ARM_ABS32"),
            lambda value: value["constructor_aliases"][0]["symbols"].reverse(),
            lambda value: value["prior_artifacts"].update(handoff_sha256="0" * 64),
            lambda value: value["pp1_pp9_bindings"].append({"slot": "PP1"}),
            lambda value: value["selected_slot_paths"].append({"path": "forged"}),
            lambda value: value["persistence_paths"].append({"path": "forged"}),
            lambda value: value["processing_paths"].append({"path": "forged"}),
            lambda value: value["output_paths"].append({"path": "forged"}),
            lambda value: value.update(raw_bytes="forbidden"),
        )
        for mutate in mutations:
            value = raw()
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(PictureProfileVtableInterfaceError):
                normalize_picture_profile_vtable_interface_export(value)

    def test_report_is_digest_pinned_and_cannot_promote_interface_reuse(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertEqual(validate_picture_profile_vtable_interface_report(report), report)
        for mutate in (
            lambda value: value["summary"].update(artifact_sha256="0" * 64),
            lambda value: value["claims"].update(interface_reuse_found=True),
            lambda value: value.update(camera_policy="unknown"),
        ):
            value = copy.deepcopy(report)
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(PictureProfileVtableInterfaceError):
                validate_picture_profile_vtable_interface_report(value)

    @unittest.skipUnless(RAW_ARTIFACT.is_file(), "ignored static artifact unavailable")
    def test_committed_report_digest_matches_the_actual_ignored_raw_artifact(self):
        self.assertTrue(RAW_ARTIFACT.is_file(), "actual ignored raw artifact must be present")
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        raw_document = json.loads(RAW_ARTIFACT.read_text(encoding="utf-8"))
        summary = normalize_picture_profile_vtable_interface_export(raw_document)
        self.assertEqual(summary["artifact_sha256"], report["summary"]["artifact_sha256"])


class ExporterTests(unittest.TestCase):
    def test_static_export_pins_the_typed_interface_metadata(self):
        module = exporter_module()
        self.assertEqual(module.build_raw_export()["clone_slot"], raw()["clone_slot"])

    def test_output_is_contained(self):
        module = exporter_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            allowed = root / "allowed"
            denied = root / "denied"
            allowed.mkdir()
            denied.mkdir()
            with self.assertRaises(RuntimeError):
                module.write_json_atomic(denied / "raw-picture-profile-vtable-interface.json", {}, allowed)


if __name__ == "__main__":
    unittest.main()
