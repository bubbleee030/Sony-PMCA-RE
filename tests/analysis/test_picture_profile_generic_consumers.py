"""Fail-closed tests for α6400 Picture Profile generic vtable consumers."""
from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from pmca.analysis.picture_profile_generic_consumers import (
    CAUTION_CONFIG_SHA256,
    CAUTION_CONFIG_SIZE,
    CLAIMS,
    PictureProfileGenericConsumerError,
    normalize_picture_profile_generic_consumer_export,
    validate_picture_profile_generic_consumer_report,
)

ROOT = Path(__file__).resolve().parents[2]
EXPORTER = ROOT / "tools" / "static" / "export_a6400_picture_profile_generic_consumers.py"
REPORT = ROOT / "analysis" / "a6400-picture-profile-generic-consumers.json"
RAW_ARTIFACT = ROOT / ".artifacts" / "picture-profile-generic-consumer-trace" / "a6400-v2.00" / "raw-picture-profile-generic-consumers.json"


def raw():
    methods = [
        ("selected-item", 12, 16723, "_ZN18CmnViewSettingNode15getSelectedItemEPPS_", "0x7c6bd3", "0x7c6bd2", "0x7d6bd2", 68),
        ("selected-item", 13, 17912, "_ZN18CmnViewSettingNode20getIndexSelectedItemERi", "0x7c6c17", "0x7c6c16", "0x7d6c16", 20),
        ("selected-item", 14, 19101, "_ZN18CmnViewSettingNode20getSRNumSelectedItemERi", "0x7c6c2b", "0x7c6c2a", "0x7d6c2a", 36),
        ("state", 21, 27424, "_ZN18CmnViewSettingNode8getStateERi", "0x7c6d53", "0x7c6d52", "0x7d6d52", 12),
        ("state", 22, 28613, "_ZN18CmnViewSettingNode15getStateByIndexEiRi", "0x7c6d5f", "0x7c6d5e", "0x7d6d5e", 36),
        ("state", 23, 29802, "_ZN18CmnViewSettingNode15getStateBySRNumEiRi", "0x7c6d83", "0x7c6d82", "0x7d6d82", 36),
        ("selected-item", 39, 48826, "_ZN18CmnViewSettingNode14isItemSelectedEv", "0x7c6f27", "0x7c6f26", "0x7d6f26", 34),
        ("selected-item", 40, 50015, "_ZN18CmnViewSettingNode21isItemSelectedByIndexEi", "0x7c6f49", "0x7c6f48", "0x7d6f48", 34),
        ("selected-item", 41, 51204, "_ZN18CmnViewSettingNode21isItemSelectedBySRNumEi", "0x7c6f6b", "0x7c6f6a", "0x7d6f6a", 34),
        ("set-selected", 48, 59527, "_ZN18CmnViewSettingNode15setItemSelectedEv", "0x7c705b", "0x7c705a", "0x7d705a", 128),
        ("set-selected", 49, 60716, "_ZN18CmnViewSettingNode22setItemSelectedByIndexEi", "0x7c70db", "0x7c70da", "0x7d70da", 34),
        ("set-selected", 50, 61905, "_ZN18CmnViewSettingNode22setItemSelectedBySRNumEi", "0x7c70fd", "0x7c70fc", "0x7d70fc", 34),
        ("set-selected", 51, 63094, "_ZN18CmnViewSettingNode26setItemSelectedByDiffSRNumEi", "0x7c711f", "0x7c711e", "0x7d711e", 62),
        ("set-selected", 63, 76174, "_ZN18CmnViewSettingNode17setItemUnselectedEv", "0x7c72fb", "0x7c72fa", "0x7d72fa", 50),
    ]
    return {
        "program": "CautionConfig.so", "sha256": CAUTION_CONFIG_SHA256, "file_size": CAUTION_CONFIG_SIZE,
        "analysis_mode": {"read_only": True, "static_elf_metadata": True, "thumb_control_flow": True},
        "program_changed": False, "analysis_load_bias": "0x10000",
        "generic_methods": [
            {"group": group, "slot": slot, "relocation_index": relocation_index,
             "relocation_type": "R_ARM_ABS32", "symbol": symbol, "elf_thumb_target": thumb,
             "elf_owner": elf_owner, "analysis_owner": analysis_owner, "function_size": size}
            for group, slot, relocation_index, symbol, thumb, elf_owner, analysis_owner, size in methods
        ],
        "named_direct_control_flow": [], "dynamic_typed_relocations": [], "pp1_pp9_references": [],
        "constructor_plt_bindings": [
            {"role": "copy-construction", "relocation_index": 676, "relocation_type": "R_ARM_JUMP_SLOT", "got_address": "0xb0cc64", "plt_elf_address": "0x7b3540", "plt_analysis_address": "0x7c3540", "symbol": "_ZN32CmnViewSettingNodePictureProfileC1ERKS_"},
            {"role": "construction", "relocation_index": 3601, "relocation_type": "R_ARM_JUMP_SLOT", "got_address": "0xb0fa18", "plt_elf_address": "0x7bbe70", "plt_analysis_address": "0x7cbe70", "symbol": "_ZN32CmnViewSettingNodePictureProfileC1EPP18CmnViewSettingNodeiPK24CmnViewSettingProperties"},
        ],
        "prior_artifacts": {
            "handoff_sha256": "c1c792b2aa28bbae168209329df4c0ce46dc5834f0d024f8d21cebb364aa74ff",
            "clone_boundary_sha256": "d95b525159e1ad291eab0a6b05dfede9cfedb49398ceb811db512ae8102690da",
            "vtable_interface_sha256": "e8772c3112c8eea444ab5778dfa8cd7b39bed1592b39dbe920e914f831368f59",
        },
        "selected_state_paths": [], "persistence_paths": [], "processing_paths": [], "output_paths": [],
        "reuse_paths": [], "truncated": False,
    }


def exporter_module():
    spec = importlib.util.spec_from_file_location("pp_generic_consumer_exporter", EXPORTER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PictureProfileGenericConsumerTests(unittest.TestCase):
    def test_exact_generic_methods_and_empty_bounded_results_are_fail_closed(self):
        summary = normalize_picture_profile_generic_consumer_export(raw())
        self.assertEqual(summary["generic_method_count"], 14)
        self.assertEqual(summary["claims"], CLAIMS)

    def test_binding_path_and_safety_tampering_is_rejected(self):
        mutations = (
            lambda value: value.update(program="other.so"),
            lambda value: value["analysis_mode"].update(thumb_control_flow=False),
            lambda value: value.update(program_changed=True),
            lambda value: value["generic_methods"][0].update(slot=11),
            lambda value: value["generic_methods"][0].update(function_size=66),
            lambda value: value["generic_methods"][0].update(analysis_owner="0x7c6bd2"),
            lambda value: value["named_direct_control_flow"].append({"forged": True}),
            lambda value: value["dynamic_typed_relocations"].append({"forged": True}),
            lambda value: value["pp1_pp9_references"].append({"forged": True}),
            lambda value: value["constructor_plt_bindings"].reverse(),
            lambda value: value["constructor_plt_bindings"][1].update(got_address="0x0"),
            lambda value: value["prior_artifacts"].update(handoff_sha256="0" * 64),
            lambda value: value["selected_state_paths"].append({"forged": True}),
            lambda value: value["reuse_paths"].append({"forged": True}),
            lambda value: value.update(raw_bytes="forbidden"),
        )
        for mutate in mutations:
            value = raw()
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(PictureProfileGenericConsumerError):
                normalize_picture_profile_generic_consumer_export(value)

    def test_report_is_digest_pinned_and_cannot_promote_reuse(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertEqual(validate_picture_profile_generic_consumer_report(report), report)
        for mutate in (
            lambda value: value["summary"].update(artifact_sha256="0" * 64),
            lambda value: value["claims"].update(interface_reuse_found=True),
            lambda value: value.update(camera_policy="unknown"),
        ):
            value = copy.deepcopy(report)
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(PictureProfileGenericConsumerError):
                validate_picture_profile_generic_consumer_report(value)

    @unittest.skipUnless(RAW_ARTIFACT.is_file(), "ignored static artifact unavailable")
    def test_committed_report_digest_matches_actual_ignored_raw_artifact(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        raw_document = json.loads(RAW_ARTIFACT.read_text(encoding="utf-8"))
        self.assertEqual(
            normalize_picture_profile_generic_consumer_export(raw_document)["artifact_sha256"],
            report["summary"]["artifact_sha256"],
        )


class ExporterTests(unittest.TestCase):
    @unittest.skipUnless(exporter_module().capstone_available(), "local Capstone decoder unavailable")
    def test_static_export_pins_generic_methods_and_empty_results(self):
        document = exporter_module().build_raw_export()
        self.assertEqual(document["generic_methods"], raw()["generic_methods"])
        self.assertEqual(document["named_direct_control_flow"], [])

    def test_output_is_contained(self):
        module = exporter_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            allowed, denied = root / "allowed", root / "denied"
            allowed.mkdir(); denied.mkdir()
            with self.assertRaises(RuntimeError):
                module.write_json_atomic(denied / "raw-picture-profile-generic-consumers.json", {}, allowed)

    def test_output_rejects_symlinked_literal_approved_root(self):
        module = exporter_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target, linked = root / "target", root / "linked"
            target.mkdir()
            try:
                linked.symlink_to(target, target_is_directory=True)
            except OSError as exc:
                self.skipTest("Windows cannot create test symlinks: %s" % exc)
            with self.assertRaises(RuntimeError):
                module.write_json_atomic(linked / "raw-picture-profile-generic-consumers.json", {}, linked)


if __name__ == "__main__":
    unittest.main()
