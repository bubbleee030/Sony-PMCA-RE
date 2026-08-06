"""Fail-closed tests for the α6400 Picture Profile initializer registration trace."""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from pmca.analysis.picture_profile_initializer_registration import (
    CAUTION_CONFIG_SHA256,
    CAUTION_CONFIG_SIZE,
    PictureProfileInitializerRegistrationError,
    normalize_picture_profile_initializer_registration_export,
    validate_picture_profile_initializer_registration_report,
)


ROOT = Path(__file__).resolve().parents[2]
EXPORTER = ROOT / "tools" / "static" / "export_a6400_picture_profile_initializer_registration.py"
REPORT = ROOT / "analysis" / "a6400-picture-profile-initializer-registration.json"
RAW_ARTIFACT = ROOT / ".artifacts" / "picture-profile-initializer-registration-trace" / "a6400-v2.00" / "raw-picture-profile-initializer-registration.json"


def raw():
    return {
        "program": "CautionConfig.so",
        "sha256": CAUTION_CONFIG_SHA256,
        "file_size": CAUTION_CONFIG_SIZE,
        "analysis_mode": {"read_only": True, "static_elf_metadata": True, "source_unchanged": True},
        "program_changed": False,
        "init_array": {
            "elf_address": "0xaa6290", "size": 24,
            "entries": [
                {"relocation_index": 0, "relocation_address": "0xaa6290", "relocation_type": "R_ARM_RELATIVE", "symbol_index": 0, "thumb_target": "0x7bf5e1", "elf_owner": "0x7bf5e0", "analysis_owner": "0x7cf5e0"},
                {"relocation_index": 1, "relocation_address": "0xaa6294", "relocation_type": "R_ARM_RELATIVE", "symbol_index": 0, "thumb_target": "0x7c7809", "elf_owner": "0x7c7808", "analysis_owner": "0x7d7808"},
                {"relocation_index": 2, "relocation_address": "0xaa6298", "relocation_type": "R_ARM_RELATIVE", "symbol_index": 0, "thumb_target": "0x7c792d", "elf_owner": "0x7c792c", "analysis_owner": "0x7d792c"},
                {"relocation_index": 3, "relocation_address": "0xaa629c", "relocation_type": "R_ARM_RELATIVE", "symbol_index": 0, "thumb_target": "0x8251f9", "elf_owner": "0x8251f8", "analysis_owner": "0x8351f8"},
                {"relocation_index": 4, "relocation_address": "0xaa62a0", "relocation_type": "R_ARM_RELATIVE", "symbol_index": 0, "thumb_target": "0x93aff5", "elf_owner": "0x93aff4", "analysis_owner": "0x94aff4"},
                {"relocation_index": 5, "relocation_address": "0xaa62a4", "relocation_type": "R_ARM_RELATIVE", "symbol_index": 0, "thumb_target": "0x93b075", "elf_owner": "0x93b074", "analysis_owner": "0x94b074"},
            ],
        },
        "initializer_owner": {"elf_range_start": "0x8251f8", "elf_range_end": "0x93aff4", "analysis_range_start": "0x8351f8", "analysis_range_end": "0x94aff4", "evidence": "ARM.exidx-function"},
        "prior_artifacts": {"handoff_sha256": "c1c792b2aa28bbae168209329df4c0ce46dc5834f0d024f8d21cebb364aa74ff", "generic_consumer_sha256": "b068bf450d0c27689fa44c4f3d1698dcebb60aab5771584752385d62b08340bf"},
        "pp1_pp9_construction": {"constructor_parameter_reference_count": 18, "analysis_owner": "0x8351f8"},
        "bounded_elf_inventory": {"roots": ["lib", "bin", "sabin", "sbin"], "elf_file_count": 184, "canonical_inventory_sha256": "d5f4813f79834917315275747f19ed568d040c0dbbfde9b7f96b8dd8c89ccf50"},
        "named_symbol_scan": {"exact_name_fragments": ["CmnViewSettingNodePictureProfile", "cmnViewSettingNodePictureProfile", "cmnViewSettingPropertyListPictureProfile"], "defining_modules": ["lib/CautionConfig.so"], "direct_named_cross_module_imports": [], "persistence_verb_symbols": []},
        "dt_needed": ["libpthread.so.0", "libstdc++.so.6", "libm.so.6", "libdl.so.2", "libgcc_s.so.1", "libc.so.6", "librt.so.1"],
        "selected_state_paths": [], "ui_dispatch_paths": [], "persistence_paths": [], "processing_paths": [], "output_paths": [],
        "truncated": False,
    }


def exporter_module():
    spec = importlib.util.spec_from_file_location("pp_initializer_exporter", EXPORTER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class InitializerRegistrationContractTests(unittest.TestCase):
    def test_exact_loader_registration_is_not_promoted_to_state_or_creative_look(self):
        summary = normalize_picture_profile_initializer_registration_export(raw())
        self.assertEqual(summary["initializer_entry_count"], 6)
        self.assertEqual(summary["constructor_parameter_reference_count"], 18)
        self.assertEqual(summary["readiness"], "STATIC_CONSTRUCTION_REGISTRATION_ONLY")

    def test_tampering_or_unbounded_cross_module_claims_are_rejected(self):
        mutations = (
            lambda value: value["init_array"]["entries"][3].update(thumb_target="0x8251f7"),
            lambda value: value["init_array"].update(size=20),
            lambda value: value["initializer_owner"].update(elf_range_end="0x93b074"),
            lambda value: value["prior_artifacts"].update(handoff_sha256="0" * 64),
            lambda value: value["pp1_pp9_construction"].update(constructor_parameter_reference_count=17),
            lambda value: value["bounded_elf_inventory"].update(elf_file_count=183),
            lambda value: value["named_symbol_scan"]["defining_modules"].append("lib/viewUnified2.so"),
            lambda value: value["named_symbol_scan"]["direct_named_cross_module_imports"].append({"forged": True}),
            lambda value: value["named_symbol_scan"]["persistence_verb_symbols"].append("savePictureProfile"),
            lambda value: value["selected_state_paths"].append({"forged": True}),
            lambda value: value.update(raw_bytes="forbidden"),
        )
        for mutate in mutations:
            value = raw()
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(PictureProfileInitializerRegistrationError):
                normalize_picture_profile_initializer_registration_export(value)

    def test_committed_report_is_pinned_and_non_installable(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertEqual(validate_picture_profile_initializer_registration_report(report), report)
        value = copy.deepcopy(report)
        value["claims"]["selected_profile_state_found"] = True
        with self.assertRaises(PictureProfileInitializerRegistrationError):
            validate_picture_profile_initializer_registration_report(value)

    @unittest.skipUnless(RAW_ARTIFACT.is_file(), "ignored static artifact unavailable")
    def test_committed_digest_matches_actual_ignored_static_artifact(self):
        document = json.loads(RAW_ARTIFACT.read_text(encoding="utf-8"))
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertEqual(normalize_picture_profile_initializer_registration_export(document)["artifact_sha256"], report["summary"]["artifact_sha256"])


class InitializerRegistrationExporterTests(unittest.TestCase):
    def test_inventory_identity_is_independent_of_declared_root_order(self):
        module = exporter_module()
        records = [
            {"path": "lib/z.so", "size": 2, "sha256": "a" * 64},
            {"path": "bin/a.elf", "size": 1, "sha256": "b" * 64},
        ]
        self.assertEqual(module.canonical_inventory_digest(records), module.canonical_inventory_digest(list(reversed(records))))

    def test_output_root_rejects_escape_and_symlink(self):
        module = exporter_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            allowed, denied = root / "allowed", root / "denied"
            allowed.mkdir(); denied.mkdir()
            with self.assertRaises(RuntimeError):
                module.write_json_atomic(denied / "raw-picture-profile-initializer-registration.json", {}, allowed)
            linked = root / "linked"
            try:
                linked.symlink_to(allowed, target_is_directory=True)
            except OSError as error:
                self.skipTest("Windows cannot create test symlinks: %s" % error)
            with self.assertRaises(RuntimeError):
                module.write_json_atomic(linked / "raw-picture-profile-initializer-registration.json", {}, linked)

    @unittest.skipUnless(exporter_module().pyelftools_available(), "local pyelftools dependency unavailable")
    def test_static_export_matches_exact_initializer_contract(self):
        document = exporter_module().build_raw_export()
        self.assertEqual(document, raw())


if __name__ == "__main__":
    unittest.main()
