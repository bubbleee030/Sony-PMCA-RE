import copy
import io
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = ROOT / "analysis" / "a6400-creative-style-definition-registration.json"
EXPORTER_PATH = ROOT / "tools" / "static" / "export_a6400_creative_style_definition_registration.py"


class CreativeStyleDefinitionRegistrationTests(unittest.TestCase):
    def test_contract_accepts_only_pinned_publication_and_interface_metadata(self):
        from pmca.analysis.creative_style_definition_registration import (
            EXPECTED_RAW_EXPORT,
            normalize_creative_style_definition_registration_export,
        )

        summary = normalize_creative_style_definition_registration_export(copy.deepcopy(EXPECTED_RAW_EXPORT))
        self.assertEqual(summary["publication_relocation_index"], 87605)
        self.assertEqual(summary["vtable_typed_relocation_count"], 66)
        self.assertTrue(summary["claims"]["creative_style_definition_found"])
        self.assertTrue(summary["claims"]["root_constructor_binding_found"])
        self.assertFalse(summary["claims"]["root_constructor_runtime_provider_proven"])
        binding = EXPECTED_RAW_EXPORT["root_constructor_bindings"][0]
        self.assertEqual(binding["root_object"], "0xc5ae38")
        self.assertEqual(binding["properties_object"], "0xc10a38")
        self.assertEqual(binding["call_site"], "0x93b344")
        self.assertEqual(binding["reachable_init_array_indices"], [5])
        self.assertEqual(binding["entry_to_call_edge_count"], 250)
        self.assertFalse(binding["owner_decode_complete"])
        self.assertTrue(binding["static_init_reachable"])
        self.assertFalse(binding["runtime_provider_binding_proven"])

    def test_contract_rejects_promoted_or_fabricated_metadata(self):
        from pmca.analysis.creative_style_definition_registration import (
            EXPECTED_RAW_EXPORT,
            CreativeStyleDefinitionRegistrationError,
            normalize_creative_style_definition_registration_export,
        )

        mutations = (
            lambda value: value["root"]["symbol_index"].__class__,
            lambda value: value["publication"]["object_offset"].__class__,
        )
        # Perform concrete one-at-a-time corruptions so this remains a real contract test.
        candidates = []
        wrong_index = copy.deepcopy(EXPECTED_RAW_EXPORT)
        wrong_index["root"]["symbol_index"] = 31508
        candidates.append(wrong_index)
        wrong_offset = copy.deepcopy(EXPECTED_RAW_EXPORT)
        wrong_offset["publication"]["object_offset"] = "0x40"
        candidates.append(wrong_offset)
        promoted = copy.deepcopy(EXPECTED_RAW_EXPORT)
        promoted["claims"]["persistence_found"] = True
        candidates.append(promoted)
        unsafe = copy.deepcopy(EXPECTED_RAW_EXPORT)
        unsafe["raw_bytes"] = []
        candidates.append(unsafe)
        for candidate in candidates:
            with self.subTest(candidate=candidate.get("root", {}).get("symbol_index")):
                with self.assertRaises(CreativeStyleDefinitionRegistrationError):
                    normalize_creative_style_definition_registration_export(candidate)

    def test_report_is_static_noninstallable_and_does_not_promote_creative_look(self):
        from pmca.analysis.creative_style_definition_registration import (
            CreativeStyleDefinitionRegistrationError,
            validate_creative_style_definition_registration_report,
        )

        report = validate_creative_style_definition_registration_report(json.loads(REPORT_PATH.read_text(encoding="utf-8")))
        self.assertFalse(report["installable"])
        self.assertFalse(report["camera_test_eligible"])
        self.assertFalse(report["claims"]["first_class_creative_look"])
        forged = copy.deepcopy(report)
        forged["claims"]["selected_state_found"] = True
        with self.assertRaises(CreativeStyleDefinitionRegistrationError):
            validate_creative_style_definition_registration_report(forged)


class CreativeStyleDefinitionRegistrationExporterTests(unittest.TestCase):
    def _load(self):
        spec = importlib.util.spec_from_file_location("creative_style_definition_registration_exporter", EXPORTER_PATH)
        exporter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(exporter)
        return exporter

    def test_exporter_rejects_fabricated_metadata_before_writing(self):
        exporter = self._load()

        class Adapter:
            def metadata(self):
                value = copy.deepcopy(exporter.EXPECTED_RAW_EXPORT)
                value["negative_symbol_scan"] = {"name_fragments": ["CreativeStyle"], "verbs": ["save"], "matches": ["fabricated"]}
                return value

        with self.assertRaises(RuntimeError):
            exporter.build_raw_export(Adapter())

    def test_root_constructor_source_mutation_is_rejected(self):
        """Break caught: a literal call label may not replace exact constructor flow."""
        exporter = self._load()
        binary = bytearray(exporter.SOURCE.read_bytes())
        _arch, _mode, _mem, _cs, ELFFile = exporter._deps()
        with io.BytesIO(bytes(binary)) as stream:
            mappings = exporter._load_mappings(ELFFile(stream))
        address = 0x93B344
        for start, end, file_offset in mappings:
            if start <= address < end:
                binary[file_offset + address - start] ^= 1
                break
        else:
            self.fail("root constructor call is not file-backed")
        with io.BytesIO(bytes(binary)) as stream:
            elf = ELFFile(stream)
            with self.assertRaises(RuntimeError):
                exporter._root_constructor_bindings(
                    elf, bytes(binary), exporter._load_mappings(elf)
                )

    def test_prepare_output_root_rejects_precreation_ancestor_symlink_escape(self):
        exporter = self._load()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary) / "artifacts"
            base.mkdir()
            escaped = Path(temporary) / "escaped"
            escaped.mkdir()
            link = base / "creative-style-definition-registration-trace"
            try:
                link.symlink_to(escaped, target_is_directory=True)
            except (NotImplementedError, OSError):
                self.skipTest("symlink creation unavailable")
            with self.assertRaises(RuntimeError):
                exporter.prepare_output_root(base / "creative-style-definition-registration-trace" / "a6400-v2.00", base)

    def test_prepare_output_root_rejects_a_dangling_ancestor_symlink(self):
        exporter = self._load()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary) / "artifacts"
            base.mkdir()
            link = base / "creative-style-definition-registration-trace"
            try:
                link.symlink_to(Path(temporary) / "missing-target", target_is_directory=True)
            except (NotImplementedError, OSError):
                self.skipTest("symlink creation unavailable")
            with self.assertRaises(RuntimeError):
                exporter.prepare_output_root(base / "creative-style-definition-registration-trace" / "a6400-v2.00", base)

    def test_writer_rejects_noncanonical_output_and_symlink_target(self):
        exporter = self._load()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary) / "artifacts"
            root = base / "creative-style-definition-registration-trace" / "a6400-v2.00"
            root.mkdir(parents=True)
            with mock.patch.object(exporter, "OUTPUT_ROOT", root), mock.patch.object(exporter, "ARTIFACT_BASE", base):
                exporter.write_json_atomic(root / "raw-creative-style-definition-registration.json", exporter.EXPECTED_RAW_EXPORT, root, base)
                with self.assertRaises(RuntimeError):
                    exporter.write_json_atomic(root / "elsewhere.json", exporter.EXPECTED_RAW_EXPORT, root, base)
                target = root / "raw-creative-style-definition-registration.json"
                with mock.patch.object(exporter.Path, "is_symlink", return_value=True):
                    with self.assertRaises(RuntimeError):
                        exporter.write_json_atomic(target, exporter.EXPECTED_RAW_EXPORT, root, base)


if __name__ == "__main__":
    unittest.main()
