import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "pmca" / "analysis" / "creative_style_registry_consumers.py"
EXPORTER_PATH = ROOT / "tools" / "static" / "export_a6400_creative_style_registry_consumers.py"
REPORT_PATH = ROOT / "analysis" / "a6400-creative-style-registry-consumers.json"
ROOT_CONSUMERS_REPORT_PATH = ROOT / "analysis" / "a6400-creative-style-root-consumers.json"


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_LIVE_EXPORT = {}


def _live_registry_export():
    if not _LIVE_EXPORT:
        exporter = _load(EXPORTER_PATH, "creative_style_registry_consumers_live_exporter")
        if not exporter.pyelftools_available():
            raise unittest.SkipTest("local pyelftools unavailable")
        _LIVE_EXPORT.update({"exporter": exporter, "document": exporter.build_raw_export()})
    return _LIVE_EXPORT["exporter"], copy.deepcopy(_LIVE_EXPORT["document"])


class CreativeStyleRegistryConsumersTests(unittest.TestCase):
    def test_prior_root_consumer_digest_matches_the_current_validated_report(self):
        module = _load(MODULE_PATH, "creative_style_registry_consumers_prior_contract")
        from pmca.analysis.creative_style_root_consumers import (
            validate_creative_style_root_consumers_report,
        )

        upstream = validate_creative_style_root_consumers_report(
            json.loads(ROOT_CONSUMERS_REPORT_PATH.read_text(encoding="utf-8"))
        )
        self.assertEqual(
            module.PRIOR_ARTIFACTS["creative_style_root_consumers_sha256"],
            upstream["export_summary"]["canonical_export_sha256"],
        )

    def test_normalizer_rejects_incomplete_duplicate_and_promoted_registry(self):
        spec = importlib.util.spec_from_file_location("creative_style_registry_consumers", MODULE_PATH)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        exporter, raw = _live_registry_export()
        self.assertEqual(len(raw["registry_entries"]), 415)
        self.assertEqual(raw["registry_entries"][15]["target_symbol"], "cmnViewSettingNodeRootCreativeStyle")
        self.assertTrue(all(entry.get("target_binding") == "STB_GLOBAL" for entry in raw["registry_entries"]))
        self.assertTrue(all(entry.get("target_defined") is True for entry in raw["registry_entries"]))
        self.assertEqual(sum(item["cell_count"] for item in raw["data_cell_symbol_coverage"]), 58)
        for mutate in (
            lambda value: value["registry_entries"].pop(),
            lambda value: value["registry_entries"].__setitem__(1, copy.deepcopy(value["registry_entries"][0])),
            lambda value: value["claims"].__setitem__("creative_look_found", True),
        ):
            candidate = copy.deepcopy(raw); mutate(candidate)
            if len(candidate["registry_entries"]) == 415:
                candidate["registry_entries_sha256"] = exporter._registry_digest(candidate["registry_entries"])
            with self.subTest(mutate=mutate), self.assertRaises(module.CreativeStyleRegistryConsumersError):
                module.normalize_creative_style_registry_consumers_export(candidate)

    def test_normalizer_pins_every_target_name_section_binding_and_definition(self):
        module = _load(MODULE_PATH, "creative_style_registry_consumers_target_contract")
        exporter, raw = _live_registry_export()
        mutations = (
            lambda value: value["registry_entries"][16].__setitem__("target_symbol", "cmnViewSettingNodeRootInvented"),
            lambda value: value["registry_entries"][16].__setitem__("target_section", ".got"),
            lambda value: value["registry_entries"][16].__setitem__("target_binding", "STB_LOCAL"),
            lambda value: value["registry_entries"][16].__setitem__("target_defined", False),
        )
        for mutate in mutations:
            candidate = copy.deepcopy(raw)
            mutate(candidate)
            candidate["registry_entries_sha256"] = exporter._registry_digest(candidate["registry_entries"])
            with self.subTest(mutate=mutate), self.assertRaises(module.CreativeStyleRegistryConsumersError):
                module.normalize_creative_style_registry_consumers_export(candidate)

    def test_normalizer_requires_unique_exact_coverage_and_abs32_inventories(self):
        module = _load(MODULE_PATH, "creative_style_registry_consumers_coverage_contract")
        _exporter, raw = _live_registry_export()
        mutations = (
            lambda value: value["data_cell_symbol_coverage"].append(copy.deepcopy(value["data_cell_symbol_coverage"][0])),
            lambda value: value["data_cell_symbol_coverage"][0].__setitem__("cell_count", 50),
            lambda value: value["consumer_relocations"]["lib/viewUnified2.so"]["creative_style_abs32"][0].__setitem__("site", "0x951290"),
            lambda value: value["consumer_relocations"]["lib/viewUnified4.so"]["creative_style_abs32"].append(copy.deepcopy(value["consumer_relocations"]["lib/viewUnified4.so"]["creative_style_abs32"][0])),
        )
        for mutate in mutations:
            candidate = copy.deepcopy(raw)
            mutate(candidate)
            with self.subTest(mutate=mutate), self.assertRaises(module.CreativeStyleRegistryConsumersError):
                module.normalize_creative_style_registry_consumers_export(candidate)

    def test_report_is_noninstallable_and_preserves_unresolved_indirect_consumers(self):
        spec = importlib.util.spec_from_file_location("creative_style_registry_consumers", MODULE_PATH)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        report = module.validate_creative_style_registry_consumers_report(json.loads(REPORT_PATH.read_text(encoding="utf-8")))
        self.assertFalse(report["installable"])
        self.assertFalse(report["claims"]["indirect_data_consumers_found"])


class CreativeStyleRegistryConsumersExporterTests(unittest.TestCase):
    def test_pyelftools_guard_uses_the_exporter_dependency_resolver(self):
        exporter = _load(EXPORTER_PATH, "creative_style_registry_consumers_dependency_guard")
        self.assertTrue(hasattr(exporter, "pyelftools_available"))
        with mock.patch.object(exporter, "_dependencies", side_effect=RuntimeError("missing")):
            self.assertFalse(exporter.pyelftools_available())
        with mock.patch.object(exporter, "_dependencies", side_effect=ImportError("broken fallback")):
            self.assertFalse(exporter.pyelftools_available())

    def test_reference_metadata_keeps_named_symbols_when_relocations_are_absent(self):
        exporter = _load(EXPORTER_PATH, "creative_style_registry_consumers_reference_metadata")

        class Symbol:
            def __init__(self, name):
                self.name = name

        class Symbols:
            def iter_symbols(self):
                return iter((Symbol(""), Symbol("cmnViewSettingNodesRootDefault")))

        class Elf:
            def get_section_by_name(self, name):
                return Symbols() if name == ".dynsym" else None

        self.assertEqual(
            exporter._registry_reference_metadata(Elf()),
            {"symbol_indexes": {"cmnViewSettingNodesRootDefault": 1}, "plt_reference_indices": []},
        )

    def test_canonical_inventory_digest_is_order_independent(self):
        spec = importlib.util.spec_from_file_location("creative_style_registry_consumers_exporter", EXPORTER_PATH)
        exporter = importlib.util.module_from_spec(spec); spec.loader.exec_module(exporter)
        records = [{"path": "b", "size": 1, "sha256": "b"}, {"path": "a", "size": 2, "sha256": "a"}]
        self.assertEqual(exporter.canonical_inventory_digest(records), exporter.canonical_inventory_digest(list(reversed(records))))

    def test_output_rejects_escape_and_symlinked_ancestor(self):
        spec = importlib.util.spec_from_file_location("creative_style_registry_consumers_exporter", EXPORTER_PATH)
        exporter = importlib.util.module_from_spec(spec); spec.loader.exec_module(exporter)
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve() / "artifacts"; base.mkdir()
            root = base / "trace"
            with mock.patch.object(exporter, "OUTPUT_ROOT", root):
                exporter.write_json_atomic(root / exporter.OUTPUT_NAME, {"ok": True}, approved_root=root, artifact_base=base)
                with self.assertRaises(RuntimeError):
                    exporter.write_json_atomic(base / "outside.json", {"ok": True}, approved_root=root, artifact_base=base)
            with mock.patch.object(exporter.Path, "is_symlink", return_value=True):
                with self.assertRaises(RuntimeError):
                    exporter.prepare_output_root(root, base)


if __name__ == "__main__":
    unittest.main()
