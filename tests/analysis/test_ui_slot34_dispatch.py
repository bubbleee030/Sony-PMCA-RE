import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = ROOT / "analysis" / "a6400-ui-slot34-dispatch.json"
EXPORTER_PATH = ROOT / "tools" / "static" / "export_a6400_ui_slot34_dispatch.py"
ARTIFACT_ROOT = ROOT / ".artifacts"
FIRMWARE_LIB = ARTIFACT_ROOT / "decrypted" / "a6400-tw-v2.00" / "ma1co" / "firmware.tar_unpacked" / "0700_part_image" / "dev" / "nflasha15_unpacked" / "lib"
VTABLE_EXPORT = ARTIFACT_ROOT / "ui-layout-vtable-interface-trace" / "a6400-v2.00" / "raw-ui-layout-vtable-interface.json"
OWNER_EXPORT = ARTIFACT_ROOT / "ui-factory-owner-registration-trace" / "a6400-v2.00" / "raw-ui-factory-owner-registration.json"


class UISlot34DispatchTests(unittest.TestCase):
    def test_normalizer_requires_separate_pinned_runtime_name_occurrences(self):
        """Catches claims that turn independent strings into a shared registry."""
        from pmca.analysis.ui_slot34_dispatch import (
            UISlot34DispatchError,
            EXPECTED_RAW_EXPORT,
            normalize_ui_slot34_dispatch_export,
        )

        # Hand-derived from the pinned VU2/VU7 inputs.  The two strings are
        # separate unique NUL-terminated occurrences; their shared container
        # and any resulting runtime dispatch remain unproven.
        candidate = copy.deepcopy(EXPECTED_RAW_EXPORT)
        candidate["runtime_consumption_boundary"] = {
            "vu2_source": {
                "module": "lib/viewUnified2.so",
                "size": 11_530_552,
                "sha256": "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2",
            },
            "unique_nul_terminated_name_occurrences": [
                {"name": "viewUnified7.so", "address": 0x7AEBE2, "occurrence_count": 1},
                {"name": "17LkmLayoutModeMngr", "address": 0x7AEC2F, "occurrence_count": 1},
            ],
            "same_registry_or_container_proven": False,
            "dynamic_linkage": {"vu2_needed_vu7": False, "vu7_needed_vu2": False},
            "typed_layout_dynsym_linkage": {
                "checked_modules": ["lib/viewUnified2.so", "lib/viewUnified7.so"],
                "layoutst_dial_modules": [],
                "layout_converter_base_modules": [],
            },
            "first_unresolved_boundary": "runtime-loading-object-selection-and-dispatch-consumption",
        }
        normalized = normalize_ui_slot34_dispatch_export(candidate)
        self.assertFalse(normalized["runtime_consumption_boundary"]["same_registry_or_container_proven"])
        self.assertEqual(normalized["runtime_consumption_boundary"]["unique_nul_terminated_name_occurrences"][0]["address"], 0x7AEBE2)
        forged = copy.deepcopy(normalized)
        forged["runtime_consumption_boundary"]["same_registry_or_container_proven"] = True
        with self.assertRaises(UISlot34DispatchError):
            normalize_ui_slot34_dispatch_export(forged)

    def test_normalizer_accepts_only_the_pinned_empty_structural_result(self):
        from pmca.analysis.ui_slot34_dispatch import (
            EXPECTED_RAW_EXPORT,
            normalize_ui_slot34_dispatch_export,
        )

        normalized = normalize_ui_slot34_dispatch_export(copy.deepcopy(EXPECTED_RAW_EXPORT))
        self.assertEqual(len(normalized["header_references"]), 5)
        self.assertEqual(
            normalized["header_references"][0]["addend"],
            normalized["table_evidence"][0]["header"],
        )
        self.assertEqual(
            set(normalized["structural_scan"]["direct_pc_literal_loads"][0]),
            {"kind", "function", "site"},
        )
        self.assertEqual(normalized["structural_scan"]["accepted_candidates"], [])
        self.assertEqual(normalized["direct_owner_inbound_edges"], [])
        self.assertEqual(normalized["root_path_summary"]["paths_to_owner"], [])
        self.assertFalse(normalized["claims"]["slot_34_dispatch_found"])
        self.assertFalse(normalized["behavior_support"]["menu_touch_selection"])

    def test_normalizer_rejects_fabricated_dispatches_promotions_and_unpinned_evidence(self):
        from pmca.analysis.ui_slot34_dispatch import (
            UISlot34DispatchError,
            EXPECTED_RAW_EXPORT,
            normalize_ui_slot34_dispatch_export,
        )

        mutations = (
            lambda value: value["structural_scan"].__setitem__("accepted_candidates", [{"function": 0x529CC}]),
            lambda value: value["header_references"][0].__setitem__("addend", value["table_evidence"][0]["address_point"]),
            lambda value: value["direct_owner_inbound_edges"].append({"caller": 0x1000, "site": 0x1002}),
            lambda value: value["root_path_summary"]["paths_to_owner"].append([0x2D2C6, 0x529CC]),
            lambda value: value["prior_vtable_interface"].__setitem__("canonical_export_sha256", "0" * 64),
            lambda value: value["claims"].__setitem__("slot_34_dispatch_found", True),
            lambda value: value.__setitem__("instructions", []),
        )
        for mutate in mutations:
            candidate = copy.deepcopy(EXPECTED_RAW_EXPORT)
            mutate(candidate)
            with self.subTest(mutate=mutate), self.assertRaises(UISlot34DispatchError):
                normalize_ui_slot34_dispatch_export(candidate)

    def test_report_is_pinned_noninstallable_and_retains_unresolved_routes(self):
        from pmca.analysis.ui_slot34_dispatch import (
            UISlot34DispatchError,
            validate_ui_slot34_dispatch_report,
        )

        report = validate_ui_slot34_dispatch_report(json.loads(REPORT_PATH.read_text(encoding="utf-8")))
        self.assertFalse(report["installable"])
        self.assertFalse(report["camera_test_eligible"])
        self.assertEqual(report["structural_scan"]["accepted_candidate_count"], 0)
        self.assertIn("runtime loading", report["conclusion"])
        forged = copy.deepcopy(report)
        forged["behavior_support"]["menu_touch_selection"] = True
        with self.assertRaises(UISlot34DispatchError):
            validate_ui_slot34_dispatch_report(forged)


class UISlot34DispatchExporterTests(unittest.TestCase):
    def _load(self):
        spec = importlib.util.spec_from_file_location("ui_slot34_dispatch_exporter", EXPORTER_PATH)
        exporter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(exporter)
        return exporter

    def test_exporter_requires_exact_static_metadata(self):
        exporter = self._load()

        class Adapter:
            def metadata(self):
                return copy.deepcopy(exporter.EXPECTED_RAW_EXPORT)

        raw = exporter.build_raw_export(Adapter())
        self.assertEqual(raw["structural_scan"]["accepted_candidates"], [])
        self.assertEqual(len(raw["header_references"]), 5)

    def test_file_adapter_requires_the_pinned_runtime_name_sources(self):
        """Exercises source validation, not a hand-written metadata adapter."""
        if not all(path.is_file() for path in (FIRMWARE_LIB / "viewUnified7.so", FIRMWARE_LIB / "viewUnified2.so", VTABLE_EXPORT, OWNER_EXPORT)):
            self.skipTest("pinned offline static inputs are unavailable")
        exporter = self._load()
        raw = exporter.build_raw_export(exporter.FileAdapter(FIRMWARE_LIB / "viewUnified7.so", VTABLE_EXPORT, OWNER_EXPORT, FIRMWARE_LIB / "viewUnified2.so"))
        boundary = raw["runtime_consumption_boundary"]
        self.assertEqual(boundary["unique_nul_terminated_name_occurrences"][1]["address"], 0x7AEC2F)
        self.assertFalse(boundary["same_registry_or_container_proven"])

    def test_source_boundary_validators_reject_mutated_name_dependency_and_dynsym_results(self):
        """Each runtime-boundary source check rejects a changed static result."""
        if not all(path.is_file() for path in (FIRMWARE_LIB / "viewUnified7.so", FIRMWARE_LIB / "viewUnified2.so")):
            self.skipTest("pinned offline static inputs are unavailable")
        from elftools.elf.elffile import ELFFile

        exporter = self._load()
        vu2_path = FIRMWARE_LIB / "viewUnified2.so"
        vu7_path = FIRMWARE_LIB / "viewUnified7.so"
        with vu2_path.open("rb") as stream:
            vu2 = ELFFile(stream)
            with self.assertRaises(RuntimeError):
                exporter._unique_nul_terminated_name_address(vu2, vu2_path.read_bytes(), "viewUnified7.so", 0x7AEBE3)
        with vu7_path.open("rb") as stream:
            vu7 = ELFFile(stream)
            with mock.patch.object(exporter, "_needed", return_value=True):
                with self.assertRaises(RuntimeError):
                    exporter._runtime_consumption_boundary(vu7, vu2_path)
            with mock.patch.object(
                exporter,
                "_needed",
                side_effect=[False, True],
            ) as needed:
                with self.assertRaises(RuntimeError):
                    exporter._runtime_consumption_boundary(vu7, vu2_path)
                self.assertEqual(needed.call_count, 2)
            with mock.patch.object(exporter, "_typed_layout_dynsym_modules", return_value={"layoutst_dial_modules": ["lib/viewUnified2.so"], "layout_converter_base_modules": []}):
                with self.assertRaises(RuntimeError):
                    exporter._runtime_consumption_boundary(vu7, vu2_path)

    def test_exporter_rejects_escape_and_nonempty_structural_result(self):
        exporter = self._load()

        class Adapter:
            def metadata(self):
                value = copy.deepcopy(exporter.EXPECTED_RAW_EXPORT)
                value["structural_scan"]["accepted_candidates"] = [{"function": 0x529CC}]
                return value

        with self.assertRaises(RuntimeError):
            exporter.build_raw_export(Adapter())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with mock.patch.object(exporter, "OUTPUT_ROOT", root):
                exporter.write_json_atomic(root / "raw-ui-slot34-dispatch.json", exporter.EXPECTED_RAW_EXPORT)
                with self.assertRaises(RuntimeError):
                    exporter.write_json_atomic(root / "other.json", exporter.EXPECTED_RAW_EXPORT)

    def test_exporter_rejects_a_symlinked_output_root(self):
        exporter = self._load()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with mock.patch.object(exporter, "OUTPUT_ROOT", root), mock.patch.object(exporter.Path, "is_symlink", return_value=True):
                with self.assertRaises(RuntimeError):
                    exporter.write_json_atomic(root / "raw-ui-slot34-dispatch.json", exporter.EXPECTED_RAW_EXPORT)


if __name__ == "__main__":
    unittest.main()
