import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = ROOT / "analysis" / "a6400-ui-layout-vtable-interface.json"
EXPORTER_PATH = ROOT / "tools" / "static" / "export_a6400_ui_layout_vtable_interface.py"


TABLES = (
    ("N14LG_viewtridial13LayoutST_DIALE", 0x70EF8, 0x70E58, 0x70E60, 0x70EF8),
    ("N14LG_viewtridial19LayoutConverterBaseE", 0x70F04, 0x70F10, 0x70F18, 0x70FB0),
    ("N14LG_viewtridial23LayoutST_DIAL_CLASSICALE", 0x71050, 0x70FB0, 0x70FB8, 0x71050),
    ("N14LG_viewtridial32LayoutST_DIAL_CLASSICAL_PANORAMAE", 0x71100, 0x71060, 0x71068, 0x71100),
    ("N14LG_viewtridial17LayoutST_DIAL_EVFE", 0x711B0, 0x71110, 0x71118, 0x711B0),
)


def raw_export():
    local_targets = {
        "N14LG_viewtridial13LayoutST_DIALE": {32: 0x520E5, 33: 0x520C9, 35: 0x518E5},
        "N14LG_viewtridial23LayoutST_DIAL_CLASSICALE": {32: 0x52199, 33: 0x5217D, 35: 0x519B1},
        "N14LG_viewtridial32LayoutST_DIAL_CLASSICAL_PANORAMAE": {32: 0x52259, 33: 0x5223D, 35: 0x51C25},
        "N14LG_viewtridial17LayoutST_DIAL_EVFE": {32: 0x52319, 33: 0x522FD, 35: 0x51E79},
    }
    tables = []
    for name, rtti, header, address_point, end in TABLES:
        slots = []
        for index in (32, 33, 34, 35):
            address = address_point + index * 4
            slot = {"index": index, "address": address, "relocation": {"address": address, "section_name": ".rel.dyn", "relocation_type": "R_ARM_RELATIVE", "evidence_kind": "relocation"}}
            if index == 34:
                slot["relocation"]["thumb_target"] = 0x529CD
                slot["normalized_owner"] = 0x529CC
            elif name == "N14LG_viewtridial19LayoutConverterBaseE":
                symbols = {
                    32: "_ZN2ux6wgtlay15LayoutConverter20isValidWidgetVersionEjjjjPKc",
                    33: "_ZN2ux6wgtlay15LayoutConverter23isValidAnimationVersionEjjjjPKc",
                    35: "_ZN2ux6wgtlay15LayoutConverter23getLayoutMasterWidgetIDEjRj",
                }
                slot["relocation"] = {"address": address, "section_name": ".rel.dyn", "relocation_type": "R_ARM_ABS32", "evidence_kind": "relocation", "symbol": symbols[index]}
            else:
                slot["relocation"]["thumb_target"] = local_targets[name][index]
                slot["normalized_owner"] = local_targets[name][index] & ~1
            slots.append(slot)
        tables.append({
            "class_name": name,
            "rtti": {"address": rtti, "class_typeinfo_relocation": {"address": rtti, "section_name": ".rel.dyn", "relocation_type": "R_ARM_ABS32", "symbol": "_ZTVN10__cxxabiv120__si_class_type_infoE", "evidence_kind": "relocation"}, "name_relocation": {"address": rtti + 4, "section_name": ".rel.dyn", "relocation_type": "R_ARM_RELATIVE", "evidence_kind": "relocation", "target": {"N14LG_viewtridial13LayoutST_DIALE": 0x5E7BE, "N14LG_viewtridial19LayoutConverterBaseE": 0x5E7E0, "N14LG_viewtridial23LayoutST_DIAL_CLASSICALE": 0x5E808, "N14LG_viewtridial32LayoutST_DIAL_CLASSICAL_PANORAMAE": 0x5E834, "N14LG_viewtridial17LayoutST_DIAL_EVFE": 0x5E869}[name]}},
            "vtable": {"header": header, "address_point": address_point, "end": end, "rtti_relocation": {"address": header + 4, "section_name": ".rel.dyn", "relocation_type": "R_ARM_RELATIVE", "evidence_kind": "relocation", "target": rtti}, "slots": slots},
        })
    return {"schema_version": 1, "program": "viewUnified7.so", "sha256": "c48cde43ff22d808ad23c42019ddae516fff7da060004eb81ed2bb85012aa538", "image_size": 541024, "analysis_mode": {"engine": "elf-relocation-rtti", "read_only": True, "source_unchanged": True}, "prior_owner_registration": {"analysis_contract": "ui_factory_owner_registration", "canonical_export_sha256": "a6a669db167c7335a65cd3015c59a20a08af4b8de46330a4ca1c3231fa2b8e0a"}, "owner": {"range": {"start": 0x529CC, "end": 0x529E8}, "forwarding_edge": {"caller": 0x529CC, "site": 0x529D6, "target": 0x52840, "kind": "direct"}, "evidence": {"owner_kind": "ARM.exidx-function", "call_kind": "thumb-direct"}}, "tables": tables, "truncated": False}


class UILayoutVtableInterfaceTests(unittest.TestCase):
    def test_five_typed_vtables_share_exact_slot_34_owner(self):
        from pmca.analysis.ui_layout_vtable_interface import normalize_ui_layout_vtable_interface_export
        normalized = normalize_ui_layout_vtable_interface_export(raw_export())
        self.assertEqual([table["class_name"] for table in normalized["tables"]], [item[0] for item in TABLES])
        self.assertEqual([table["vtable"]["slots"][2]["normalized_owner"] for table in normalized["tables"]], [0x529CC] * 5)
        self.assertTrue(normalized["claims"]["common_layout_virtual_dispatch_hook_found"])
        self.assertFalse(normalized["claims"]["orientation_layout_object_selector_found"])
        self.assertFalse(normalized["behavior_support"]["menu_touch_selection"])
        self.assertEqual(normalized["owner"]["range"], {"start": 0x529CC, "end": 0x529E8})
        self.assertEqual(normalized["prior_owner_registration"]["canonical_export_sha256"], "a6a669db167c7335a65cd3015c59a20a08af4b8de46330a4ca1c3231fa2b8e0a")

    def test_rejects_untyped_overlap_reordering_and_promotion(self):
        from pmca.analysis.ui_layout_vtable_interface import UILayoutVtableInterfaceError, normalize_ui_layout_vtable_interface_export
        for mutate in (
            lambda value: value["tables"].reverse(),
            lambda value: value["tables"][1]["vtable"].__setitem__("header", 0x70E58),
            lambda value: value["tables"][0]["rtti"]["name_relocation"].__setitem__("evidence_kind", "pointer-scan"),
            lambda value: value["tables"][0]["vtable"]["slots"][2].__setitem__("normalized_owner", 0x529CE),
            lambda value: value["owner"]["range"].__setitem__("end", 0x529EA),
            lambda value: value["owner"]["forwarding_edge"].__setitem__("site", 0x529D4),
            lambda value: value["prior_owner_registration"].__setitem__("canonical_export_sha256", "0" * 64),
            lambda value: value.__setitem__("instructions", []),
        ):
            candidate = raw_export(); mutate(candidate)
            with self.subTest(candidate=candidate), self.assertRaises(UILayoutVtableInterfaceError):
                normalize_ui_layout_vtable_interface_export(candidate)

    def test_report_is_pinned_noninstallable_and_noninteractive(self):
        from pmca.analysis.ui_layout_vtable_interface import UILayoutVtableInterfaceError, validate_ui_layout_vtable_interface_report
        report = validate_ui_layout_vtable_interface_report(json.loads(REPORT_PATH.read_text(encoding="utf-8")))
        self.assertFalse(report["installable"])
        self.assertFalse(report["camera_test_eligible"])
        forged = copy.deepcopy(report); forged["claims"]["orientation_layout_object_selector_found"] = True
        with self.assertRaises(UILayoutVtableInterfaceError): validate_ui_layout_vtable_interface_report(forged)
        forged = copy.deepcopy(report); forged["export_summary"]["canonical_export_sha256"] = "0" * 64
        with self.assertRaises(UILayoutVtableInterfaceError): validate_ui_layout_vtable_interface_report(forged)


class UILayoutVtableInterfaceExporterTests(unittest.TestCase):
    def test_exporter_requires_exact_typed_table_metadata(self):
        spec = importlib.util.spec_from_file_location("ui_layout_vtable_exporter", EXPORTER_PATH)
        exporter = importlib.util.module_from_spec(spec); spec.loader.exec_module(exporter)
        class Adapter:
            def program_name(self): return exporter.EXPECTED_PROGRAM
            def program_sha256(self): return exporter.EXPECTED_SHA256
            def program_size(self): return exporter.EXPECTED_IMAGE_SIZE
            def analysis_mode(self): return exporter.EXPECTED_ANALYSIS_MODE
            def owner_metadata(self): return exporter.EXPECTED_OWNER
            def prior_owner_registration(self): return exporter.EXPECTED_PRIOR_OWNER_REGISTRATION
            def table_metadata(self): return exporter.EXPECTED_TABLES
        raw = exporter.build_raw_export(Adapter())
        self.assertEqual(len(raw["tables"]), 5)
        self.assertEqual(raw["tables"][0]["vtable"]["slots"][2]["normalized_owner"], 0x529CC)

    def test_exporter_rejects_bad_tables_and_escaping_output(self):
        spec = importlib.util.spec_from_file_location("ui_layout_vtable_exporter", EXPORTER_PATH)
        exporter = importlib.util.module_from_spec(spec); spec.loader.exec_module(exporter)
        class Adapter:
            def program_name(self): return exporter.EXPECTED_PROGRAM
            def program_sha256(self): return exporter.EXPECTED_SHA256
            def program_size(self): return exporter.EXPECTED_IMAGE_SIZE
            def analysis_mode(self): return exporter.EXPECTED_ANALYSIS_MODE
            def owner_metadata(self): return exporter.EXPECTED_OWNER
            def prior_owner_registration(self): return exporter.EXPECTED_PRIOR_OWNER_REGISTRATION
            def table_metadata(self): return ()
        with self.assertRaises(RuntimeError): exporter.build_raw_export(Adapter())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with mock.patch.object(exporter, "OUTPUT_ROOT", root):
                exporter.write_json_atomic(root / "raw-ui-layout-vtable-interface.json", {"schema_version": 1})
                with self.assertRaises(RuntimeError): exporter.write_json_atomic(root / "wrong.json", {})
                (root / "raw-ui-layout-vtable-interface.json").unlink()
                (root / "raw-ui-layout-vtable-interface.json").mkdir()
                with self.assertRaises(RuntimeError): exporter.write_json_atomic(root / "raw-ui-layout-vtable-interface.json", {})

    def test_main_rejects_any_output_other_than_the_pinned_artifact_path(self):
        spec = importlib.util.spec_from_file_location("ui_layout_vtable_exporter", EXPORTER_PATH)
        exporter = importlib.util.module_from_spec(spec); spec.loader.exec_module(exporter)
        with tempfile.TemporaryDirectory() as temporary:
            wrong = Path(temporary) / "raw-ui-layout-vtable-interface.json"
            with self.assertRaises(RuntimeError):
                exporter.main(["missing.so", "missing-prior.json", str(wrong)])


if __name__ == "__main__":
    unittest.main()
