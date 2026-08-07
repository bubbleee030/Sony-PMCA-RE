"""Fail-closed tests for typed generic-dispatch table containers."""
from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "analysis" / "a6400-dispatch-table-container-provenance.json"
EXPORTER = ROOT / "tools" / "static" / "export_a6400_dispatch_table_container_provenance.py"


class DispatchTableContainerContractTests(unittest.TestCase):
    def test_all_three_dispatchers_are_typed_slot_64_overrides(self):
        from pmca.analysis.dispatch_table_container_provenance import EXPECTED_EXPORT

        rows = EXPECTED_EXPORT["dispatcher_owners"]
        self.assertEqual([row["type_name"] for row in rows], ["ViewFocusArea_C", "ViewCustomZebra", "ViewFocusArea"])
        self.assertEqual([row["dispatcher_slot"] for row in rows], [64, 64, 64])
        self.assertEqual([row["dispatcher"] for row in rows], [0xCF106, 0x17AD50, 0x31040])
        self.assertEqual([row["target"] for row in rows], [0xCE0A8, 0x17A95A, 0x2D284])
        self.assertTrue(all(row["typed_rtti_vtable_membership"] for row in rows))

    def test_vu7_initializer_and_dispatcher_share_view_focus_area_vtable(self):
        from pmca.analysis.dispatch_table_container_provenance import EXPECTED_EXPORT

        owner = EXPECTED_EXPORT["dispatcher_owners"][2]
        self.assertEqual(owner["rtti"], 0x6FDC4)
        self.assertEqual(owner["type_name_encoding"], "13ViewFocusArea")
        self.assertEqual(owner["primary_vtable"], {"header": 0x6FDE8, "address_point": 0x6FDF0, "end": 0x6FF6C, "slot_count": 95})
        self.assertEqual(owner["next_secondary_header"], {"offset_to_top_cell": 0x6FF6C, "offset_to_top": -0x28, "typeinfo_cell": 0x6FF70})
        self.assertEqual(owner["initializer"], 0x30750)
        self.assertEqual(owner["initializer_slot"], 54)
        self.assertEqual(owner["dispatcher_slot"], 64)
        self.assertEqual(owner["local_relative_window"], {"start": 0x6FEBC, "end": 0x6FEFC, "first_slot": 51, "last_slot": 66, "relocation_count": 16})
        self.assertEqual(
            owner["bases"],
            [
                {"type": "ViewBaseForMR", "offset": 0, "public": True, "virtual": False},
                {"type": "WrapperSettingUtil", "offset": 0x140, "public": True, "virtual": False},
            ],
        )
        self.assertEqual(owner["wrapper_secondary_vtable"]["offset_to_top"], -0x140)
        self.assertEqual(owner["wrapper_secondary_vtable"]["address_point"], 0x6FF84)
        self.assertTrue(owner["initializer_and_dispatcher_same_typed_vtable"])
        self.assertFalse(owner["runtime_same_instance_or_order_proven"])

    def test_vu4_types_and_distinct_tables_are_exact(self):
        from pmca.analysis.dispatch_table_container_provenance import EXPECTED_EXPORT

        focus, zebra = EXPECTED_EXPORT["dispatcher_owners"][:2]
        self.assertEqual((focus["rtti"], focus["type_name_encoding"]), (0x2677EC, "15ViewFocusArea_C"))
        self.assertEqual(focus["primary_vtable"], {"header": 0x267828, "address_point": 0x267830, "end": 0x2679A8, "slot_count": 94})
        self.assertEqual(focus["next_secondary_header"], {"offset_to_top_cell": 0x2679A8, "offset_to_top": -0x28, "typeinfo_cell": 0x2679AC})
        self.assertEqual(
            focus["bases"],
            [
                {"type": "ViewBaseForMR", "offset": 0, "public": True, "virtual": False},
                {"type": "WrapperSettingUtil", "offset": 0x140, "public": True, "virtual": False},
            ],
        )
        self.assertEqual((zebra["rtti"], zebra["type_name_encoding"]), (0x273E50, "15ViewCustomZebra"))
        self.assertEqual(zebra["primary_vtable"], {"header": 0x273CD8, "address_point": 0x273CE0, "end": 0x273E3C, "slot_count": 87})
        self.assertEqual(zebra["next_secondary_header"], {"offset_to_top_cell": 0x273E3C, "offset_to_top": -0x28, "typeinfo_cell": 0x273E40})
        self.assertEqual(zebra["bases"], [{"type": "ViewBaseProduct", "offset": 0, "public": True, "virtual": False}])
        self.assertNotEqual(focus["primary_vtable"]["address_point"], zebra["primary_vtable"]["address_point"])
        self.assertEqual(zebra["adjacent_split_entry"], {"cell": 0x273DE4, "slot": 65, "target": 0x17A91C})

    def test_claims_do_not_promote_non_creative_view_owners(self):
        from pmca.analysis.dispatch_table_container_provenance import (
            DispatchTableContainerProvenanceError,
            EXPECTED_EXPORT,
            normalize_dispatch_table_container_provenance_export,
        )

        claims = EXPECTED_EXPORT["claims"]
        boundary = EXPECTED_EXPORT["creative_style_boundary"]
        self.assertFalse(boundary["typed_primary_vtable_creative_style_edge_found"])
        self.assertNotIn("creative_style_root_or_type_edge_found", boundary)
        self.assertTrue(all("to_instance_symbol" in owner and "factory" not in owner for owner in EXPECTED_EXPORT["dispatcher_owners"]))
        self.assertTrue(claims["concrete_dispatcher_owner_types_found"])
        self.assertTrue(claims["shared_generic_slot_64_pattern_found"])
        self.assertTrue(claims["vu7_initializer_dispatcher_same_typed_vtable_found"])
        for key in (
            "to_instance_to_vtable_binding_proven",
            "creative_style_owner_binding_found",
            "selected_model_value_storage_found",
            "final_model_setter_or_commit_found",
            "renderer_binding_found",
            "touch_routing_found",
            "commit_or_persistence_found",
            "creative_look_equivalence_found",
            "runtime_execution_proven",
        ):
            self.assertFalse(claims[key])
            changed = copy.deepcopy(EXPECTED_EXPORT)
            changed["claims"][key] = True
            with self.subTest(key=key), self.assertRaises(DispatchTableContainerProvenanceError):
                normalize_dispatch_table_container_provenance_export(changed)

        changed = copy.deepcopy(EXPECTED_EXPORT)
        changed["dispatcher_owners"][0]["next_secondary_header"]["offset_to_top"] = -0x24
        with self.assertRaises(DispatchTableContainerProvenanceError):
            normalize_dispatch_table_container_provenance_export(changed)

    def test_checked_in_report_validates(self):
        from pmca.analysis.dispatch_table_container_provenance import validate_dispatch_table_container_provenance_report

        report = json.loads(REPORT.read_text(encoding="utf-8"))
        checked = validate_dispatch_table_container_provenance_report(report)
        self.assertEqual(checked["readiness"], "TYPED_NON_CREATIVE_GENERIC_DISPATCH_OWNERS")
        self.assertFalse(checked["installable"])
        self.assertFalse(checked["camera_test_eligible"])


class DispatchTableContainerExporterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("dispatch_container_exporter", EXPORTER)
        cls.exporter = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(cls.exporter)

    def test_adapter_is_normalized(self):
        from pmca.analysis.dispatch_table_container_provenance import EXPECTED_EXPORT

        class FakeAdapter:
            def metadata(self):
                return copy.deepcopy(EXPECTED_EXPORT)

        self.assertEqual(cls_export := self.exporter.build_raw_export(FakeAdapter()), EXPECTED_EXPORT)
        self.assertEqual(cls_export["analysis_mode"]["source_unchanged"], True)

    def test_real_export_matches_when_available(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned sources or parser dependencies are unavailable")
        self.assertEqual(self.exporter.build_raw_export(), self.exporter.EXPECTED_EXPORT)


if __name__ == "__main__":
    unittest.main()
