"""Fail-closed tests for the target Creative Style view/model binding."""
from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "analysis" / "a6400-creative-style-view-model-binding.json"
EXPORTER = ROOT / "tools" / "static" / "export_a6400_creative_style_view_model_binding.py"


class CreativeStyleViewModelBindingContractTests(unittest.TestCase):
    def test_view_owner_and_constructor_are_exact(self):
        from pmca.analysis.creative_style_view_model_binding import EXPECTED_EXPORT

        view = EXPECTED_EXPORT["view"]
        self.assertEqual((view["type_name"], view["rtti"]), ("ViewCreativeStyle", 0x93EC9C))
        self.assertEqual(
            view["primary_vtable"],
            {"header": 0x93ECB8, "address_point": 0x93ECC0, "end": 0x93EE38, "slot_count": 94},
        )
        self.assertEqual(view["secondary_vtable"]["address_point"], 0x93EE40)
        self.assertEqual(view["constructor"]["object_size"], 0x194)
        self.assertEqual(view["constructor"]["primary_vptr_store"], {"site": 0x5CD682, "object_offset": 0, "address_point": 0x93ECC0})
        self.assertEqual(view["constructor"]["secondary_vptr_store"], {"site": 0x5CD684, "object_offset": 0x28, "address_point": 0x93EE40})

    def test_view_initialization_and_dispatch_are_bounded(self):
        from pmca.analysis.creative_style_view_model_binding import EXPECTED_EXPORT

        init = EXPECTED_EXPORT["view"]["initializer"]
        self.assertEqual(init["slot"], 54)
        self.assertEqual(
            [(record["site"], record["name"], record["count"], record["event_id"]) for record in init["event_attachments"]],
            [(0x5CD024, "@M00B", 1, 9), (0x5CD036, "@M096", 1, 8)],
        )
        self.assertEqual(init["event_attachment_vtable_slot"], 91)
        self.assertEqual(init["event_attachment_symbol"], "_ZN13ViewBaseForMR13attachEventIdEPKcii")
        self.assertEqual(init["model_request"], {
            "site": 0x5CD04E,
            "vtable_slot": 87,
            "method": "ViewBaseForMR::requestModelExecute",
            "model_id_source": "CmnModelAndTreeId::getCurrentStillRecModelId",
            "request_code": 75,
            "param_list": None,
        })
        dispatch = EXPECTED_EXPORT["view"]["dispatcher"]
        self.assertEqual((dispatch["slot"], dispatch["case_count"]), (64, 20))
        self.assertEqual(dispatch["guard"], {"compare_site": 0x5D0592, "branch_site": 0x5D0594, "out_of_range_target": 0x5D065E})
        self.assertEqual(len(dispatch["case_targets"]), 20)

    def test_process_id_maps_to_typed_custom_creative_style_element(self):
        from pmca.analysis.creative_style_view_model_binding import EXPECTED_EXPORT

        binding = EXPECTED_EXPORT["process_binding"]
        self.assertEqual(binding["view_helper_process_id"], 42)
        self.assertEqual(binding["view_dispatch_join"], {
            "case_index": 16,
            "case_target": 0x5CE0A8,
            "owner": {"start": 0x5CE0A8, "end": 0x5CE180, "complete": True},
            "read_helper_call_site": 0x5CE0FA,
            "write_helper_call_site": 0x5CE114,
        })
        self.assertEqual(binding["read_helper"]["typed_element_slot"], 10)
        self.assertEqual(binding["write_helper"]["typed_element_slot"], 21)
        self.assertEqual(binding["manager_mapping"], {
            "table": 0x7AF2C4,
            "index": 42,
            "entry_site": 0x7AF36C,
            "value": 45,
        })
        self.assertEqual(binding["factory_dispatch"]["selector_index"], 45)
        self.assertEqual(binding["factory_dispatch"]["accessor"], 0x42ECA8)
        element = binding["typed_element"]
        self.assertEqual((element["type_name"], element["rtti"]), ("CmnViewProcessDataElementCustomCreativeStyle", 0x90EDF0))
        self.assertEqual(element["vtable_address_point"], 0x90ED88)
        self.assertEqual(element["value_getter_slot"], 10)
        self.assertEqual(element["value_getter_signature"], "getValue(int&,int&,int&,int&,int&,int,int)")
        self.assertEqual(element["value_getter"], 0x48B8AC)
        self.assertEqual(element["value_setter_slot"], 21)
        self.assertEqual(element["value_setter_signature"], "setValue(int,int,int,int,int)")
        self.assertEqual(element["value_setter"], 0x4893AC)
        join = binding["join_proof"]
        self.assertEqual(join["lookup_input_register"], "r1")
        self.assertEqual(join["lookup_factory_call_site"], 0x4390A0)
        self.assertEqual(join["read_receiver"]["typed_element_slot"], 10)
        self.assertEqual(join["write_receiver"]["typed_element_slot"], 21)
        self.assertEqual(join["typed_accessor"]["constructor_call_site"], 0x42ECCA)
        self.assertEqual(join["typed_accessor"]["vptr_store_site"], 0x48B7FE)

    def test_value_setter_reaches_backup_and_model_request(self):
        from pmca.analysis.creative_style_view_model_binding import EXPECTED_EXPORT

        setter = EXPECTED_EXPORT["value_commit"]
        self.assertEqual(setter["owner"], {"start": 0x4893AC, "end": 0x489644, "complete": True})
        self.assertEqual(setter["backup_write_call_sites"], [0x489540, 0x48955A, 0x489574, 0x489588, 0x489598])
        self.assertEqual(setter["model_request"], {
            "site": 0x4895FA,
            "model": "@M00B",
            "request_code": 38,
            "param_list_add_count": 5,
        })
        self.assertEqual(setter["first_backup_id"], 0x01070762)
        self.assertFalse(setter["five_argument_semantics_resolved"])

    def test_controller_mode_is_not_promoted_to_selected_style(self):
        from pmca.analysis.creative_style_view_model_binding import (
            CreativeStyleViewModelBindingError,
            EXPECTED_EXPORT,
            normalize_creative_style_view_model_binding_export,
        )

        mode = EXPECTED_EXPORT["controller_mode"]
        self.assertEqual(mode["field_offset"], 0x15C)
        self.assertEqual(mode["storage_width_bytes"], 4)
        self.assertEqual(mode["backup_storage_width_bytes"], 1)
        self.assertEqual(mode["observed_values"], [0, 1, 2, 3, 4])
        self.assertEqual(mode["backup_id"], 0x01070763)
        self.assertTrue(mode["reset_to_zero_on_slot_57"])
        self.assertFalse(mode["selected_creative_style_value_proven"])
        self.assertEqual(mode["classification"], "controller-mode-word-with-one-byte-backup-not-selected-style")

        changed = copy.deepcopy(EXPECTED_EXPORT)
        changed["controller_mode"]["selected_creative_style_value_proven"] = True
        with self.assertRaises(CreativeStyleViewModelBindingError):
            normalize_creative_style_view_model_binding_export(changed)

    def test_claims_are_positive_only_at_the_proven_boundary(self):
        from pmca.analysis.creative_style_view_model_binding import (
            CreativeStyleViewModelBindingError,
            EXPECTED_EXPORT,
            normalize_creative_style_view_model_binding_export,
        )

        claims = EXPECTED_EXPORT["claims"]
        for key in (
            "creative_style_view_owner_found",
            "typed_custom_process_element_binding_found",
            "creative_style_value_read_boundary_found",
            "creative_style_value_write_boundary_found",
            "backup_write_boundary_found",
            "model_request_boundary_found",
        ):
            self.assertTrue(claims[key])
        for key in (
            "factory_registration_route_found",
            "selected_creative_style_field_identified",
            "five_argument_semantics_resolved",
            "eight_axis_creative_look_model_found",
            "renderer_or_output_sink_found",
            "touch_routing_found",
            "creative_look_equivalence_found",
            "runtime_execution_proven",
        ):
            self.assertFalse(claims[key])
            changed = copy.deepcopy(EXPECTED_EXPORT)
            changed["claims"][key] = True
            with self.subTest(key=key), self.assertRaises(CreativeStyleViewModelBindingError):
                normalize_creative_style_view_model_binding_export(changed)

    def test_checked_in_report_validates(self):
        from pmca.analysis.creative_style_view_model_binding import validate_creative_style_view_model_binding_report

        report = json.loads(REPORT.read_text(encoding="utf-8"))
        checked = validate_creative_style_view_model_binding_report(report)
        self.assertEqual(checked["readiness"], "TARGET_NATIVE_CREATIVE_STYLE_UI_MODEL_COMMIT_BOUNDARY")
        self.assertFalse(checked["installable"])
        self.assertFalse(checked["camera_test_eligible"])


class CreativeStyleViewModelBindingExporterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("creative_style_view_model_binding_exporter", EXPORTER)
        cls.exporter = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(cls.exporter)

    def test_adapter_is_normalized(self):
        from pmca.analysis.creative_style_view_model_binding import EXPECTED_EXPORT

        class FakeAdapter:
            def metadata(self):
                return copy.deepcopy(EXPECTED_EXPORT)

        self.assertEqual(self.exporter.build_raw_export(FakeAdapter()), EXPECTED_EXPORT)

    def _validate_real_process_binding(self):
        exporter = self.exporter
        blob = exporter.SOURCE_PATH.read_bytes()
        deps = exporter._dependencies()
        with exporter.SOURCE_PATH.open("rb") as handle:
            elf = deps["ELFFile"](handle)
            mappings = exporter._mappings(elf)
            rels, by_site = exporter._relocations(elf)
            dynsym = elf.get_section_by_name(".dynsym")
            plt_symbols = exporter._plt_symbols(elf, blob, mappings)
            exidx = exporter._exidx_ranges(elf, blob)
            return exporter._validate_process_binding(
                elf, blob, mappings, deps, rels, by_site, dynsym, plt_symbols, exidx,
            )

    def test_process_register_join_checks_reject_clobbers(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned source or parser dependencies are unavailable")
        exporter = self.exporter
        deps = exporter._dependencies()
        original_decode = exporter._decode

        class RegisterClobber:
            def __init__(self, register):
                self.register = register

            def regs_access(self):
                return [], [self.register]

        ranges = [
            (0x2D7CBA, 0x2D7CD2, deps["r1"]),
            (0x439092, 0x43909C, deps["r1"]),
            (0x437AA0, 0x437AB0, deps["r1"]),
        ]
        for changed_start, changed_end, register in ranges:
            def changed_decode(blob, mappings, local_deps, start, end, *, complete=True):
                items = original_decode(blob, mappings, local_deps, start, end, complete=complete)
                if (start, end) == (changed_start, changed_end):
                    return [RegisterClobber(register), *items]
                return items

            with self.subTest(start=changed_start), mock.patch.object(exporter, "_decode", side_effect=changed_decode):
                with self.assertRaisesRegex(RuntimeError, "preservation"):
                    self._validate_real_process_binding()

    def test_typed_vptr_adjustment_is_required(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned source or parser dependencies are unavailable")
        exporter = self.exporter
        original_instruction = exporter._instruction

        class WrongInstruction:
            def __init__(self, instruction):
                self._instruction = instruction
                self.id = -1

            def __getattr__(self, name):
                return getattr(self._instruction, name)

        def changed_instruction(blob, mappings, deps, site):
            item = original_instruction(blob, mappings, deps, site)
            return WrongInstruction(item) if site == 0x48B7FC else item

        with mock.patch.object(exporter, "_instruction", side_effect=changed_instruction):
            with self.assertRaisesRegex(RuntimeError, "singleton/vptr"):
                self._validate_real_process_binding()

    def test_init_array_target_count_uses_factory_range(self):
        count = self.exporter._count_targets_in_range
        self.assertEqual(count([0x5CD88E, 0x5CD8A0, 0x5CD8B2], 0x5CD88E, 0x5CD8B2), 2)
        self.assertEqual(count([0x5CD664, 0x5CD8B2], 0x5CD88E, 0x5CD8B2), 0)
        with self.assertRaises(RuntimeError):
            count([], 3, 3)

    def test_real_export_matches_when_available(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned source or parser dependencies are unavailable")
        self.assertEqual(self.exporter.build_raw_export(), self.exporter.EXPECTED_EXPORT)


if __name__ == "__main__":
    unittest.main()
