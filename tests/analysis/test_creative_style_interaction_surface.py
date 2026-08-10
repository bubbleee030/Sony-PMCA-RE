"""Fail-closed tests for the native Creative Style interaction surface."""
from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEEP_DIVE = ROOT / "analysis" / "a6400a-updater-and-creative-style-deep-dive.md"
REPORT = ROOT / "analysis" / "a6400-creative-style-interaction-surface.json"
EXPORTER = ROOT / "tools" / "static" / "export_a6400_creative_style_interaction_surface.py"


class _MemoryProxy:
    def __init__(self, memory, *, displacement=None):
        self.base = memory.base
        self.index = memory.index
        self.disp = memory.disp if displacement is None else displacement


class _OperandProxy:
    def __init__(self, operand, *, register=None, memory=None):
        self.type = operand.type
        self.reg = operand.reg if register is None else register
        self.imm = operand.imm
        self.mem = operand.mem if memory is None else memory


class _InstructionProxy:
    def __init__(self, item, operands=None, *, instruction_id=None, mnemonic=None, groups=None):
        self._item = item
        self.address = item.address
        self.size = item.size
        self.id = item.id if instruction_id is None else instruction_id
        self.mnemonic = item.mnemonic if mnemonic is None else mnemonic
        self.operands = item.operands if operands is None else operands
        self._groups = groups

    def group(self, group_id):
        if self._groups is None:
            return self._item.group(group_id)
        return group_id in self._groups

    def __getattr__(self, name):
        return getattr(self._item, name)


class CreativeStyleInteractionSurfaceContractTests(unittest.TestCase):
    def test_deep_dive_keeps_viewbase_constructor_candidate_unbound(self):
        text = DEEP_DIVE.read_text(encoding="utf-8")
        self.assertIn("matching global definition in", text)
        self.assertIn("does not declare that", text)
        self.assertIn("Neither fact\nproves the binding", text)
        self.assertNotIn("stop at an unresolved external `ViewBase` constructor", text)

    def test_widget_lookup_only_reaches_generic_btncombo_cast(self):
        """Changing the post-lookup target/type filter must invalidate the boundary."""
        from pmca.analysis.creative_style_interaction_surface import EXPECTED_EXPORT

        edge = EXPECTED_EXPORT["post_lookup_widget_cast"]
        self.assertEqual(edge["call"], {"site": 0x5CE128, "target": 0x599C54})
        self.assertEqual(edge["thunk_owner"], {"start": 0x599C54, "end": 0x599C60})
        self.assertEqual(edge["tail"], {"site": 0x599C5C, "target": 0x1501AC})
        self.assertEqual(edge["interworking_veneer"], 0x1501B0)
        self.assertEqual(edge["got"], 0x944F48)
        self.assertEqual(edge["rel_plt_index"], 551)
        self.assertEqual(edge["symbol"], "_ZN12PAS_BtnCombo4castEPN2ux6wgtsys6WidgetE")
        self.assertEqual(edge["cast_owner"], {"start": 0x599510, "end": 0x59953C})
        self.assertEqual(edge["virtual_type_slot"], 0x190)
        self.assertTrue(edge["generic_widget_type_filter_proven"])
        self.assertTrue(edge["returns_original_widget_or_null"])

        from pmca.analysis.creative_style_interaction_surface import CLAIMS

        self.assertFalse(CLAIMS["creative_style_touch_route_found"])
        self.assertFalse(CLAIMS["selection_dispatch_found"])
        self.assertFalse(CLAIMS["field_0x14c_concrete_type_resolved"])

    def test_native_layout_and_helper_scaffold_is_exact(self):
        from pmca.analysis.creative_style_interaction_surface import EXPECTED_EXPORT

        layout = EXPECTED_EXPORT["creative_style_layout"]
        self.assertEqual(layout["layout_key"], 0x1FA14683)
        self.assertEqual(layout["layout_callback"], 0x5CD730)
        self.assertEqual(
            [(item["type"], item["size"], item["object_offset"]) for item in layout["helpers"]],
            [
                ("CmnViewMenuData", 0x50, 0x144),
                ("CmnMenuTableUtil", 0x14, 0x148),
                ("CmnZakoMenuUtil", 0x3C, 0x150),
            ],
        )

    def test_menu_table_and_belt_boundary_are_bounded(self):
        from pmca.analysis.creative_style_interaction_surface import EXPECTED_EXPORT

        dispatcher = EXPECTED_EXPORT["view_dispatcher"]
        self.assertEqual(dispatcher["selected_cases"], {"0": 0x5CF398, "13": 0x5CFD14, "16": 0x5CE0A8})
        menu = EXPECTED_EXPORT["menu_table"]
        self.assertEqual(
            {key: menu["index_loop"][key] for key in ("first", "last", "iteration_count")},
            {"first": 0, "last": 18, "iteration_count": 19},
        )
        self.assertEqual(len(menu["set_greyout_call_sites"]), 12)
        belt = EXPECTED_EXPORT["belt_cursor"]
        self.assertEqual((belt["belt_object_offset"], belt["menu_util_offset"]), (0x14C, 0x148))
        self.assertEqual((belt["flag_1"], belt["flag_2"]), (True, False))
        self.assertFalse(belt["concrete_belt_type_proven"])
        self.assertFalse(belt["belt_creation_or_store_proven"])

    def test_viewbase_constructor_candidate_is_unbound_and_has_no_direct_belt_store(self):
        """A matching libObj symbol must not become Creative Style ownership evidence."""
        from pmca.analysis.creative_style_interaction_surface import EXPECTED_EXPORT

        boundary = EXPECTED_EXPORT["field_0x14c_constructor_boundary"]
        import_edge = boundary["viewbase_constructor_import"]
        self.assertEqual(
            import_edge,
            {
                "module": "lib/viewUnified2.so",
                "call_site": 0x2F29FC,
                "symbol": "_ZN8ViewBaseC2EP11ViewManager",
                "dynsym_index": 1112,
                "symbol_undefined": True,
                "rel_plt_index": 1573,
                "got": 0x945F40,
                "relocation_type": 22,
                "branch_target": 0x153810,
                "declared_dependencies": ["CautionConfig.so", "libgcc_s.so.1", "libc.so.6"],
                "candidate_module_declared_dependency": False,
                "binding_proven": False,
            },
        )
        candidate = boundary["libobj_candidate"]
        self.assertEqual(
            candidate["source"],
            {
                "module": "lib/libObj.so",
                "size": 20_860_436,
                "sha256": "60ffd2b0f31f4bc139a7c13a4f62c25cdeb6a531ad5ef35df48471e6e36e88b1",
            },
        )
        self.assertEqual(candidate["symbol"], "_ZN8ViewBaseC2EP11ViewManager")
        self.assertEqual(candidate["symbol_entry"], 0x3EDBAD)
        self.assertEqual(candidate["owner"], {"start": 0x3EDBAC, "end": 0x3EDC7C, "instruction_count": 73})
        self.assertEqual(candidate["receiver_transfer_site"], 0x3EDBB0)
        self.assertEqual(
            candidate["receiver_store_offsets"],
            {
                "0x3edbd6": 0x0,
                "0x3edbd8": 0x28,
                "0x3edbf8": 0x74,
                "0x3edbfc": 0x78,
                "0x3edc08": 0xD8,
                "0x3edc2a": 0x100,
                "0x3edc2e": 0x64,
                "0x3edc3a": 0x11C,
            },
        )
        self.assertFalse(candidate["direct_0x14c_store_found"])
        self.assertEqual(
            candidate["first_plt_boundary"],
            {
                "call_site": 0x3EDBBA,
                "plt_target": 0x1004F4,
                "rel_plt_index": 1231,
                "got": 0x136B668,
                "relocation_type": 22,
                "symbol": "_ZN8ViewBase18getViewBootElementEv",
                "dynsym_index": 2501,
                "same_module_definition": {"entry": 0x3EBFE7, "size": 0x46},
                "binding_proven": False,
            },
        )
        self.assertFalse(boundary["field_0x14c_concrete_type_resolved"])

    def test_navigation_selector_is_not_controller_or_style_state(self):
        from pmca.analysis.creative_style_interaction_surface import EXPECTED_EXPORT

        navigation = EXPECTED_EXPORT["navigation"]
        self.assertEqual(navigation["field_offset"], 0x190)
        self.assertEqual(navigation["routes"], {
            "3": {"operation": "openView", "name": "view/FNMENU"},
            "2": {"operation": "openView", "name": "view/QUICK_NAVI"},
            "other": {"operation": "closeView", "name": "@V01D"},
        })
        self.assertFalse(navigation["creative_style_selection_proven"])

    def test_touchability_candidate_is_not_promoted(self):
        from pmca.analysis.creative_style_interaction_surface import (
            CreativeStyleInteractionSurfaceError,
            EXPECTED_EXPORT,
            normalize_creative_style_interaction_surface_export,
        )

        touch = EXPECTED_EXPORT["touchability_candidate"]
        self.assertEqual(touch["movie_view"]["type_name"], "ViewMovieRecPatch")
        self.assertEqual(touch["movie_view"]["set_touchable_value"], False)
        self.assertEqual(touch["converter"]["type_name"], "PAS_BarCtrlDialConverter")
        self.assertFalse(touch["converter"]["forwarded_value_semantics_resolved"])
        for key in (
            "creative_style_touch_route_found", "coordinate_input_found",
            "hit_test_found", "gesture_found", "selection_dispatch_found",
            "reusable_touch_adjustment_implementation_found",
        ):
            self.assertFalse(EXPECTED_EXPORT["claims"][key])
            changed = copy.deepcopy(EXPECTED_EXPORT)
            changed["claims"][key] = True
            with self.subTest(key=key), self.assertRaises(CreativeStyleInteractionSurfaceError):
                normalize_creative_style_interaction_surface_export(changed)

    def test_generic_belt_input_chain_is_conditional_and_not_creative_style_touch(self):
        from pmca.analysis.creative_style_interaction_surface import EXPECTED_EXPORT

        chain = EXPECTED_EXPORT["generic_belt_input_chain"]
        self.assertEqual(chain["status"], "CONDITIONAL_STATIC_PATH")
        self.assertEqual(chain["pas_belt"]["type_name"], "PAS_MenuDataSelectBelt")
        self.assertEqual(chain["pas_belt"]["vtable_address_point"], 0x92EFA8)
        self.assertEqual(chain["embedded_grid"]["object_offset"], 0x3F8)
        self.assertEqual(chain["embedded_grid"]["candidate_type_name"], "GEN_GridList")
        self.assertEqual(chain["embedded_grid"]["candidate_vtable_address_point"], 0x133C908)
        self.assertEqual(
            chain["embedded_grid"]["candidate_slots"],
            {
                "mouse_wrapper": {"slot": 26, "relocation_index": 37135, "target": 0x3E850C},
                "mouse_handler": {"slot": 27, "relocation_index": 37136, "target": 0x3E9BCC},
                "action_callback": {"slot": 88, "relocation_index": 37156, "target": 0x3EA35A},
                "selection_update": {"slot": 121, "relocation_index": 37173, "target": 0x3EAF0C},
                "custom_region_test": {"slot": 126, "relocation_index": 37178, "target": 0x3E86D6},
            },
        )
        self.assertEqual(chain["path"]["event_type"], 4)
        self.assertEqual(chain["path"]["custom_region_call_site"], 0x3E9F3E)
        self.assertEqual(chain["path"]["selection_update_call_site"], 0x3EA00A)
        self.assertEqual(chain["path"]["registered_callback_call_site"], 0x3E8C70)
        self.assertEqual(chain["path"]["set_item_select_call_site"], 0x59E844)
        self.assertEqual(chain["path"]["belt_check_call_site"], 0x59E7B6)
        self.assertEqual(chain["path"]["event_push_tail_site"], 0x56EDFE)
        self.assertTrue(chain["findings"]["slot27_to_custom_region_test_proven"])
        self.assertTrue(chain["findings"]["slot27_to_selection_update_proven"])
        self.assertFalse(chain["findings"]["slot27_to_registered_callback_proven"])
        self.assertFalse(chain["findings"]["selection_callback_enable_state_proven"])
        self.assertEqual(chain["findings"]["selection_callback_constructor_initial_value"], 0)
        self.assertTrue(chain["findings"]["enabled_callback_to_grid_selection_proven"])
        self.assertTrue(chain["findings"]["enabled_callback_to_typed_pas_belt_event_push_boundary_proven"])
        self.assertFalse(chain["findings"]["widget_is_hit_used_by_this_path"])
        delivery = chain["candidate_widget_system_delivery"]
        self.assertEqual(delivery["status"], "CONDITIONAL_ON_LIBOBJ_PROVIDER_BINDINGS")
        self.assertEqual(delivery["view_constructor_chain"]["pas_base_call_site"], 0x56E86C)
        self.assertEqual(delivery["view_constructor_chain"]["layoutable_base_import_call_site"], 0x401270)
        self.assertEqual(delivery["candidate_provider"]["layoutable_constructor_entry"], 0x413281)
        self.assertEqual(delivery["candidate_provider"]["widget_constructor_call_site"], 0x84243C)
        self.assertEqual(delivery["layer_attachment"]["set_layer_call_site"], 0x5ED766)
        self.assertEqual(delivery["layer_attachment"]["widget_node_offset"], 4)
        self.assertEqual(delivery["layer_attachment"]["layer_widget_list_offset"], 0x18)
        self.assertEqual(delivery["parent_chain"]["pas_to_base_call_site"], 0x56E8EC)
        self.assertEqual(delivery["parent_chain"]["base_to_grid_call_site"], 0x59DE46)
        self.assertEqual(delivery["hit_delivery"]["recursive_hit_call_site"], 0x5F1B80)
        self.assertEqual(delivery["hit_delivery"]["hook_dispatch_call_site"], 0x5F11CA)
        self.assertIn("static_mouse_post_pipeline", delivery)
        pipeline = delivery["static_mouse_post_pipeline"]
        self.assertEqual(
            pipeline["status"],
            "STATIC_POST_API_TO_WIDGET_DELIVERY_PROVEN__UPSTREAM_PRODUCER_UNRESOLVED",
        )
        self.assertEqual(
            [(item["role"], item["entry"], item["event_type"]) for item in pipeline["public_entries"]],
            [("move", 0x5F2151, 0), ("press", 0x5F21E1, 1), ("release", 0x5F2249, 2)],
        )
        self.assertEqual(pipeline["posted_queue"]["got_cell"], 0x1373468)
        self.assertEqual(pipeline["posted_queue"]["queue_object"], 0x13EF6F4)
        self.assertEqual(pipeline["transfer"]["secondary_queue_object"], 0x13EF700)
        self.assertEqual(pipeline["transfer"]["initial_record_eligible_branch_target"], 0x5F2926)
        self.assertEqual(pipeline["transfer"]["loop_record_eligible_branch_target"], 0x5F2924)
        self.assertEqual(pipeline["member_dispatch"]["table_address"], 0x134A480)
        self.assertEqual(
            [(item["event_type"], item["target"], item["hit_update_call_site"]) for item in pipeline["member_dispatch"]["entries"]],
            [(0, 0x5F1F88, 0x5F1FB2), (1, 0x5F1ECC, 0x5F1F02), (2, 0x5F1DC0, 0x5F1DF8)],
        )
        self.assertTrue(chain["findings"]["candidate_provider_layer_attachment_path_proven"])
        self.assertTrue(chain["findings"]["candidate_provider_parent_chain_to_embedded_grid_proven"])
        self.assertTrue(chain["findings"]["candidate_provider_widget_system_hit_delivery_path_proven"])
        self.assertTrue(chain["findings"]["static_public_mouse_post_to_hit_delivery_pipeline_proven"])
        for key in (
            "runtime_provider_binding_proven",
            "registration_method_invocation_proven",
            "runtime_widget_system_delivery_to_embedded_grid_proven",
            "runtime_registered_root_attachment_proven",
            "raw_mouse_input_producer_proven",
            "viewcreative_style_field_0x14c_instance_join_proven",
            "viewcreative_style_case16_selector_proven",
        ):
            self.assertFalse(chain["preconditions"][key])

        claims = EXPECTED_EXPORT["claims"]
        self.assertTrue(claims["conditional_generic_pas_belt_input_chain_found"])
        self.assertFalse(claims["creative_style_touch_route_found"])
        self.assertFalse(claims["coordinate_input_found"])
        self.assertFalse(claims["selection_dispatch_found"])

    def test_checked_in_report_is_non_installable(self):
        from pmca.analysis.creative_style_interaction_surface import validate_creative_style_interaction_surface_report

        report = validate_creative_style_interaction_surface_report(json.loads(REPORT.read_text(encoding="utf-8")))
        self.assertEqual(report["readiness"], "NATIVE_CREATIVE_STYLE_LAYOUT_AND_BELT_TOUCH_UNPROVEN")
        self.assertFalse(report["camera_executed"])
        self.assertFalse(report["installable"])
        self.assertFalse(report["camera_test_eligible"])


class CreativeStyleInteractionSurfaceExporterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("creative_style_interaction_surface_exporter", EXPORTER)
        cls.exporter = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(cls.exporter)

    def test_adapter_is_normalized(self):
        from pmca.analysis.creative_style_interaction_surface import EXPECTED_EXPORT

        class FakeAdapter:
            def metadata(self):
                return copy.deepcopy(EXPECTED_EXPORT)

        self.assertEqual(self.exporter.build_raw_export(FakeAdapter()), EXPECTED_EXPORT)

    def test_branch_join_checks_reject_nonbranches(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned source or parser dependencies are unavailable")
        exporter = self.exporter
        original_instruction = exporter._instruction

        class WrongMnemonic:
            def __init__(self, instruction):
                self._instruction = instruction
                self.mnemonic = "nop"

            def __getattr__(self, name):
                return getattr(self._instruction, name)

        for changed_site in (0x5CF3C0, 0x5CFF8A):
            def changed_instruction(blob, mappings, deps, site):
                item = original_instruction(blob, mappings, deps, site)
                return WrongMnemonic(item) if site == changed_site else item

            with self.subTest(site=changed_site), mock.patch.object(exporter, "_instruction", side_effect=changed_instruction):
                with self.assertRaises(RuntimeError):
                    exporter.ElfAdapter().metadata()

    def test_pointer_and_receiver_joins_reject_clobbers(self):
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

        for changed_start, changed_end, register in (
            (0x5CE0B4, 0x5CE0C0, deps["r1"]),
            (0x627634, 0x62763A, deps["r0"]),
        ):
            def changed_decode(blob, mappings, local_deps, start, end, *, complete=True):
                items = original_decode(blob, mappings, local_deps, start, end, complete=complete)
                return [RegisterClobber(register), *items] if (start, end) == (changed_start, changed_end) else items

            with self.subTest(start=changed_start), mock.patch.object(exporter, "_decode", side_effect=changed_decode):
                with self.assertRaisesRegex(RuntimeError, "preservation"):
                    exporter.ElfAdapter().metadata()

    def test_real_export_matches_when_available(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned source or parser dependencies are unavailable")
        self.assertEqual(self.exporter.build_raw_export(), self.exporter.EXPECTED_EXPORT)

    def test_generic_belt_input_chain_rejects_source_anchor_mutations(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned source or parser dependencies are unavailable")
        exporter = self.exporter
        deps = exporter._dependencies()
        original_instruction = exporter._instruction

        for changed_site in (
            0x3E9C04, 0x3EA6B2, 0x3E8C70, 0x59E844, 0x56EDFE, 0x5ED766,
            0x5F11CA, 0x5F21C8, 0x5F2234, 0x5F291C, 0x5F2920, 0x5F2924,
            0x5F292E, 0x5F293E, 0x5F2A22, 0x5F1116,
        ):
            def changed_instruction(blob, mappings, local_deps, site, *, changed_site=changed_site):
                item = original_instruction(blob, mappings, local_deps, site)
                if site != changed_site:
                    return item
                return _InstructionProxy(item, instruction_id=0, mnemonic="nop", groups=[])

            with self.subTest(site=changed_site), mock.patch.object(
                exporter, "_instruction", side_effect=changed_instruction
            ), self.assertRaises(RuntimeError):
                exporter.ElfAdapter().metadata()

    def test_widget_cast_and_constructor_static_mutations_fail_closed(self):
        """Wrong call, PLT, type filter, or constructor edge cannot prove a belt type."""
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned source or parser dependencies are unavailable")
        exporter = self.exporter
        deps = exporter._dependencies()
        blob = exporter.SOURCE_PATH.read_bytes()
        with exporter.SOURCE_PATH.open("rb") as stream:
            elf = exporter._dependencies()["ELFFile"](stream)
            mappings = exporter._mappings(elf)
            plt_symbols = exporter._plt_symbols(elf, blob, mappings)
            exidx = exporter._exidx_ranges(elf, blob)

            original_target = exporter._direct_target
            original_instruction = exporter._instruction
            for site in (0x5CE128, 0x599C5C):
                def wrong_target(item, local_deps, *, site=site):
                    return 0 if item.address == site else original_target(item, local_deps)

                with self.subTest(call_site=site), mock.patch.object(
                    exporter, "_direct_target", side_effect=wrong_target
                ), self.assertRaises(RuntimeError):
                    exporter._validate_post_lookup_widget_cast(
                        blob, mappings, deps, elf, plt_symbols, exidx
                    )

            def tail_is_not_a_jump(local_blob, local_mappings, local_deps, site):
                item = original_instruction(local_blob, local_mappings, local_deps, site)
                if site == 0x599C5C:
                    return _InstructionProxy(item, groups=[])
                return item

            with mock.patch.object(
                exporter, "_instruction", side_effect=tail_is_not_a_jump
            ), self.assertRaises(RuntimeError):
                exporter._validate_post_lookup_widget_cast(
                    blob, mappings, deps, elf, plt_symbols, exidx
                )

            def wrong_gate(local_blob, local_mappings, local_deps, site):
                item = original_instruction(local_blob, local_mappings, local_deps, site)
                return _InstructionProxy(item, instruction_id=0) if site == 0x1501AC else item

            with mock.patch.object(exporter, "_instruction", side_effect=wrong_gate), self.assertRaises(RuntimeError):
                exporter._validate_post_lookup_widget_cast(blob, mappings, deps, elf, plt_symbols, exidx)

            def wrong_slot(local_blob, local_mappings, local_deps, site):
                item = original_instruction(local_blob, local_mappings, local_deps, site)
                if site != 0x59951E:
                    return item
                operands = list(item.operands)
                operands[1] = _OperandProxy(
                    operands[1], memory=_MemoryProxy(operands[1].mem, displacement=0x194)
                )
                return _InstructionProxy(item, operands)

            with mock.patch.object(exporter, "_instruction", side_effect=wrong_slot), self.assertRaises(RuntimeError):
                exporter._validate_post_lookup_widget_cast(blob, mappings, deps, elf, plt_symbols, exidx)

            def wrong_compare(local_blob, local_mappings, local_deps, site):
                item = original_instruction(local_blob, local_mappings, local_deps, site)
                if site != 0x599528:
                    return item
                operands = list(item.operands)
                operands[1] = _OperandProxy(operands[1], register=deps["r1"])
                return _InstructionProxy(item, operands)

            with mock.patch.object(exporter, "_instruction", side_effect=wrong_compare), self.assertRaises(RuntimeError):
                exporter._validate_post_lookup_widget_cast(blob, mappings, deps, elf, plt_symbols, exidx)

            for site in (0x59951C, 0x599522):
                def wrong_instruction(local_blob, local_mappings, local_deps, address, *, site=site):
                    item = original_instruction(local_blob, local_mappings, local_deps, address)
                    return _InstructionProxy(item, instruction_id=0) if address == site else item

                with self.subTest(structural_site=site), mock.patch.object(
                    exporter, "_instruction", side_effect=wrong_instruction
                ), self.assertRaises(RuntimeError):
                    exporter._validate_post_lookup_widget_cast(
                        blob, mappings, deps, elf, plt_symbols, exidx
                    )

            original_decode = exporter._decode
            for changed_site in (0x59952A, 0x59952E):
                def changed_conditional(
                    local_blob, local_mappings, local_deps, start, end,
                    *, complete=True, changed_site=changed_site,
                ):
                    items = original_decode(
                        local_blob, local_mappings, local_deps, start, end,
                        complete=complete,
                    )
                    if (start, end) != (0x59952A, 0x599530):
                        return items
                    return [
                        _InstructionProxy(item, mnemonic="mov")
                        if item.address == changed_site else item
                        for item in items
                    ]

                with self.subTest(conditional_site=changed_site), mock.patch.object(
                    exporter, "_decode", side_effect=changed_conditional
                ), self.assertRaises(RuntimeError):
                    exporter._validate_post_lookup_widget_cast(
                        blob, mappings, deps, elf, plt_symbols, exidx
                    )

            with mock.patch.object(
                exporter, "_decoded_plt_addresses_exact", return_value={0x944F48: 0x1501C0}
            ), self.assertRaises(RuntimeError):
                exporter._validate_post_lookup_widget_cast(blob, mappings, deps, elf, plt_symbols, exidx)

            relplt = list(elf.get_section_by_name(".rel.plt").iter_relocations())

            class WrongRelocation:
                def __init__(self, real):
                    self.real = real

                def __getitem__(self, key):
                    return 0 if key == "r_offset" else self.real[key]

            class RelocationSection:
                def iter_relocations(self):
                    return [
                        WrongRelocation(item) if index == 551 else item
                        for index, item in enumerate(relplt)
                    ]

            class ElfWithWrongRelocation:
                def get_section_by_name(self, name):
                    return RelocationSection() if name == ".rel.plt" else elf.get_section_by_name(name)

            with self.assertRaises(RuntimeError):
                exporter._validate_post_lookup_widget_cast(
                    blob, mappings, deps, ElfWithWrongRelocation(), plt_symbols, exidx
                )

            class WrongSymbol:
                def __init__(self, real, *, name=None, value=None):
                    self.real = real
                    self.name = real.name if name is None else name
                    self.value = value

                def __getitem__(self, key):
                    if key == "st_value" and self.value is not None:
                        return self.value
                    return self.real[key]

            class DynsymWithWrongCastSymbol:
                def get_symbol(self, index):
                    real = elf.get_section_by_name(".dynsym").get_symbol(index)
                    return WrongSymbol(real, name="wrong_symbol") if index == relplt[551]["r_info_sym"] else real

            class ElfWithWrongDynsym:
                def get_section_by_name(self, name):
                    return DynsymWithWrongCastSymbol() if name == ".dynsym" else elf.get_section_by_name(name)

            with self.assertRaises(RuntimeError):
                exporter._validate_post_lookup_widget_cast(
                    blob, mappings, deps, ElfWithWrongDynsym(), plt_symbols, exidx
                )

            class DynsymWithWrongCastValue:
                def get_symbol(self, index):
                    real = elf.get_section_by_name(".dynsym").get_symbol(index)
                    return WrongSymbol(real, value=0x599541) if index == relplt[551]["r_info_sym"] else real

            class ElfWithWrongDynsymValue:
                def get_section_by_name(self, name):
                    return DynsymWithWrongCastValue() if name == ".dynsym" else elf.get_section_by_name(name)

            with self.assertRaises(RuntimeError):
                exporter._validate_post_lookup_widget_cast(
                    blob, mappings, deps, ElfWithWrongDynsymValue(), plt_symbols, exidx
                )

            with self.assertRaises(RuntimeError):
                exporter._validate_post_lookup_widget_cast(
                    blob, mappings, deps, elf,
                    {**plt_symbols, 0x1501B0: "wrong_symbol"}, exidx,
                )

            with mock.patch.object(exporter, "_call_symbol", return_value="wrong_constructor"), self.assertRaises(RuntimeError):
                exporter._validate_field_0x14c_constructor_boundary(
                    blob, mappings, deps, plt_symbols, exidx
                )

    def test_libobj_constructor_byte_mutation_rejects_candidate_boundary(self):
        """Changing the proven receiver-transfer byte must invalidate the candidate evidence."""
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned source or parser dependencies are unavailable")
        exporter = self.exporter
        deps = exporter._dependencies()
        view_blob = exporter.SOURCE_PATH.read_bytes()
        candidate_blob = bytearray(exporter.LIBOBJ_SOURCE_PATH.read_bytes())
        with exporter.SOURCE_PATH.open("rb") as view_stream, exporter.LIBOBJ_SOURCE_PATH.open("rb") as candidate_stream:
            view_elf = deps["ELFFile"](view_stream)
            candidate_elf = deps["ELFFile"](candidate_stream)
            view_mappings = exporter._mappings(view_elf)
            candidate_mappings = exporter._mappings(candidate_elf)
            view_plt_symbols = exporter._plt_symbols(view_elf, view_blob, view_mappings)
            self.assertEqual(
                exporter._validate_viewbase_constructor_candidate(
                    view_blob, view_mappings, view_elf, view_plt_symbols,
                    candidate_blob, candidate_mappings, candidate_elf, deps,
                ),
                exporter.EXPECTED_EXPORT["field_0x14c_constructor_boundary"],
            )

            transfer = exporter.EXPECTED_EXPORT["field_0x14c_constructor_boundary"]["libobj_candidate"]["receiver_transfer_site"]
            for segment in candidate_elf.iter_segments():
                if segment["p_type"] == "PT_LOAD" and segment["p_vaddr"] <= transfer < segment["p_vaddr"] + segment["p_filesz"]:
                    candidate_blob[segment["p_offset"] + transfer - segment["p_vaddr"]] ^= 0x01
                    break
            else:
                self.fail("candidate receiver-transfer address is not file-backed")

            with self.assertRaises(RuntimeError):
                exporter._validate_viewbase_constructor_candidate(
                    view_blob, view_mappings, view_elf, view_plt_symbols,
                    candidate_blob, candidate_mappings, candidate_elf, deps,
                )


if __name__ == "__main__":
    unittest.main()
