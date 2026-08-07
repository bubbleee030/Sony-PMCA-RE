"""Fail-closed tests for Creative Style model-request transport evidence."""
from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "analysis" / "a6400-creative-style-model-request-transport.json"
EXPORTER = ROOT / "tools" / "static" / "export_a6400_creative_style_model_request_transport.py"


class CreativeStyleModelRequestTransportContractTests(unittest.TestCase):
    def test_typed_request_and_wrapper_chain_are_exact(self):
        from pmca.analysis.creative_style_model_request_transport import EXPECTED_EXPORT

        request = EXPECTED_EXPORT["typed_request"]
        self.assertEqual((request["site"], request["model"], request["request_code"]), (0x4895FA, "@M00B", 38))
        self.assertEqual(request["param_list_add_count"], 5)
        wrapper = EXPECTED_EXPORT["view_wrapper_transport"]
        self.assertEqual(wrapper["wrapper_owner"], {"start": 0x2F11E4, "end": 0x2F1202, "complete": True})
        self.assertEqual(wrapper["tail_branch"], {"site": 0x2F11FE, "target": 0x33A450})
        self.assertEqual(wrapper["helper_call"], {"site": 0x33A462, "target": 0x339CBC})

    def test_operation_38_reaches_shared_edge_but_not_named_handler(self):
        from pmca.analysis.creative_style_model_request_transport import EXPECTED_EXPORT

        boundary = EXPECTED_EXPORT["candidate_cross_module_boundary"]
        self.assertEqual(boundary["site"], 0x339EA0)
        self.assertEqual(boundary["symbol"], "_ZN13viewManagerIf19requestModelExecuteEPKcmP9ParamList")
        self.assertTrue(boundary["operation_38_branch_proven"])
        self.assertTrue(EXPECTED_EXPORT["claims"]["end_to_end_operation_38_event_queue_join_found"])
        self.assertFalse(EXPECTED_EXPORT["claims"]["named_model_handler_found"])

    def test_operation_38_dispatch_path_is_exact_but_model_identity_is_not(self):
        from pmca.analysis.creative_style_model_request_transport import EXPECTED_EXPORT

        path = EXPECTED_EXPORT["operation_38_dispatch_path"]
        self.assertEqual(path["wrapper_argument_capture_sites"], {
            "model": 0x2F11EE, "request_code": 0x2F11EA, "param_list": 0x2F11EC,
        })
        self.assertEqual(path["dispatcher_param_list_capture_site"], 0x339CD0)
        self.assertEqual(path["model_mapping_call_site"], 0x339CF8)
        self.assertEqual(path["model_mapping_target"], 0x3391D8)
        self.assertEqual((path["gate_subtract_value"], path["gate_compare_value"]), (40, 1))
        self.assertEqual(path["gate_branch"], {
            "site": 0x339D04, "target": 0x339E9A, "condition": "unsigned-higher",
        })
        self.assertEqual((path["input_request_code"], path["normalized_gate_value"]), (38, 0xFFFFFFFE))
        self.assertEqual(path["shared_call_site"], 0x339EA0)
        self.assertFalse(path["original_model_identity_preserved"])
        self.assertFalse(EXPECTED_EXPORT["claims"]["original_model_identity_preserved"])
        self.assertFalse(EXPECTED_EXPORT["claims"]["literal_operation_38_event_field_proven"])

    def test_shared_event_transport_and_indirect_blockers_are_exact(self):
        from pmca.analysis.creative_style_model_request_transport import EXPECTED_EXPORT

        shared = EXPECTED_EXPORT["shared_libobj_transport"]
        self.assertEqual(shared["request_owner"], {"start": 0x3F2AA8, "end": 0x3F2AEC, "complete": True})
        self.assertEqual(shared["id_generator_call_site"], 0x3F2AC0)
        self.assertEqual(shared["event_builder_call_site"], 0x3F2AD6)
        self.assertEqual(shared["event_builder_owner"], {"start": 0x8430AC, "end": 0x843118, "complete": True})
        self.assertTrue(shared["shared_request_to_event_queue_join_found"])
        queue = EXPECTED_EXPORT["event_queue_boundary"]
        self.assertEqual(queue["push_owner"], {"start": 0x842598, "end": 0x84264C, "complete": True})
        self.assertEqual(queue["indirect_call_sites"], [0x8425C6, 0x8425D6, 0x842620])
        self.assertFalse(queue["consumer_dispatch_resolved"])

    def test_shared_request_to_event_queue_join_is_exact(self):
        from pmca.analysis.creative_style_model_request_transport import EXPECTED_EXPORT

        join = EXPECTED_EXPORT["shared_request_to_event_queue_join"]
        self.assertEqual(join["continuation_owner"], {"start": 0x3F2A6C, "end": 0x3F2AA8, "complete": True})
        self.assertEqual(join["event_result_capture_site"], 0x3F2A70)
        self.assertEqual((join["parameter_key"], join["parameter_add_call_site"]), (6, 0x3F2A8C))
        self.assertEqual(join["event_argument_site"], 0x3F2A92)
        self.assertEqual(join["continuation_tail_branch"], {"site": 0x3F2A9C, "target": 0x8447F0})
        self.assertEqual(join["queue_helper_owner"], {"start": 0x8447F0, "end": 0x844800, "complete": True})
        self.assertEqual(join["queue_boolean_true_site"], 0x8447F2)
        self.assertEqual(join["queue_receiver_load_site"], 0x8447F6)
        self.assertEqual(join["queue_helper_tail_branch"], {"site": 0x8447FC, "target": 0x100D5C})
        self.assertEqual(join["thumb_to_arm_gate"], 0x100D5C)
        self.assertEqual(join["arm_plt_veneer"], 0x100D60)
        self.assertEqual(join["got_cell"], 0x136B818)
        self.assertEqual(join["relocation"], {"section": ".rel.plt", "index": 1339, "type": 22, "symbol_index": 2860})
        self.assertEqual(join["push_symbol"], "_ZN12EventManager4pushEP5Eventb")
        self.assertTrue(EXPECTED_EXPORT["claims"]["shared_request_to_event_queue_join_found"])
        self.assertTrue(EXPECTED_EXPORT["claims"]["end_to_end_operation_38_event_queue_join_found"])
        self.assertFalse(EXPECTED_EXPORT["claims"]["original_model_identity_preserved"])

    def test_operation_38_event_mapping_is_opaque_but_reaches_key_8(self):
        from pmca.analysis.creative_style_model_request_transport import EXPECTED_EXPORT

        mapping = EXPECTED_EXPORT["operation_38_event_mapping"]
        self.assertEqual(mapping["request_code_capture_site"], 0x3F2AB8)
        self.assertEqual(mapping["request_code_r9_preservation_segment"], [0x3F2ABA, 0x3F2AC4])
        self.assertEqual(mapping["r9_abi"], {
            "attribute_section": ".ARM.attributes",
            "r9_tag": "TAG_ABI_PCS_R9_USE",
            "r9_tag_present": False,
            "tag_nodefaults_present": False,
            "effective_value": 0,
            "classification": "v6-callee-saved-register",
        })
        self.assertEqual(mapping["mapper_call"], {"site": 0x3F2ACA, "target": 0x402EC4})
        self.assertEqual(mapping["mapper_owner"], {"start": 0x402EC4, "end": 0x402FC0, "complete": True})
        self.assertEqual(mapping["mapper_callback_call_site"], 0x402F4C)
        self.assertTrue(mapping["mapper_callback_is_indirect"])
        self.assertEqual(mapping["mapped_operation_builder_argument_site"], 0x3F2AD2)
        self.assertEqual(mapping["builder_operation_capture_site"], 0x8430B6)
        self.assertEqual((mapping["event_parameter_key"], mapping["event_parameter_add_site"]), (8, 0x843100))
        self.assertTrue(mapping["operation_38_origin_reaches_mapped_event_parameter"])
        self.assertFalse(mapping["literal_operation_38_event_field_proven"])
        self.assertFalse(EXPECTED_EXPORT["claims"]["literal_operation_38_event_field_proven"])

    def test_unproven_handler_and_pipeline_claims_cannot_be_promoted(self):
        from pmca.analysis.creative_style_model_request_transport import (
            CreativeStyleModelRequestTransportError,
            EXPECTED_EXPORT,
            normalize_creative_style_model_request_transport_export,
        )

        for key in (
            "original_model_identity_preserved",
            "literal_operation_38_event_field_proven",
            "named_model_handler_found", "renderer_or_live_view_sink_found",
            "still_jpeg_sink_found", "movie_sink_found", "runtime_execution_proven",
        ):
            self.assertFalse(EXPECTED_EXPORT["claims"][key])
            changed = copy.deepcopy(EXPECTED_EXPORT)
            changed["claims"][key] = True
            with self.subTest(key=key), self.assertRaises(CreativeStyleModelRequestTransportError):
                normalize_creative_style_model_request_transport_export(changed)

    def test_checked_in_report_is_non_installable(self):
        from pmca.analysis.creative_style_model_request_transport import validate_creative_style_model_request_transport_report

        report = validate_creative_style_model_request_transport_report(json.loads(REPORT.read_text(encoding="utf-8")))
        self.assertEqual(report["readiness"], "OPERATION_38_EVENT_QUEUE_TRANSPORT_NO_HANDLER")
        self.assertFalse(report["camera_executed"])
        self.assertFalse(report["installable"])
        self.assertFalse(report["camera_test_eligible"])


class CreativeStyleModelRequestTransportExporterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("creative_style_model_request_transport_exporter", EXPORTER)
        cls.exporter = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(cls.exporter)

    def test_adapter_is_normalized(self):
        from pmca.analysis.creative_style_model_request_transport import EXPECTED_EXPORT

        class FakeAdapter:
            def metadata(self):
                return copy.deepcopy(EXPECTED_EXPORT)

        self.assertEqual(self.exporter.build_raw_export(FakeAdapter()), EXPECTED_EXPORT)

    def _real_context(self, role):
        exporter = self.exporter
        path = exporter.SOURCE_PATHS[role]
        blob = path.read_bytes()
        deps = exporter._dependencies()
        handle = path.open("rb")
        elf = deps["ELFFile"](handle)
        mappings = exporter._mappings(elf)
        return (
            handle,
            blob,
            mappings,
            deps,
            elf,
            elf.get_section_by_name(".dynsym"),
            exporter._plt_symbols(elf, blob, mappings),
            exporter._exidx_ranges(elf, blob),
        )

    def test_wrapper_and_candidate_edge_mutations_are_rejected(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned sources or parser dependencies are unavailable")
        exporter = self.exporter
        handle, blob, mappings, deps, _elf, dynsym, plt_symbols, exidx = self._real_context("view")
        original_target = exporter._direct_target
        original_symbol = exporter._call_symbol

        def changed_target(item, local_deps):
            if item.address == 0x2F11FE:
                return 0
            return original_target(item, local_deps)

        def changed_symbol(local_blob, local_mappings, local_deps, local_plt, site):
            if site == 0x339EA0:
                return "wrong"
            return original_symbol(local_blob, local_mappings, local_deps, local_plt, site)

        try:
            with mock.patch.object(exporter, "_direct_target", side_effect=changed_target):
                with self.assertRaisesRegex(RuntimeError, "wrapper tail branch"):
                    exporter._validate_view_transport(blob, mappings, deps, dynsym, plt_symbols, exidx)
            with mock.patch.object(exporter, "_call_symbol", side_effect=changed_symbol):
                with self.assertRaisesRegex(RuntimeError, "candidate shared request edge"):
                    exporter._validate_candidate_boundary(blob, mappings, deps, plt_symbols)
        finally:
            handle.close()

    def test_event_builder_and_queue_shape_mutations_are_rejected(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned sources or parser dependencies are unavailable")
        exporter = self.exporter
        handle, blob, mappings, deps, _elf, dynsym, plt_symbols, exidx = self._real_context("object")
        original_symbol = exporter._call_symbol
        original_decode = exporter._decode

        def changed_symbol(local_blob, local_mappings, local_deps, local_plt, site):
            if site == 0x3F2AD6:
                return "wrong"
            return original_symbol(local_blob, local_mappings, local_deps, local_plt, site)

        class WrongOperands:
            def __init__(self, item):
                self._item = item
                self.operands = []

            def __getattr__(self, name):
                return getattr(self._item, name)

        def changed_decode(local_blob, local_mappings, local_deps, start, end, *, complete=True):
            items = original_decode(local_blob, local_mappings, local_deps, start, end, complete=complete)
            return [WrongOperands(item) if item.address == 0x8425C6 else item for item in items]

        try:
            with mock.patch.object(exporter, "_call_symbol", side_effect=changed_symbol):
                with self.assertRaisesRegex(RuntimeError, "request event builder"):
                    exporter._validate_shared_transport(blob, mappings, deps, dynsym, plt_symbols, exidx)
            with mock.patch.object(exporter, "_decode", side_effect=changed_decode):
                with self.assertRaisesRegex(RuntimeError, "indirect call shape"):
                    exporter._validate_event_queue(blob, mappings, deps, dynsym, exidx)
        finally:
            handle.close()

    def test_real_operation_38_dispatch_path_is_validated(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned sources or parser dependencies are unavailable")
        exporter = self.exporter
        handle, blob, mappings, deps, _elf, _dynsym, plt_symbols, exidx = self._real_context("view")
        try:
            self.assertEqual(
                exporter._validate_operation_38_dispatch_path(blob, mappings, deps, plt_symbols, exidx),
                exporter.EXPECTED_EXPORT["operation_38_dispatch_path"],
            )
        finally:
            handle.close()

    def test_real_shared_request_queue_join_is_validated(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned sources or parser dependencies are unavailable")
        exporter = self.exporter
        handle, blob, mappings, deps, elf, dynsym, plt_symbols, exidx = self._real_context("object")
        try:
            self.assertEqual(
                exporter._validate_shared_request_to_event_queue_join(
                    elf, blob, mappings, deps, dynsym, plt_symbols, exidx,
                ),
                exporter.EXPECTED_EXPORT["shared_request_to_event_queue_join"],
            )
        finally:
            handle.close()

    def test_real_operation_38_event_mapping_is_validated(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned sources or parser dependencies are unavailable")
        exporter = self.exporter
        handle, blob, mappings, deps, elf, _dynsym, plt_symbols, exidx = self._real_context("object")
        try:
            self.assertEqual(
                exporter._validate_operation_38_event_mapping(elf, blob, mappings, deps, plt_symbols, exidx),
                exporter.EXPECTED_EXPORT["operation_38_event_mapping"],
            )
        finally:
            handle.close()

    def test_operation_38_event_mapping_requires_default_r9_abi(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned sources or parser dependencies are unavailable")
        exporter = self.exporter
        handle, blob, mappings, deps, elf, _dynsym, plt_symbols, exidx = self._real_context("object")
        try:
            tags = exporter._arm_attribute_tags(elf)
            self.assertNotIn("TAG_ABI_PCS_R9_USE", tags)
            self.assertNotIn("TAG_NODEFAULTS", tags)
            for forbidden_tag in ("TAG_ABI_PCS_R9_USE", "TAG_NODEFAULTS"):
                with self.subTest(tag=forbidden_tag), mock.patch.object(
                    exporter, "_arm_attribute_tags", return_value={forbidden_tag},
                ):
                    with self.assertRaisesRegex(RuntimeError, "R9 ABI attribute contract"):
                        exporter._validate_operation_38_event_mapping(
                            elf, blob, mappings, deps, plt_symbols, exidx,
                        )
        finally:
            handle.close()

    def test_operation_38_event_mapping_rejects_r9_clobber(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned sources or parser dependencies are unavailable")
        exporter = self.exporter
        handle, blob, mappings, deps, elf, _dynsym, plt_symbols, exidx = self._real_context("object")
        original_decode = exporter._decode

        class RegisterClobber:
            def regs_access(self):
                return [], [deps["r9"]]

        def changed_decode(local_blob, local_mappings, local_deps, start, end, *, complete=True):
            items = original_decode(
                local_blob, local_mappings, local_deps, start, end, complete=complete,
            )
            if (start, end) == (0x3F2ABA, 0x3F2AC4):
                return [RegisterClobber(), *items]
            return items

        try:
            with mock.patch.object(exporter, "_decode", side_effect=changed_decode):
                with self.assertRaisesRegex(RuntimeError, "shared request-code r9 preservation"):
                    exporter._validate_operation_38_event_mapping(
                        elf, blob, mappings, deps, plt_symbols, exidx,
                    )
        finally:
            handle.close()

    def test_operation_38_event_mapping_rejects_alternate_route_code_clobber(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned sources or parser dependencies are unavailable")
        exporter = self.exporter
        handle, blob, mappings, deps, elf, _dynsym, plt_symbols, exidx = self._real_context("object")
        original_decode = exporter._decode

        class RegisterClobber:
            def regs_access(self):
                return [], [deps["r6"]]

        def changed_decode(local_blob, local_mappings, local_deps, start, end, *, complete=True):
            items = original_decode(
                local_blob, local_mappings, local_deps, start, end, complete=complete,
            )
            if (start, end) == (0x402ECE, 0x402F82):
                return [RegisterClobber(), *items]
            return items

        try:
            with mock.patch.object(exporter, "_decode", side_effect=changed_decode):
                with self.assertRaisesRegex(RuntimeError, "alternate-route code preservation"):
                    exporter._validate_operation_38_event_mapping(
                        elf, blob, mappings, deps, plt_symbols, exidx,
                    )
        finally:
            handle.close()

    def test_operation_38_event_mapping_rejects_indexed_callback_memory(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned sources or parser dependencies are unavailable")
        exporter = self.exporter
        handle, blob, mappings, deps, elf, _dynsym, plt_symbols, exidx = self._real_context("object")
        original_instruction = exporter._instruction

        class Memory:
            def __init__(self, original):
                self.base = original.base
                self.index = deps["r1"]
                self.disp = original.disp

        class Operand:
            def __init__(self, original):
                self._original = original
                self.mem = Memory(original.mem)

            def __getattr__(self, name):
                return getattr(self._original, name)

        class MutatedMemoryInstruction:
            def __init__(self, original, mutation):
                self._original = original
                self.operands = list(original.operands)
                self.writeback = original.writeback
                if mutation == "index":
                    self.operands[1] = Operand(self.operands[1])
                elif mutation == "writeback":
                    self.writeback = True
                elif mutation == "postindex":
                    self.operands.append(self.operands[0])

            def __getattr__(self, name):
                return getattr(self._original, name)

        try:
            for mutation in ("index", "writeback", "postindex"):
                def changed_instruction(local_blob, local_mappings, local_deps, site):
                    item = original_instruction(local_blob, local_mappings, local_deps, site)
                    return MutatedMemoryInstruction(item, mutation) if site == 0x402F26 else item

                with self.subTest(mutation=mutation), mock.patch.object(
                    exporter, "_instruction", side_effect=changed_instruction,
                ):
                    with self.assertRaisesRegex(RuntimeError, "operation mapper callback object addressing"):
                        exporter._validate_operation_38_event_mapping(
                            elf, blob, mappings, deps, plt_symbols, exidx,
                        )
        finally:
            handle.close()

    def test_operation_38_gate_and_dataflow_mutations_are_rejected(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned sources or parser dependencies are unavailable")
        exporter = self.exporter
        handle, blob, mappings, deps, _elf, _dynsym, plt_symbols, exidx = self._real_context("view")
        original_instruction = exporter._instruction
        original_decode = exporter._decode

        class WrongInstruction:
            def __init__(self, item):
                self._item = item
                self.id = -1
                self.cc = -1

            def __getattr__(self, name):
                return getattr(self._item, name)

        class RegisterClobber:
            def __init__(self, register):
                self.register = register

            def regs_access(self):
                return [], [self.register]

        try:
            for changed_site, message in (
                (0x339CFC, "unsigned dispatcher gate"),
                (0x339D04, "unsigned dispatcher gate"),
                (0x339E9E, "shared ParamList argument"),
            ):
                def changed_instruction(local_blob, local_mappings, local_deps, site):
                    item = original_instruction(local_blob, local_mappings, local_deps, site)
                    return WrongInstruction(item) if site == changed_site else item

                with self.subTest(site=changed_site), mock.patch.object(exporter, "_instruction", side_effect=changed_instruction):
                    with self.assertRaisesRegex(RuntimeError, message):
                        exporter._validate_operation_38_dispatch_path(blob, mappings, deps, plt_symbols, exidx)

            for changed_range, register, message in (
                ((0x339CD0, 0x339CFC), deps["r8"], "request-code preservation to gate"),
                ((0x339CD4, 0x339D04), deps["r6"], "ParamList preservation to gate"),
            ):
                def changed_decode(local_blob, local_mappings, local_deps, start, end, *, complete=True):
                    items = original_decode(local_blob, local_mappings, local_deps, start, end, complete=complete)
                    return [RegisterClobber(register), *items] if (start, end) == changed_range else items

                with self.subTest(span=changed_range), mock.patch.object(exporter, "_decode", side_effect=changed_decode):
                    with self.assertRaisesRegex(RuntimeError, message):
                        exporter._validate_operation_38_dispatch_path(blob, mappings, deps, plt_symbols, exidx)
        finally:
            handle.close()

    def test_operation_mapping_and_queue_join_mutations_are_rejected(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned sources or parser dependencies are unavailable")
        exporter = self.exporter
        handle, blob, mappings, deps, elf, dynsym, plt_symbols, exidx = self._real_context("object")
        original_instruction = exporter._instruction
        original_target = exporter._direct_target
        original_decode = exporter._decode

        class WrongInstruction:
            def __init__(self, item):
                self._item = item
                self.id = -1

            def __getattr__(self, name):
                return getattr(self._item, name)

        class RegisterClobber:
            def __init__(self, register):
                self.register = register

            def regs_access(self):
                return [], [self.register]

        class WrongNameSymbol:
            name = "wrong"

        class WrongPushDynsym:
            def get_symbol(self, index):
                if index == 2860:
                    return WrongNameSymbol()
                return dynsym.get_symbol(index)

        try:
            for changed_site, message in (
                (0x402F4A, "callback code argument"),
                (0x3F2AD2, "Event-builder argument"),
                (0x8430FC, "Event key"),
            ):
                def changed_instruction(local_blob, local_mappings, local_deps, site):
                    item = original_instruction(local_blob, local_mappings, local_deps, site)
                    return WrongInstruction(item) if site == changed_site else item

                with self.subTest(site=changed_site), mock.patch.object(exporter, "_instruction", side_effect=changed_instruction):
                    with self.assertRaisesRegex(RuntimeError, message):
                        exporter._validate_operation_38_event_mapping(
                            elf, blob, mappings, deps, plt_symbols, exidx,
                        )

            def changed_boolean(local_blob, local_mappings, local_deps, site):
                item = original_instruction(local_blob, local_mappings, local_deps, site)
                return WrongInstruction(item) if site == 0x8447F2 else item

            with mock.patch.object(exporter, "_instruction", side_effect=changed_boolean):
                with self.assertRaisesRegex(RuntimeError, "Event queue boolean"):
                    exporter._validate_shared_request_to_event_queue_join(
                        elf, blob, mappings, deps, dynsym, plt_symbols, exidx,
                    )

            for changed_range, register, message, validator in (
                ((0x3F2ACE, 0x3F2AD2), deps["r0"], "mapped operation return preservation", "mapping"),
                ((0x3F2A72, 0x3F2A92), deps["r5"], "shared request Event preservation", "queue"),
                ((0x3F2A94, 0x3F2A9C), deps["r1"], "Event queue argument preservation", "queue"),
                ((0x8447F0, 0x8447FC), deps["r1"], "queue helper Event preservation", "queue"),
                ((0x8447F4, 0x8447FC), deps["r2"], "queue helper boolean preservation", "queue"),
            ):
                def changed_decode(local_blob, local_mappings, local_deps, start, end, *, complete=True):
                    items = original_decode(
                        local_blob, local_mappings, local_deps, start, end, complete=complete,
                    )
                    return [RegisterClobber(register), *items] if (start, end) == changed_range else items

                with self.subTest(span=changed_range), mock.patch.object(
                    exporter, "_decode", side_effect=changed_decode,
                ):
                    with self.assertRaisesRegex(RuntimeError, message):
                        if validator == "mapping":
                            exporter._validate_operation_38_event_mapping(
                                elf, blob, mappings, deps, plt_symbols, exidx,
                            )
                        else:
                            exporter._validate_shared_request_to_event_queue_join(
                                elf, blob, mappings, deps, dynsym, plt_symbols, exidx,
                            )

            for changed_site, validator, message in (
                (0x3F2ADE, "shared", "event continuation"),
                (0x3F2ACA, "mapping", "mapper call"),
                (0x3F2A9C, "queue", "continuation tail branch"),
                (0x8447FC, "queue", "queue helper PLT tail branch"),
            ):
                def changed_target(item, local_deps):
                    return 0 if item.address == changed_site else original_target(item, local_deps)

                with self.subTest(branch=changed_site), mock.patch.object(
                    exporter, "_direct_target", side_effect=changed_target,
                ):
                    with self.assertRaisesRegex(RuntimeError, message):
                        if validator == "shared":
                            exporter._validate_shared_transport(
                                blob, mappings, deps, dynsym, plt_symbols, exidx,
                            )
                        elif validator == "mapping":
                            exporter._validate_operation_38_event_mapping(
                                elf, blob, mappings, deps, plt_symbols, exidx,
                            )
                        else:
                            exporter._validate_shared_request_to_event_queue_join(
                                elf, blob, mappings, deps, dynsym, plt_symbols, exidx,
                            )

            with mock.patch.object(exporter, "_decoded_plt_addresses_exact", return_value={}):
                with self.assertRaisesRegex(RuntimeError, "PLT veneer"):
                    exporter._validate_shared_request_to_event_queue_join(
                        elf, blob, mappings, deps, dynsym, plt_symbols, exidx,
                    )
            with self.assertRaisesRegex(RuntimeError, "relocation contract"):
                exporter._validate_shared_request_to_event_queue_join(
                    elf, blob, mappings, deps, WrongPushDynsym(), plt_symbols, exidx,
                )
        finally:
            handle.close()

    def test_real_export_matches_when_available(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned sources or parser dependencies are unavailable")
        self.assertEqual(self.exporter.build_raw_export(), self.exporter.EXPECTED_EXPORT)


if __name__ == "__main__":
    unittest.main()
