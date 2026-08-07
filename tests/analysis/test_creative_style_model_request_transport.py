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
        self.assertEqual(path["model_mapping_input_site"], 0x339CF6)
        self.assertEqual(path["dispatcher_model_preservation_segment"], [0x339CCE, 0x339CF6])
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

    def test_operation_38_event_header_is_exact(self):
        from pmca.analysis.creative_style_model_request_transport import EXPECTED_EXPORT

        header = EXPECTED_EXPORT["operation_38_event_header"]
        self.assertEqual(header["builder_owner"], {
            "start": 0x8430AC, "end": 0x843118, "complete": True,
        })
        self.assertEqual(
            (header["event_id_literal_load_site"], header["event_id_literal_address"], header["event_id"]),
            (0x8430BE, 0x843114, 0x11004003),
        )
        self.assertEqual(
            (header["destination_argument_site"], header["destination"]),
            (0x8430C0, 2),
        )
        self.assertEqual(
            (header["queue_tag_argument_site"], header["queue_tag"]),
            (0x8430C2, 0),
        )
        self.assertEqual(header["header_argument_preservation_segments"], {
            "event_id": [0x8430C0, 0x8430C6],
            "destination": [0x8430C2, 0x8430C6],
            "queue_tag": [0x8430C4, 0x8430C6],
        })
        self.assertEqual(header["constructor_owner"], {
            "start": 0x840FEC, "end": 0x841022, "complete": True,
        })
        self.assertEqual(header["event_id_store"], {
            "site": 0x840FF0, "offset": 4, "width": 4,
        })
        self.assertEqual(header["destination_store"], {
            "site": 0x840FF4, "offset": 8, "width": 1,
        })
        self.assertEqual(header["queue_tag_store"], {
            "site": 0x840FF6, "offset": 9, "width": 1,
        })
        self.assertEqual(header["set_param_list_store"], {
            "site": 0x84108A, "offset": 12, "width": 4,
        })
        self.assertEqual(header["add_parameter_param_list_load"], {
            "site": 0x347940, "offset": 12, "width": 4,
        })
        self.assertTrue(EXPECTED_EXPORT["claims"]["operation_38_event_header_proven"])
        self.assertFalse(EXPECTED_EXPORT["claims"]["literal_operation_38_event_field_proven"])

    def test_m00b_alias_resolves_to_model_camera_but_numeric_key_7_id_does_not(self):
        from pmca.analysis.creative_style_model_request_transport import EXPECTED_EXPORT

        alias = EXPECTED_EXPORT["operation_38_model_alias"]
        self.assertEqual(alias["mapper_owner"], {
            "start": 0x3391D8, "end": 0x339234, "complete": True,
        })
        self.assertEqual((alias["input_model"], alias["resolved_model_alias"]), (
            "@M00B", "model/CAMERA",
        ))
        self.assertEqual(alias["table"], {
            "literal_load_site": 0x3391F0,
            "literal_address": 0x339230,
            "pc_add_site": 0x3391F4,
            "base": 0x8D760C,
            "entry_stride": 8,
            "entry_count": 23,
        })
        self.assertEqual(alias["entry_zero"], {
            "key_cell": 0x8D760C,
            "key_relocation": {"section": ".rel.dyn", "index": 13096, "type": 23, "symbol_index": 0},
            "key_address": 0x667129,
            "key": "@M00B",
            "result_cell": 0x8D7610,
            "result_relocation": {"section": ".rel.dyn", "index": 13097, "type": 23, "symbol_index": 0},
            "result_address": 0x6671FB,
            "result": "model/CAMERA",
        })
        self.assertEqual(alias["id_generator_owner"], {
            "start": 0x402DB4, "end": 0x402EC4, "complete": True,
        })
        self.assertEqual(alias["id_generator_call_site"], 0x3F2AC0)
        self.assertEqual(alias["id_generator_model_preservation_segment"], [0x3F2AB8, 0x3F2AC0])
        self.assertEqual(alias["id_generator_result_preservation_segment"], [0x3F2AC8, 0x3F2ACE])
        self.assertEqual(alias["builder_id_preservation_segment"], [0x8430B6, 0x8430DA])
        self.assertEqual((alias["event_parameter_key"], alias["event_parameter_add_site"]), (7, 0x8430E8))
        self.assertTrue(alias["semantic_model_alias_resolved"])
        self.assertFalse(alias["original_model_literal_preserved"])
        self.assertFalse(alias["numeric_model_id_resolved"])
        self.assertTrue(EXPECTED_EXPORT["claims"]["creative_style_request_model_alias_resolved"])
        self.assertTrue(EXPECTED_EXPORT["claims"]["operation_38_model_id_reaches_event_key_7"])
        self.assertFalse(EXPECTED_EXPORT["claims"]["operation_38_key_7_numeric_model_id_resolved"])
        self.assertFalse(EXPECTED_EXPORT["claims"]["named_model_handler_found"])

    def test_operation_38_tag_zero_bypasses_all_queue_indirect_calls(self):
        from pmca.analysis.creative_style_model_request_transport import EXPECTED_EXPORT

        dispatch = EXPECTED_EXPORT["operation_38_queue_dispatch"]
        self.assertEqual(dispatch["queue_tag_reader_owner"], {
            "start": 0x842458, "end": 0x84248C, "complete": True,
        })
        self.assertEqual(dispatch["queue_tag_reader_function"], {
            "start": 0x842484, "end": 0x84248C,
        })
        self.assertEqual(dispatch["queue_tag_read_call"], {
            "site": 0x8425A8, "target": 0x842484,
        })
        self.assertEqual(dispatch["tag_one_compare_site"], 0x8425AC)
        self.assertEqual(dispatch["tag_three_compare_site"], 0x8425B2)
        self.assertEqual(dispatch["other_tag_branch"], {
            "site": 0x8425B4, "target": 0x842624,
        })
        self.assertEqual(dispatch["tag_zero_fallthrough_site"], 0x842624)
        self.assertEqual(dispatch["queue_zero_call"], {
            "site": 0x842632, "target": 0x840CE2,
        })
        self.assertEqual(dispatch["queue_zero_helper_owner"], {
            "start": 0x840CE2, "end": 0x840D02, "complete": True,
        })
        self.assertEqual(
            dispatch["bypassed_indirect_call_sites"],
            [0x8425C6, 0x8425D6, 0x842620],
        )
        self.assertTrue(EXPECTED_EXPORT["claims"]["operation_38_tag_zero_queue_path_proven"])
        self.assertTrue(EXPECTED_EXPORT["claims"]["operation_38_indirect_queue_callbacks_bypassed"])
        self.assertFalse(EXPECTED_EXPORT["claims"]["named_model_handler_found"])

    def test_operation_38_queue_to_consumer_identity_remains_unproven(self):
        from pmca.analysis.creative_style_model_request_transport import EXPECTED_EXPORT

        identity = EXPECTED_EXPORT["operation_38_queue_consumer_identity"]
        self.assertEqual(identity["producer_global"], {
            "got_cell": 0x136EC90,
            "relocation": {
                "section": ".rel.dyn", "index": 65700, "type": 23,
                "symbol_index": 0, "target": 0x13EF0C0,
            },
        })
        self.assertEqual(identity["producer_receiver_steps"], [
            "utility_manager=load(app_config+0x10)",
            "wrapper=load(utility_manager+0x0c)",
            "producer_event_manager=load(wrapper+0x10)",
        ])
        self.assertEqual(identity["consumer_receiver_steps"], [
            "outer=thread_stack_frame+4",
            "consumer_event_manager=load(outer+0x10)",
        ])
        self.assertEqual(identity["consumer_pop"], {
            "queue_index_site": 0x84409C,
            "queue_index": 0,
            "receiver_load_site": 0x84409E,
            "call": {"site": 0x8440A6, "target": 0x842574},
        })
        self.assertEqual(identity["consumer_dispatch"], {
            "event_argument_site": 0x8440AA,
            "receiver_site": 0x8440AC,
            "call": {"site": 0x8440AE, "target": 0x843A84},
            "event_preservation_segment": [0x8440AC, 0x8440AE],
        })
        self.assertTrue(identity["producer_receiver_expression_proven"])
        self.assertTrue(identity["consumer_receiver_expression_proven"])
        self.assertFalse(identity["utility_manager_outer_backref_proven"])
        self.assertFalse(identity["same_event_manager_instance_proven"])
        self.assertFalse(identity["operation_38_queue_to_consumer_identity_proven"])
        self.assertFalse(EXPECTED_EXPORT["claims"]["operation_38_queue_to_consumer_identity_proven"])
        self.assertFalse(EXPECTED_EXPORT["claims"]["operation_38_reaches_model_manager_dispatch"])

    def test_model_manager_request_event_candidate_is_bounded_without_operation_38_join(self):
        from pmca.analysis.creative_style_model_request_transport import EXPECTED_EXPORT

        candidate = EXPECTED_EXPORT["model_manager_request_event_candidate"]
        self.assertEqual((candidate["event_id"], candidate["destination"]), (0x11004003, 2))
        self.assertEqual(candidate["central_dispatch_owner"], {
            "start": 0x843A84, "end": 0x843C48, "complete": True,
        })
        self.assertEqual(candidate["destination_two_call"], {
            "site": 0x843B6A, "target": 0x84A830,
        })
        self.assertEqual(candidate["central_event_preservation_segment"], [0x843A8E, 0x843B68])
        self.assertEqual(candidate["model_manager_dispatch_owner"], {
            "start": 0x84A830, "end": 0x84AC94, "complete": True,
        })
        self.assertEqual(candidate["request_event_branch"], {
            "site": 0x84A896, "target": 0x84A95C,
        })
        self.assertEqual(candidate["parameter_keys"], {
            "request_context": {"site": 0x84A95C, "key": 6},
            "model_id": {"site": 0x84A966, "key": 7},
            "mapped_operation": {"site": 0x84A97C, "key": 8},
        })
        self.assertEqual(candidate["model_record_lookup_call"], {
            "site": 0x84A990, "target": 0x84903E,
        })
        self.assertEqual(candidate["model_id_value_flow"], {
            "event_capture_site": 0x84A83C,
            "event_preservation_segment": [0x84A83E, 0x84A964],
            "parameter_receiver_site": 0x84A964,
            "missing_branch": {"site": 0x84A96C, "target": 0x84A976},
            "scalar_result_capture_site": 0x84A972,
            "scalar_join_branch": {"site": 0x84A974, "target": 0x84A97A},
            "missing_sentinel_site": 0x84A976,
            "missing_sentinel": -1,
            "lookup_argument_site": 0x84A98E,
            "preservation_segment": [0x84A97A, 0x84A98E],
        })
        self.assertEqual(candidate["mapped_operation_value_flow"], {
            "parameter_receiver_site": 0x84A97A,
            "event_preservation_segment": [0x84A83E, 0x84A97A],
            "pointer_or_null_capture_site": 0x84A982,
            "missing_branch": {"site": 0x84A984, "target": 0x84A98C},
            "scalar_result_capture_site": 0x84A98A,
            "joined_preservation_segment": [0x84A98C, 0x84A9B8],
            "secondary_event_id_site": 0x84A9B8,
        })
        self.assertEqual(candidate["model_record_validity"], {
            "compare_site": 0x84A996,
            "missing_branch": {"site": 0x84A998, "target": 0x84A9FE},
            "executor_argument_site": 0x84A9E0,
            "record_preservation_segment": [0x84A996, 0x84A9E0],
        })
        self.assertEqual(candidate["model_executor_inputs"], {
            "secondary_event_capture_site": 0x84A9BC,
            "secondary_event_preservation_segment": [0x84A9BE, 0x84A9E2],
            "record_argument_site": 0x84A9E0,
            "event_argument_site": 0x84A9E2,
        })
        self.assertEqual(candidate["executor_validity"], {
            "presence_branch": {"site": 0x8411AA, "target": 0x8411B4},
            "missing_sentinel_site": 0x8411B4,
            "missing_sentinel": -1,
            "event_preservation_segment": [0x8411A4, 0x8411AC],
        })
        self.assertEqual(candidate["model_executor_call"], {
            "site": 0x84A9E4, "target": 0x8411A4,
        })
        self.assertEqual(candidate["executor_virtual_slot"], 0x18)
        self.assertTrue(candidate["model_manager_request_event_branch_found"])
        self.assertFalse(candidate["operation_38_queue_join_proven"])
        self.assertFalse(candidate["concrete_model_record_found"])
        self.assertFalse(candidate["concrete_model_executor_handler_found"])
        self.assertTrue(EXPECTED_EXPORT["claims"]["model_manager_request_event_branch_found"])
        self.assertFalse(EXPECTED_EXPORT["claims"]["operation_38_reaches_model_manager_dispatch"])
        self.assertFalse(EXPECTED_EXPORT["claims"]["concrete_model_record_found"])

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
        self.assertEqual(report["readiness"], "OPERATION_38_TAG_ZERO_QUEUE_NO_CONSUMER_IDENTITY")
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

    def _real_context_dict(self, role):
        handle, blob, mappings, deps, elf, dynsym, plt_symbols, exidx = self._real_context(role)
        return handle, deps, {
            "elf": elf,
            "blob": blob,
            "mappings": mappings,
            "dynsym": dynsym,
            "plt_symbols": plt_symbols,
            "exidx": exidx,
        }

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

    def test_real_operation_38_event_header_is_validated(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned sources or parser dependencies are unavailable")
        exporter = self.exporter
        handle, blob, mappings, deps, _elf, _dynsym, plt_symbols, exidx = self._real_context("object")
        try:
            self.assertEqual(
                exporter._validate_operation_38_event_header(
                    blob, mappings, deps, plt_symbols, exidx,
                ),
                exporter.EXPECTED_EXPORT["operation_38_event_header"],
            )
        finally:
            handle.close()

    def test_real_m00b_model_alias_and_key_7_transport_are_validated(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned sources or parser dependencies are unavailable")
        exporter = self.exporter
        view_handle, deps, view = self._real_context_dict("view")
        object_handle, object_deps, obj = self._real_context_dict("object")
        self.assertEqual(deps.keys(), object_deps.keys())
        try:
            self.assertEqual(
                exporter._validate_operation_38_model_alias(view, obj, deps),
                exporter.EXPECTED_EXPORT["operation_38_model_alias"],
            )
        finally:
            object_handle.close()
            view_handle.close()

    def test_m00b_model_alias_and_key_7_mutations_are_rejected(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned sources or parser dependencies are unavailable")
        exporter = self.exporter
        view_handle, deps, view = self._real_context_dict("view")
        object_handle, _object_deps, obj = self._real_context_dict("object")
        original_instruction = exporter._instruction
        original_symbol = exporter._call_symbol
        original_word = exporter._word
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

        try:
            for changed_site, message in (
                (0x3391E8, "model-alias first-byte gate"),
                (0x3391F6, "model-alias candidate pointer"),
                (0x339214, "model-alias result load"),
                (0x3F2AC6, "model ID result capture"),
                (0x8430E4, "model ID Event key"),
                (0x402DBE, "IdGenerator first-byte gate"),
            ):
                def changed_instruction(local_blob, local_mappings, local_deps, site):
                    item = original_instruction(local_blob, local_mappings, local_deps, site)
                    return WrongInstruction(item) if site == changed_site else item

                with self.subTest(site=changed_site), mock.patch.object(
                    exporter, "_instruction", side_effect=changed_instruction,
                ):
                    with self.assertRaisesRegex(RuntimeError, message):
                        exporter._validate_operation_38_model_alias(view, obj, deps)

            for changed_range, register, message in (
                ((0x3F2AB8, 0x3F2AC0), deps["r0"], "model IdGenerator argument preservation"),
                ((0x3F2AC8, 0x3F2ACE), deps["r6"], "model ID result preservation"),
                ((0x8430B6, 0x8430DA), deps["r6"], "Event-builder model ID preservation"),
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
                        exporter._validate_operation_38_model_alias(view, obj, deps)

            def changed_word(local_blob, local_mappings, address, **kwargs):
                if address == 0x8D7610:
                    return 0
                return original_word(local_blob, local_mappings, address, **kwargs)

            with mock.patch.object(exporter, "_word", side_effect=changed_word):
                with self.assertRaisesRegex(RuntimeError, "model-alias entry-zero relocation target"):
                    exporter._validate_operation_38_model_alias(view, obj, deps)

            for changed_site, message in (
                (0x3F2AC0, "model IdGenerator call"),
                (0x402E34, "runtime model-ID lookup"),
                (0x8430E8, "model ID Event parameter add"),
            ):
                def changed_symbol(local_blob, local_mappings, local_deps, local_plt, site):
                    if site == changed_site:
                        return "wrong"
                    return original_symbol(local_blob, local_mappings, local_deps, local_plt, site)

                with self.subTest(site=changed_site), mock.patch.object(
                    exporter, "_call_symbol", side_effect=changed_symbol,
                ):
                    with self.assertRaisesRegex(RuntimeError, message):
                        exporter._validate_operation_38_model_alias(view, obj, deps)
        finally:
            object_handle.close()
            view_handle.close()

    def test_operation_38_event_header_mutations_are_rejected(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned sources or parser dependencies are unavailable")
        exporter = self.exporter
        handle, blob, mappings, deps, _elf, _dynsym, plt_symbols, exidx = self._real_context("object")
        original_instruction = exporter._instruction
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

        class Memory:
            def __init__(self, original):
                self.base = original.base
                self.index = original.index
                self.disp = original.disp + 4

        class Operand:
            def __init__(self, original):
                self._original = original
                self.mem = Memory(original.mem)

            def __getattr__(self, name):
                return getattr(self._original, name)

        class WrongDisplacement:
            def __init__(self, item):
                self._item = item
                self.operands = list(item.operands)
                self.operands[1] = Operand(self.operands[1])

            def __getattr__(self, name):
                return getattr(self._item, name)

        try:
            for changed_site, message in (
                (0x8430C0, "Event destination argument"),
                (0x8430C2, "Event queue-tag argument"),
                (0x840FF0, "Event ID store"),
                (0x840FF4, "Event destination store"),
                (0x840FF6, "Event queue-tag store"),
            ):
                def changed_instruction(local_blob, local_mappings, local_deps, site):
                    item = original_instruction(local_blob, local_mappings, local_deps, site)
                    return WrongInstruction(item) if site == changed_site else item

                with self.subTest(site=changed_site), mock.patch.object(
                    exporter, "_instruction", side_effect=changed_instruction,
                ):
                    with self.assertRaisesRegex(RuntimeError, message):
                        exporter._validate_operation_38_event_header(
                            blob, mappings, deps, plt_symbols, exidx,
                        )

            for changed_site, message in (
                (0x84108A, "Event ParamList store"),
                (0x347940, "Event add-parameter ParamList load"),
                (0x842480, "Event destination load"),
                (0x842488, "Event queue-tag load"),
            ):
                def changed_instruction(local_blob, local_mappings, local_deps, site):
                    item = original_instruction(local_blob, local_mappings, local_deps, site)
                    return WrongDisplacement(item) if site == changed_site else item

                with self.subTest(site=changed_site), mock.patch.object(
                    exporter, "_instruction", side_effect=changed_instruction,
                ):
                    with self.assertRaisesRegex(RuntimeError, message):
                        exporter._validate_operation_38_event_header(
                            blob, mappings, deps, plt_symbols, exidx,
                        )

            with mock.patch.object(exporter, "_word", return_value=0):
                with self.assertRaisesRegex(RuntimeError, "Event ID literal value"):
                    exporter._validate_operation_38_event_header(
                        blob, mappings, deps, plt_symbols, exidx,
                    )

            for changed_range, register, message in (
                ((0x8430C0, 0x8430C6), deps["r1"], "Event ID argument preservation"),
                ((0x8430C2, 0x8430C6), deps["r2"], "Event destination argument preservation"),
                ((0x8430C4, 0x8430C6), deps["r3"], "Event queue-tag argument preservation"),
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
                        exporter._validate_operation_38_event_header(
                            blob, mappings, deps, plt_symbols, exidx,
                        )
        finally:
            handle.close()

    def test_real_queue_consumer_identity_boundary_is_validated(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned sources or parser dependencies are unavailable")
        exporter = self.exporter
        handle, blob, mappings, deps, elf, dynsym, _plt_symbols, exidx = self._real_context("object")
        try:
            self.assertEqual(
                exporter._validate_operation_38_queue_consumer_identity(
                    elf, blob, mappings, deps, dynsym, exidx,
                ),
                exporter.EXPECTED_EXPORT["operation_38_queue_consumer_identity"],
            )
        finally:
            handle.close()

    def test_queue_consumer_identity_mutations_are_rejected(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned sources or parser dependencies are unavailable")
        exporter = self.exporter
        handle, blob, mappings, deps, elf, dynsym, _plt_symbols, exidx = self._real_context("object")
        original_instruction = exporter._instruction
        original_target = exporter._direct_target
        original_decode = exporter._decode
        original_word = exporter._word

        class WrongInstruction:
            def __init__(self, item):
                self._item = item
                self.id = -1

            def __getattr__(self, name):
                return getattr(self._item, name)

        class RegisterClobber:
            def regs_access(self):
                return [], [deps["r1"]]

        try:
            for changed_site, message in (
                (0x3FD93A, "UtilityManager source load"),
                (0x3F29DE, "producer wrapper load"),
                (0x3F29EA, "producer global store"),
                (0x3F2A96, "producer global value load"),
                (0x8447F6, "producer EventManager receiver load"),
                (0x843D58, "outer EventManager store"),
                (0x84409E, "consumer EventManager receiver load"),
                (0x8440AA, "consumer central-dispatch Event argument"),
                (0x8440AC, "consumer central-dispatch receiver"),
            ):
                def changed_instruction(local_blob, local_mappings, local_deps, site):
                    item = original_instruction(local_blob, local_mappings, local_deps, site)
                    return WrongInstruction(item) if site == changed_site else item

                with self.subTest(site=changed_site), mock.patch.object(
                    exporter, "_instruction", side_effect=changed_instruction,
                ):
                    with self.assertRaisesRegex(RuntimeError, message):
                        exporter._validate_operation_38_queue_consumer_identity(
                            elf, blob, mappings, deps, dynsym, exidx,
                        )

            for changed_site, message in (
                (0x3FD93C, "producer initializer call"),
                (0x8431AE, "outer constructor call"),
                (0x8431DE, "outer consumer-loop call"),
                (0x8440A6, "consumer queue-zero pop"),
                (0x8440AE, "consumer central Event dispatch"),
            ):
                def changed_target(item, local_deps):
                    return 0 if item.address == changed_site else original_target(item, local_deps)

                with self.subTest(site=changed_site), mock.patch.object(
                    exporter, "_direct_target", side_effect=changed_target,
                ):
                    with self.assertRaisesRegex(RuntimeError, message):
                        exporter._validate_operation_38_queue_consumer_identity(
                            elf, blob, mappings, deps, dynsym, exidx,
                        )

            def changed_decode(local_blob, local_mappings, local_deps, start, end, *, complete=True):
                items = original_decode(
                    local_blob, local_mappings, local_deps, start, end, complete=complete,
                )
                return [RegisterClobber(), *items] if (start, end) == (0x8440AC, 0x8440AE) else items

            with mock.patch.object(exporter, "_decode", side_effect=changed_decode):
                with self.assertRaisesRegex(RuntimeError, "consumer central-dispatch Event preservation"):
                    exporter._validate_operation_38_queue_consumer_identity(
                        elf, blob, mappings, deps, dynsym, exidx,
                    )

            def changed_word(local_blob, local_mappings, address, **kwargs):
                if address == 0x136EC90:
                    return 0
                return original_word(local_blob, local_mappings, address, **kwargs)

            with mock.patch.object(exporter, "_word", side_effect=changed_word):
                with self.assertRaisesRegex(RuntimeError, "producer global relocation target"):
                    exporter._validate_operation_38_queue_consumer_identity(
                        elf, blob, mappings, deps, dynsym, exidx,
                    )
        finally:
            handle.close()

    def test_real_model_manager_request_event_candidate_is_validated(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned sources or parser dependencies are unavailable")
        exporter = self.exporter
        handle, blob, mappings, deps, _elf, _dynsym, plt_symbols, exidx = self._real_context("object")
        try:
            self.assertEqual(
                exporter._validate_model_manager_request_event_candidate(
                    blob, mappings, deps, plt_symbols, exidx,
                ),
                exporter.EXPECTED_EXPORT["model_manager_request_event_candidate"],
            )
        finally:
            handle.close()

    def test_model_manager_request_event_candidate_mutations_are_rejected(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned sources or parser dependencies are unavailable")
        exporter = self.exporter
        handle, blob, mappings, deps, _elf, _dynsym, plt_symbols, exidx = self._real_context("object")
        original_instruction = exporter._instruction
        original_target = exporter._direct_target
        original_symbol = exporter._call_symbol
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

        try:
            for changed_site, message in (
                (0x843B54, "destination-two mask"),
                (0x843B66, "ModelManager receiver load"),
                (0x84A83C, "ModelManager Event capture"),
                (0x84A888, "request Event-ID subtract"),
                (0x84A890, "request Event-ID add"),
                (0x84A966, "model-ID parameter key"),
                (0x84A964, "model-ID parameter receiver"),
                (0x84A96C, "model-ID missing branch"),
                (0x84A972, "model-ID scalar result capture"),
                (0x84A976, "model-ID missing sentinel"),
                (0x84A98E, "model-ID lookup argument"),
                (0x84A996, "model-record validity comparison"),
                (0x84A97C, "mapped-operation parameter key"),
                (0x84A97A, "mapped-operation parameter receiver"),
                (0x84A982, "mapped-operation getter result capture"),
                (0x84A984, "mapped-operation missing branch"),
                (0x84A98A, "mapped-operation scalar result capture"),
                (0x84A9B8, "secondary Event mapped-operation ID"),
                (0x84A9BC, "secondary Event capture"),
                (0x84A9E0, "model-record executor argument"),
                (0x84A9E2, "model-executor Event argument"),
                (0x8411A4, "model-record executor load"),
                (0x8411AA, "model-executor presence branch"),
                (0x8411B4, "model-executor missing sentinel"),
                (0x843028, "executor virtual target load"),
                (0x84302A, "executor virtual call"),
            ):
                def changed_instruction(local_blob, local_mappings, local_deps, site):
                    item = original_instruction(local_blob, local_mappings, local_deps, site)
                    return WrongInstruction(item) if site == changed_site else item

                with self.subTest(site=changed_site), mock.patch.object(
                    exporter, "_instruction", side_effect=changed_instruction,
                ):
                    with self.assertRaisesRegex(RuntimeError, message):
                        exporter._validate_model_manager_request_event_candidate(
                            blob, mappings, deps, plt_symbols, exidx,
                        )

            for changed_site, message in (
                (0x843B6A, "destination-two ModelManager call"),
                (0x84A896, "request Event-ID branch"),
                (0x84A974, "model-ID scalar join branch"),
                (0x84A984, "mapped-operation missing branch"),
                (0x84A998, "missing model-record branch"),
                (0x84A990, "model-record lookup call"),
                (0x84A9E4, "model-executor call"),
                (0x8411AC, "executor dispatch call"),
            ):
                def changed_target(item, local_deps):
                    return 0 if item.address == changed_site else original_target(item, local_deps)

                with self.subTest(site=changed_site), mock.patch.object(
                    exporter, "_direct_target", side_effect=changed_target,
                ):
                    with self.assertRaisesRegex(RuntimeError, message):
                        exporter._validate_model_manager_request_event_candidate(
                            blob, mappings, deps, plt_symbols, exidx,
                        )

            for changed_range, register, message in (
                ((0x843A8E, 0x843B68), deps["r5"], "central Event preservation"),
                ((0x84A83E, 0x84A964), deps["r5"], "ModelManager Event preservation"),
                ((0x84A83E, 0x84A97A), deps["r5"], "ModelManager Event preservation to mapped operation"),
                ((0x84A97A, 0x84A98E), deps["r6"], "model-ID joined value preservation"),
                ((0x84A98C, 0x84A9B8), deps["r9"], "mapped-operation joined value preservation"),
                ((0x84A996, 0x84A9E0), deps["r8"], "model-record preservation"),
                ((0x84A9BE, 0x84A9E2), deps["r6"], "secondary Event preservation"),
                ((0x8411A4, 0x8411AC), deps["r1"], "executor Event preservation"),
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
                        exporter._validate_model_manager_request_event_candidate(
                            blob, mappings, deps, plt_symbols, exidx,
                        )

            for changed_site, message in (
                (0x843AF2, "Event destination call"),
                (0x84A83E, "Event ID call"),
            ):
                def changed_symbol(local_blob, local_mappings, local_deps, local_plt, site):
                    if site == changed_site:
                        return "wrong"
                    return original_symbol(local_blob, local_mappings, local_deps, local_plt, site)

                with self.subTest(site=changed_site), mock.patch.object(
                    exporter, "_call_symbol", side_effect=changed_symbol,
                ):
                    with self.assertRaisesRegex(RuntimeError, message):
                        exporter._validate_model_manager_request_event_candidate(
                            blob, mappings, deps, plt_symbols, exidx,
                        )
        finally:
            handle.close()

    def test_real_operation_38_tag_zero_queue_dispatch_is_validated(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned sources or parser dependencies are unavailable")
        exporter = self.exporter
        handle, blob, mappings, deps, _elf, _dynsym, _plt_symbols, exidx = self._real_context("object")
        try:
            self.assertEqual(
                exporter._validate_operation_38_queue_dispatch(blob, mappings, deps, exidx),
                exporter.EXPECTED_EXPORT["operation_38_queue_dispatch"],
            )
        finally:
            handle.close()

    def test_operation_38_tag_zero_queue_mutations_are_rejected(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned sources or parser dependencies are unavailable")
        exporter = self.exporter
        handle, blob, mappings, deps, _elf, _dynsym, _plt_symbols, exidx = self._real_context("object")
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
            def regs_access(self):
                return [], [deps["r5"]]

        try:
            for changed_site, message in (
                (0x8425AC, "queue tag-one comparison"),
                (0x8425B2, "queue tag-three comparison"),
                (0x842624, "queue tag-zero fallthrough"),
            ):
                def changed_instruction(local_blob, local_mappings, local_deps, site):
                    item = original_instruction(local_blob, local_mappings, local_deps, site)
                    return WrongInstruction(item) if site == changed_site else item

                with self.subTest(site=changed_site), mock.patch.object(
                    exporter, "_instruction", side_effect=changed_instruction,
                ):
                    with self.assertRaisesRegex(RuntimeError, message):
                        exporter._validate_operation_38_queue_dispatch(blob, mappings, deps, exidx)

            for changed_range in ((0x8425A6, 0x8425B4), (0x842624, 0x84262E)):
                def changed_decode(local_blob, local_mappings, local_deps, start, end, *, complete=True):
                    items = original_decode(
                        local_blob, local_mappings, local_deps, start, end, complete=complete,
                    )
                    return [RegisterClobber(), *items] if (start, end) == changed_range else items

                with self.subTest(span=changed_range), mock.patch.object(
                    exporter, "_decode", side_effect=changed_decode,
                ):
                    with self.assertRaisesRegex(RuntimeError, "queue Event argument preservation"):
                        exporter._validate_operation_38_queue_dispatch(blob, mappings, deps, exidx)

            for changed_site, message in (
                (0x8425A8, "queue tag reader call"),
                (0x8425B4, "queue non-one-or-three branch"),
                (0x842632, "queue-zero direct call"),
            ):
                def changed_target(item, local_deps):
                    return 0 if item.address == changed_site else original_target(item, local_deps)

                with self.subTest(site=changed_site), mock.patch.object(
                    exporter, "_direct_target", side_effect=changed_target,
                ):
                    with self.assertRaisesRegex(RuntimeError, message):
                        exporter._validate_operation_38_queue_dispatch(blob, mappings, deps, exidx)
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
                (0x339CF6, "model-mapping input"),
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
                ((0x339CCE, 0x339CF6), deps["r5"], "dispatcher model preservation to mapper"),
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
