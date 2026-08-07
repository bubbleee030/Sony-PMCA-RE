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

    def test_cross_module_edge_is_candidate_not_operation_38_handler(self):
        from pmca.analysis.creative_style_model_request_transport import EXPECTED_EXPORT

        boundary = EXPECTED_EXPORT["candidate_cross_module_boundary"]
        self.assertEqual(boundary["site"], 0x339EA0)
        self.assertEqual(boundary["symbol"], "_ZN13viewManagerIf19requestModelExecuteEPKcmP9ParamList")
        self.assertFalse(boundary["operation_38_branch_proven"])
        self.assertFalse(EXPECTED_EXPORT["claims"]["end_to_end_operation_38_event_queue_join_found"])

    def test_shared_event_transport_and_indirect_blockers_are_exact(self):
        from pmca.analysis.creative_style_model_request_transport import EXPECTED_EXPORT

        shared = EXPECTED_EXPORT["shared_libobj_transport"]
        self.assertEqual(shared["request_owner"], {"start": 0x3F2AA8, "end": 0x3F2AEC, "complete": True})
        self.assertEqual(shared["id_generator_call_site"], 0x3F2AC0)
        self.assertEqual(shared["event_builder_call_site"], 0x3F2AD6)
        self.assertEqual(shared["event_builder_owner"], {"start": 0x8430AC, "end": 0x843118, "complete": True})
        self.assertFalse(shared["shared_request_to_event_queue_join_found"])
        queue = EXPECTED_EXPORT["event_queue_boundary"]
        self.assertEqual(queue["push_owner"], {"start": 0x842598, "end": 0x84264C, "complete": True})
        self.assertEqual(queue["indirect_call_sites"], [0x8425C6, 0x8425D6, 0x842620])
        self.assertFalse(queue["consumer_dispatch_resolved"])

    def test_unproven_handler_and_pipeline_claims_cannot_be_promoted(self):
        from pmca.analysis.creative_style_model_request_transport import (
            CreativeStyleModelRequestTransportError,
            EXPECTED_EXPORT,
            normalize_creative_style_model_request_transport_export,
        )

        for key in (
            "operation_38_candidate_branch_proven", "end_to_end_operation_38_event_queue_join_found",
            "shared_request_to_event_queue_join_found",
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
        self.assertEqual(report["readiness"], "REQUEST_WRAPPER_AND_CANDIDATE_EVENT_TRANSPORT_ONLY")
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
            elf.get_section_by_name(".dynsym"),
            exporter._plt_symbols(elf, blob, mappings),
            exporter._exidx_ranges(elf, blob),
        )

    def test_wrapper_and_candidate_edge_mutations_are_rejected(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned sources or parser dependencies are unavailable")
        exporter = self.exporter
        handle, blob, mappings, deps, dynsym, plt_symbols, exidx = self._real_context("view")
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
        handle, blob, mappings, deps, dynsym, plt_symbols, exidx = self._real_context("object")
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

    def test_real_export_matches_when_available(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned sources or parser dependencies are unavailable")
        self.assertEqual(self.exporter.build_raw_export(), self.exporter.EXPECTED_EXPORT)


if __name__ == "__main__":
    unittest.main()
