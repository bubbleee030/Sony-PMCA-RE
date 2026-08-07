import copy
import importlib.util
import io
import json
import unittest
from pathlib import Path
from unittest import mock

from pmca.analysis.creative_style_runtime_binding import (
    CLAIMS,
    EXPECTED_EXPORT,
    UNPROVEN_CLAIMS,
    CreativeStyleRuntimeBindingError,
    build_creative_style_runtime_binding_report,
    normalize_creative_style_runtime_binding_export,
    summarize_creative_style_runtime_binding_export,
    validate_creative_style_runtime_binding_report,
)


ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = ROOT / "analysis" / "a6400-creative-style-runtime-binding.json"
EXPORTER = ROOT / "tools" / "static" / "export_a6400_creative_style_runtime_binding.py"


class _MemoryProxy:
    def __init__(self, memory, *, base=None, index=None, displacement=None):
        self.base = memory.base if base is None else base
        self.index = memory.index if index is None else index
        self.disp = memory.disp if displacement is None else displacement


class _OperandProxy:
    def __init__(self, operand, *, register=None, immediate=None, memory=None):
        self.type = operand.type
        self.reg = operand.reg if register is None else register
        self.imm = operand.imm if immediate is None else immediate
        self.mem = operand.mem if memory is None else memory


class _InstructionProxy:
    def __init__(self, instruction, operands):
        self.address = instruction.address
        self.size = instruction.size
        self.id = instruction.id
        self.cc = instruction.cc
        self.writeback = instruction.writeback
        self.operands = operands
        self._instruction = instruction

    def group(self, group):
        return self._instruction.group(group)


class CreativeStyleRuntimeBindingTests(unittest.TestCase):
    def test_generic_loader_and_executor_are_proven_without_modelcamera_identity(self):
        self.assertTrue(CLAIMS["model_camera_alias_reaches_id_generator_get_proven"])
        self.assertTrue(CLAIMS["generic_dynamic_loader_chain_proven"])
        self.assertTrue(CLAIMS["modelbase_scheduler_slot_proven"])
        self.assertTrue(CLAIMS["destination_4_receiver_route_and_default_predicate_found"])
        self.assertFalse(CLAIMS["model_camera_numeric_id_resolved"])
        self.assertFalse(CLAIMS["model_camera_name_split_proven"])
        self.assertFalse(CLAIMS["key7_to_record_join_proven"])
        self.assertFalse(CLAIMS["record_is_modelcamera_proven"])
        self.assertFalse(CLAIMS["executor_is_modelcamera_proven"])
        self.assertFalse(CLAIMS["operation38_to_candidate_branch_join_proven"])
        self.assertFalse(CLAIMS["operation38_to_modelcamera_executor_join_proven"])
        self.assertFalse(CLAIMS["operation38_to_destination_4_default_path_join_proven"])
        self.assertFalse(CLAIMS["five_field_consumption_proven"])
        self.assertFalse(CLAIMS["native_creative_look_pipeline_proven"])

    def test_exact_static_boundaries_are_pinned(self):
        normalized = normalize_creative_style_runtime_binding_export(EXPECTED_EXPORT)

        self.assertEqual(normalized["id_generator"]["input_alias"], "model/CAMERA")
        self.assertFalse(normalized["id_generator"]["splitter_delimiter_semantics_resolved"])
        self.assertFalse(normalized["id_generator"]["model_table_key_resolved"])
        self.assertFalse(normalized["id_generator"]["camera_row_key_resolved"])
        self.assertEqual(
            normalized["id_generator"]["validated_static_set_table_call"],
            {
                "module": "lib/viewUnified2.so",
                "site": 0x37FD10,
                "symbol": "_ZN11IdGenerator8SetTableESsP7IdTable",
                "table_key_resolved": False,
            },
        )
        self.assertEqual(normalized["model_manager_records"]["map_offset"], 0x88)
        self.assertEqual(
            normalized["dynamic_loader"]["factory_call"],
            {
                "site": 0x84114C,
                "target_register": "r3",
                "key_load_site": 0x841148,
                "key_record_offset": 0,
                "manager_load_site": 0x84114A,
                "manager_record_offset": 0x20,
                "result_store_site": 0x84114E,
                "result_record_offset": 0x1C,
            },
        )
        self.assertEqual(
            normalized["modelcamera_candidate"]["manifest"],
            {
                "alias": {"address": 0xF03447, "value": "@M00B"},
                "component": {"address": 0xF0344D, "value": "modelCamera.so"},
                "factory": {"address": 0xF0345C, "value": "ModelCameraToInstance"},
            },
        )
        self.assertFalse(normalized["generic_executor"]["scheduled_event_id_resolved_generically"])
        self.assertEqual(
            normalized["modelcamera_candidate"]["default_scheduler_event"]["value"],
            0x11004001,
        )
        self.assertEqual(
            normalized["generic_executor"]["model_manager_dispatch_owner"],
            {"start": 0x84A830, "end": 0x84AC94},
        )
        self.assertEqual(
            normalized["generic_executor"]["candidate_branch_range"],
            {"start": 0x84A95C, "end": 0x84A9E4},
        )
        self.assertTrue(
            normalized["generic_executor"]["param_list_clone_forwarded_to_secondary_event"]
        )
        self.assertEqual(normalized["destination_4"]["receiver"], 0x846710)
        self.assertEqual(normalized["destination_4"]["default_predicate_call"], 0x8468D2)

    def test_unproven_claims_cannot_be_promoted(self):
        for claim in UNPROVEN_CLAIMS:
            mutated = copy.deepcopy(EXPECTED_EXPORT)
            mutated["claims"][claim] = True
            with self.subTest(claim=claim), self.assertRaises(
                CreativeStyleRuntimeBindingError
            ):
                normalize_creative_style_runtime_binding_export(mutated)

    def test_every_evidence_section_and_nested_field_is_exact(self):
        mutations = (
            ("id_generator", "get_owner", "end", 0x402EC2),
            ("id_generator", "splitter_owner", "start", 0x402426),
            ("id_generator", "find_id_call", "site", 0x402E36),
            ("model_manager_records", "lookup_owner", "end", 0x849086),
            ("model_manager_records", "map_offset", None, 0x8C),
            ("model_manager_records", "map_constructor", "site", 0x849892),
            ("model_manager_records", "record_allocation", "size", 0x28),
            ("model_manager_records", "activation_owner", "end", 0x8411A2),
            ("dynamic_loader", "dlopen_call", "site", 0x841134),
            ("dynamic_loader", "mode_argument", "value", 0x102),
            ("dynamic_loader", "dlsym_call", "symbol", "wrong"),
            ("dynamic_loader", "handle_store", "record_offset", 0x14),
            ("dynamic_loader", "factory_call", "target_register", "r4"),
            ("modelcamera_candidate", "factory", "instance_size", 0x6438),
            ("modelcamera_candidate", "rtti", "name", "wrong"),
            ("modelcamera_candidate", "slot_cell", "address", 0x1341B0C),
            ("modelcamera_candidate", "slot_target_owner", "end", 0x3FE6DA),
            ("generic_executor", "virtual_call", "site", 0x84302C),
            ("generic_executor", "scalar_event_parameters", "request_context", {}),
            ("generic_executor", "secondary_event", "constructor_call_site", 0x84A9BC),
            ("generic_executor", "scheduled_event_id_instance_offset", None, 0x64),
            ("destination_4", "destination_bit_test", "mask", 2),
            ("destination_4", "validated_event_id_comparisons", None, []),
            ("destination_4", "default_predicate_call", None, 0x8468D4),
        )
        for section, field, nested, value in mutations:
            mutated = copy.deepcopy(EXPECTED_EXPORT)
            if nested is None:
                mutated[section][field] = value
            else:
                mutated[section][field][nested] = value
            with self.subTest(section=section, field=field), self.assertRaises(
                CreativeStyleRuntimeBindingError
            ):
                normalize_creative_style_runtime_binding_export(mutated)

    def test_identity_digest_scope_and_reconstructive_fields_are_strict(self):
        candidates = []

        mutated = copy.deepcopy(EXPECTED_EXPORT)
        mutated["sources"]["object"]["sha256"] = "0" * 64
        candidates.append(mutated)

        mutated = copy.deepcopy(EXPECTED_EXPORT)
        mutated["upstream"]["evidence_digest"] = "0" * 64
        candidates.append(mutated)

        mutated = copy.deepcopy(EXPECTED_EXPORT)
        mutated["analysis_scope"] = "runtime-tested"
        candidates.append(mutated)

        mutated = copy.deepcopy(EXPECTED_EXPORT)
        mutated["evidence_digest"] = "0" * 64
        candidates.append(mutated)

        mutated = copy.deepcopy(EXPECTED_EXPORT)
        mutated["raw_bytes"] = [1, 2, 3]
        candidates.append(mutated)

        mutated = copy.deepcopy(EXPECTED_EXPORT)
        del mutated["dynamic_loader"]
        candidates.append(mutated)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                CreativeStyleRuntimeBindingError
            ):
                normalize_creative_style_runtime_binding_export(candidate)

    def test_summary_and_report_remain_offline_noninstallable(self):
        summary = summarize_creative_style_runtime_binding_export(EXPECTED_EXPORT)
        report = build_creative_style_runtime_binding_report(EXPECTED_EXPORT)

        self.assertRegex(summary["canonical_export_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(summary["proven_static_claim_count"], 7)
        self.assertEqual(summary["resolved_model_identity_count"], 0)
        self.assertFalse(report["camera_executed"])
        self.assertFalse(report["camera_test_eligible"])
        self.assertFalse(report["installable"])
        self.assertEqual(
            report["readiness"],
            "GENERIC_RUNTIME_BINDING_NO_MODELCAMERA_RECORD_OR_PIPELINE",
        )
        self.assertEqual(validate_creative_style_runtime_binding_report(report), report)

    def test_every_internal_runtime_join_remains_explicitly_unproven(self):
        false_fields = (
            ("id_generator", "model_table_static_registration_found"),
            ("id_generator", "camera_row_numeric_value_resolved"),
            ("id_generator", "splitter_delimiter_semantics_resolved"),
            ("id_generator", "model_table_key_resolved"),
            ("id_generator", "camera_row_key_resolved"),
            ("model_manager_records", "runtime_descriptor_provider_resolved"),
            ("model_manager_records", "key7_to_record_lookup_join_found"),
            ("dynamic_loader", "exact_modelcamera_descriptor_join_found"),
            ("dynamic_loader", "descriptor_population_dataflow_resolved"),
            ("modelcamera_candidate", "manifest_to_operation38_model_alias_join_found"),
            ("modelcamera_candidate", "manifest_to_runtime_descriptor_join_found"),
            ("generic_executor", "scheduled_event_id_resolved_generically"),
            ("generic_executor", "scheduler_direct_incoming_event_read_found"),
            ("generic_executor", "scheduler_direct_creative_style_field_read_found"),
            ("generic_executor", "operation38_to_candidate_branch_join_found"),
            ("generic_executor", "candidate_branch_to_modelcamera_executor_join_found"),
            ("generic_executor", "operation38_to_modelcamera_executor_join_found"),
            (
                "destination_4",
                "modelcamera_candidate_default_event_matches_validated_comparisons",
            ),
            ("destination_4", "downstream_concrete_receiver_resolved"),
            ("destination_4", "operation38_to_default_path_join_found"),
        )
        for section, field in false_fields:
            mutated = copy.deepcopy(EXPECTED_EXPORT)
            self.assertIs(mutated[section][field], False)
            mutated[section][field] = True
            with self.subTest(section=section, field=field), self.assertRaises(
                CreativeStyleRuntimeBindingError
            ):
                normalize_creative_style_runtime_binding_export(mutated)

    def test_committed_report_is_exact(self):
        document = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        validated = validate_creative_style_runtime_binding_report(document)

        self.assertEqual(validated, build_creative_style_runtime_binding_report(EXPECTED_EXPORT))
        self.assertEqual(
            validated["upstream"],
            {
                "report": "analysis/a6400-creative-style-model-request-transport.json",
                "evidence_digest": "3303e96ac7f7f6bd237c4bf043056874aafde56b4ceb3ef3b2b4d38989619f0d",
            },
        )


class CreativeStyleRuntimeBindingExporterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("runtime_binding_exporter", EXPORTER)
        cls.exporter = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(cls.exporter)
        cls.deps = cls.exporter._dependencies()
        cls.contexts = {}
        for role, path in cls.exporter.SOURCES.items():
            blob = path.read_bytes()
            stream = io.BytesIO(blob)
            elf = cls.deps["ELFFile"](stream)
            mappings = cls.exporter._mappings(elf)
            plt = cls.exporter._plt_symbols(elf, blob, mappings)
            cls.contexts[role] = {
                "blob": blob,
                "stream": stream,
                "elf": elf,
                "mappings": mappings,
                "exidx": cls.exporter._exidx_ranges(elf, blob),
                "plt": plt,
                "plt_symbols": plt,
                "dynsym": elf.get_section_by_name(".dynsym"),
            }

    @classmethod
    def tearDownClass(cls):
        for context in cls.contexts.values():
            context["stream"].close()

    def test_adapter_is_normalized(self):
        class FakeAdapter:
            def metadata(self):
                return copy.deepcopy(EXPECTED_EXPORT)

        self.assertEqual(self.exporter.build_raw_export(FakeAdapter()), EXPECTED_EXPORT)

    def test_source_identity_is_pinned_for_both_modules(self):
        self.assertEqual(
            self.exporter.SOURCES["object"],
            self.exporter.FIRMWARE_LIB / "libObj.so",
        )
        self.assertEqual(
            self.exporter.SOURCES["view"],
            self.exporter.FIRMWARE_LIB / "viewUnified2.so",
        )
        self.assertTrue(self.exporter.dependencies_available())

    def test_metadata_rejects_schema_mutation_after_static_validation(self):
        class MutatedAdapter:
            def metadata(self):
                document = copy.deepcopy(EXPECTED_EXPORT)
                document["dynamic_loader"]["dlopen_call"]["symbol"] = "wrong"
                return document

        with self.assertRaises(RuntimeError):
            self.exporter.build_raw_export(MutatedAdapter())

    def test_real_export_matches_exact_static_contract_when_available(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned sources or parser dependencies are unavailable")
        self.assertEqual(self.exporter.build_raw_export(), EXPECTED_EXPORT)

    def test_id_generator_static_mutations_fail_closed(self):
        original_target = self.exporter._direct_target
        for changed_site in (0x402DEE, 0x402E10, 0x402E34, 0x37FD10):
            def changed_target(item, deps, *, changed_site=changed_site):
                if item.address == changed_site:
                    return 0
                return original_target(item, deps)

            with self.subTest(site=changed_site), mock.patch.object(
                self.exporter, "_direct_target", side_effect=changed_target
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_id_generator(
                        self.contexts["object"], self.contexts["view"], self.deps
                    )

        original_instruction = self.exporter._instruction

        def changed_store(blob, mappings, deps, site):
            item = original_instruction(blob, mappings, deps, site)
            if site != 0x402C7A:
                return item
            operands = list(item.operands)
            operands[0] = _OperandProxy(operands[0], register=deps["r3"])
            return _InstructionProxy(item, operands)

        with mock.patch.object(self.exporter, "_instruction", side_effect=changed_store):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_id_generator(
                    self.contexts["object"], self.contexts["view"], self.deps
                )

    def test_record_and_loader_static_mutations_fail_closed(self):
        original_instruction = self.exporter._instruction

        original_target = self.exporter._direct_target
        for changed_site in (
            0x849890,
            0x849054,
            0x849DA6,
            0x849DEE,
            0x849E00,
            0x841132,
            0x841140,
        ):
            def changed_target(item, deps, *, changed_site=changed_site):
                if item.address == changed_site:
                    return 0
                return original_target(item, deps)

            with self.subTest(site=changed_site), mock.patch.object(
                self.exporter, "_direct_target", side_effect=changed_target
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_records_and_loader(
                        self.contexts["object"], self.deps
                    )

        def changed_map_offset(blob, mappings, deps, site):
            item = original_instruction(blob, mappings, deps, site)
            if site != 0x84988A:
                return item
            operands = list(item.operands)
            operands[2] = _OperandProxy(operands[2], immediate=0x8C)
            return _InstructionProxy(item, operands)

        with mock.patch.object(self.exporter, "_instruction", side_effect=changed_map_offset):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_records_and_loader(self.contexts["object"], self.deps)

        def changed_mode(blob, mappings, deps, site):
            item = original_instruction(blob, mappings, deps, site)
            if site != 0x84112C:
                return item
            operands = list(item.operands)
            operands[1] = _OperandProxy(operands[1], immediate=0x102)
            return _InstructionProxy(item, operands)

        with mock.patch.object(self.exporter, "_instruction", side_effect=changed_mode):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_records_and_loader(self.contexts["object"], self.deps)

        def changed_component_base(blob, mappings, deps, site):
            item = original_instruction(blob, mappings, deps, site)
            if site != 0x841130:
                return item
            operands = list(item.operands)
            operands[1] = _OperandProxy(
                operands[1], memory=_MemoryProxy(operands[1].mem, base=deps["r4"])
            )
            return _InstructionProxy(item, operands)

        with mock.patch.object(
            self.exporter, "_instruction", side_effect=changed_component_base
        ):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_records_and_loader(self.contexts["object"], self.deps)

        def changed_factory_register(blob, mappings, deps, site):
            item = original_instruction(blob, mappings, deps, site)
            if site != 0x84114C:
                return item
            operands = list(item.operands)
            operands[0] = _OperandProxy(operands[0], register=deps["r4"])
            return _InstructionProxy(item, operands)

        with mock.patch.object(
            self.exporter, "_instruction", side_effect=changed_factory_register
        ):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_records_and_loader(self.contexts["object"], self.deps)

        def changed_factory_result(blob, mappings, deps, site):
            item = original_instruction(blob, mappings, deps, site)
            if site != 0x84114E:
                return item
            operands = list(item.operands)
            operands[1] = _OperandProxy(
                operands[1], memory=_MemoryProxy(operands[1].mem, displacement=0x18)
            )
            return _InstructionProxy(item, operands)

        with mock.patch.object(
            self.exporter, "_instruction", side_effect=changed_factory_result
        ):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_records_and_loader(self.contexts["object"], self.deps)

    def test_modelcamera_static_mutations_fail_closed(self):
        original_at = self.exporter._at
        for changed_address in (0xF03447, 0xF0344D, 0xF0345C, 0xF68740):
            def changed_string(blob, mappings, address, length, *, changed_address=changed_address):
                value = original_at(blob, mappings, address, length)
                if address == changed_address:
                    return b"X" + value[1:]
                return value

            with self.subTest(address=changed_address), mock.patch.object(
                self.exporter, "_at", side_effect=changed_string
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_modelcamera(
                        self.contexts["object"], self.deps
                    )

        original_target = self.exporter._direct_target
        for changed_site in (0x4D32EA, 0x4D32F0, 0x4D3104, 0x3FE5E0):
            def changed_target(item, deps, *, changed_site=changed_site):
                if item.address == changed_site:
                    return 0
                return original_target(item, deps)

            with self.subTest(site=changed_site), mock.patch.object(
                self.exporter, "_direct_target", side_effect=changed_target
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_modelcamera(
                        self.contexts["object"], self.deps
                    )

        original_instruction = self.exporter._instruction

        def changed_allocation_size(blob, mappings, deps, site):
            item = original_instruction(blob, mappings, deps, site)
            if site != 0x4D32E2:
                return item
            operands = list(item.operands)
            operands[1] = _OperandProxy(operands[1], immediate=0x6438)
            return _InstructionProxy(item, operands)

        with mock.patch.object(
            self.exporter, "_instruction", side_effect=changed_allocation_size
        ):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_modelcamera(self.contexts["object"], self.deps)

        for changed_site, operand_index in (
            (0x4D3102, 0),
            (0x3FE58E, 0),
            (0x3FE5DE, 1),
        ):
            def changed_this_flow(
                blob, mappings, deps, site, *, changed_site=changed_site,
                operand_index=operand_index,
            ):
                item = original_instruction(blob, mappings, deps, site)
                if site != changed_site:
                    return item
                operands = list(item.operands)
                operands[operand_index] = _OperandProxy(
                    operands[operand_index], register=deps["r4"]
                )
                return _InstructionProxy(item, operands)

            with self.subTest(this_flow=changed_site), mock.patch.object(
                self.exporter, "_instruction", side_effect=changed_this_flow
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_modelcamera(
                        self.contexts["object"], self.deps
                    )

        original_word = self.exporter._word

        for changed_address in (0x1341ADC, 0x1341AEC, 0x1341B08):
            def changed_relocation(blob, mappings, address, *, changed_address=changed_address):
                if address == changed_address:
                    return 0
                return original_word(blob, mappings, address)

            with self.subTest(address=changed_address), mock.patch.object(
                self.exporter, "_word", side_effect=changed_relocation
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_modelcamera(
                        self.contexts["object"], self.deps
                    )

    def test_executor_and_destination_static_mutations_fail_closed(self):
        original_target = self.exporter._direct_target

        for changed_site in (
            0x84A960,
            0x84A968,
            0x84A97E,
            0x84A9BE,
            0x84A9C4,
            0x84A9CC,
            0x84A9D4,
            0x84A9DC,
            0x3FE634,
            0x3FE648,
            0x848278,
            0x843B24,
            0x8468D2,
        ):
            def changed_target(item, deps, *, changed_site=changed_site):
                if item.address == changed_site:
                    return 0
                return original_target(item, deps)

            with self.subTest(site=changed_site), mock.patch.object(
                self.exporter, "_direct_target", side_effect=changed_target
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_executor_and_destination(
                        self.contexts["object"], self.deps
                    )

        original_instruction = self.exporter._instruction

        def changed_mask(blob, mappings, deps, site):
            item = original_instruction(blob, mappings, deps, site)
            if site != 0x843B0E:
                return item
            operands = list(item.operands)
            operands[2] = _OperandProxy(operands[2], immediate=2)
            return _InstructionProxy(item, operands)

        with mock.patch.object(self.exporter, "_instruction", side_effect=changed_mask):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_executor_and_destination(
                    self.contexts["object"], self.deps
                )

        def changed_secondary_header(blob, mappings, deps, site):
            item = original_instruction(blob, mappings, deps, site)
            if site != 0x84A9B6:
                return item
            operands = list(item.operands)
            operands[1] = _OperandProxy(operands[1], immediate=1)
            return _InstructionProxy(item, operands)

        with mock.patch.object(
            self.exporter, "_instruction", side_effect=changed_secondary_header
        ):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_executor_and_destination(
                    self.contexts["object"], self.deps
                )

        def changed_virtual_slot(blob, mappings, deps, site):
            item = original_instruction(blob, mappings, deps, site)
            if site != 0x843028:
                return item
            operands = list(item.operands)
            operands[1] = _OperandProxy(
                operands[1], memory=_MemoryProxy(operands[1].mem, displacement=0x1C)
            )
            return _InstructionProxy(item, operands)

        with mock.patch.object(
            self.exporter, "_instruction", side_effect=changed_virtual_slot
        ):
            with self.assertRaises(RuntimeError):
                self.exporter._validate_executor_and_destination(
                    self.contexts["object"], self.deps
                )

        original_word = self.exporter._word
        literal_addresses = []
        for record in EXPECTED_EXPORT["destination_4"]["validated_event_id_comparisons"]:
            load = original_instruction(
                self.contexts["object"]["blob"],
                self.contexts["object"]["mappings"],
                self.deps,
                record["literal_site"],
            )
            literal_addresses.append(
                self.exporter._transport._thumb_literal_address(
                    load, self.deps, self.deps["r3"], "test Event-ID literal"
                )
            )
        for changed_address in literal_addresses:
            def changed_literal(blob, mappings, address, *, changed_address=changed_address):
                if address == changed_address:
                    return 0
                return original_word(blob, mappings, address)

            with self.subTest(literal=changed_address), mock.patch.object(
                self.exporter, "_word", side_effect=changed_literal
            ):
                with self.assertRaises(RuntimeError):
                    self.exporter._validate_executor_and_destination(
                        self.contexts["object"], self.deps
                    )

    def test_report_rejects_safety_or_pipeline_promotion(self):
        report = build_creative_style_runtime_binding_report(EXPECTED_EXPORT)
        candidates = []
        for field in ("camera_executed", "camera_test_eligible", "installable"):
            mutated = copy.deepcopy(report)
            mutated[field] = True
            candidates.append(mutated)
        for field in (
            "record_is_modelcamera_proven",
            "five_field_consumption_proven",
            "native_creative_look_pipeline_proven",
            "runtime_execution_proven",
        ):
            mutated = copy.deepcopy(report)
            mutated["claims"][field] = True
            candidates.append(mutated)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                CreativeStyleRuntimeBindingError
            ):
                validate_creative_style_runtime_binding_report(candidate)


if __name__ == "__main__":
    unittest.main()
