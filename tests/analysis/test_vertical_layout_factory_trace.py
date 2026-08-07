import copy
import importlib.util
import json
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from pmca.analysis.vertical_layout_factory_trace import (
    VerticalLayoutFactoryTraceError,
    normalize_vertical_layout_factory_export,
    summarize_vertical_layout_factory_export,
    validate_vertical_layout_factory_report,
)


ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = ROOT / "analysis" / "a6400-vertical-layout-factory.json"
EXPORTER_PATH = ROOT / "tools" / "static" / "export_a6400_vertical_layout_factory.py"
SOURCE_PATH = (
    ROOT / ".artifacts" / "decrypted" / "a6400-tw-v2.00" / "ma1co"
    / "firmware.tar_unpacked" / "0700_part_image" / "dev" / "nflasha15_unpacked"
    / "lib" / "viewUnified7.so"
)
VIEW_UNIFIED2_PATH = SOURCE_PATH.with_name("viewUnified2.so")


def raw_export(*, reverse_callers=None):
    return {
        "schema_version": 1,
        "program": "viewUnified7.so",
        "sha256": "c48cde43ff22d808ad23c42019ddae516fff7da060004eb81ed2bb85012aa538",
        "image_size": 541024,
        "analysis_mode": {"engine": "elf-capstone-thumb", "read_only": True, "source_unchanged": True},
        "factory": {
            "root": 0x52840,
            "owner": {"start": 0x52840, "end": 0x529B8},
            "total_constructor_arm_count": 12,
            "group_id": 0x1B906244,
            "vertical_classical_arms": [
                {"id": "info", "class_id": 0x61DC811C, "site": 0x52934, "target": 0x14E9C},
                {"id": "footer", "class_id": 0x186C17F6, "site": 0x52944, "target": 0x14028},
                {"id": "header-manual-info", "class_id": 0x8E7FDF88, "site": 0x52914, "target": 0x14148},
                {"id": "manual", "class_id": 0x7BE1C309, "site": 0x52954, "target": 0x14D64},
                {"id": "error", "class_id": 0xBDBC36BD, "site": 0x52924, "target": 0x14B04},
            ],
            "branch_value_classification": "local-branching-observed",
            "constructors": [
                {"id": "header-manual-info", "caller": 0x52840, "site": 0x52914, "target": 0x14148, "kind": "direct"},
                {"id": "error", "caller": 0x52840, "site": 0x52924, "target": 0x14B04, "kind": "direct"},
                {"id": "info", "caller": 0x52840, "site": 0x52934, "target": 0x14E9C, "kind": "direct"},
                {"id": "footer", "caller": 0x52840, "site": 0x52944, "target": 0x14028, "kind": "direct"},
                {"id": "manual", "caller": 0x52840, "site": 0x52954, "target": 0x14D64, "kind": "direct"},
            ],
            "reverse_callers": copy.deepcopy(reverse_callers if reverse_callers is not None else [{"caller": 0x529CC, "site": 0x529D6, "target": 0x52840, "kind": "direct"}]),
            "unresolved_indirect_terminals": [],
        },
        "upstream_roots": {
            "camera_orientation_owners": [0x2D2C6, 0x30750],
            "status_orientation_owners": [0x189DC, 0x1B070, 0x1C56C],
            "layout_mode": {"site_count": 28, "owner_count": 15, "owner_overlap_with_factory": False},
        },
        "invalid_offset_classifications": [
            {"offset": 0x181F18, "classification": "internal-conditional-branch"},
            {"offset": 0x24222C, "classification": "non-instruction-boundary-second-halfword"},
            {"offset": 0x3BA6DC, "classification": "non-instruction-boundary-second-halfword"},
            {"offset": 0x651684, "classification": "non-instruction-boundary-second-halfword"},
        ],
        "false_class_id_paths": [
            {"offset": offset, "classification": "constructor-vptr-material-path", "class_id_load": False}
            for offset in (0x37B614, 0x37AA18, 0x37B5E0, 0x37B648, 0x37B578)
        ],
        "truncated": False,
    }


class VerticalLayoutFactoryTraceTests(unittest.TestCase):
    def test_vertical_subset_owner_and_negative_runtime_boundary_are_exact(self):
        normalized = normalize_vertical_layout_factory_export(raw_export())

        factory = normalized["factory"]
        self.assertEqual(factory["owner"], {"start": 0x52840, "end": 0x529B8})
        self.assertEqual(factory["total_constructor_arm_count"], 12)
        self.assertEqual(factory["group_id"], 0x1B906244)
        self.assertEqual(
            [(arm["class_id"], arm["site"]) for arm in factory["vertical_classical_arms"]],
            [(0x61DC811C, 0x52934), (0x186C17F6, 0x52944), (0x8E7FDF88, 0x52914),
             (0x7BE1C309, 0x52954), (0xBDBC36BD, 0x52924)],
        )
        self.assertTrue(normalized["claims"]["five_wrapper_registrations_found"])
        self.assertFalse(normalized["claims"]["runtime_factory_invocation_proven"])
        self.assertFalse(normalized["claims"]["orientation_to_factory_join_proven"])

    def test_factory_rejects_arm_group_and_invalid_boundary_mutations(self):
        mutations = (
            lambda value: value["factory"].__setitem__("group_id", 0),
            lambda value: value["factory"]["vertical_classical_arms"][0].__setitem__("class_id", 0),
            lambda value: value["factory"]["vertical_classical_arms"][0].__setitem__("site", 0x52936),
            lambda value: value["invalid_offset_classifications"][0].__setitem__("classification", "factory"),
            lambda value: value["false_class_id_paths"][0].__setitem__("class_id_load", True),
        )
        for mutate in mutations:
            candidate = raw_export()
            mutate(candidate)
            with self.subTest(mutate=mutate), self.assertRaises(VerticalLayoutFactoryTraceError):
                normalize_vertical_layout_factory_export(candidate)
    def test_exact_five_way_factory_normalizes_without_ui_promotion(self):
        normalized = normalize_vertical_layout_factory_export(raw_export())

        self.assertEqual(normalized["factory"]["root"], 0x52840)
        self.assertEqual(
            [edge["site"] for edge in normalized["factory"]["constructors"]],
            [0x52914, 0x52924, 0x52934, 0x52944, 0x52954],
        )
        self.assertTrue(normalized["claims"]["vertical_layout_factory_found"])
        self.assertFalse(normalized["claims"]["orientation_layout_selector_found"])
        self.assertFalse(normalized["behavior_support"]["touch-coordinate-transform"])

    def test_factory_requires_exact_membership_and_order(self):
        for mutate in (
            lambda value: value["factory"]["constructors"].pop(),
            lambda value: value["factory"]["constructors"].reverse(),
            lambda value: value["factory"]["constructors"].__setitem__(0, {**value["factory"]["constructors"][0], "site": 0x52916}),
        ):
            candidate = raw_export()
            mutate(candidate)
            with self.subTest(candidate=candidate), self.assertRaises(VerticalLayoutFactoryTraceError):
                normalize_vertical_layout_factory_export(candidate)

    def test_ambiguous_or_unresolved_reverse_evidence_cannot_promote_selector(self):
        candidate = raw_export(reverse_callers=[
            {"caller": 0x2D2C6, "site": 0x2D2CC, "kind": "direct"},
            {"caller": 0x30750, "site": 0x30934, "kind": "direct"},
        ])
        with self.assertRaises(VerticalLayoutFactoryTraceError):
            normalize_vertical_layout_factory_export(candidate)

    def test_identity_scope_and_forbidden_material_are_strict(self):
        bad_identity = raw_export()
        bad_identity["sha256"] = "0" * 64
        forbidden = raw_export()
        forbidden["factory"]["instructions"] = ["forbidden"]
        for candidate in (bad_identity, forbidden):
            with self.subTest(candidate=candidate), self.assertRaises(VerticalLayoutFactoryTraceError):
                normalize_vertical_layout_factory_export(candidate)

    def test_summary_is_digestable_and_noninstallable(self):
        summary = summarize_vertical_layout_factory_export(raw_export())

        self.assertRegex(summary["canonical_export_sha256"], r"^[0-9a-f]{64}$")
        self.assertTrue(summary["claims"]["vertical_layout_factory_found"])
        self.assertFalse(summary["claims"]["orientation_layout_selector_found"])

    def test_committed_report_is_fail_closed(self):
        report = validate_vertical_layout_factory_report(
            json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        )

        self.assertTrue(report["claims"]["vertical_layout_factory_found"])
        self.assertFalse(report["claims"]["orientation_layout_selector_found"])
        self.assertFalse(report["installable"])
        self.assertFalse(report["camera_test_eligible"])
        self.assertIn("registration is not invocation", report["conclusion"])

    def test_report_rejects_selector_touch_or_digest_promotion(self):
        original = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        forged = copy.deepcopy(original)
        forged["export_summary"]["canonical_export_sha256"] = "0" * 64
        for section, field in (("claims", "orientation_layout_selector_found"), ("behavior_support", "touch-coordinate-transform")):
            candidate = copy.deepcopy(original)
            candidate[section][field] = True
            with self.subTest(section=section), self.assertRaises(VerticalLayoutFactoryTraceError):
                validate_vertical_layout_factory_report(candidate)
        with self.assertRaises(VerticalLayoutFactoryTraceError):
            validate_vertical_layout_factory_report(forged)


class VerticalLayoutFactoryExporterTests(unittest.TestCase):
    def _load(self):
        spec = importlib.util.spec_from_file_location("vertical_factory_exporter", EXPORTER_PATH)
        exporter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(exporter)
        return exporter

    def _validation_inputs(self, exporter, source_path=SOURCE_PATH):
        if not source_path.is_file():
            self.skipTest(f"pinned {source_path.name} is unavailable")
        dependencies = exporter._require_dependencies()
        if isinstance(dependencies, dict):
            deps = dependencies
            ELFFile = deps["ELFFile"]
        else:
            Cs, arch, _arm_mode, thumb_mode, call_group, imm, ELFFile = dependencies
            from capstone import CS_GRP_JUMP
            from capstone.arm import ARM_INS_CMP, ARM_INS_LDR, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC
            deps = {
                "Cs": Cs, "arch": arch, "thumb_mode": thumb_mode,
                "call_group": call_group, "jump_group": CS_GRP_JUMP, "imm": imm,
                "cmp": ARM_INS_CMP, "ldr": ARM_INS_LDR, "mem": ARM_OP_MEM,
                "reg": ARM_OP_REG, "pc": ARM_REG_PC,
            }
        blob = source_path.read_bytes()
        with source_path.open("rb") as stream:
            elf = ELFFile(stream)
            mappings = tuple(
                (segment["p_vaddr"], segment["p_vaddr"] + segment["p_filesz"], segment["p_offset"])
                for segment in elf.iter_segments() if segment["p_type"] == "PT_LOAD"
            )
            exidx = elf.get_section_by_name(".ARM.exidx")
            starts = sorted(
                exporter._prel31(
                    int.from_bytes(blob[offset:offset + 4], "little"),
                    exidx["sh_addr"] + index * 8,
                )
                for index, offset in enumerate(
                    range(exidx["sh_offset"], exidx["sh_offset"] + exidx["sh_size"], 8)
                )
            )
        ranges = tuple(zip(starts, starts[1:]))
        return blob, mappings, deps, ranges, {"malloc": 0x14A08}

    @staticmethod
    def _mutate_va(blob, mappings, address):
        mutated = bytearray(blob)
        for start, end, file_offset in mappings:
            if start <= address < end:
                mutated[file_offset + address - start] ^= 1
                return bytes(mutated)
        raise AssertionError(f"unmapped mutation site: {address:#x}")

    def test_byte_level_validator_rejects_decision_arm_allocation_and_wrapper_mutations(self):
        exporter = self._load()
        blob, mappings, deps, exidx, plt_symbols = self._validation_inputs(exporter)
        mutation_sites = [
            ("group-literal", 0x52980), ("group-compare", 0x52846),
            ("group-branch", 0x52848),
        ]
        mutation_sites.extend(
            (f"decision-literal-{site:x}", site)
            for site in (0x52984, 0x52988, 0x5298C, 0x52990, 0x52994,
                         0x52998, 0x5299C, 0x529A0, 0x529A4, 0x529A8,
                         0x529AC, 0x529B0, 0x529B4)
        )
        mutation_sites.extend(
            (f"decision-compare-{site:x}", site)
            for site in (0x5284C, 0x52854, 0x5285C, 0x52866, 0x5286C,
                         0x528BE, 0x528C6, 0x528CC, 0x528D2, 0x528DA,
                         0x528E2, 0x528EA, 0x528F0)
        )
        mutation_sites.extend(
            (f"decision-branch-{site:x}", site)
            for site in (0x5284E, 0x52856, 0x52858, 0x5285E, 0x52862,
                         0x52868, 0x5286E, 0x52872, 0x528C0, 0x528C2,
                         0x528C8, 0x528CE, 0x528D4, 0x528D6, 0x528DC,
                         0x528DE, 0x528E4, 0x528E6, 0x528EC, 0x528F2,
                         0x528F4)
        )
        mutation_sites.extend(
            (f"allocation-size-{site:x}", site)
            for site in (0x52874, 0x52886, 0x52898, 0x528AA, 0x528F6, 0x52908,
                         0x5291A, 0x5292A, 0x5293A, 0x5294A, 0x5295A, 0x5296A)
        )
        mutation_sites.extend(
            (f"allocation-call-{site:x}", site)
            for site in (0x52876, 0x52888, 0x5289A, 0x528AC, 0x528F8, 0x5290A,
                         0x5291C, 0x5292C, 0x5293C, 0x5294C, 0x5295C, 0x5296C)
        )
        mutation_sites.extend(
            (f"constructor-{site:x}", site)
            for site in (0x52880, 0x52892, 0x528A4, 0x528B6, 0x52902, 0x52914,
                         0x52924, 0x52934, 0x52944, 0x52954, 0x52964, 0x52974)
        )
        mutation_sites.append(("wrapper-forwarding", 0x529D6))
        for label, site in mutation_sites:
            with self.subTest(label=label), self.assertRaises(RuntimeError):
                exporter._validate_factory(
                    self._mutate_va(blob, mappings, site), mappings, deps, exidx, plt_symbols
                )

    def test_byte_level_validator_derives_exact_owner_and_twelve_arms(self):
        exporter = self._load()
        blob, mappings, deps, exidx, plt_symbols = self._validation_inputs(exporter)

        result = exporter._validate_factory(blob, mappings, deps, exidx, plt_symbols)

        self.assertEqual(result["owner"], {"start": 0x52840, "end": 0x529B8})
        self.assertEqual(result["total_constructor_arm_count"], 12)
        self.assertEqual(len(result["constructors"]), 5)

    def test_byte_level_validator_rejects_owner_boundary_mutation(self):
        exporter = self._load()
        blob, mappings, deps, exidx, plt_symbols = self._validation_inputs(exporter)
        mutated_exidx = tuple(
            (start, 0x529BA if start == 0x52840 else end) for start, end in exidx
        )

        with self.assertRaises(RuntimeError):
            exporter._validate_factory(blob, mappings, deps, mutated_exidx, plt_symbols)

    def test_sibling_view_unified2_classifications_are_byte_validated(self):
        exporter = self._load()
        self.assertTrue(
            hasattr(exporter, "_validate_invalid_offset_classifications"),
            "exporter lacks sibling viewUnified2 byte validator",
        )
        blob, mappings, deps, exidx, _plt_symbols = self._validation_inputs(
            exporter, VIEW_UNIFIED2_PATH
        )
        result = exporter._validate_invalid_offset_classifications(
            blob, mappings, deps, exidx
        )
        self.assertEqual(result, exporter.INVALID_OFFSET_CLASSIFICATIONS)
        mutation_sites = (
            0x181F18, 0x24222A, 0x3BA6DA, 0x651682,
            0x37B614, 0x37AA18, 0x37B5E0, 0x37B648, 0x37B578,
        )
        for site in mutation_sites:
            with self.subTest(site=site), self.assertRaises(RuntimeError):
                exporter._validate_invalid_offset_classifications(
                    self._mutate_va(blob, mappings, site), mappings, deps, exidx
                )

    def test_file_adapter_requires_pinned_sibling_view_unified2_validation(self):
        exporter = self._load()
        with mock.patch.object(
            exporter,
            "_validate_view_unified2_classifications",
            create=True,
            side_effect=RuntimeError("sibling classification validation failed"),
        ):
            with self.assertRaisesRegex(RuntimeError, "sibling classification"):
                exporter.FileAdapter(SOURCE_PATH).factory_metadata(exporter.FACTORY_ROOT)

    def test_exporter_requests_only_pinned_factory_and_upstream_roots(self):
        spec = importlib.util.spec_from_file_location("vertical_factory_exporter", EXPORTER_PATH)
        exporter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(exporter)

        class Adapter:
            def program_name(self): return exporter.EXPECTED_PROGRAM
            def program_sha256(self): return exporter.EXPECTED_SHA256
            def program_size(self): return exporter.EXPECTED_IMAGE_SIZE
            def analysis_mode(self): return {"engine": "elf-capstone-thumb", "read_only": True, "source_unchanged": True}
            def factory_metadata(self, root):
                self.root = root
                return {"constructors": exporter.CONSTRUCTORS, "reverse_callers": exporter.REVERSE_CALLERS, "unresolved_indirect_terminals": (), "owner": exporter.FACTORY_OWNER, "total_constructor_arm_count": exporter.TOTAL_CONSTRUCTOR_ARM_COUNT, "group_id": exporter.FACTORY_GROUP_ID, "vertical_classical_arms": exporter.VERTICAL_CLASSICAL_ARMS, "invalid_offset_classifications": exporter.INVALID_OFFSET_CLASSIFICATIONS, "false_class_id_paths": exporter.FALSE_CLASS_ID_PATHS}
            def upstream_roots(self): self.upstream_requested = True; return exporter.UPSTREAM_ROOTS

        adapter = Adapter()
        raw = exporter.build_raw_export(adapter)
        self.assertEqual(adapter.root, 0x52840)
        self.assertTrue(adapter.upstream_requested)
        self.assertEqual(raw["upstream_roots"]["camera_orientation_owners"], [0x2D2C6, 0x30750])
        self.assertFalse(raw["truncated"])

    def test_exporter_rejects_dirty_analyzed_bad_target_and_escaping_output(self):
        spec = importlib.util.spec_from_file_location("vertical_factory_exporter", EXPORTER_PATH)
        exporter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(exporter)

        class Adapter:
            def __init__(self, read_only=True, unchanged=True, target=0x14148): self.read_only, self.unchanged, self.target = read_only, unchanged, target
            def program_name(self): return exporter.EXPECTED_PROGRAM
            def program_sha256(self): return exporter.EXPECTED_SHA256
            def program_size(self): return exporter.EXPECTED_IMAGE_SIZE
            def analysis_mode(self): return {"engine": "elf-capstone-thumb", "read_only": self.read_only, "source_unchanged": self.unchanged}
            def upstream_roots(self): return exporter.UPSTREAM_ROOTS
            def factory_metadata(self, root):
                constructors = [dict(item) for item in exporter.CONSTRUCTORS]
                constructors[0]["target"] = self.target
                return {"constructors": tuple(constructors), "reverse_callers": exporter.REVERSE_CALLERS, "unresolved_indirect_terminals": (), "owner": exporter.FACTORY_OWNER, "total_constructor_arm_count": exporter.TOTAL_CONSTRUCTOR_ARM_COUNT, "group_id": exporter.FACTORY_GROUP_ID, "vertical_classical_arms": exporter.VERTICAL_CLASSICAL_ARMS, "invalid_offset_classifications": exporter.INVALID_OFFSET_CLASSIFICATIONS, "false_class_id_paths": exporter.FALSE_CLASS_ID_PATHS}

        for adapter in (Adapter(read_only=False), Adapter(unchanged=False), Adapter(target=0x1414A)):
            with self.subTest(adapter=adapter), self.assertRaises(RuntimeError): exporter.build_raw_export(adapter)

        bad_upstream = Adapter()
        bad_upstream.upstream_roots = lambda: {
            **exporter.UPSTREAM_ROOTS,
            "layout_mode": {"site_count": 27, "owner_count": 15, "owner_overlap_with_factory": False},
        }
        with self.assertRaises(RuntimeError):
            exporter.build_raw_export(bad_upstream)

    def test_output_is_contained(self):
        spec = importlib.util.spec_from_file_location("vertical_factory_exporter", EXPORTER_PATH)
        exporter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(exporter)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            document = {"schema_version": 1}
            good = root / "raw-vertical-layout-factory.json"
            exporter.write_json_atomic(good, document, root)
            self.assertEqual(json.loads(good.read_text(encoding="utf-8")), document)
            for escaped in (root / "wrong.json", root.parent / "raw-vertical-layout-factory.json"):
                with self.subTest(escaped=escaped), self.assertRaises(RuntimeError):
                    exporter.write_json_atomic(escaped, document, root)

    def test_missing_static_dependencies_fail_closed(self):
        spec = importlib.util.spec_from_file_location("vertical_factory_exporter", EXPORTER_PATH)
        exporter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(exporter)
        with mock.patch.object(exporter, "_require_dependencies", side_effect=RuntimeError("missing")):
            with self.assertRaisesRegex(RuntimeError, "missing"):
                exporter._metadata_from_file(ROOT / "missing.so")


if __name__ == "__main__":
    unittest.main()
