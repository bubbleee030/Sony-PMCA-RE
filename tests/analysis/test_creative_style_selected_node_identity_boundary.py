import copy
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from pmca.analysis.creative_style_selected_node_identity_boundary import (
    EXPECTED_EXPORT,
    build_creative_style_selected_node_identity_boundary_report,
    normalize_creative_style_selected_node_identity_boundary_export,
    validate_creative_style_selected_node_identity_boundary_report,
)


class CreativeStyleSelectedNodeIdentityBoundaryContractTests(unittest.TestCase):
    def test_schema_3_reports_source_derived_selected_ordinal_writers(self):
        """Break caught: selected-ordinal writes may not remain asserted lifecycle prose."""
        report = validate_creative_style_selected_node_identity_boundary_report(
            build_creative_style_selected_node_identity_boundary_report(
                EXPECTED_EXPORT
            )
        )
        self.assertEqual(report["schema_version"], 3)
        writers = report["selected_ordinal_writers"]
        self.assertEqual(writers["field_offset"], 0x18)
        self.assertEqual(
            [item["site"] for item in writers["writers"]],
            [0x7C6C00, 0x7C70AA, 0x7C7358, 0x7C73CE, 0x7C7470],
        )
        self.assertEqual(
            [item["role"] for item in writers["writers"]],
            [
                "selected-item-cache-clamp",
                "parent-selected-ordinal-from-child-one-based-field",
                "root-default-minus-one",
                "child-default-minus-one",
                "fallback-missing-child-minus-one",
            ],
        )
        self.assertTrue(writers["typed_owner_inventory_complete"])
        self.assertTrue(
            writers[
                "parent_selected_ordinal_from_child_one_based_field_proven"
            ]
        )
        self.assertFalse(
            writers["candidate_provider_conditional_ordinal_triplet_proven"]
        )
        self.assertFalse(
            writers["runtime_selected_ordinal_triplet_1_5_2_proven"]
        )

    def test_productaction_candidates_explain_each_bounded_rejection(self):
        """Break caught: rejected callers may not remain unexplained booleans."""
        report = validate_creative_style_selected_node_identity_boundary_report(
            build_creative_style_selected_node_identity_boundary_report(
                EXPECTED_EXPORT
            )
        )
        delivery = report["productaction_delivery"]
        calls = delivery["canonical_slot_37_calls"]
        self.assertEqual(
            [item["rejection_reason"] for item in calls],
            [
                "receiver-untyped-and-selector-call-clobbered",
                "receiver-untyped-and-selector-call-clobbered",
                "receiver-untyped-and-selector-call-clobbered",
                "receiver-untyped-and-selector-call-clobbered",
                "af-helper-return-receiver-and-selector-call-clobbered",
                "entry-r2-receiver-and-helper-return-selector",
            ],
        )
        self.assertEqual(
            calls[4]["owner_identity"],
            {
                "kind": "defined-dynsym",
                "symbol_index": 1718,
                "symbol": (
                    "_ZN27CmnWrpOrientationRegisterAF26"
                    "getRecallRegisteredAfFrameEv"
                ),
            },
        )
        self.assertEqual(calls[4]["receiver_origin"], "helper-return-0x35f670")
        self.assertEqual(calls[4]["selector_origin"], "call-clobbered")
        self.assertEqual(calls[5]["receiver_origin"], "entry-r2-preserved-r5")
        self.assertEqual(calls[5]["selector_origin"], "helper-return-0x3e12fc")
        self.assertEqual(delivery["accepted_candidates"], [])
        self.assertEqual(
            delivery["unresolved_universes"],
            [
                "decode-incomplete-or-terminal-exidx-owners",
                "noncanonical-virtual-dispatch",
                "indirect-callback-or-runtime-initialized-receiver",
                "cross-module-or-loader-mediated-delivery",
            ],
        )

    def test_exact_static_path_is_positive_but_runtime_selection_is_false(self):
        """Break caught: static membership may not become runtime selection."""
        report = validate_creative_style_selected_node_identity_boundary_report(
            build_creative_style_selected_node_identity_boundary_report(
                EXPECTED_EXPORT
            )
        )
        self.assertEqual(report["schema_version"], 3)
        self.assertEqual(report["static_path"]["zero_based_indices"], [0, 4, 1])
        self.assertEqual(
            report["runtime_selection"]["required_one_based_ordinals"],
            [1, 5, 2],
        )
        self.assertEqual(
            (
                report["root_initialization"]["root_vptr_load_site"],
                report["root_initialization"]["init_slot_offset"],
                report["root_initialization"]["init_call_site"],
            ),
            (0x210992, 0x08, 0x2109A4),
        )
        self.assertEqual(
            [
                (item["got"], item["relocation_index"], item["symbol"])
                for item in report["root_initialization"]["default_root_bindings"]
            ],
            [
                (0x948AA0, 130801, "cmnViewSettingNodesRootDefault"),
                (0x94B8E4, 130996, "cmnViewSettingNodesNumOfRootDefault"),
            ],
        )
        self.assertEqual(
            report["candidate_lifecycle"]["one_based_ordinal_field_offset"],
            0x20,
        )
        self.assertEqual(
            report["productaction_delivery"]["canonical_slot_37_call_count"],
            6,
        )
        self.assertEqual(
            report["productaction_delivery"]["accepted_candidates"], []
        )
        self.assertFalse(
            report["productaction_delivery"]["whole_program_absence_proven"]
        )
        self.assertTrue(
            report["claims"][
                "creative_style_static_selected_child_path_0_4_1_found"
            ]
        )
        self.assertFalse(
            report["claims"]["runtime_selected_ordinal_triplet_1_5_2_proven"]
        )
        self.assertFalse(
            report["claims"][
                "runtime_selected_node_is_creative_style_root_proven"
            ]
        )
        self.assertFalse(report["claims"]["process_id_42_activation_accepted"])
        self.assertFalse(report["claims"]["first_class_creative_look_proven"])
        self.assertTrue(
            report["claims"]["viewsettingmenu_product_root_init_call_found"]
        )
        self.assertTrue(
            report["claims"][
                "candidate_recursive_one_based_ordinal_assignment_found"
            ]
        )
        self.assertTrue(
            report["claims"][
                "productaction_forwards_selector_to_slot_64_found"
            ]
        )
        self.assertFalse(
            report["claims"][
                "viewsettingmenu_productaction_10_delivery_proven"
            ]
        )
        self.assertEqual(
            report["first_unresolved_boundary"],
            (
                "caution-provider-bound-creative-style-selected-ordinal-chain-"
                "and-viewsettingmenu-productaction-10-delivery"
            ),
        )

    def test_export_rejects_claim_path_ordinal_dependency_and_boundary_mutations(self):
        """Break caught: no exact evidence field may drift without rejection."""
        for claim, expected in EXPECTED_EXPORT["claims"].items():
            mutated = copy.deepcopy(EXPECTED_EXPORT)
            mutated["claims"][claim] = not expected
            with self.subTest(claim=claim), self.assertRaises(ValueError):
                normalize_creative_style_selected_node_identity_boundary_export(
                    mutated
                )

        mutations = (
            lambda d: d["static_path"].__setitem__("zero_based_indices", [0, 4, 2]),
            lambda d: d["runtime_selection"].__setitem__(
                "required_one_based_ordinals", [1, 5, 3]
            ),
            lambda d: d["dependencies"][0].__setitem__("digest", "0" * 64),
            lambda d: d.__setitem__(
                "first_unresolved_boundary", "runtime-selection-proven"
            ),
        )
        for index, mutate in enumerate(mutations):
            mutated = copy.deepcopy(EXPECTED_EXPORT)
            mutate(mutated)
            with self.subTest(mutation=index), self.assertRaises(ValueError):
                normalize_creative_style_selected_node_identity_boundary_export(
                    mutated
                )

    def test_report_rejects_prohibited_narrative_promotions(self):
        """Break caught: prose may not contradict the fail-closed claims."""
        report = build_creative_style_selected_node_identity_boundary_report(
            EXPECTED_EXPORT
        )
        for text in (
            "The runtime selected node is Creative Style.",
            "Process ID 42 is activated.",
            "Creative Look is implemented.",
            "The package is installable and camera testing is eligible.",
        ):
            mutated = copy.deepcopy(report)
            mutated["conclusion"] = text
            with self.subTest(text=text), self.assertRaises(ValueError):
                validate_creative_style_selected_node_identity_boundary_report(
                    mutated
                )


class CreativeStyleSelectedNodeIdentityBoundaryExporterTests(unittest.TestCase):
    _cached_contexts = None

    def _real_contexts(self):
        from tools.static.export_a6400_creative_style_selected_node_identity_boundary import (
            CAUTION_SOURCE_PATH,
            SOURCE_PATH,
            _context,
            _dependencies,
            sources_available,
        )

        if not sources_available():
            self.skipTest("authenticated α6400 sources are unavailable")
        if self.__class__._cached_contexts is None:
            deps = _dependencies()
            self.__class__._cached_contexts = (
                _context(SOURCE_PATH.read_bytes(), deps),
                _context(CAUTION_SOURCE_PATH.read_bytes(), deps),
                deps,
            )
        return self.__class__._cached_contexts

    @staticmethod
    def _mutated_blob_context(context, address, mask=1):
        blob = bytearray(context["blob"])
        offsets = [
            file_offset + address - start
            for start, end, file_offset in context["mappings"]
            if start <= address < end
        ]
        if len(offsets) != 1:
            raise AssertionError(f"address does not map exactly once: {address:#x}")
        blob[offsets[0]] ^= mask
        mutated = dict(context)
        mutated["blob"] = bytes(blob)
        return mutated

    def test_builder_rejects_source_and_dependency_drift(self):
        """Break caught: stale inputs may not retain the positive static path."""
        from tools.static.export_a6400_creative_style_selected_node_identity_boundary import (
            build_raw_export,
        )

        mutations = (
            lambda d: d["source"].__setitem__("sha256", "0" * 64),
            lambda d: d["supporting_source"].__setitem__("sha256", "0" * 64),
            lambda d: d["dependencies"][0].__setitem__("digest", "0" * 64),
            lambda d: d["dependencies"][1].__setitem__("digest", "0" * 64),
            lambda d: d["dependencies"][2].__setitem__("digest", "0" * 64),
        )
        for index, mutate in enumerate(mutations):
            metadata = copy.deepcopy(EXPECTED_EXPORT)
            mutate(metadata)
            adapter = SimpleNamespace(metadata=lambda value=metadata: value)
            with self.subTest(mutation=index), self.assertRaises(RuntimeError):
                build_raw_export(adapter)

    def test_real_export_reproduces_the_exact_static_contract(self):
        """Break caught: source drift may not retain the selected-child path."""
        from tools.static.export_a6400_creative_style_selected_node_identity_boundary import (
            FileAdapter,
            sources_available,
        )

        if not sources_available():
            self.skipTest("authenticated α6400 sources are unavailable")
        self.assertEqual(FileAdapter().metadata(), EXPECTED_EXPORT)

    def test_file_adapter_rejects_nonregular_and_symlink_sources(self):
        """Break caught: source paths must be literal regular files."""
        from tools.static.export_a6400_creative_style_selected_node_identity_boundary import (
            FileAdapter,
        )

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            with self.assertRaisesRegex(RuntimeError, "literal regular file"):
                FileAdapter(source_path=base / "missing.so").metadata()

            target = base / "target.so"
            target.write_bytes(b"not firmware")
            link = base / "link.so"
            try:
                os.symlink(target, link)
            except OSError:
                return
            with self.assertRaisesRegex(RuntimeError, "literal regular file"):
                FileAdapter(source_path=link).metadata()

    def test_product_root_operand_mutations_are_rejected(self):
        """Break caught: selector bytes may not drift behind pinned metadata."""
        from tools.static.export_a6400_creative_style_selected_node_identity_boundary import (
            _validate_product_root,
        )

        view, _caution, deps = self._real_contexts()
        for site in (0x20882C, 0x20865A, 0x208668, 0x20881A, 0x210986, 0x21098C):
            mutated = self._mutated_blob_context(view, site)
            with self.subTest(site=f"{site:#x}"), self.assertRaises(RuntimeError):
                _validate_product_root(mutated, deps)

    def test_constructor_graph_operand_mutations_are_rejected(self):
        """Break caught: CFG or constructor argument drift must invalidate the path."""
        from tools.static.export_a6400_creative_style_selected_node_identity_boundary import (
            _validate_constructor_graph,
        )

        view, _caution, deps = self._real_contexts()
        sites = [0x214812]
        for call_site in (0x21EE7E, 0x21EDCA, 0x21EAFA):
            sites.extend(
                (
                    call_site - 0x16,
                    call_site - 0x12,
                    call_site - 0x0E,
                    call_site - 0x0C,
                    call_site,
                )
            )
        for site in sites:
            mutated = self._mutated_blob_context(view, site)
            with self.subTest(site=f"{site:#x}"), self.assertRaises(RuntimeError):
                _validate_constructor_graph(mutated, deps)

    def test_path_relocation_mutations_are_rejected(self):
        """Break caught: list-cell relocation identity may not be asserted."""
        from tools.static.export_a6400_creative_style_selected_node_identity_boundary import (
            _validate_static_path,
        )

        view, _caution, _deps = self._real_contexts()
        for cell in (0x957C80, 0x956B88, 0x9548C0):
            mutated = self._mutated_blob_context(view, cell)
            with self.subTest(cell=f"{cell:#x}"), self.assertRaises(RuntimeError):
                _validate_static_path(mutated)

            index, relocation = view["by_site"][cell]
            for label, changed_index, changed_relocation in (
                ("index", index + 1, relocation),
                (
                    "type",
                    index,
                    {
                        "r_info_type": relocation["r_info_type"] ^ 1,
                        "r_info_sym": relocation["r_info_sym"],
                    },
                ),
                (
                    "symbol",
                    index,
                    {
                        "r_info_type": relocation["r_info_type"],
                        "r_info_sym": relocation["r_info_sym"] + 1,
                    },
                ),
            ):
                mutated = dict(view)
                mutated["by_site"] = dict(view["by_site"])
                mutated["by_site"][cell] = (changed_index, changed_relocation)
                with self.subTest(cell=f"{cell:#x}", field=label), self.assertRaises(
                    RuntimeError
                ):
                    _validate_static_path(mutated)

    def test_selected_child_and_candidate_semantic_mutations_are_rejected(self):
        """Break caught: chained receivers and ordinal semantics must remain exact."""
        from tools.static.export_a6400_creative_style_selected_node_identity_boundary import (
            _validate_runtime_selection,
            _validate_selected_child_mechanism,
        )

        view, caution, deps = self._real_contexts()
        for site in (
            0x207C52,
            0x207C5E,
            0x207C64,
            0x207C66,
            0x207C68,
            0x207C6C,
            0x207C72,
            0x207C74,
            0x207C76,
            0x207C7A,
            0x207C7E,
            0x207C80,
            0x207C82,
        ):
            mutated = self._mutated_blob_context(view, site)
            with self.subTest(site=f"{site:#x}"), self.assertRaises(RuntimeError):
                _validate_selected_child_mechanism(mutated, deps)

        for site in (
            0x7C6BDC,
            0x7C6BE6,
            0x7C6BEA,
            0x7C6BEE,
            0x7C6BF4,
            0x7C6BFE,
            0x7C6C02,
            0x7C6C04,
            0x7C6C08,
            0x7C72CC,
            0x7C72D4,
            0x7C72DA,
            0x7C72DC,
        ):
            mutated = self._mutated_blob_context(caution, site)
            with self.subTest(site=f"{site:#x}"), self.assertRaises(RuntimeError):
                _validate_runtime_selection(mutated, deps)

    def test_root_initialization_and_candidate_lifecycle_are_source_derived(self):
        """Break caught: root/lifecycle positives may not be unvalidated constants."""
        import tools.static.export_a6400_creative_style_selected_node_identity_boundary as exporter

        root_validator = getattr(exporter, "_validate_root_initialization", None)
        lifecycle_validator = getattr(exporter, "_validate_candidate_lifecycle", None)
        self.assertTrue(callable(root_validator))
        self.assertTrue(callable(lifecycle_validator))
        view, caution, deps = self._real_contexts()
        self.assertEqual(
            root_validator(view, deps), EXPECTED_EXPORT["root_initialization"]
        )
        self.assertEqual(
            lifecycle_validator(caution, deps),
            EXPECTED_EXPORT["candidate_lifecycle"],
        )

    def test_root_initialization_and_lifecycle_operand_mutations_are_rejected(self):
        """Break caught: root/lifecycle claims must fail on source drift."""
        import tools.static.export_a6400_creative_style_selected_node_identity_boundary as exporter

        root_validator = getattr(exporter, "_validate_root_initialization", None)
        lifecycle_validator = getattr(exporter, "_validate_candidate_lifecycle", None)
        self.assertTrue(callable(root_validator))
        self.assertTrue(callable(lifecycle_validator))
        view, caution, deps = self._real_contexts()
        for site in (
            0x210992,
            0x210994,
            0x210996,
            0x21099E,
            0x2109A2,
            0x2109A4,
            0x2084FE,
            0x208504,
            0x208508,
            0x20850A,
            0x208518,
            0x20851E,
            0x208520,
            0x208528,
        ):
            mutated = self._mutated_blob_context(view, site)
            with self.subTest(source="view", site=f"{site:#x}"), self.assertRaises(
                RuntimeError
            ):
                root_validator(mutated, deps)

        for got in (0x948AA0, 0x94B8E4):
            index, relocation = view["by_site"][got]
            for label, changed_index, changed_relocation in (
                ("index", index + 1, relocation),
                (
                    "type",
                    index,
                    {
                        "r_info_type": relocation["r_info_type"] ^ 1,
                        "r_info_sym": relocation["r_info_sym"],
                    },
                ),
                (
                    "symbol",
                    index,
                    {
                        "r_info_type": relocation["r_info_type"],
                        "r_info_sym": relocation["r_info_sym"] + 1,
                    },
                ),
            ):
                mutated = dict(view)
                mutated["by_site"] = dict(view["by_site"])
                mutated["by_site"][got] = (changed_index, changed_relocation)
                with self.subTest(got=f"{got:#x}", field=label), self.assertRaises(
                    RuntimeError
                ):
                    root_validator(mutated, deps)

        for site in (
            0xAB9408,
            0xAB94F8,
            0xAB94FC,
            0x7C6AF2,
            0x7C6AFC,
            0x7C6B08,
            0x7C6B0E,
            0x7C6B16,
            0x7C6B1A,
            0x7C73B8,
            0x7C73BE,
            0x7C73C4,
            0x7C73C8,
            0x7C73CE,
            0x7C73FA,
            0x7C7402,
            0x7C740C,
            0x7C7410,
            0x7C741A,
            0x7C741E,
            0x7C7428,
            0x7C742A,
            0x7C7430,
            0x7C7432,
            0x7C7436,
            0x7C7438,
            0x7C743A,
            0x7C743E,
            0x7C7452,
            0x7C745A,
            0x7C745C,
            0x7C7464,
            0x7C7468,
            0x7C7470,
        ):
            mutated = self._mutated_blob_context(caution, site)
            with self.subTest(source="caution", site=f"{site:#x}"), self.assertRaises(
                RuntimeError
            ):
                lifecycle_validator(mutated, deps)

        for role in ("init_setting_node", "recursive_init", "set_head_selected"):
            cell = EXPECTED_EXPORT["candidate_lifecycle"][role]["cell"]
            index, relocation = caution["by_site"][cell]
            for label, changed_index, changed_relocation in (
                ("index", index + 1, relocation),
                (
                    "type",
                    index,
                    {
                        "r_info_type": relocation["r_info_type"] ^ 1,
                        "r_info_sym": relocation["r_info_sym"],
                    },
                ),
                (
                    "symbol",
                    index,
                    {
                        "r_info_type": relocation["r_info_type"],
                        "r_info_sym": relocation["r_info_sym"] + 1,
                    },
                ),
            ):
                mutated = dict(caution)
                mutated["by_site"] = dict(caution["by_site"])
                mutated["by_site"][cell] = (changed_index, changed_relocation)
                with self.subTest(role=role, field=label), self.assertRaises(
                    RuntimeError
                ):
                    lifecycle_validator(mutated, deps)

    def test_selected_ordinal_writer_inventory_is_source_derived(self):
        """Break caught: writer roles may not be emitted without decoding their stores."""
        import tools.static.export_a6400_creative_style_selected_node_identity_boundary as exporter

        validator = getattr(exporter, "_validate_selected_ordinal_writers", None)
        self.assertTrue(callable(validator))
        _view, caution, deps = self._real_contexts()
        self.assertEqual(
            validator(caution, deps), EXPECTED_EXPORT["selected_ordinal_writers"]
        )

    def test_selected_ordinal_writer_source_mutations_are_rejected(self):
        """Break caught: a wrong writer receiver or value producer must fail closed."""
        import tools.static.export_a6400_creative_style_selected_node_identity_boundary as exporter

        validator = getattr(exporter, "_validate_selected_ordinal_writers", None)
        self.assertTrue(callable(validator))
        _view, caution, deps = self._real_contexts()
        sites = (
            0x7C6BFA,
            0x7C6BFC,
            0x7C6C00,
            0x7C70A4,
            0x7C70A6,
            0x7C70AA,
            0x7C734E,
            0x7C7358,
            0x7C73CA,
            0x7C73CE,
            0x7C746C,
            0x7C7470,
        )
        for site in sites:
            mutated = self._mutated_blob_context(caution, site)
            with self.subTest(site=f"{site:#x}"), self.assertRaisesRegex(
                RuntimeError, "selected-ordinal writer"
            ):
                validator(mutated, deps)

    def test_productaction_interface_is_source_derived(self):
        """Break caught: ProductAction forwarding may not be an asserted constant."""
        import tools.static.export_a6400_creative_style_selected_node_identity_boundary as exporter

        validator = getattr(exporter, "_validate_productaction_interface", None)
        self.assertTrue(callable(validator))
        view, _caution, deps = self._real_contexts()
        expected = EXPECTED_EXPORT["productaction_delivery"]
        self.assertEqual(
            expected["productaction"]["symbol_range"],
            {"start": 0x2F1350, "end": 0x2F135E},
        )
        self.assertEqual(
            expected["productaction"]["exidx_owner"],
            {"start": 0x2F12EC, "end": 0x2F135E, "complete": True},
        )
        self.assertEqual(
            validator(view, deps),
            {
                "viewsettingmenu_vtable_address_point": expected[
                    "viewsettingmenu_vtable_address_point"
                ],
                "slot_37": expected["slot_37"],
                "productaction": expected["productaction"],
                "slot_64": expected["slot_64"],
            },
        )

    def test_productaction_interface_source_mutations_are_rejected(self):
        """Break caught: wrapper bytes, relocations, or symbol identity may not drift."""
        import tools.static.export_a6400_creative_style_selected_node_identity_boundary as exporter

        validator = getattr(exporter, "_validate_productaction_interface", None)
        self.assertTrue(callable(validator))
        view, _caution, deps = self._real_contexts()
        for site in (
            0x8E2304,
            0x2F1350,
            0x2F1352,
            0x2F1354,
            0x2F1356,
            0x2F135A,
            0x2F135C,
            0x8E2370,
        ):
            mutated = self._mutated_blob_context(view, site)
            with self.subTest(site=f"{site:#x}"), self.assertRaises(RuntimeError):
                validator(mutated, deps)

        for role in ("slot_37", "slot_64"):
            record = EXPECTED_EXPORT["productaction_delivery"][role]
            cell = record["cell"]
            index, relocation = view["by_site"][cell]
            for label, changed_index, changed_relocation in (
                ("index", index + 1, relocation),
                (
                    "type",
                    index,
                    {
                        "r_info_type": relocation["r_info_type"] ^ 1,
                        "r_info_sym": relocation["r_info_sym"],
                    },
                ),
                (
                    "symbol",
                    index,
                    {
                        "r_info_type": relocation["r_info_type"],
                        "r_info_sym": relocation["r_info_sym"] + 1,
                    },
                ),
            ):
                mutated = dict(view)
                mutated["by_site"] = dict(view["by_site"])
                mutated["by_site"][cell] = (changed_index, changed_relocation)
                with self.subTest(role=role, field=label), self.assertRaises(
                    RuntimeError
                ):
                    validator(mutated, deps)

        real_elf = view["elf"]
        symbol_index = EXPECTED_EXPORT["productaction_delivery"]["productaction"][
            "symbol_index"
        ]

        class SymbolProxy:
            def __init__(self, real, field, value):
                self.real = real
                self.field = field
                self.value = value
                self.name = real.name

            def __getitem__(self, key):
                return self.value if key == self.field else self.real[key]

        class DynsymProxy:
            def __init__(self, field, value):
                self.field = field
                self.value = value

            def get_symbol(self, index):
                real = real_elf.get_section_by_name(".dynsym").get_symbol(index)
                if index == symbol_index:
                    return SymbolProxy(real, self.field, self.value)
                return real

        class ElfProxy:
            def __init__(self, field, value):
                self.field = field
                self.value = value

            def get_section_by_name(self, name):
                if name == ".dynsym":
                    return DynsymProxy(self.field, self.value)
                return real_elf.get_section_by_name(name)

        for field, value in (("st_value", 0x2F1361), ("st_size", 12)):
            mutated = dict(view)
            mutated["elf"] = ElfProxy(field, value)
            with self.subTest(symbol_field=field), self.assertRaises(RuntimeError):
                validator(mutated, deps)

    def test_productaction_delivery_scan_is_source_derived(self):
        """Break caught: bounded ProductAction caller coverage may not be asserted."""
        import tools.static.export_a6400_creative_style_selected_node_identity_boundary as exporter

        validator = getattr(exporter, "_validate_productaction_delivery", None)
        self.assertTrue(callable(validator))
        view, _caution, deps = self._real_contexts()
        actual = validator(view, deps)
        self.assertEqual(actual, EXPECTED_EXPORT["productaction_delivery"])
        self.assertEqual(actual["fully_decoded_owner_count"], 28_869)
        self.assertEqual(actual["incomplete_or_terminal_owner_count"], 1_594)
        self.assertEqual(
            [
                {
                    key: item[key]
                    for key in (
                        "owner",
                        "vptr_load_site",
                        "slot_load_site",
                        "call_site",
                        "receiver_register",
                        "receiver_identity_proven",
                        "selector_10_proven",
                        "accepted",
                    )
                }
                for item in actual["canonical_slot_37_calls"]
            ],
            [
                {
                    "owner": {"start": 0x310CD8, "end": 0x310E30, "complete": True},
                    "vptr_load_site": 0x310CFE,
                    "slot_load_site": 0x310D02,
                    "call_site": 0x310D06,
                    "receiver_register": "r4",
                    "receiver_identity_proven": False,
                    "selector_10_proven": False,
                    "accepted": False,
                },
                {
                    "owner": {"start": 0x310CD8, "end": 0x310E30, "complete": True},
                    "vptr_load_site": 0x310D6C,
                    "slot_load_site": 0x310D70,
                    "call_site": 0x310D74,
                    "receiver_register": "r4",
                    "receiver_identity_proven": False,
                    "selector_10_proven": False,
                    "accepted": False,
                },
                {
                    "owner": {"start": 0x310CD8, "end": 0x310E30, "complete": True},
                    "vptr_load_site": 0x310D9A,
                    "slot_load_site": 0x310D9E,
                    "call_site": 0x310DA2,
                    "receiver_register": "r4",
                    "receiver_identity_proven": False,
                    "selector_10_proven": False,
                    "accepted": False,
                },
                {
                    "owner": {"start": 0x310CD8, "end": 0x310E30, "complete": True},
                    "vptr_load_site": 0x310DC8,
                    "slot_load_site": 0x310DCC,
                    "call_site": 0x310DD0,
                    "receiver_register": "r4",
                    "receiver_identity_proven": False,
                    "selector_10_proven": False,
                    "accepted": False,
                },
                {
                    "owner": {"start": 0x35F66C, "end": 0x35F67E, "complete": True},
                    "vptr_load_site": 0x35F674,
                    "slot_load_site": 0x35F676,
                    "call_site": 0x35F67A,
                    "receiver_register": "r0",
                    "receiver_identity_proven": False,
                    "selector_10_proven": False,
                    "accepted": False,
                },
                {
                    "owner": {"start": 0x3E11D4, "end": 0x3E134C, "complete": True},
                    "vptr_load_site": 0x3E1318,
                    "slot_load_site": 0x3E1322,
                    "call_site": 0x3E1328,
                    "receiver_register": "r5",
                    "receiver_identity_proven": False,
                    "selector_10_proven": False,
                    "accepted": False,
                },
            ],
        )
        self.assertEqual(actual["accepted_candidates"], [])
        self.assertFalse(actual["whole_program_absence_proven"])

    def test_productaction_caller_provenance_source_mutations_are_rejected(self):
        """Break caught: caller rejection reasons must fail when their dataflow drifts."""
        import tools.static.export_a6400_creative_style_selected_node_identity_boundary as exporter

        validator = getattr(exporter, "_validate_productaction_delivery", None)
        self.assertTrue(callable(validator))
        view, _caution, deps = self._real_contexts()
        for site in (0x310CDE, 0x35F670, 0x3E11DE, 0x3E1300, 0x3E131A):
            mutated = self._mutated_blob_context(view, site)
            with self.subTest(site=f"{site:#x}"), self.assertRaisesRegex(
                RuntimeError, "ProductAction caller provenance"
            ):
                validator(mutated, deps)

        real_elf = view["elf"]

        class SymbolProxy:
            def __init__(self, real):
                self.real = real
                self.name = "wrongAfWrapper"

            def __getitem__(self, key):
                return self.real[key]

        class DynsymProxy:
            def get_symbol(self, index):
                real = real_elf.get_section_by_name(".dynsym").get_symbol(index)
                return SymbolProxy(real) if index == 1718 else real

            def iter_symbols(self):
                real_dynsym = real_elf.get_section_by_name(".dynsym")
                for index, real in enumerate(real_dynsym.iter_symbols()):
                    yield SymbolProxy(real) if index == 1718 else real

        class ElfProxy:
            def get_section_by_name(self, name):
                if name == ".dynsym":
                    return DynsymProxy()
                return real_elf.get_section_by_name(name)

        mutated = dict(view)
        mutated["elf"] = ElfProxy()
        with self.assertRaisesRegex(
            RuntimeError, "ProductAction caller provenance"
        ):
            validator(mutated, deps)

    def test_productaction_delivery_scan_drift_and_promotion_are_rejected(self):
        """Break caught: scan drift or a fabricated selector-10 receiver must fail."""
        import tools.static.export_a6400_creative_style_selected_node_identity_boundary as exporter

        validator = getattr(exporter, "_validate_productaction_delivery", None)
        result_validator = getattr(exporter, "_validate_productaction_scan_result", None)
        self.assertTrue(callable(validator))
        self.assertTrue(callable(result_validator))
        view, _caution, deps = self._real_contexts()

        mutated_source = self._mutated_blob_context(view, 0x310D06)
        with self.assertRaises(RuntimeError):
            validator(mutated_source, deps)

        expected = copy.deepcopy(EXPECTED_EXPORT["productaction_delivery"])
        mutations = []
        changed = copy.deepcopy(expected)
        changed["fully_decoded_owner_count"] -= 1
        mutations.append(changed)
        changed = copy.deepcopy(expected)
        changed["incomplete_or_terminal_owner_count"] += 1
        mutations.append(changed)
        changed = copy.deepcopy(expected)
        changed["canonical_slot_37_calls"].pop()
        changed["canonical_slot_37_call_count"] -= 1
        mutations.append(changed)
        changed = copy.deepcopy(expected)
        fabricated = copy.deepcopy(changed["canonical_slot_37_calls"][0])
        fabricated["receiver_identity_proven"] = True
        fabricated["selector_10_proven"] = True
        fabricated["accepted"] = True
        changed["canonical_slot_37_calls"].append(fabricated)
        changed["canonical_slot_37_call_count"] += 1
        changed["accepted_candidates"] = [fabricated]
        changed["receiver_identity_proven"] = True
        changed["selector_10_proven"] = True
        mutations.append(changed)
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=index), self.assertRaises(RuntimeError):
                result_validator(mutation)

    def test_authenticated_export_fails_if_productaction_validation_fails(self):
        """Break caught: the full exporter may not bypass ProductAction validation."""
        import tools.static.export_a6400_creative_style_selected_node_identity_boundary as exporter

        if not exporter.sources_available():
            self.skipTest("authenticated α6400 sources are unavailable")
        with mock.patch.object(
            exporter,
            "_validate_productaction_delivery",
            side_effect=RuntimeError("forced ProductAction validation failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "forced ProductAction"):
                exporter._metadata_from_blobs(
                    exporter.SOURCE_PATH.read_bytes(),
                    exporter.CAUTION_SOURCE_PATH.read_bytes(),
                    exporter._dependencies(),
                )

    def test_checked_report_matches_fresh_deterministic_export(self):
        """Break caught: the checked report may not drift from authenticated sources."""
        from tools.static.export_a6400_creative_style_selected_node_identity_boundary import (
            REPORT_PATH,
            build_report,
            sources_available,
        )

        if not sources_available():
            self.skipTest("authenticated α6400 sources are unavailable")
        self.assertTrue(REPORT_PATH.is_file(), "checked report is missing")
        first = build_report()
        second = build_report()
        self.assertEqual(first, second)
        self.assertEqual(
            json.loads(REPORT_PATH.read_text(encoding="utf-8")),
            first,
        )

    def test_validation_failure_does_not_write_the_checked_report(self):
        """Break caught: invalid evidence may not partially replace the report."""
        from tools.static.export_a6400_creative_style_selected_node_identity_boundary import (
            REPORT_PATH,
            write_report,
        )

        before = REPORT_PATH.read_bytes()
        invalid = json.loads(before.decode("utf-8"))
        invalid["claims"]["runtime_selected_node_is_creative_style_root_proven"] = True
        with self.assertRaises(ValueError):
            write_report(invalid)
        self.assertEqual(REPORT_PATH.read_bytes(), before)

    def test_lifecycle_source_failure_does_not_write_the_checked_report(self):
        """Break caught: source validation must finish before the atomic write."""
        import tools.static.export_a6400_creative_style_selected_node_identity_boundary as exporter

        if not exporter.sources_available():
            self.skipTest("authenticated α6400 sources are unavailable")
        before = exporter.REPORT_PATH.read_bytes()
        with mock.patch.object(
            exporter,
            "_validate_candidate_lifecycle",
            side_effect=RuntimeError("forced lifecycle validation failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "forced lifecycle"):
                exporter.main()
        self.assertEqual(exporter.REPORT_PATH.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
