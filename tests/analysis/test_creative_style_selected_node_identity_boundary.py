import copy
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from pmca.analysis.creative_style_selected_node_identity_boundary import (
    EXPECTED_EXPORT,
    build_creative_style_selected_node_identity_boundary_report,
    normalize_creative_style_selected_node_identity_boundary_export,
    validate_creative_style_selected_node_identity_boundary_report,
)


class CreativeStyleSelectedNodeIdentityBoundaryContractTests(unittest.TestCase):
    def test_exact_static_path_is_positive_but_runtime_selection_is_false(self):
        """Break caught: static membership may not become runtime selection."""
        report = validate_creative_style_selected_node_identity_boundary_report(
            build_creative_style_selected_node_identity_boundary_report(
                EXPECTED_EXPORT
            )
        )
        self.assertEqual(report["schema_version"], 2)
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
            "viewsettingmenu-live-selected-ordinals-1-5-2-and-productaction-10-delivery",
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


if __name__ == "__main__":
    unittest.main()
