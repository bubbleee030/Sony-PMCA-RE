import copy
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
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["static_path"]["zero_based_indices"], [0, 4, 1])
        self.assertEqual(
            report["runtime_selection"]["required_one_based_ordinals"],
            [1, 5, 2],
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
        self.assertEqual(
            report["first_unresolved_boundary"],
            "viewsettingmenu-runtime-selected-ordinal-triplet-1-5-2-and-action-provenance",
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


if __name__ == "__main__":
    unittest.main()
