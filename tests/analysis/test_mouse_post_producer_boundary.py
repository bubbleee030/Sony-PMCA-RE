import copy
import unittest


class MousePostProducerBoundaryContractTests(unittest.TestCase):
    def test_expected_boundary_pins_api_scope_and_unresolved_producer(self):
        from pmca.analysis.mouse_post_producer_boundary import (
            EXPECTED_EXPORT,
            FIRST_UNRESOLVED_BOUNDARY,
            PUBLIC_APIS,
            READINESS,
            normalize_mouse_post_producer_boundary_export,
        )

        validated = normalize_mouse_post_producer_boundary_export(EXPECTED_EXPORT)
        self.assertEqual(tuple(validated["public_apis"]), PUBLIC_APIS)
        self.assertEqual(
            validated["first_unresolved_boundary"],
            FIRST_UNRESOLVED_BOUNDARY,
        )
        self.assertEqual(validated["readiness"], READINESS)
        self.assertEqual(
            validated["libobj_publication_scan"]["owner_count"],
            59_614,
        )
        self.assertEqual(
            validated["libobj_publication_scan"]["complete_owner_count"],
            56_271,
        )
        self.assertEqual(
            validated["libobj_publication_scan"]["incomplete_owner_count"],
            3_343,
        )
        self.assertFalse(validated["claims"]["raw_mouse_input_producer_found"])
        self.assertFalse(validated["claims"]["queue_processor_invocation_found"])

    def test_boundary_rejects_fabricated_producers_and_runtime_promotion(self):
        from pmca.analysis.mouse_post_producer_boundary import (
            EXPECTED_EXPORT,
            normalize_mouse_post_producer_boundary_export,
        )

        mutations = (
            (
                "external_import",
                lambda document: document["symbol_universe"][
                    "external_imports"
                ].append({"module": "lib/fake.so", "role": "move"}),
            ),
            (
                "direct_call",
                lambda document: document["libobj_publication_scan"][
                    "direct_inbound_calls"
                ]["move"].append(
                    {"owner_start": 1, "owner_end": 2, "site": 1}
                ),
            ),
            (
                "runtime",
                lambda document: document["claims"].__setitem__(
                    "runtime_mouse_input_delivery_proven", True
                ),
            ),
        )
        for label, mutate in mutations:
            candidate = copy.deepcopy(EXPECTED_EXPORT)
            mutate(candidate)
            with self.subTest(label=label), self.assertRaises(ValueError):
                normalize_mouse_post_producer_boundary_export(candidate)

    def test_validated_boundary_is_a_deep_copy(self):
        from pmca.analysis.mouse_post_producer_boundary import (
            EXPECTED_EXPORT,
            normalize_mouse_post_producer_boundary_export,
        )

        validated = normalize_mouse_post_producer_boundary_export(EXPECTED_EXPORT)
        validated["public_apis"][0]["role"] = "changed"
        self.assertEqual(EXPECTED_EXPORT["public_apis"][0]["role"], "move")


if __name__ == "__main__":
    unittest.main()
