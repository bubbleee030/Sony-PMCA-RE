import copy
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
EXPORTER_PATH = (
    ROOT / "tools" / "static" / "export_a6400_mouse_post_producer_boundary.py"
)


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


class MousePostProducerBoundaryExporterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "mouse_post_producer_boundary_exporter",
            EXPORTER_PATH,
        )
        cls.exporter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.exporter)

    def test_real_export_matches_exact_boundary_when_available(self):
        if not self.exporter.sources_available() or not self.exporter.dependencies_available():
            self.skipTest("pinned source or parser dependencies are unavailable")
        self.assertEqual(
            self.exporter.build_raw_export(),
            self.exporter.EXPECTED_EXPORT,
        )

    def test_exporter_rejects_every_new_static_producer_candidate(self):
        exporter = self.exporter

        class Adapter:
            def __init__(self, document):
                self.document = document

            def inventory(self):
                return copy.deepcopy(self.document["firmware_inventory"]), ()

            def interaction_dependency(self):
                return copy.deepcopy(self.document["interaction_dependency"])

            def symbol_universe(self, _elf_paths):
                return copy.deepcopy(self.document["symbol_universe"])

            def libobj_publication_scan(self):
                return copy.deepcopy(self.document["libobj_publication_scan"])

            def queue_processor(self, _publication_scan):
                return copy.deepcopy(self.document["queue_processor"])

        def append_publication(document, field, role="move"):
            document["libobj_publication_scan"][field][role].append(
                {"site": 1, "owner_start": 1, "owner_end": 2}
            )

        mutations = (
            (
                "external-symbol-consumer",
                lambda document: document["symbol_universe"][
                    "external_imports"
                ].append({"module": "lib/fake.so", "role": "move"}),
            ),
            (
                "short-name-file",
                lambda document: document["symbol_universe"][
                    "short_name_occurrences"
                ][0]["modules"].append("lib/fake.so"),
            ),
            (
                "decoded-direct-caller",
                lambda document: append_publication(
                    document, "direct_inbound_calls"
                ),
            ),
            (
                "dynamic-relocation",
                lambda document: append_publication(
                    document, "relocation_publications"
                ),
            ),
            (
                "allocated-aligned-pointer",
                lambda document: append_publication(
                    document, "aligned_pointer_publications"
                ),
            ),
            (
                "address-materialization",
                lambda document: append_publication(
                    document, "address_materializations"
                ),
            ),
            (
                "queue-processor-direct-caller",
                lambda document: document["queue_processor"][
                    "direct_inbound_calls"
                ].append({"site": 1, "owner_start": 1, "owner_end": 2}),
            ),
        )
        for label, mutate in mutations:
            candidate = copy.deepcopy(exporter.EXPECTED_EXPORT)
            mutate(candidate)
            with self.subTest(label=label), self.assertRaisesRegex(
                RuntimeError,
                label,
            ):
                exporter.build_raw_export(Adapter(candidate))


if __name__ == "__main__":
    unittest.main()
