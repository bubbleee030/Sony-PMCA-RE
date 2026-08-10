import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
EXPORTER_PATH = (
    ROOT / "tools" / "static" / "export_a6400_mouse_post_producer_boundary.py"
)
REPORT_PATH = ROOT / "analysis" / "a6400-mouse-post-producer-boundary.json"
DEEP_DIVE_PATH = ROOT / "analysis" / "a6400a-updater-and-creative-style-deep-dive.md"


def expected_adapter(exporter, document=None):
    expected = copy.deepcopy(exporter.EXPECTED_EXPORT if document is None else document)

    class Adapter:
        def inventory(self):
            return copy.deepcopy(expected["firmware_inventory"]), ()

        def interaction_dependency(self):
            return copy.deepcopy(expected["interaction_dependency"])

        def symbol_universe(self, _elf_paths):
            return copy.deepcopy(expected["symbol_universe"])

        def libobj_publication_scan(self):
            return copy.deepcopy(expected["libobj_publication_scan"])

        def queue_processor(self, _publication_scan):
            return copy.deepcopy(expected["queue_processor"])

    return Adapter()


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

    def test_checked_report_is_exact_and_fail_closed(self):
        from pmca.analysis.mouse_post_producer_boundary import (
            READINESS,
            validate_mouse_post_producer_boundary_report,
        )

        report = validate_mouse_post_producer_boundary_report(
            json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        )
        self.assertEqual(report["readiness"], READINESS)
        self.assertFalse(report["camera_executed"])
        self.assertFalse(report["installable"])
        self.assertFalse(report["camera_test_eligible"])
        self.assertFalse(report["claims"]["raw_mouse_input_producer_found"])
        self.assertFalse(report["claims"]["queue_processor_invocation_found"])

    def test_deep_dive_preserves_the_bounded_negative_scope(self):
        text = DEEP_DIVE_PATH.read_text(encoding="utf-8")
        for phrase in (
            "59,614 exception-index owners",
            "56,271 fully decoded",
            "3,343 incomplete",
            "no decoded direct caller or static publication",
            "does not prove that no runtime or computed producer exists",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)
        for forbidden in (
            "no raw input producer exists",
            "runtime touch proven",
            "Creative Style touch proven",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)


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
                exporter.build_raw_export(expected_adapter(exporter, candidate))

    def test_outputs_are_deterministic_and_validated_before_any_write(self):
        exporter = self.exporter
        first = exporter.build_outputs(expected_adapter(exporter))
        second = exporter.build_outputs(expected_adapter(exporter))
        encode = lambda document: json.dumps(
            document,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        ).encode("utf-8") + b"\n"
        self.assertEqual(
            {path.name: encode(value) for path, value in first.items()},
            {path.name: encode(value) for path, value in second.items()},
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            raw_root = root / "raw"
            report_root = root / "report"
            raw_root.mkdir()
            report_root.mkdir()
            raw_path = raw_root / "raw-mouse-post-producer-boundary.json"
            report_path = report_root / "a6400-mouse-post-producer-boundary.json"
            raw_path.write_text("old raw\n", encoding="utf-8")
            report_path.write_text("old report\n", encoding="utf-8")
            with (
                mock.patch.object(exporter, "RAW_OUTPUT_ROOT", raw_root),
                mock.patch.object(exporter, "REPORT_OUTPUT_ROOT", report_root),
                mock.patch.object(exporter, "RAW_OUTPUT_PATH", raw_path),
                mock.patch.object(exporter, "REPORT_PATH", report_path),
                mock.patch.object(
                    exporter,
                    "validate_mouse_post_producer_boundary_report",
                    side_effect=RuntimeError("report validation failed"),
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "report validation failed"):
                    exporter.publish_outputs(expected_adapter(exporter))
            self.assertEqual(raw_path.read_text(encoding="utf-8"), "old raw\n")
            self.assertEqual(
                report_path.read_text(encoding="utf-8"),
                "old report\n",
            )


if __name__ == "__main__":
    unittest.main()
