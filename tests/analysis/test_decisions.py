import copy
import unittest

from pmca.analysis.decisions import (
    DecisionError,
    REQUIRED_CAPABILITIES,
    render_markdown,
    validate_evidence,
)


EXPECTED_CAPABILITIES = (
    "creative-look-discovery",
    "creative-look-emulation",
    "touch-menu",
    "vertical-ui",
    "signature-enforcement",
    "hardware-dependencies",
    "recovery",
)


def synthetic_document():
    statuses = (
        "FEASIBLE",
        "PARTIAL",
        "BLOCKED",
        "INSUFFICIENT_EVIDENCE",
        "FEASIBLE",
        "PARTIAL",
        "BLOCKED",
    )
    capabilities = []
    for index, capability_id in enumerate(EXPECTED_CAPABILITIES):
        capabilities.append(
            {
                "id": capability_id,
                "status": statuses[index],
                "summary": f"Synthetic summary {index + 1}.",
                "evidence": [
                    {
                        "kind": "OBSERVATION",
                        "source": f"analysis/reports/synthetic-{index + 1}.json",
                        "claim": f"Synthetic observation {index + 1}.",
                    }
                ],
                "next_action": f"Synthetic next action {index + 1}.",
            }
        )
    return {"schema_version": 1, "capabilities": capabilities}


class DecisionValidationTests(unittest.TestCase):
    def test_required_capability_contract_is_exact_and_ordered(self):
        self.assertEqual(REQUIRED_CAPABILITIES, EXPECTED_CAPABILITIES)

    def test_valid_document_is_deep_copied_and_ordered(self):
        document = synthetic_document()
        document["capabilities"].reverse()

        normalized = validate_evidence(document)
        document["capabilities"][0]["evidence"][0]["claim"] = "Changed later."

        self.assertEqual(
            tuple(item["id"] for item in normalized["capabilities"]),
            EXPECTED_CAPABILITIES,
        )
        self.assertEqual(
            normalized["capabilities"][-1]["evidence"][0]["claim"],
            "Synthetic observation 7.",
        )
        self.assertIsNot(normalized, document)
        self.assertIsNot(normalized["capabilities"], document["capabilities"])

    def test_missing_unknown_and_duplicate_capabilities_are_rejected(self):
        cases = {}

        missing = synthetic_document()
        missing["capabilities"].pop()
        cases["missing"] = missing

        unknown = synthetic_document()
        unknown["capabilities"][-1]["id"] = "synthetic-extra"
        cases["unknown"] = unknown

        duplicate = synthetic_document()
        duplicate["capabilities"][-1]["id"] = EXPECTED_CAPABILITIES[0]
        cases["duplicate"] = duplicate

        for name, document in cases.items():
            with self.subTest(name=name), self.assertRaises(DecisionError):
                validate_evidence(document)

    def test_unknown_status_is_rejected(self):
        document = synthetic_document()
        document["capabilities"][0]["status"] = "LIKELY"

        with self.assertRaises(DecisionError):
            validate_evidence(document)

    def test_empty_summary_evidence_and_next_action_are_rejected(self):
        for field, value in (
            ("summary", "   "),
            ("evidence", []),
            ("next_action", ""),
        ):
            with self.subTest(field=field):
                document = synthetic_document()
                document["capabilities"][0][field] = value
                with self.assertRaises(DecisionError):
                    validate_evidence(document)

    def test_evidence_schema_kind_source_and_claim_are_exact(self):
        mutations = (
            ("unsupported kind", {"kind": "OPINION"}),
            ("empty source", {"source": "  "}),
            ("empty claim", {"claim": ""}),
            ("extra evidence field", {"confidence": "high"}),
        )

        for name, update in mutations:
            with self.subTest(name=name):
                document = synthetic_document()
                document["capabilities"][0]["evidence"][0].update(update)
                with self.assertRaises(DecisionError):
                    validate_evidence(document)

    def test_non_text_status_kind_and_malformed_url_are_rejected(self):
        mutations = (
            ("status", ["FEASIBLE"]),
            ("kind", ["OBSERVATION"]),
            ("source", "https://["),
        )

        for field, value in mutations:
            with self.subTest(field=field):
                document = synthetic_document()
                if field == "status":
                    document["capabilities"][0][field] = value
                else:
                    document["capabilities"][0]["evidence"][0][field] = value
                with self.assertRaises(DecisionError):
                    validate_evidence(document)

    def test_evidence_sources_are_strictly_allowlisted(self):
        allowed = (
            "https://www.sony.com.tw/official/path",
            "https://helpguide.sony.net/official/path",
            "analysis/reports/a6400-tw-v2.00.json",
        )
        denied = (
            "http://www.sony.com.tw/official/path",
            "https://example.com/official/path",
            "https://user@www.sony.com.tw/official/path",
            "analysis/other/report.json",
            "analysis/reports/../report.json",
            "analysis\\reports\\report.json",
            "https://[",
        )

        for source in allowed:
            with self.subTest(source=source):
                document = synthetic_document()
                document["capabilities"][0]["evidence"][0]["source"] = source
                validate_evidence(document)
        for source in denied:
            with self.subTest(source=source):
                document = synthetic_document()
                document["capabilities"][0]["evidence"][0]["source"] = source
                with self.assertRaises(DecisionError):
                    validate_evidence(document)
    def test_inference_requires_an_observation_in_the_same_capability(self):
        document = synthetic_document()
        document["capabilities"][0]["evidence"] = [
            {
                "kind": "INFERENCE",
                "source": "analysis/reports/synthetic-1.json",
                "claim": "Synthetic inference.",
            }
        ]

        with self.assertRaises(DecisionError):
            validate_evidence(document)

        document["capabilities"][0]["evidence"].insert(
            0,
            {
                "kind": "OBSERVATION",
                "source": "https://www.sony.com.tw/synthetic-fixture",
                "claim": "Synthetic observation.",
            },
        )
        normalized = validate_evidence(document)
        self.assertEqual(
            [
                item["kind"]
                for item in normalized["capabilities"][0]["evidence"]
            ],
            ["OBSERVATION", "INFERENCE"],
        )

    def test_unknown_schema_fields_and_schema_version_are_rejected(self):
        cases = []

        wrong_version = synthetic_document()
        wrong_version["schema_version"] = 2
        cases.append(wrong_version)

        extra_document_field = synthetic_document()
        extra_document_field["title"] = "Synthetic override"
        cases.append(extra_document_field)

        extra_capability_field = synthetic_document()
        extra_capability_field["capabilities"][0]["confidence"] = "high"
        cases.append(extra_capability_field)

        for document in cases:
            with self.subTest(document=document), self.assertRaises(DecisionError):
                validate_evidence(document)


class DecisionRenderingTests(unittest.TestCase):
    def test_markdown_is_deterministic_ordered_and_labels_inferences(self):
        document = synthetic_document()
        document["capabilities"].reverse()
        discovery = next(
            item
            for item in document["capabilities"]
            if item["id"] == "creative-look-discovery"
        )
        discovery["evidence"].append(
            {
                "kind": "INFERENCE",
                "source": "analysis/reports/synthetic-1.json",
                "claim": "Synthetic inference 1.",
            }
        )

        first = render_markdown(document)
        second = render_markdown(copy.deepcopy(document))

        self.assertEqual(first, second)
        self.assertTrue(
            first.startswith(
                "# Sony α6400 Firmware Feasibility Decisions\n\n"
                "Generation source: validated evidence document (schema version 1)."
            )
        )
        offsets = [first.index(f"## {item}") for item in EXPECTED_CAPABILITIES]
        self.assertEqual(offsets, sorted(offsets))
        self.assertIn(
            "- **OBSERVATION** — `analysis/reports/synthetic-1.json`: "
            "Synthetic observation 1.",
            first,
        )
        self.assertIn(
            "- **INFERENCE** — `analysis/reports/synthetic-1.json`: "
            "Synthetic inference 1.",
            first,
        )
        self.assertIn("Status: `FEASIBLE`", first)
        self.assertIn("Summary: Synthetic summary 1.", first)
        self.assertIn("Next permitted action: Synthetic next action 1.", first)
        self.assertTrue(first.endswith("\n"))

    def test_renderer_rejects_invalid_documents_instead_of_adding_a_conclusion(self):
        document = synthetic_document()
        document["capabilities"][0]["status"] = "UNKNOWN"

        with self.assertRaises(DecisionError):
            render_markdown(document)


if __name__ == "__main__":
    unittest.main()
