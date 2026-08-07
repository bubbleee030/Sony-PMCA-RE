import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from pmca.analysis.recovery_path import validate_recovery_report

from pmca.analysis.decisions import (
    DecisionError,
    REQUIRED_CAPABILITIES,
    derive_recovery_capability,
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

APPROVED_REPORT = "analysis/reports/a6400-tw-v2.00.json"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_PATH = REPOSITORY_ROOT / "analysis" / "feature-evidence.json"
FEASIBILITY_REPORT_PATH = (
    REPOSITORY_ROOT / "analysis" / "a6400-feasibility-report.md"
)
RUNBOOK_PATH = (
    REPOSITORY_ROOT
    / "docs"
    / "superpowers"
    / "runbooks"
    / "a6400-stock-200-recovery-readiness.md"
)
APPROVED_SONY_URL = (
    "https://www.sony.com.tw/zh/electronics/support/"
    "e-mount-body-ilce-6000-series/ilce-6400/downloads/00016145"
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
                        "source": APPROVED_REPORT,
                        "claim": f"Synthetic observation {index + 1}.",
                    }
                ],
                "next_action": f"Synthetic next action {index + 1}.",
            }
        )
    capabilities[-1] = derive_recovery_capability()
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
            derive_recovery_capability()["evidence"][0]["claim"],
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
            APPROVED_SONY_URL,
            "https://www.sony.com.tw/zh/electronics/support/"
            "e-mount-body-ilce-6000-series/ilce-6700/software/00298440",
            "https://helpguide.sony.net/ilc/2320/v1/en/contents/"
            "0411B_creative_look.html",
            "https://helpguide.sony.net/ilc/2320/v1/en/contents/"
            "211h_touchpanel_settings.html",
            "https://helpguide.sony.net/ilc/2320/v1/en/contents/"
            "221h_touch_function_icon.html",
            "https://helpguide.sony.net/ilc/1810/v1/en/contents/"
            "TP0002264693.html",
            "https://helpguide.sony.net/ilc/1810/v1/en/contents/"
            "TP0002278024.html",
            "https://helpguide.sony.net/ilc/1810/v1/en/contents/"
            "TP0002241295.html",
            "https://helpguide.sony.net/ilc/1810/v1/en/contents/"
            "TP0002280339.html",
            "https://helpguide.sony.net/ilc/2540/v1/en/contents/"
            "251h_vertical_ui_display.html",
            "analysis/reports/a6400-tw-v2.00.json",
            "analysis/reports/a6700-tw-v2.00.json",
            "analysis/reports/a7v-tw-v2.00.json",
            "analysis/structures/a6400-tw-v2.00.json",
            "analysis/structures/a6700-tw-v2.00.json",
            "analysis/structures/a7v-tw-v2.00.json",
            "analysis/tool-baselines/ma1co-fwtool.json",
            "analysis/tool-baselines/joeording3-fwtool.json",
            "analysis/tool-baselines/ironpayne22-fwtool.json",
            "analysis/signature-experiments.json",
            "analysis/feature-compatibility.json",
            "analysis/creative-look-recipes.json",
            "analysis/a6400-creative-look-guide.md",
            "analysis/firmware-manifest.json",
            "analysis/tool-provenance.json",
            "analysis/a6400-stock-200-bundle.json",
            "analysis/a6400-recovery-scenarios.json",
            "analysis/a6400-stock-200-recovery.json",
            "README.md",
        )
        denied = (
            "http://www.sony.com.tw/official/path",
            "https://example.com/official/path",
            "https://user@www.sony.com.tw/official/path",
            "https://www.sony.com.tw/unreviewed/path",
            "https://helpguide.sony.net/unreviewed/path",
            f"{APPROVED_SONY_URL}?download=1",
            f"{APPROVED_SONY_URL}#requirements",
            "analysis/other/report.json",
            "analysis/reports/unreviewed.json",
            "analysis/reports/../report.json",
            "analysis\\reports\\report.json",
            "docs/README.md",
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

    def test_free_text_rejects_line_breaks_and_control_characters(self):
        mutations = (
            ("summary LF", "summary", "First line\nSecond line"),
            ("summary CR", "summary", "First line\rSecond line"),
            ("next action tab", "next_action", "Next\taction"),
            ("claim NUL", "claim", "Claim\x00suffix"),
            ("claim C1 control", "claim", "Claim\u0085suffix"),
        )

        for name, field, value in mutations:
            with self.subTest(name=name):
                document = synthetic_document()
                if field == "claim":
                    document["capabilities"][0]["evidence"][0][field] = value
                else:
                    document["capabilities"][0][field] = value
                with self.assertRaises(DecisionError):
                    validate_evidence(document)

    def test_free_text_fields_have_a_finite_size_limit(self):
        for field in ("summary", "next_action", "claim"):
            with self.subTest(field=field):
                document = synthetic_document()
                if field == "claim":
                    document["capabilities"][0]["evidence"][0][field] = "x" * 5000
                else:
                    document["capabilities"][0][field] = "x" * 5000
                with self.assertRaises(DecisionError):
                    validate_evidence(document)

    def test_inference_requires_an_observation_in_the_same_capability(self):
        document = synthetic_document()
        document["capabilities"][0]["evidence"] = [
            {
                "kind": "INFERENCE",
                "source": APPROVED_REPORT,
                "claim": "Synthetic inference.",
            }
        ]

        with self.assertRaises(DecisionError):
            validate_evidence(document)

        document["capabilities"][0]["evidence"].insert(
            0,
            {
                "kind": "OBSERVATION",
                "source": APPROVED_SONY_URL,
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

    def test_real_recovery_decision_is_derived_from_strict_reports(self):
        document = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
        recovery = next(
            item
            for item in validate_evidence(document)["capabilities"]
            if item["id"] == "recovery"
        )

        self.assertEqual(recovery, derive_recovery_capability())
        self.assertEqual(recovery["status"], "BLOCKED")
        self.assertEqual(
            [item["source"] for item in recovery["evidence"]],
            [
                "analysis/a6400-stock-200-bundle.json",
                "analysis/a6400-recovery-scenarios.json",
                "analysis/a6400-stock-200-recovery.json",
                "analysis/a6400a-updater-control-bootstrap.json",
                "analysis/a6400-stock-200-recovery.json",
            ],
        )
        self.assertIn(
            "different-model",
            recovery["evidence"][3]["claim"].casefold(),
        )

    def test_recovery_decision_cannot_be_manually_promoted_or_reworded(self):
        base = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
        index = next(
            index
            for index, item in enumerate(base["capabilities"])
            if item["id"] == "recovery"
        )
        mutations = (
            ("status", "FEASIBLE"),
            ("summary", "Recovery works."),
            ("next_action", "Proceed."),
        )
        for field, value in mutations:
            document = copy.deepcopy(base)
            document["capabilities"][index][field] = value
            with self.subTest(field=field), self.assertRaises(DecisionError):
                validate_evidence(document)

    def test_future_static_readiness_still_cannot_authorize_camera_testing(self):
        recovery_path = REPOSITORY_ROOT / "analysis" / "a6400-stock-200-recovery.json"
        future = validate_recovery_report(
            json.loads(recovery_path.read_text(encoding="utf-8"))
        )
        future["readiness"] = "READY_FOR_FUTURE_VALIDATION_DESIGN"
        future["readiness_basis"] = {
            "authenticated_stock_bundle": True,
            "runtime_independent_entry_established": True,
            "write_scope_established": True,
            "write_order_established": True,
            "post_write_verification_established": True,
            "scenario_overclaim_count": 0,
        }

        with patch(
            "pmca.analysis.decisions.validate_recovery_report",
            return_value=future,
        ):
            recovery = derive_recovery_capability({})

        self.assertEqual(recovery["status"], "BLOCKED")
        self.assertIn("design", recovery["summary"].lower())
        self.assertIn("fresh authorization", recovery["next_action"].lower())
        self.assertNotIn("camera_test_eligible true", str(recovery).lower())

    def test_recovery_readiness_runbook_is_non_operational_and_complete(self):
        text = RUNBOOK_PATH.read_text(encoding="utf-8")

        for required in (
            "a6400-tw-v2.00",
            "official-updater-reinstall",
            "usb-recovery-or-updater-mode",
            "independent-maintenance-path",
            "modified-ui-runtime-failure",
            "interrupted-feature-update",
            "nonbooting-application-layer",
            "version-or-downgrade-rejection",
            "boot-chain-failure",
            "power-loss-during-stock-restore",
            "BLOCKED_STATIC_EVIDENCE",
            "camera_test_eligible=false",
            "recovery_validated=false",
        ):
            with self.subTest(required=required):
                self.assertIn(required, text)
        for forbidden in (
            "diskpart",
            "fastboot",
            "DeviceIoControl",
            "write partition",
            "service-mode command",
            "firmware payload path",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden.lower(), text.lower())


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
                "source": APPROVED_REPORT,
                "claim": "Synthetic inference 1.",
            }
        )

        first = render_markdown(document)
        second = render_markdown(copy.deepcopy(document))

        self.assertEqual(first, second)
        self.assertTrue(
            first.startswith(
                "# Sony α6400 Firmware Feasibility Decisions\n\n"
                "Generated decision section source: validated evidence document "
                "(schema version 1)."
            )
        )
        offsets = [first.index(f"## {item}") for item in EXPECTED_CAPABILITIES]
        self.assertEqual(offsets, sorted(offsets))
        self.assertIn(
            "- **OBSERVATION** — `analysis/reports/a6400-tw-v2.00.json`: "
            "Synthetic observation 1.",
            first,
        )
        self.assertIn(
            "- **INFERENCE** — `analysis/reports/a6400-tw-v2.00.json`: "
            "Synthetic inference 1.",
            first,
        )
        self.assertIn("Status: `FEASIBLE`", first)
        self.assertIn("Summary: Synthetic summary 1.", first)
        self.assertIn("Next permitted action: Synthetic next action 1.", first)
        self.assertTrue(first.endswith("\n"))

    def test_committed_report_generated_prefix_matches_validated_evidence(self):
        document = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
        report = FEASIBILITY_REPORT_PATH.read_text(encoding="utf-8")
        marker = "\n\n# Integrated Offline Research Result"

        self.assertIn(marker, report)
        committed_prefix = report.split(marker, 1)[0] + "\n"
        self.assertEqual(committed_prefix, render_markdown(document))
        normalized = " ".join(report.split())
        self.assertIn("Creative Look remains the product goal", normalized)
        self.assertIn("Creative Style is the target-native substrate", normalized)
        self.assertIn("registration does not prove runtime invocation", normalized)
        self.assertIn("static table equality does not prove a runtime transaction", normalized)
        self.assertIn("BLOCKED_STATIC_EVIDENCE", normalized)

    def test_renderer_rejects_invalid_documents_instead_of_adding_a_conclusion(self):
        document = synthetic_document()
        document["capabilities"][0]["status"] = "UNKNOWN"

        with self.assertRaises(DecisionError):
            render_markdown(document)

    def test_renderer_rejects_output_over_a_finite_size_ceiling(self):
        document = synthetic_document()
        document["capabilities"][0]["evidence"] = [
            {
                "kind": "OBSERVATION",
                "source": APPROVED_REPORT,
                "claim": f"Bounded claim {index}: " + ("x" * 1900),
            }
            for index in range(40)
        ]

        with self.assertRaises(DecisionError):
            render_markdown(document)


if __name__ == "__main__":
    unittest.main()
