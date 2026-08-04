import copy
import json
import unittest
from pathlib import Path

from pmca.analysis.updater_gates import (
    UpdaterGateError,
    render_updater_gate_report,
    validate_updater_gate_map,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
GATE_MAP_PATH = REPOSITORY_ROOT / "analysis" / "a6400-updater-gates.json"
REPORT_PATH = REPOSITORY_ROOT / "analysis" / "a6400-updater-re-report.md"


def committed_gate_map():
    return json.loads(GATE_MAP_PATH.read_text(encoding="utf-8"))


class UpdaterGateReportTests(unittest.TestCase):
    def test_committed_gate_map_is_valid_and_fail_closed(self):
        document = committed_gate_map()

        self.assertEqual(validate_updater_gate_map(document), document)
        self.assertFalse(document["camera_executed"])
        self.assertFalse(document["physical_transport_observed"])
        self.assertFalse(document["bypass_established"])
        self.assertFalse(document["installable"])

    def test_all_gate_layers_are_explicit_and_ordered(self):
        document = committed_gate_map()

        self.assertEqual(
            [gate["layer"] for gate in document["gates"]],
            [
                "host-wrapper",
                "transport",
                "camera-updater",
                "boot",
                "runtime-integrity",
            ],
        )
        self.assertEqual(
            [gate["status"] for gate in document["gates"]],
            ["PARTIAL", "PARTIAL", "PARTIAL", "INSUFFICIENT_EVIDENCE", "INSUFFICIENT_EVIDENCE"],
        )

    def test_static_camera_gate_evidence_is_not_promoted_to_a_bypass(self):
        document = committed_gate_map()
        camera_gate = next(
            gate for gate in document["gates"] if gate["layer"] == "camera-updater"
        )
        claims = "\n".join(item["claim"] for item in camera_gate["evidence"])

        for command in ("0x01", "0x10", "0x20", "0x30", "0x40", "0x100", "0x200"):
            self.assertIn(command, claims)
        for status in ("0x140", "0x141", "0x142"):
            self.assertIn(status, claims)
        self.assertIn("display", claims.casefold())
        self.assertIn("ModelName.ini", claims)
        self.assertFalse(document["bypass_established"])

    def test_each_gate_separates_observation_inference_and_unresolved_work(self):
        document = committed_gate_map()

        for gate in document["gates"]:
            with self.subTest(layer=gate["layer"]):
                classifications = {
                    item["classification"] for item in gate["evidence"]
                }
                self.assertIn("UNRESOLVED", classifications)
                self.assertTrue(
                    classifications.intersection({"OBSERVATION", "INFERENCE"})
                )
                self.assertTrue(gate["next_experiment"])
                self.assertTrue(gate["feature_relevance"])

    def test_report_is_deterministic_and_matches_the_committed_artifact(self):
        document = committed_gate_map()
        rendered = render_updater_gate_report(document)

        self.assertEqual(rendered, render_updater_gate_report(document))
        self.assertEqual(REPORT_PATH.read_text(encoding="utf-8"), rendered)
        self.assertIn("No physical camera transport command was observed", rendered)
        self.assertIn("0x140", rendered)
        self.assertIn("0x142", rendered)
        self.assertIn("Vertical UI", rendered)
        self.assertIn("Creative Looks", rendered)

    def test_claim_promotion_or_unknown_fields_are_rejected(self):
        document = committed_gate_map()
        cases = []

        dynamic = copy.deepcopy(document)
        dynamic["physical_transport_observed"] = True
        cases.append(dynamic)

        bypass = copy.deepcopy(document)
        bypass["bypass_established"] = True
        cases.append(bypass)

        installable = copy.deepcopy(document)
        installable["installable"] = True
        cases.append(installable)

        promoted = copy.deepcopy(document)
        boot_gate = next(g for g in promoted["gates"] if g["layer"] == "boot")
        boot_gate["status"] = "SOLVED"
        cases.append(promoted)

        extra = copy.deepcopy(document)
        extra["raw_payload"] = "deadbeef"
        cases.append(extra)

        for candidate in cases:
            with self.subTest(candidate=candidate):
                with self.assertRaises(UpdaterGateError):
                    validate_updater_gate_map(candidate)


if __name__ == "__main__":
    unittest.main()
