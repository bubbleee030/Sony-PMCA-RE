import copy
import json
import unittest
from pathlib import Path

from pmca.analysis.creative_look_stack import (
    AXIS_IDS,
    LAYER_IDS,
    LOOK_IDS,
    CreativeLookStackError,
    validate_creative_look_stack,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
STACK_PATH = REPOSITORY_ROOT / "analysis" / "a6400-creative-look-stack.json"


class CreativeLookStackTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(STACK_PATH.read_text(encoding="utf-8"))

    def test_committed_stack_has_exact_first_class_membership(self):
        validated = validate_creative_look_stack(self.document)

        self.assertEqual(validated["looks"], list(LOOK_IDS))
        self.assertEqual(validated["axes"], list(AXIS_IDS))
        self.assertEqual(list(validated["layers"]), list(LAYER_IDS))
        self.assertEqual(list(validated["axis_records"]), list(AXIS_IDS))
        self.assertEqual(
            list(validated["pipeline_outputs"]),
            ["live_view", "still_jpeg", "movie"],
        )
        self.assertTrue(
            all(
                record["status"] == "UNESTABLISHED"
                for record in validated["layers"].values()
            )
        )
        self.assertFalse(validated["native_creative_look_established"])

    def test_creative_style_fallback_cannot_establish_native_stack(self):
        candidate = copy.deepcopy(self.document)
        candidate["fallback"]["creative_style_available"] = True
        candidate["native_creative_look_established"] = True

        with self.assertRaises(CreativeLookStackError):
            validate_creative_look_stack(candidate)

    def test_axis_records_are_independent_and_unavailable_axes_stay_zero(self):
        validated = validate_creative_look_stack(self.document)

        for axis_id, record in validated["axis_records"].items():
            with self.subTest(axis_id=axis_id):
                self.assertEqual(
                    set(record),
                    {"status", "ui", "state", "pipeline", "evidence", "blocker"},
                )
                self.assertFalse(record["ui"])
                self.assertFalse(record["state"])
                self.assertFalse(record["pipeline"])

        missing = copy.deepcopy(self.document)
        del missing["axis_records"]["clarity"]

        promoted = copy.deepcopy(self.document)
        promoted["axis_records"]["clarity"]["ui"] = True

        for candidate in (missing, promoted):
            with self.subTest(candidate=candidate), self.assertRaises(
                CreativeLookStackError
            ):
                validate_creative_look_stack(candidate)

    def test_duplicate_or_reordered_membership_is_rejected(self):
        candidates = []

        candidate = copy.deepcopy(self.document)
        candidate["looks"][-1] = "ST"
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["axes"] = list(reversed(candidate["axes"]))
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["layers"] = dict(reversed(list(candidate["layers"].items())))
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                CreativeLookStackError
            ):
                validate_creative_look_stack(candidate)

    def test_non_unestablished_records_require_bounded_evidence(self):
        candidates = []

        candidate = copy.deepcopy(self.document)
        candidate["layers"]["interface"]["status"] = "TARGET_NATIVE"
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["axis_records"]["contrast"]["status"] = "APPROXIMATION_ONLY"
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["pipeline_outputs"]["still_jpeg"]["status"] = "TARGET_NATIVE"
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                CreativeLookStackError
            ):
                validate_creative_look_stack(candidate)

    def test_native_claim_requires_every_native_layer_axis_and_output(self):
        candidate = copy.deepcopy(self.document)
        candidate["native_creative_look_established"] = True

        with self.assertRaises(CreativeLookStackError):
            validate_creative_look_stack(candidate)

    def test_unknown_fields_bad_types_and_fallback_evidence_leak_are_rejected(self):
        candidates = []

        candidate = copy.deepcopy(self.document)
        candidate["unexpected"] = True
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["schema_version"] = True
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["layers"]["state"]["blocker"] = "  "
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["layers"]["base_looks"]["evidence"] = [
            {
                "source": "analysis/a6400-creative-look-guide.md",
                "path_id": "creative-style-recipes",
                "semantic": "base_looks",
                "level": "CONFIRMED",
                "claim": "Fallback recipes are not native Creative Look evidence.",
            }
        ]
        candidate["layers"]["base_looks"]["status"] = "TARGET_NATIVE"
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                CreativeLookStackError
            ):
                validate_creative_look_stack(candidate)

    def test_validated_stack_is_a_deep_copy(self):
        validated = validate_creative_look_stack(self.document)
        validated["layers"]["interface"]["blocker"] = "changed"

        self.assertNotEqual(
            validated["layers"]["interface"]["blocker"],
            self.document["layers"]["interface"]["blocker"],
        )


if __name__ == "__main__":
    unittest.main()
