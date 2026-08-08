import copy
import json
import unittest
from pathlib import Path

import pmca.analysis.creative_look_stack as creative_stack
from pmca.analysis.creative_look_stack import (
    AXIS_DEFINITIONS,
    AXIS_IDS,
    BUILT_IN_LOOK_IDS,
    CUSTOM_LOOK_IDS,
    LAYER_IDS,
    PIPELINE_OUTPUT_IDS,
    REASON_CODES,
    RESTRICTION_IDS,
    WORKFLOW_IDS,
    CreativeLookStackError,
    derive_presentation_availability,
    validate_creative_look_stack,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
STACK_PATH = REPOSITORY_ROOT / "analysis" / "a6400-creative-look-stack.json"


class CreativeLookStackTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(STACK_PATH.read_text(encoding="utf-8"))

    def test_schema_two_reference_catalog_matches_alpha7v_exactly(self):
        expected_looks = (
            "ST",
            "PT",
            "NT",
            "VV",
            "VV2",
            "FL",
            "FL2",
            "FL3",
            "IN",
            "SH",
            "BW",
            "SE",
        )
        expected_custom = tuple(f"Custom{index}" for index in range(1, 7))
        expected_axes = {
            "contrast": (-9, 9),
            "highlights": (-9, 9),
            "shadows": (-9, 9),
            "fade": (0, 9),
            "saturation": (-9, 9),
            "sharpness": (0, 9),
            "sharpness_range": (1, 5),
            "clarity": (0, 9),
        }

        validated = validate_creative_look_stack(self.document)
        self.assertEqual(validated["schema_version"], 2)
        self.assertEqual(BUILT_IN_LOOK_IDS, expected_looks)
        self.assertEqual(CUSTOM_LOOK_IDS, expected_custom)
        self.assertEqual(AXIS_DEFINITIONS, expected_axes)
        self.assertEqual(
            validated["reference_catalog"]["source"],
            "https://helpguide.sony.net/ilc/2540/v1/en/contents/"
            "0411B_creative_look.html",
        )
        self.assertEqual(
            validated["reference_catalog"]["built_in_looks"],
            list(expected_looks),
        )
        self.assertEqual(
            validated["reference_catalog"]["custom_slots"], list(expected_custom)
        )
        self.assertEqual(
            list(validated["reference_catalog"]["axes"]), list(AXIS_IDS)
        )
        for axis_id, (minimum, maximum) in expected_axes.items():
            with self.subTest(axis_id=axis_id):
                self.assertEqual(
                    validated["reference_catalog"]["axes"][axis_id],
                    {"minimum": minimum, "maximum": maximum, "default": None},
                )

    def test_reference_workflows_and_restrictions_are_exact(self):
        validated = validate_creative_look_stack(self.document)

        self.assertEqual(
            WORKFLOW_IDS,
            (
                "select_look",
                "edit_axes",
                "modified_marker",
                "reset_one_look",
                "select_custom_base",
            ),
        )
        self.assertEqual(
            RESTRICTION_IDS,
            (
                "intelligent_auto",
                "picture_profile_not_off",
                "flexible_iso_log",
                "bw_se_saturation",
                "movie_sharpness_range",
            ),
        )
        self.assertEqual(
            validated["reference_catalog"]["workflow_actions"], list(WORKFLOW_IDS)
        )
        self.assertEqual(
            list(validated["reference_catalog"]["restrictions"]),
            list(RESTRICTION_IDS),
        )
        self.assertNotIn("copy_select", validated["workflow_records"])

    def test_all_reference_items_are_visible_and_currently_disabled(self):
        validated = validate_creative_look_stack(self.document)
        presentation = validated["presentation"]

        self.assertEqual(presentation, derive_presentation_availability(validated))
        expected_sections = {
            "looks": BUILT_IN_LOOK_IDS,
            "custom_slots": CUSTOM_LOOK_IDS,
            "axes": AXIS_IDS,
            "workflow_actions": WORKFLOW_IDS,
            "restriction_rules": RESTRICTION_IDS,
            "output_bindings": PIPELINE_OUTPUT_IDS,
        }
        for section, identifiers in expected_sections.items():
            self.assertEqual(list(presentation[section]), list(identifiers))
            for identifier, record in presentation[section].items():
                with self.subTest(section=section, identifier=identifier):
                    self.assertEqual(record["visibility"], "VISIBLE")
                    self.assertEqual(record["availability"], "DISABLED_UNPROVEN")
                    self.assertTrue(record["reasons"])
                    self.assertTrue(set(record["reasons"]).issubset(REASON_CODES))

    def test_partial_axis_evidence_cannot_enable_an_axis(self):
        candidate = copy.deepcopy(self.document)
        record = candidate["axis_records"]["contrast"]
        record.update(
            {
                "status": "APPROXIMATION_ONLY",
                "ui": True,
                "state": True,
                "range": True,
                "default": True,
                "pipeline": False,
                "evidence": [
                    {
                        "source": "analysis/a6400-creative-look-boundary.json",
                        "path_id": "creative-style-contrast-fallback",
                        "semantic": "contrast",
                        "level": "PARTIAL",
                        "claim": "Creative Style exposes a fallback contrast control.",
                    }
                ],
            }
        )
        candidate["presentation"] = derive_presentation_availability(candidate)

        validated = validate_creative_look_stack(candidate)
        availability = validated["presentation"]["axes"]["contrast"]
        self.assertEqual(availability["availability"], "DISABLED_UNPROVEN")
        self.assertIn("AXIS_PIPELINE_UNPROVEN", availability["reasons"])

    def test_stale_membership_workflow_and_ranges_are_rejected(self):
        candidates = []

        candidate = copy.deepcopy(self.document)
        candidate["reference_catalog"]["built_in_looks"].remove("FL2")
        candidate["reference_catalog"]["built_in_looks"].remove("FL3")
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["reference_catalog"]["workflow_actions"] = ["copy_select"]
        candidates.append(candidate)

        for axis_id, minimum in (
            ("sharpness", -9),
            ("sharpness_range", 0),
            ("clarity", -9),
        ):
            candidate = copy.deepcopy(self.document)
            candidate["reference_catalog"]["axes"][axis_id]["minimum"] = minimum
            candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                CreativeLookStackError
            ):
                validate_creative_look_stack(candidate)

    def test_presentation_is_derived_not_authored_freely(self):
        candidate = copy.deepcopy(self.document)
        candidate["presentation"]["looks"]["ST"]["availability"] = "ENABLED_OFFLINE"
        candidate["presentation"]["looks"]["ST"]["reasons"] = []

        with self.assertRaises(CreativeLookStackError):
            validate_creative_look_stack(candidate)

    def test_creative_style_fallback_is_separate_and_cannot_promote_native(self):
        validated = validate_creative_look_stack(self.document)
        fallback = validated["fallback"]

        self.assertEqual(fallback["status"], "APPROXIMATION_ONLY")
        self.assertEqual(fallback["policy"], "LAST_RESORT_ONLY")
        self.assertFalse(fallback["native_claim_basis"])
        self.assertEqual(
            fallback["represented_reference_looks"],
            ["ST", "PT", "NT", "VV", "VV2", "FL", "IN", "SH", "BW", "SE"],
        )
        self.assertEqual(fallback["unrepresented_reference_looks"], ["FL2", "FL3"])

        candidate = copy.deepcopy(self.document)
        candidate["fallback"]["native_claim_basis"] = True
        candidate["native_creative_look_established"] = True
        with self.assertRaises(CreativeLookStackError):
            validate_creative_look_stack(candidate)

    def test_capability_records_are_independent_and_fail_closed(self):
        validated = validate_creative_look_stack(self.document)

        self.assertEqual(list(validated["layers"]), list(LAYER_IDS))
        self.assertEqual(list(validated["look_records"]), list(BUILT_IN_LOOK_IDS))
        self.assertEqual(list(validated["custom_records"]), list(CUSTOM_LOOK_IDS))
        self.assertEqual(list(validated["axis_records"]), list(AXIS_IDS))
        self.assertEqual(list(validated["workflow_records"]), list(WORKFLOW_IDS))
        self.assertEqual(
            list(validated["restriction_records"]), list(RESTRICTION_IDS)
        )
        self.assertEqual(
            list(validated["pipeline_outputs"]), list(PIPELINE_OUTPUT_IDS)
        )
        for collection in (
            "layers",
            "look_records",
            "custom_records",
            "axis_records",
            "workflow_records",
            "restriction_records",
            "pipeline_outputs",
        ):
            for identifier, record in validated[collection].items():
                with self.subTest(collection=collection, identifier=identifier):
                    self.assertEqual(record["status"], "UNESTABLISHED")
                    self.assertEqual(record["evidence"], [])
                    self.assertTrue(record["blocker"])

    def test_non_unestablished_records_require_bounded_evidence(self):
        candidates = []
        for collection, identifier in (
            ("layers", "interface"),
            ("look_records", "ST"),
            ("custom_records", "Custom1"),
            ("axis_records", "contrast"),
            ("workflow_records", "select_look"),
            ("restriction_records", "intelligent_auto"),
            ("pipeline_outputs", "still_jpeg"),
        ):
            candidate = copy.deepcopy(self.document)
            candidate[collection][identifier]["status"] = "TARGET_NATIVE"
            candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                CreativeLookStackError
            ):
                validate_creative_look_stack(candidate)

    def test_safety_snapshot_remains_fail_closed(self):
        validated = validate_creative_look_stack(self.document)
        safety = validated["safety"]
        self.assertEqual(
            safety["reference"], "analysis/a6400-stock-200-recovery.json"
        )
        self.assertRegex(safety["canonical_report_sha256"], r"[0-9a-f]{64}\Z")
        self.assertEqual(safety["readiness"], "BLOCKED_STATIC_EVIDENCE")
        self.assertFalse(safety["recovery_validated"])
        self.assertFalse(safety["camera_test_eligible"])
        self.assertFalse(safety["installable"])

        for field, value in (
            ("readiness", "READY"),
            ("recovery_validated", True),
            ("camera_test_eligible", True),
            ("installable", True),
        ):
            candidate = copy.deepcopy(self.document)
            candidate["safety"][field] = value
            with self.subTest(field=field), self.assertRaises(
                CreativeLookStackError
            ):
                validate_creative_look_stack(candidate)

    def test_native_claim_requires_every_capability_and_output(self):
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
