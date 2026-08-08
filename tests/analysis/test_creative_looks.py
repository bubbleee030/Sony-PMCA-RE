import copy
import unittest
from pathlib import Path

from pmca.analysis.creative_look_stack import BUILT_IN_LOOK_IDS
from pmca.analysis.creative_looks import (
    DIRECT_STYLE_MAP,
    INFERRED_STYLE_MAP,
    LOOK_CODES,
    A6400Recipe,
    CreativeLookError,
    ModernLook,
    render_recipe_guide,
    translate_to_a6400,
    validate_recipe_document,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def _look(code, **changes):
    values = {
        "code": code,
        "base": code,
        "contrast": 0,
        "highlights": 0,
        "shadows": 0,
        "fade": 0,
        "saturation": 0,
        "sharpness": 0,
        "sharpness_range": 1,
        "clarity": 0,
        "wb_kelvin": None,
        "wb_shift_ab": 0,
        "wb_shift_gm": 0,
        "source": "https://helpguide.sony.net/fixture",
    }
    values.update(changes)
    return ModernLook(**values)


def synthetic_document():
    defaults = []
    for code in LOOK_CODES:
        modern = _look(code)
        recipe = translate_to_a6400(modern)
        defaults.append(
            {
                "source_kind": "creative-style-fallback-approximation",
                "modern": modern.__dict__ if hasattr(modern, "__dict__") else {
                    field: getattr(modern, field) for field in modern.__dataclass_fields__
                },
                "a6400": {
                    field: list(getattr(recipe, field))
                    if field == "unrepresented_axes"
                    else getattr(recipe, field)
                    for field in recipe.__dataclass_fields__
                },
                "note": "Synthetic translation; not an exact Sony colorimetric match.",
            }
        )
    return {
        "schema_version": 2,
        "artifact_role": "CREATIVE_STYLE_FALLBACK",
        "native_claim_basis": False,
        "reference_source": "https://helpguide.sony.net/ilc/2540/v1/en/contents/0411B_creative_look.html",
        "creative_style_source": "https://helpguide.sony.net/ilc/1810/v1/en/contents/TP0002264693.html",
        "represented_reference_looks": list(LOOK_CODES),
        "unrepresented_reference_looks": ["FL2", "FL3"],
        "defaults": defaults,
        "community_experiments": [],
        "disclaimer": "These are starting points, not exact Sony colorimetric matches.",
        "validation_protocol": [
            "same lens",
            "same scene",
            "same exposure",
            "same lighting",
            "same white balance",
            "same JPEG settings",
            "no postprocessing",
        ],
    }


class CreativeLookTranslationTests(unittest.TestCase):
    def test_mapping_contract_is_exact(self):
        self.assertEqual(
            LOOK_CODES,
            ("ST", "PT", "NT", "VV", "VV2", "FL", "IN", "SH", "BW", "SE"),
        )
        self.assertEqual(
            DIRECT_STYLE_MAP,
            {
                "ST": "Standard",
                "PT": "Portrait",
                "NT": "Neutral",
                "VV": "Vivid",
                "BW": "B/W",
                "SE": "Sepia",
            },
        )
        self.assertEqual(
            INFERRED_STYLE_MAP,
            {"VV2": "Clear", "FL": "Deep", "IN": "Neutral", "SH": "Light"},
        )

    def test_translation_clamps_target_axes_and_lists_missing_modern_axes(self):
        recipe = translate_to_a6400(
            _look(
                "FL",
                contrast=-8,
                highlights=-2,
                shadows=3,
                fade=1,
                saturation=7,
                sharpness=7,
                sharpness_range=2,
                clarity=4,
                wb_kelvin=5600,
                wb_shift_ab=2,
                wb_shift_gm=-1,
            )
        )

        self.assertEqual(recipe.creative_style, "Deep")
        self.assertEqual((recipe.contrast, recipe.saturation, recipe.sharpness), (-3, 3, 3))
        self.assertEqual(recipe.wb_kelvin, 5600)
        self.assertEqual((recipe.wb_shift_ab, recipe.wb_shift_gm), (2, -1))
        self.assertEqual(recipe.confidence, "INFERRED")
        self.assertEqual(
            recipe.unrepresented_axes,
            ("highlights", "shadows", "fade", "sharpness_range", "clarity"),
        )

    def test_direct_mappings_are_partial_not_exact(self):
        for code, style in DIRECT_STYLE_MAP.items():
            with self.subTest(code=code):
                recipe = translate_to_a6400(_look(code))
                self.assertEqual(recipe.creative_style, style)
                self.assertEqual(recipe.confidence, "PARTIAL")

    def test_catalog_requires_all_ten_unique_valid_entries(self):
        validated = validate_recipe_document(synthetic_document())
        self.assertEqual(tuple(item["modern"]["code"] for item in validated["defaults"]), LOOK_CODES)
        self.assertEqual(
            tuple(validated["represented_reference_looks"]), LOOK_CODES
        )
        self.assertEqual(
            validated["unrepresented_reference_looks"], ["FL2", "FL3"]
        )
        self.assertEqual(
            set(validated["represented_reference_looks"])
            | set(validated["unrepresented_reference_looks"]),
            set(BUILT_IN_LOOK_IDS),
        )

        invalid = synthetic_document()
        invalid["defaults"][0]["modern"]["code"] = "BAD"
        with self.assertRaises(CreativeLookError):
            validate_recipe_document(invalid)

    def test_values_sources_and_unrepresented_axes_are_validated(self):
        cases = []
        bad_range = synthetic_document()
        bad_range["defaults"][0]["a6400"]["contrast"] = 4
        cases.append(bad_range)
        bad_kelvin = synthetic_document()
        bad_kelvin["defaults"][0]["modern"]["wb_kelvin"] = 1200
        cases.append(bad_kelvin)
        bad_shift = synthetic_document()
        bad_shift["defaults"][0]["a6400"]["wb_shift_ab"] = 10
        cases.append(bad_shift)
        bad_url = synthetic_document()
        bad_url["defaults"][0]["modern"]["source"] = "http://example.com"
        cases.append(bad_url)
        dropped_axis = synthetic_document()
        dropped_axis["defaults"][0]["modern"]["highlights"] = 1
        cases.append(dropped_axis)
        stale_sharpness = synthetic_document()
        stale_sharpness["defaults"][0]["modern"]["sharpness"] = -1
        cases.append(stale_sharpness)
        stale_range = synthetic_document()
        stale_range["defaults"][0]["modern"]["sharpness_range"] = 0
        cases.append(stale_range)
        stale_clarity = synthetic_document()
        stale_clarity["defaults"][0]["modern"]["clarity"] = -1
        cases.append(stale_clarity)
        for document in cases:
            with self.subTest(document=document):
                with self.assertRaises(CreativeLookError):
                    validate_recipe_document(document)

    def test_guide_contains_all_codes_protocol_and_no_exact_claim(self):
        guide = render_recipe_guide(synthetic_document())
        for code in LOOK_CODES:
            self.assertIn(f"| {code} |", guide)
        for condition in synthetic_document()["validation_protocol"]:
            self.assertIn(condition, guide)
        self.assertIn("not exact Sony colorimetric matches", guide)
        self.assertIn("four Style Boxes", guide)
        self.assertIn("FL2 and FL3 have no fallback representation", guide)
        self.assertNotIn("| FL2 |", guide)
        self.assertNotIn("| FL3 |", guide)

    def test_fallback_role_native_claim_and_fabricated_recipes_are_rejected(self):
        candidates = []

        candidate = synthetic_document()
        candidate["artifact_role"] = "NATIVE_CREATIVE_LOOK"
        candidates.append(candidate)

        candidate = synthetic_document()
        candidate["native_claim_basis"] = True
        candidates.append(candidate)

        candidate = synthetic_document()
        candidate["defaults"].append(copy.deepcopy(candidate["defaults"][0]))
        candidate["defaults"][-1]["modern"]["code"] = "FL2"
        candidate["defaults"][-1]["modern"]["base"] = "FL2"
        candidate["defaults"][-1]["a6400"]["code"] = "FL2"
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                CreativeLookError
            ):
                validate_recipe_document(candidate)

    def test_committed_guide_is_prominently_fallback_only(self):
        guide = (
            REPOSITORY_ROOT / "analysis" / "a6400-creative-look-guide.md"
        ).read_text(encoding="utf-8")
        normalized = " ".join(guide.split())

        self.assertLess(guide.index("## Fallback-only status"), guide.index("## On-camera setup"))
        self.assertIn("LAST_RESORT_ONLY", guide)
        self.assertIn("does not reproduce the Creative Look interface", normalized)
        self.assertIn("eight-axis adjustment model", normalized)
        self.assertIn("authenticated base-look tables", normalized)
        self.assertIn("Nothing in this guide establishes native Creative Look support", normalized)
        self.assertIn("Sony-exact colorimetry", normalized)

    def test_deep_dive_reports_first_class_result_before_fallback(self):
        report = (
            REPOSITORY_ROOT
            / "analysis"
            / "a6400a-updater-and-creative-style-deep-dive.md"
        ).read_text(encoding="utf-8")
        normalized = " ".join(report.split())

        self.assertLess(
            report.index("## First-class Creative Look boundary result"),
            report.index("## Native α6400 Creative Style selector"),
        )
        self.assertIn("all five Creative Look layers remain `UNESTABLISHED`", normalized)
        self.assertIn("all eight axes remain independently `UNESTABLISHED`", normalized)
        self.assertIn("live view, still JPEG, and movie", normalized)
        self.assertIn("Creative Look remains the product goal", normalized)
        self.assertIn("Creative Style is the target-native substrate", normalized)
        self.assertIn("registration does not prove runtime invocation", normalized)
        self.assertIn("static table equality does not prove a runtime transaction", normalized)
        self.assertIn("fixed numeric domains and static setter/getter family equality", normalized)
        self.assertIn("independently supplied runtime indices", normalized)
        self.assertIn("BLOCKED_STATIC_EVIDENCE", normalized)
        for stale in (
            "master layout factory at `0x181f18`",
            "vertical-info layout factory at `0x24222c`",
            "five individual class-ID owners",
            "without assigning numeric record IDs",
            "numeric semantics of all dynamic backup ID sources",
        ):
            self.assertNotIn(stale, normalized)


if __name__ == "__main__":
    unittest.main()
